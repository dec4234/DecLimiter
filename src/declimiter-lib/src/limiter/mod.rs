pub mod adapter_management;
pub mod network;
pub mod packets;

use crate::error::DecLimiterError;
use crate::limiter::network::{FlowAddress, FlowEntry, parse_flow_dest, parse_flow_source};
use crate::limiter::packets::{TokenBucket, read_packet, reinject_packet};
use crate::util::get_process_name;
use log::{debug, error, trace};
use ndisapi::{DirectionFlags, IntermediateBuffer, Ndisapi};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::sleep;

pub type ProcessPair = (u32, String);

const ETHERNET_HEADER_LEN: usize = 14;
const SPEED_UPDATE_INTERVAL: Duration = Duration::from_secs(1);
const STALE_ENTRY_TIMEOUT: Duration = Duration::from_secs(30);
const STALE_FLOW_TIMEOUT: Duration = Duration::from_secs(120);

/// Per-process speed limit configuration.
#[derive(Debug, Clone)]
pub struct LimitConfig {
	pub download_byterate: Option<u64>,
	pub upload_byterate: Option<u64>,
}

/// Shared map of PID -> speed limits.
pub type LimitsMap = Arc<std::sync::RwLock<HashMap<u32, LimitConfig>>>;

/// Snapshot of a single process's network traffic.
#[derive(Debug, Clone)]
pub struct ProcessTraffic {
	pub pid: u32,
	pub name: String,
	pub download_bytes: u64,
	pub upload_bytes: u64,
	pub download_speed: f64,
	pub upload_speed: f64,
}

/// Internal mutable state for tracking a process's traffic.
struct ProcessTrafficInner {
	name: String,
	download_bytes: u64,
	upload_bytes: u64,
	prev_download_bytes: u64,
	prev_upload_bytes: u64,
	download_speed: f64,
	upload_speed: f64,
	last_seen: Instant,
}

/// Aggregate byte counters for all traffic passing through the monitor,
/// regardless of whether PID attribution succeeded.
struct TotalTrafficCounters {
	download_bytes: u64,
	upload_bytes: u64,
	prev_download_bytes: u64,
	prev_upload_bytes: u64,
	download_speed: f64,
	upload_speed: f64,
}

/// Per-PID throttle state kept locally in the packet processing thread.
/// Uses token buckets to calculate reinjection delays without blocking.
struct ThrottleState {
	dl_bucket: Option<TokenBucket>,
	ul_bucket: Option<TokenBucket>,
}

impl ThrottleState {
	fn new() -> Self {
		Self { dl_bucket: None, ul_bucket: None }
	}

	/// Get or create the download bucket, updating the rate if it changed.
	fn dl(&mut self, rate: u64) -> &mut TokenBucket {
		self.dl_bucket.get_or_insert_with(|| TokenBucket::new(rate))
	}

	/// Get or create the upload bucket, updating the rate if it changed.
	fn ul(&mut self, rate: u64) -> &mut TokenBucket {
		self.ul_bucket.get_or_insert_with(|| TokenBucket::new(rate))
	}
}

#[derive(Clone)]
pub struct DecLimiter {
	map: Arc<RwLock<HashMap<FlowAddress, FlowEntry>>>,
	traffic: Arc<std::sync::RwLock<HashMap<u32, ProcessTrafficInner>>>,
	totals: Arc<std::sync::RwLock<TotalTrafficCounters>>,
	limits: LimitsMap,
}

impl DecLimiter {
	pub fn new() -> Result<Self, DecLimiterError> {
		let driver = Ndisapi::new("NDISRD").map_err(DecLimiterError::WindowsError)?;

		debug!("Detected Windows Packet Filter version {}", driver.get_version().map_err(DecLimiterError::WindowsError)?);

		let adapters = driver.get_tcpip_bound_adapters_info().map_err(DecLimiterError::WindowsError)?;

		if adapters.is_empty() {
			return Err(DecLimiterError::NoAdapterFound);
		}

		for (i, adapter) in adapters.iter().enumerate() {
			debug!("Available adapter [{}]: {}", i, adapter.get_name());
		}

		Ok(Self {
			map: Arc::new(RwLock::new(HashMap::new())),
			traffic: Arc::new(std::sync::RwLock::new(HashMap::new())),
			totals: Arc::new(std::sync::RwLock::new(TotalTrafficCounters {
				download_bytes: 0,
				upload_bytes: 0,
				prev_download_bytes: 0,
				prev_upload_bytes: 0,
				download_speed: 0.0,
				upload_speed: 0.0,
			})),
			limits: Arc::new(std::sync::RwLock::new(HashMap::new())),
		})
	}

	/// Returns a clone of the shared limits map for external mutation (e.g. from the GUI).
	pub fn limits(&self) -> LimitsMap {
		self.limits.clone()
	}

	/// Check if the given PID matches the PID associated with the given flow address.
	fn pid_matches_blocking(map: &Arc<RwLock<HashMap<FlowAddress, FlowEntry>>>, flow: &FlowAddress, pid: u32) -> bool {
		let map_lock = map.blocking_read();
		if let Some(entry) = map_lock.get(flow) {
			return entry.pid == pid;
		}
		// Fallback: UDP sockets bound to INADDR_ANY (0.0.0.0 / ::) appear in
		// the connection table with a wildcard IP, but inbound packets carry the
		// machine's specific IP.  Try matching by port alone against those entries.
		let unspec = match flow.ip {
			IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
			IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
		};
		let wildcard = FlowAddress::new(unspec, flow.port);
		map_lock.get(&wildcard).map_or(false, |entry| entry.pid == pid)
	}

	/// Record bytes in the total and per-PID traffic counters.
	/// Called at *reinjection* time so the speed display reflects actual
	/// delivered throughput, not intercepted-but-queued traffic.
	fn count_traffic(totals: &Arc<std::sync::RwLock<TotalTrafficCounters>>, traffic: &Arc<std::sync::RwLock<HashMap<u32, ProcessTrafficInner>>>, pid: Option<u32>, is_outbound: bool, frame_len: usize) {
		if let Ok(mut t) = totals.write() {
			if is_outbound {
				t.upload_bytes += frame_len as u64;
			} else {
				t.download_bytes += frame_len as u64;
			}
		}

		if let Some(pid) = pid.filter(|&p| p != 0) {
			if let Ok(mut traffic_lock) = traffic.write() {
				let inner = traffic_lock.entry(pid).or_insert_with(|| {
					let name = get_process_name(pid).unwrap_or_else(|| format!("PID {}", pid));
					ProcessTrafficInner {
						name,
						download_bytes: 0,
						upload_bytes: 0,
						prev_download_bytes: 0,
						prev_upload_bytes: 0,
						download_speed: 0.0,
						upload_speed: 0.0,
						last_seen: Instant::now(),
					}
				});
				if is_outbound {
					inner.upload_bytes += frame_len as u64;
				} else {
					inner.download_bytes += frame_len as u64;
				}
				inner.last_seen = Instant::now();
			}
		}
	}

	/// Polls the Windows TCP/UDP connection tables to build PID-to-port mappings.
	pub fn start(&self) -> JoinHandle<Result<(), DecLimiterError>> {
		let map = self.map.clone();

		tokio::spawn(async move {
			debug!("Starting PID-to-port mapping via connection table polling...");

			loop {
				let mappings = network::get_pid_port_mappings();

				{
					let mut map_lock = map.write().await;
					for (ip, port, pid) in mappings {
						let flow = FlowAddress::new(ip, port);
						map_lock
							.entry(flow)
							.and_modify(|e| {
								e.pid = pid;
								e.update_last_seen();
							})
							.or_insert(FlowEntry::new(pid));
					}
				}

				sleep(Duration::from_millis(100)).await;
			}
		})
	}

	/// Limit network speed for a specific process via its PID.
	/// Intercepts packets on ALL adapters to match WinDivert's behavior.
	/// Throttled packets are deferred into a delay queue so non-target traffic
	/// is never blocked.
	pub fn limit_speed_pid(&self, pid: u32, download_byterate: Option<u64>, upload_byterate: Option<u64>) -> JoinHandle<Result<(), DecLimiterError>> {
		let map = self.map.clone();

		tokio::task::spawn_blocking(move || {
			debug!("Starting speed limiter for PID: {} (download: {:?}, upload: {:?})", pid, download_byterate, upload_byterate);

			let driver = Ndisapi::new("NDISRD").map_err(DecLimiterError::WindowsError)?;
			let (adapter_handles, events) = adapter_management::setup_adapters(&driver)?;

			let mut packet = IntermediateBuffer::default();
			let mut dl_bucket: Option<TokenBucket> = download_byterate.map(TokenBucket::new);
			let mut ul_bucket: Option<TokenBucket> = upload_byterate.map(TokenBucket::new);
			let mut delay_queue: std::collections::VecDeque<adapter_management::DelayedPacket> = std::collections::VecDeque::new();
			let mut reinjected: Vec<adapter_management::ReinjectedInfo> = Vec::new();

			loop {
				let timeout = if delay_queue.is_empty() { u32::MAX } else { 1 };
				adapter_management::wait_for_any_event_timeout(&events, timeout);

				// Flush delayed packets that are now ready.
				reinjected.clear();
				adapter_management::flush_delayed(&driver, &mut delay_queue, &mut reinjected);

				for (adapter_idx, &adapter_handle) in adapter_handles.iter().enumerate() {
					adapter_management::process_adapter_packets(&driver, adapter_handle, adapter_idx, &mut packet, &map, pid, &mut dl_bucket, &mut ul_bucket, &mut delay_queue);
				}

				for &event in &events {
					adapter_management::reset_event(event);
				}
			}
		})
	}

	/// Intercept packets on all adapters, count bytes per process, and apply
	/// speed limits from the shared limits map. Supports per-PID limits,
	/// system-wide limits (PID 0), and blocking (byterate 0 = drop packet).
	///
	/// Throttled packets are deferred into a local delay queue and reinjected
	/// once their release time arrives, so non-limited traffic is never blocked.
	pub fn start_monitor(&self) -> JoinHandle<Result<(), DecLimiterError>> {
		let flow_map = self.map.clone();
		let traffic = self.traffic.clone();
		let totals = self.totals.clone();
		let limits = self.limits.clone();

		tokio::task::spawn_blocking(move || {
			debug!("Starting packet monitor...");
			let driver = Ndisapi::new("NDISRD").map_err(DecLimiterError::WindowsError)?;
			let (adapter_handles, events) = adapter_management::setup_adapters(&driver)?;

			let mut packet = IntermediateBuffer::default();
			let mut throttle_states: HashMap<u32, ThrottleState> = HashMap::new();
			let mut delay_queue: std::collections::VecDeque<adapter_management::DelayedPacket> = std::collections::VecDeque::new();
			let mut reinjected: Vec<adapter_management::ReinjectedInfo> = Vec::new();

			loop {
				// If delayed packets are pending, use a short timeout so we can
				// flush them promptly. Otherwise block until new traffic arrives.
				let timeout = if delay_queue.is_empty() { u32::MAX } else { 1 };
				adapter_management::wait_for_any_event_timeout(&events, timeout);

				// Flush any delayed packets that are now ready for reinjection.
				// Count their traffic now (at delivery time).
				reinjected.clear();
				adapter_management::flush_delayed(&driver, &mut delay_queue, &mut reinjected);
				for info in &reinjected {
					Self::count_traffic(&totals, &traffic, info.pid, info.is_outbound, info.frame_len);
				}

				for (idx, &handle) in adapter_handles.iter().enumerate() {
					while read_packet(&driver, handle, &mut packet) {
						let is_outbound = packet.get_device_flags() == DirectionFlags::PACKET_FLAG_ON_SEND;
						let data = packet.get_data();
						let mut should_drop = false;
						let mut delay = Duration::ZERO;
						// Resolved PID for this packet (used for traffic counting
						// and per-PID limiting).
						let mut resolved_pid: Option<u32> = None;

						if data.len() > ETHERNET_HEADER_LEN {
							let ip_data = &data[ETHERNET_HEADER_LEN..];
							// Use the full frame length for the token bucket so the
							// rate limit reflects actual wire throughput.
							let frame_len = data.len();

							let flow = if is_outbound { parse_flow_source(ip_data) } else { parse_flow_dest(ip_data) };

							let pid = flow.and_then(|f| {
								let map = flow_map.blocking_read();
								map.get(&f).map(|e| e.pid).or_else(|| {
									// Fallback for sockets bound to INADDR_ANY / IN6ADDR_ANY.
									let unspec = match f.ip {
										IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
										IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
									};
									let wildcard = FlowAddress::new(unspec, f.port);
									map.get(&wildcard).map(|e| e.pid)
								})
							});
							resolved_pid = pid;

							// Apply limits: system-wide (PID 0) first, then per-PID
							if let Ok(limits_lock) = limits.read() {
								// System-wide limit
								if let Some(config) = limits_lock.get(&0) {
									let rate = if is_outbound { config.upload_byterate } else { config.download_byterate };
									match rate {
										Some(0) => should_drop = true,
										Some(rate) => {
											let ts = throttle_states.entry(0).or_insert_with(ThrottleState::new);
											let d = if is_outbound { ts.ul(rate).consume(frame_len) } else { ts.dl(rate).consume(frame_len) };
											delay = delay.max(d);
										}
										None => {}
									}
								}

								// Per-PID limit
								if !should_drop {
									if let Some(pid) = pid {
										if let Some(config) = limits_lock.get(&pid) {
											let rate = if is_outbound { config.upload_byterate } else { config.download_byterate };
											match rate {
												Some(0) => should_drop = true,
												Some(rate) => {
													let ts = throttle_states.entry(pid).or_insert_with(ThrottleState::new);
													let d = if is_outbound { ts.ul(rate).consume(frame_len) } else { ts.dl(rate).consume(frame_len) };
													delay = delay.max(d);
												}
												None => {}
											}
										}
									}
								}
							}
						}

						if should_drop {
							// Packet is blocked — do not reinject.
							// Still update last_seen so the process stays visible.
							if let Some(pid) = resolved_pid.filter(|&p| p != 0) {
								if let Ok(mut traffic_lock) = traffic.write() {
									if let Some(inner) = traffic_lock.get_mut(&pid) {
										inner.last_seen = Instant::now();
									}
								}
							}
						} else if delay > Duration::ZERO {
							// Defer reinjection: take the buffer, enqueue it.
							let frame_len = packet.get_data().len();
							let deferred = std::mem::take(&mut packet);
							delay_queue.push_back(adapter_management::DelayedPacket {
								buffer: deferred,
								adapter_handle: handle,
								is_outbound,
								release_at: Instant::now() + delay,
								frame_len,
								pid: resolved_pid,
							});
						} else {
							// Reinject immediately — count bytes now.
							let frame_len = packet.get_data().len();
							Self::count_traffic(&totals, &traffic, resolved_pid, is_outbound, frame_len);
							if let Err(e) = reinject_packet(&driver, handle, &packet, is_outbound) {
								error!("Monitor: packet reinject error on adapter [{}]: {}", idx, e);
							}
						}
					}
				}

				for &event in &events {
					adapter_management::reset_event(event);
				}
			}
		})
	}

	/// Periodically computes per-process speeds and garbage-collects stale entries
	/// from both the traffic and flow maps.
	pub fn start_speed_calculator(&self) -> JoinHandle<()> {
		let traffic = self.traffic.clone();
		let totals = self.totals.clone();
		let flow_map = self.map.clone();

		tokio::spawn(async move {
			debug!("Starting speed calculator...");
			loop {
				sleep(SPEED_UPDATE_INTERVAL).await;

				if let Ok(mut lock) = traffic.write() {
					let now = Instant::now();
					lock.retain(|_, inner| {
						inner.download_speed = (inner.download_bytes - inner.prev_download_bytes) as f64;
						inner.upload_speed = (inner.upload_bytes - inner.prev_upload_bytes) as f64;
						inner.prev_download_bytes = inner.download_bytes;
						inner.prev_upload_bytes = inner.upload_bytes;
						now.duration_since(inner.last_seen) < STALE_ENTRY_TIMEOUT
					});
				}

				if let Ok(mut t) = totals.write() {
					t.download_speed = (t.download_bytes - t.prev_download_bytes) as f64;
					t.upload_speed = (t.upload_bytes - t.prev_upload_bytes) as f64;
					t.prev_download_bytes = t.download_bytes;
					t.prev_upload_bytes = t.upload_bytes;
				}

				{
					let mut map_lock = flow_map.write().await;
					let now = Instant::now();
					map_lock.retain(|_, entry| now.duration_since(entry.last_seen) < STALE_FLOW_TIMEOUT);
				}
			}
		})
	}

	/// Get a snapshot of all process traffic stats, sorted by download speed descending.
	pub fn get_snapshot(&self) -> Vec<ProcessTraffic> {
		let lock = self.traffic.read().unwrap();
		let mut stats: Vec<ProcessTraffic> = lock
			.iter()
			.map(|(&pid, inner)| ProcessTraffic {
				pid,
				name: inner.name.clone(),
				download_bytes: inner.download_bytes,
				upload_bytes: inner.upload_bytes,
				download_speed: inner.download_speed,
				upload_speed: inner.upload_speed,
			})
			.collect();
		stats.sort_by(|a, b| b.download_speed.partial_cmp(&a.download_speed).unwrap_or(std::cmp::Ordering::Equal));
		stats
	}

	/// Get the total traffic counters (all traffic, including unattributed).
	pub fn get_totals(&self) -> ProcessTraffic {
		let t = self.totals.read().unwrap();
		ProcessTraffic {
			pid: 0,
			name: "System".to_string(),
			download_bytes: t.download_bytes,
			upload_bytes: t.upload_bytes,
			download_speed: t.download_speed,
			upload_speed: t.upload_speed,
		}
	}

	/// Periodically removes stale flow entries that have not been seen within the specified maximum age.
	pub fn garbage_collect_flows(&self, max_age: Duration) -> JoinHandle<Result<(), DecLimiterError>> {
		let map = self.map.clone();

		tokio::spawn(async move {
			debug!("Starting garbage collection for flow entries...");

			loop {
				sleep(Duration::from_secs(60)).await;

				let now = Instant::now();
				let mut map_lock = map.write().await;

				map_lock.retain(|flow, entry| {
					let age = now.duration_since(entry.last_seen);
					if age > max_age {
						trace!("Removing stale flow entry: {flow:?}");
						false
					} else {
						true
					}
				});
			}
		})
	}
}
