pub mod adapter_management;
pub mod network;
pub mod packets;
pub mod process_watch;

use crate::error::DecLimiterError;
use crate::limiter::network::{FlowAddress, FlowEntry, parse_flow_dest, parse_flow_source};
use crate::limiter::packets::{TokenBucket, read_packet, reinject_packet};
use crate::limiter::process_watch::ProcessWatcher;
use crate::util::get_process_name;
use log::{debug, error, trace};
use ndisapi::{DirectionFlags, IntermediateBuffer, Ndisapi};
use std::collections::HashMap;
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
		Self::bucket(&mut self.dl_bucket, rate)
	}

	/// Get or create the upload bucket, updating the rate if it changed.
	fn ul(&mut self, rate: u64) -> &mut TokenBucket {
		Self::bucket(&mut self.ul_bucket, rate)
	}

	/// Get or create a bucket. If the limit changed since the bucket was made,
	/// the bucket takes the new rate and keeps its tokens.
	fn bucket(slot: &mut Option<TokenBucket>, rate: u64) -> &mut TokenBucket {
		let bucket = slot.get_or_insert_with(|| TokenBucket::new(rate));
		if bucket.rate() != rate {
			bucket.set_rate(rate);
		}
		bucket
	}
}

/// The device name of the Windows Packet Filter driver.
const DRIVER_NAME: &str = "NDISRD";

/// Returns true if the Windows Packet Filter driver is installed and this
/// process can open it.
pub fn driver_available() -> bool {
	Ndisapi::new(DRIVER_NAME).is_ok()
}

#[derive(Clone)]
pub struct DecLimiter {
	map: Arc<RwLock<HashMap<FlowAddress, FlowEntry>>>,
	traffic: Arc<std::sync::RwLock<HashMap<u32, ProcessTrafficInner>>>,
	totals: Arc<std::sync::RwLock<TotalTrafficCounters>>,
	limits: LimitsMap,
	/// Tells us as soon as a process that we track ends.
	watcher: Arc<ProcessWatcher>,
}

impl DecLimiter {
	pub fn new() -> Result<Self, DecLimiterError> {
		let driver = Ndisapi::new(DRIVER_NAME).map_err(DecLimiterError::WindowsError)?;

		debug!("Detected Windows Packet Filter version {}", driver.get_version().map_err(DecLimiterError::WindowsError)?);

		let adapters = driver.get_tcpip_bound_adapters_info().map_err(DecLimiterError::WindowsError)?;

		if adapters.is_empty() {
			return Err(DecLimiterError::NoAdapterFound);
		}

		for (i, adapter) in adapters.iter().enumerate() {
			debug!("Available adapter [{}]: {}", i, adapter.get_name());
		}

		Ok(Self::empty())
	}

	/// Creates the shared state with no traffic, flows or limits. This does
	/// not open the packet filter driver.
	fn empty() -> Self {
		Self {
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
			watcher: Arc::new(ProcessWatcher::new()),
		}
	}

	/// Returns a clone of the shared limits map for external mutation (e.g. from the GUI).
	pub fn limits(&self) -> LimitsMap {
		self.limits.clone()
	}

	/// Check if the given PID matches the PID associated with the given flow address.
	fn pid_matches_blocking(map: &Arc<RwLock<HashMap<FlowAddress, FlowEntry>>>, flow: &FlowAddress, pid: u32) -> bool {
		network::lookup_pid(&map.blocking_read(), flow) == Some(pid)
	}

	/// Record bytes in the total and per-PID traffic counters.
	/// Called at *reinjection* time so the speed display reflects actual
	/// delivered throughput, not intercepted-but-queued traffic.
	fn count_traffic(totals: &Arc<std::sync::RwLock<TotalTrafficCounters>>, traffic: &Arc<std::sync::RwLock<HashMap<u32, ProcessTrafficInner>>>, watcher: &Arc<ProcessWatcher>, pid: Option<u32>, is_outbound: bool, frame_len: usize) {
		if let Ok(mut t) = totals.write() {
			if is_outbound {
				t.upload_bytes += frame_len as u64;
			} else {
				t.download_bytes += frame_len as u64;
			}
		}

		if let Some(pid) = pid.filter(|&p| p != 0) {
			if let Ok(mut traffic_lock) = traffic.write() {
				let mut is_new = false;
				let inner = traffic_lock.entry(pid).or_insert_with(|| {
					is_new = true;
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
				drop(traffic_lock);

				// Ask Windows to tell us when this process ends, so that the
				// list drops it at once instead of after the timeout.
				if is_new {
					watcher.watch(pid);
				}
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
					for (flow, pid) in mappings {
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

			let driver = Ndisapi::new(DRIVER_NAME).map_err(DecLimiterError::WindowsError)?;
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
		let watcher = self.watcher.clone();

		tokio::task::spawn_blocking(move || {
			debug!("Starting packet monitor...");
			let driver = Ndisapi::new(DRIVER_NAME).map_err(DecLimiterError::WindowsError)?;
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
					Self::count_traffic(&totals, &traffic, &watcher, info.pid, info.is_outbound, info.frame_len);
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

							let pid = flow.and_then(|f| network::lookup_pid(&flow_map.blocking_read(), &f));
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
							Self::count_traffic(&totals, &traffic, &watcher, resolved_pid, is_outbound, frame_len);
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
		let watcher = self.watcher.clone();

		tokio::spawn(async move {
			debug!("Starting speed calculator...");
			// The time of the last sample of each counter set. The sleep and the
			// work in this loop make each interval longer than the nominal
			// value, thus the speed must use the measured time.
			let mut last_traffic_sample = Instant::now();
			let mut last_totals_sample = Instant::now();

			loop {
				sleep(SPEED_UPDATE_INTERVAL).await;

				let mut stale: Vec<u32> = Vec::new();

				if let Ok(mut lock) = traffic.write() {
					let now = Instant::now();
					let elapsed = now.duration_since(last_traffic_sample).as_secs_f64();
					last_traffic_sample = now;
					lock.retain(|&pid, inner| {
						inner.download_speed = (inner.download_bytes - inner.prev_download_bytes) as f64 / elapsed;
						inner.upload_speed = (inner.upload_bytes - inner.prev_upload_bytes) as f64 / elapsed;
						inner.prev_download_bytes = inner.download_bytes;
						inner.prev_upload_bytes = inner.upload_bytes;

						let keep = now.duration_since(inner.last_seen) < STALE_ENTRY_TIMEOUT;
						if !keep {
							stale.push(pid);
						}
						keep
					});
				}

				// A process that stops to send traffic can keep running. Release
				// its exit wait, because the list no longer shows it.
				for pid in stale {
					watcher.forget(pid);
				}

				if let Ok(mut t) = totals.write() {
					let now = Instant::now();
					let elapsed = now.duration_since(last_totals_sample).as_secs_f64();
					last_totals_sample = now;
					t.download_speed = (t.download_bytes - t.prev_download_bytes) as f64 / elapsed;
					t.upload_speed = (t.upload_bytes - t.prev_upload_bytes) as f64 / elapsed;
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

	/// Removes the processes that ended since the last call, and returns their
	/// PIDs.
	///
	/// Windows reports the end of a process at once, thus a call to this
	/// function immediately before [`Self::get_snapshot`] keeps the list free
	/// of processes that no longer run.
	pub fn reap_exited(&self) -> Vec<u32> {
		let exited = self.watcher.take_exited();

		if exited.is_empty() {
			return exited;
		}

		if let Ok(mut traffic_lock) = self.traffic.write() {
			for pid in &exited {
				traffic_lock.remove(pid);
			}
		}

		// A limit on a PID that no longer runs must not apply to a different
		// process that receives the same PID later.
		if let Ok(mut limits_lock) = self.limits.write() {
			for pid in &exited {
				limits_lock.remove(pid);
			}
		}

		debug!("Removed {} process(es) that ended: {:?}", exited.len(), exited);

		exited
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

#[cfg(test)]
mod tests {
	use super::*;

	fn inner(name: &str, download_speed: f64, upload_speed: f64) -> ProcessTrafficInner {
		ProcessTrafficInner {
			name: name.to_string(),
			download_bytes: 0,
			upload_bytes: 0,
			prev_download_bytes: 0,
			prev_upload_bytes: 0,
			download_speed,
			upload_speed,
			last_seen: Instant::now(),
		}
	}

	fn count(limiter: &DecLimiter, pid: Option<u32>, is_outbound: bool, frame_len: usize) {
		DecLimiter::count_traffic(&limiter.totals, &limiter.traffic, &limiter.watcher, pid, is_outbound, frame_len);
	}

	/// Polls `reap_exited` until it returns something, or five seconds pass.
	fn reap_until_some(limiter: &DecLimiter) -> Vec<u32> {
		let deadline = Instant::now() + Duration::from_secs(5);
		while Instant::now() < deadline {
			let exited = limiter.reap_exited();
			if !exited.is_empty() {
				return exited;
			}
			std::thread::sleep(Duration::from_millis(10));
		}
		Vec::new()
	}

	#[test]
	fn throttle_state_creates_each_bucket_once() {
		let mut state = ThrottleState::new();
		assert!(state.dl_bucket.is_none());
		assert!(state.ul_bucket.is_none());

		state.dl(1_000_000);
		assert!(state.dl_bucket.is_some());
		assert!(state.ul_bucket.is_none(), "the download bucket must not create the upload bucket");

		// The second call gives the same bucket, with the tokens already used.
		assert_eq!(state.dl(1_000_000).consume(50_000), Duration::ZERO);
		assert!(state.dl(1_000_000).consume(50_000) > Duration::ZERO);

		state.ul(2_000);
		assert!(state.ul_bucket.is_some());
	}

	/// A change of a limit in the GUI must also apply to a process that the
	/// monitor already throttles.
	#[test]
	fn throttle_state_follows_a_new_rate() {
		let mut state = ThrottleState::new();
		// Empty a bucket at 1000 B/s.
		state.dl(1_000).consume(1_500);
		// At 1 MB/s, a debt of 1000 bytes needs approximately 1 ms. At the old
		// rate it needs 1 second.
		let delay = state.dl(1_000_000).consume(1_000);
		assert!(delay < Duration::from_millis(100), "the old rate is still in use: {delay:?}");

		// The upload bucket changes rate separately.
		state.ul(1_000_000);
		state.ul(2_000);
		assert_eq!(state.ul_bucket.as_ref().unwrap().rate(), 2_000);
		assert_eq!(state.dl_bucket.as_ref().unwrap().rate(), 1_000_000);
	}

	#[test]
	fn throttle_state_keeps_tokens_when_the_rate_is_the_same() {
		let mut state = ThrottleState::new();
		// Use most of the 50 000 byte burst.
		assert_eq!(state.dl(1_000_000).consume(45_000), Duration::ZERO);
		// The same rate must not refill the bucket.
		assert!(state.dl(1_000_000).consume(10_000) > Duration::ZERO);
	}

	#[test]
	fn empty_limiter_has_no_traffic() {
		let limiter = DecLimiter::empty();
		assert!(limiter.get_snapshot().is_empty());
		assert!(limiter.reap_exited().is_empty());

		let totals = limiter.get_totals();
		assert_eq!(totals.pid, 0);
		assert_eq!(totals.name, "System");
		assert_eq!(totals.download_bytes, 0);
		assert_eq!(totals.upload_bytes, 0);
		assert_eq!(totals.download_speed, 0.0);
		assert_eq!(totals.upload_speed, 0.0);
	}

	#[test]
	fn limits_gives_the_shared_map() {
		let limiter = DecLimiter::empty();
		let limits = limiter.limits();
		limits.write().unwrap().insert(5, LimitConfig { download_byterate: Some(10), upload_byterate: None });

		assert!(Arc::ptr_eq(&limits, &limiter.limits));
		assert_eq!(limiter.limits.read().unwrap().get(&5).unwrap().download_byterate, Some(10));

		// A clone of the limiter shares the same state.
		let copy = limiter.clone();
		assert!(Arc::ptr_eq(&copy.limits(), &limits));
	}

	#[test]
	fn count_traffic_adds_to_totals_by_direction() {
		let limiter = DecLimiter::empty();
		count(&limiter, None, false, 1500);
		count(&limiter, None, false, 500);
		count(&limiter, None, true, 60);

		let totals = limiter.get_totals();
		assert_eq!(totals.download_bytes, 2000);
		assert_eq!(totals.upload_bytes, 60);
	}

	#[test]
	fn count_traffic_without_pid_or_with_pid_zero_makes_no_process_entry() {
		let limiter = DecLimiter::empty();
		count(&limiter, None, false, 100);
		count(&limiter, Some(0), true, 100);

		assert!(limiter.get_snapshot().is_empty());
		let totals = limiter.get_totals();
		assert_eq!(totals.download_bytes, 100);
		assert_eq!(totals.upload_bytes, 100);
	}

	#[test]
	fn count_traffic_tracks_each_process() {
		let limiter = DecLimiter::empty();
		let pid = std::process::id();
		count(&limiter, Some(pid), false, 1000);
		count(&limiter, Some(pid), true, 200);
		count(&limiter, Some(pid), false, 24);

		let snapshot = limiter.get_snapshot();
		assert_eq!(snapshot.len(), 1);
		let own = &snapshot[0];
		assert_eq!(own.pid, pid);
		assert_eq!(own.download_bytes, 1024);
		assert_eq!(own.upload_bytes, 200);

		// The name comes from the operating system.
		let exe = std::env::current_exe().unwrap();
		let exe_name = exe.file_name().unwrap().to_string_lossy();
		assert!(own.name.eq_ignore_ascii_case(&exe_name), "name {:?} is not {exe_name:?}", own.name);

		// The process traffic is also part of the totals.
		let totals = limiter.get_totals();
		assert_eq!(totals.download_bytes, 1024);
		assert_eq!(totals.upload_bytes, 200);
	}

	#[test]
	fn count_traffic_names_an_unknown_pid_by_number() {
		let limiter = DecLimiter::empty();
		// Windows PIDs are multiples of 4, thus this PID never exists.
		let pid = u32::MAX - 2;
		count(&limiter, Some(pid), false, 10);

		let snapshot = limiter.get_snapshot();
		assert_eq!(snapshot[0].name, format!("PID {pid}"));
	}

	#[test]
	fn snapshot_is_sorted_by_download_speed_descending() {
		let limiter = DecLimiter::empty();
		{
			let mut traffic = limiter.traffic.write().unwrap();
			traffic.insert(1, inner("slow", 10.0, 900.0));
			traffic.insert(2, inner("fast", 5000.0, 0.0));
			traffic.insert(3, inner("medium", 300.0, 1.0));
		}

		let snapshot = limiter.get_snapshot();
		let order: Vec<u32> = snapshot.iter().map(|p| p.pid).collect();
		assert_eq!(order, vec![2, 3, 1]);

		assert_eq!(snapshot[0].name, "fast");
		assert_eq!(snapshot[0].download_speed, 5000.0);
		assert_eq!(snapshot[2].upload_speed, 900.0);
	}

	#[test]
	fn snapshot_with_a_nan_speed_does_not_panic() {
		let limiter = DecLimiter::empty();
		{
			let mut traffic = limiter.traffic.write().unwrap();
			traffic.insert(1, inner("a", 1.0, 0.0));
			traffic.insert(2, inner("b", f64::NAN, 0.0));
		}
		assert_eq!(limiter.get_snapshot().len(), 2);
	}

	#[test]
	fn reap_exited_removes_traffic_and_limits_of_an_ended_process() {
		let limiter = DecLimiter::empty();

		let mut child = std::process::Command::new("cmd").args(["/c", "pause"]).stdin(std::process::Stdio::piped()).spawn().expect("cannot start the test process");
		let pid = child.id();
		let other = std::process::id();

		// count_traffic starts to watch a new PID.
		count(&limiter, Some(pid), false, 100);
		count(&limiter, Some(other), false, 100);
		{
			let mut limits = limiter.limits.write().unwrap();
			limits.insert(pid, LimitConfig { download_byterate: Some(1), upload_byterate: None });
			limits.insert(other, LimitConfig { download_byterate: Some(2), upload_byterate: None });
			limits.insert(0, LimitConfig { download_byterate: Some(3), upload_byterate: None });
		}

		assert!(limiter.reap_exited().is_empty(), "the process still runs");

		child.kill().expect("cannot stop the test process");
		child.wait().expect("cannot collect the test process");

		assert_eq!(reap_until_some(&limiter), vec![pid]);

		let pids: Vec<u32> = limiter.get_snapshot().iter().map(|p| p.pid).collect();
		assert_eq!(pids, vec![other]);

		let limits = limiter.limits.read().unwrap();
		assert!(!limits.contains_key(&pid), "the limit of the ended process must go");
		assert!(limits.contains_key(&other));
		assert!(limits.contains_key(&0), "the system wide limit must stay");
		drop(limits);

		// The totals keep the bytes of the ended process.
		assert_eq!(limiter.get_totals().download_bytes, 200);
		// A second call reports nothing new.
		assert!(limiter.reap_exited().is_empty());
	}
}
