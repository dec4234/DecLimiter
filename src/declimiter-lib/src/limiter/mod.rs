pub mod network;
pub mod packets;
pub mod adapter_management;

use crate::error::DecLimiterError;
use crate::limiter::network::{FlowAddress, FlowEntry, parse_flow_dest, parse_flow_source};
use crate::limiter::packets::{read_packet, reinject_packet, throttle_packet};
use crate::util::get_process_name;
use log::{debug, error, trace};
use ndisapi::{DirectionFlags, IntermediateBuffer, Ndisapi};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::sleep;

pub type ProcessPair = (u32, String);

const MOV_AVG_WINDOW_SIZE: usize = 500;
const ETHERNET_HEADER_LEN: usize = 14;
const MAX_DELAY_US: i64 = 10_000;
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

/// Per-PID throttle state kept locally in the packet processing thread.
struct ThrottleState {
	dl_window: VecDeque<(Instant, usize)>,
	ul_window: VecDeque<(Instant, usize)>,
	dl_delay_us: i64,
	ul_delay_us: i64,
}

impl ThrottleState {
	fn new() -> Self {
		Self {
			dl_window: VecDeque::with_capacity(MOV_AVG_WINDOW_SIZE),
			ul_window: VecDeque::with_capacity(MOV_AVG_WINDOW_SIZE),
			dl_delay_us: 0,
			ul_delay_us: 0,
		}
	}
}

#[derive(Clone)]
pub struct DecLimiter {
	map: Arc<Mutex<HashMap<FlowAddress, FlowEntry>>>,
	traffic: Arc<std::sync::RwLock<HashMap<u32, ProcessTrafficInner>>>,
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
			map: Arc::new(Mutex::new(HashMap::new())),
			traffic: Arc::new(std::sync::RwLock::new(HashMap::new())),
			limits: Arc::new(std::sync::RwLock::new(HashMap::new())),
		})
	}

	/// Returns a clone of the shared limits map for external mutation (e.g. from the GUI).
	pub fn limits(&self) -> LimitsMap {
		self.limits.clone()
	}

	/// Check if the given PID matches the PID associated with the given flow address.
	fn pid_matches_blocking(map: &Arc<Mutex<HashMap<FlowAddress, FlowEntry>>>, flow: &FlowAddress, pid: u32) -> bool {
		let map_lock = map.blocking_lock();
		map_lock.get(flow).map_or(false, |entry| entry.pid == pid)
	}

	/// Polls the Windows TCP/UDP connection tables to build PID-to-port mappings.
	pub fn start(&self) -> JoinHandle<Result<(), DecLimiterError>> {
		let map = self.map.clone();

		tokio::spawn(async move {
			debug!("Starting PID-to-port mapping via connection table polling...");

			loop {
				let mappings = network::get_pid_port_mappings();

				{
					let mut map_lock = map.lock().await;
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

				sleep(Duration::from_secs(2)).await;
			}
		})
	}

	/// Limit network speed for a specific process via its PID.
	/// Intercepts packets on ALL adapters to match WinDivert's behavior.
	pub fn limit_speed_pid(&self, pid: u32, download_byterate: Option<u64>, upload_byterate: Option<u64>) -> JoinHandle<Result<(), DecLimiterError>> {
		let map = self.map.clone();

		tokio::task::spawn_blocking(move || {
			debug!("Starting speed limiter for PID: {} (download: {:?}, upload: {:?})", pid, download_byterate, upload_byterate);

			let driver = Ndisapi::new("NDISRD").map_err(DecLimiterError::WindowsError)?;
			let (adapter_handles, events) = adapter_management::setup_adapters(&driver)?;

			let mut packet = IntermediateBuffer::default();
			let mut dl_window: VecDeque<(Instant, usize)> = VecDeque::with_capacity(MOV_AVG_WINDOW_SIZE);
			let mut ul_window: VecDeque<(Instant, usize)> = VecDeque::with_capacity(MOV_AVG_WINDOW_SIZE);
			let mut dl_delay_us: i64 = 0;
			let mut ul_delay_us: i64 = 0;

			loop {
				adapter_management::wait_for_any_event(&events);

				for (adapter_idx, &adapter_handle) in adapter_handles.iter().enumerate() {
					adapter_management::process_adapter_packets(
						&driver, adapter_handle, adapter_idx,
						&mut packet, &map, pid,
						download_byterate, upload_byterate,
						&mut dl_window, &mut ul_window,
						&mut dl_delay_us, &mut ul_delay_us,
						MAX_DELAY_US,
					);
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
	pub fn start_monitor(&self) -> JoinHandle<Result<(), DecLimiterError>> {
		let flow_map = self.map.clone();
		let traffic = self.traffic.clone();
		let limits = self.limits.clone();

		tokio::task::spawn_blocking(move || {
			debug!("Starting packet monitor...");
			let driver = Ndisapi::new("NDISRD").map_err(DecLimiterError::WindowsError)?;
			let (adapter_handles, events) = adapter_management::setup_adapters(&driver)?;

			let mut packet = IntermediateBuffer::default();
			let mut throttle_states: HashMap<u32, ThrottleState> = HashMap::new();

			loop {
				adapter_management::wait_for_any_event(&events);

				for (idx, &handle) in adapter_handles.iter().enumerate() {
					while read_packet(&driver, handle, &mut packet) {
						let is_outbound = packet.get_device_flags() == DirectionFlags::PACKET_FLAG_ON_SEND;
						let data = packet.get_data();
						let mut should_drop = false;

						if data.len() > ETHERNET_HEADER_LEN {
							let ip_data = &data[ETHERNET_HEADER_LEN..];
							let packet_len = ip_data.len();

							let flow = if is_outbound { parse_flow_source(ip_data) } else { parse_flow_dest(ip_data) };

							let pid = flow.and_then(|f| {
								flow_map.blocking_lock().get(&f).map(|e| e.pid)
							});

							// Apply limits: system-wide (PID 0) first, then per-PID
							if let Ok(limits_lock) = limits.read() {
								// System-wide limit
								if let Some(config) = limits_lock.get(&0) {
									let rate = if is_outbound { config.upload_byterate } else { config.download_byterate };
									match rate {
										Some(0) => should_drop = true,
										Some(rate) => {
											let ts = throttle_states.entry(0).or_insert_with(ThrottleState::new);
											if is_outbound {
												throttle_packet(&mut ts.ul_window, &mut ts.ul_delay_us, MAX_DELAY_US, rate, packet_len);
											} else {
												throttle_packet(&mut ts.dl_window, &mut ts.dl_delay_us, MAX_DELAY_US, rate, packet_len);
											}
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
													if is_outbound {
														throttle_packet(&mut ts.ul_window, &mut ts.ul_delay_us, MAX_DELAY_US, rate, packet_len);
													} else {
														throttle_packet(&mut ts.dl_window, &mut ts.dl_delay_us, MAX_DELAY_US, rate, packet_len);
													}
												}
												None => {}
											}
										}
									}
								}
							}

							// Count bytes for known PIDs only if the packet is not dropped.
							// Skip PID 0 (System Process) — its traffic is covered by the
							// GUI's synthetic System row which aggregates all processes.
							if !should_drop {
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
											inner.upload_bytes += packet_len as u64;
										} else {
											inner.download_bytes += packet_len as u64;
										}
										inner.last_seen = Instant::now();
									}
								}
							}
						}

						if !should_drop {
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

				{
					let mut map_lock = flow_map.lock().await;
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

	/// Periodically removes stale flow entries that have not been seen within the specified maximum age.
	pub fn garbage_collect_flows(&self, max_age: Duration) -> JoinHandle<Result<(), DecLimiterError>> {
		let map = self.map.clone();

		tokio::spawn(async move {
			debug!("Starting garbage collection for flow entries...");

			loop {
				sleep(Duration::from_secs(60)).await;

				let now = Instant::now();
				let mut map_lock = map.lock().await;

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
