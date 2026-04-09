pub mod network;
pub mod packets;
pub mod adapter_management;

use crate::error::DecLimiterError;
use crate::limiter::network::{FlowAddress, FlowEntry};
use log::{debug, trace};
use ndisapi::{IntermediateBuffer, Ndisapi};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::sleep;

pub type ProcessPair = (u32, String);

const MOV_AVG_WINDOW_SIZE: usize = 500;
const ETHERNET_HEADER_LEN: usize = 14;

#[derive(Clone)]
pub struct DecLimiter {
	map: Arc<Mutex<HashMap<FlowAddress, FlowEntry>>>,
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
		})
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
			let max_delay_us: i64 = 10_000;

			loop {
				adapter_management::wait_for_any_event(&events);

				for (adapter_idx, &adapter_handle) in adapter_handles.iter().enumerate() {
					adapter_management::process_adapter_packets(
						&driver, adapter_handle, adapter_idx,
						&mut packet, &map, pid,
						download_byterate, upload_byterate,
						&mut dl_window, &mut ul_window,
						&mut dl_delay_us, &mut ul_delay_us,
						max_delay_us,
					);
				}

				for &event in &events {
					adapter_management::reset_event(event);
				}
			}
		})
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