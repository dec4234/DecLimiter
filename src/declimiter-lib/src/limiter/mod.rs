pub mod network;

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use log::{debug, error, trace};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Instant};
use windivert::prelude::WinDivertFlags;
use windivert::WinDivert;
use network::FlowAddress;
use crate::error::DecLimiterError;
use crate::limiter::network::FlowEntry;

pub type ProcessPair = (u32, String);

const MOV_AVG_WINDOW_SIZE: usize = 500;

#[derive(Debug, Clone)]
pub struct DecLimiter {
	map: Arc<Mutex<HashMap<FlowAddress, FlowEntry>>>,
}

impl DecLimiter {
	pub fn new() -> Self {
		let map = Arc::new(Mutex::new(HashMap::new()));
		Self { map }
	}

	pub fn start(&self) -> JoinHandle<Result<(), DecLimiterError>> {
		self.map_processid_port()
	}

	/// Get the PID associated with a given flow address.
	///
	/// # Arguments
	/// * `map` - An `Arc<Mutex<HashMap<FlowAddress, FlowEntry>>>` containing the flow to PID mappings.
	/// * `flow` - A reference to the `FlowAddress` to look up.
	///
	/// # Returns
	/// An `Option<u16>` containing the PID if found, or `None` if not found.
	pub async fn pid_from_flow(map: Arc<Mutex<HashMap<FlowAddress, FlowEntry>>>, flow: &FlowAddress) -> Option<u32> {
		let map_lock = map.lock().await;

		map_lock.get(flow).copied().map(|entry| entry.pid)
	}

	/// Check if the given PID matches the PID associated with the given flow address.
	///
	/// # Arguments
	/// * `map` - An `Arc<Mutex<HashMap<FlowAddress, FlowEntry>>>` containing the flow to PID mappings.
	/// * `flow` - A reference to the `FlowAddress` to look up.
	/// * `pid` - The PID to compare against.
	///
	/// # Returns
	/// `true` if the PIDs match, `false` if there is no pid mapped or they do not match.
	pub async fn pid_matches(map: Arc<Mutex<HashMap<FlowAddress, FlowEntry>>>, flow: &FlowAddress, pid: u32) -> bool {
		Self::pid_from_flow(map, flow).await.map_or(false, |mapped_pid| mapped_pid == pid)
	}

	/// Listens for packets and maps process IDs to their corresponding addresses.
	///
	/// # Returns
	/// A `JoinHandle<()>` for the spawned task.
	fn map_processid_port(&self) -> JoinHandle<Result<(), DecLimiterError>> {
		let map = self.map.clone();

		tokio::spawn(async move {
			debug!("Starting process ID to port mapping...");

			let handle = WinDivert::flow("tcp or udp", 0, WinDivertFlags::new().set_sniff())?;
			let mut packet = [0u8; 65535];

			loop {
				let res = handle.recv(Some(&mut packet))?;

				let pid = res.address.process_id();
				let port = res.address.local_port();

				let flow_info = FlowAddress::new(
					res.address.local_address(),
					res.address.local_port(),
				);

				let mut map_lock = map.lock().await;

				if !map_lock.contains_key(&flow_info) {
					trace!("Captured PID: {pid}, Port: {port}, Local Addr: {}", flow_info.ip);
					map_lock.insert(flow_info, FlowEntry::new(pid));
				}
			}
		})
	}

	/// Limit the download speed for a specific process via its PID.
	///
	/// # Arguments
	/// * `pid` - The process ID to limit.
	/// * `target_byterate` - The target byte rate in bytes per second.
	///
	/// # Returns
	/// A `JoinHandle<()>` for the spawned task.
	pub fn limit_speed_pid(&self, pid: u32, target_byterate: u64) -> JoinHandle<Result<(), DecLimiterError>> {
		let map = self.map.clone();

		tokio::spawn(async move {
			debug!("Starting speed limiter for PID: {}...", pid);

			// Priority is set to 1 so it doesn't usurp the flow capture. This may not be necessary.
			let handle = WinDivert::network("ip and (tcp or udp)", 1, WinDivertFlags::new().set_fragments())?;
			let mut packet = [0u8; 65535];

			let mut window: VecDeque<(Instant, usize)> = VecDeque::with_capacity(MOV_AVG_WINDOW_SIZE);

			let mut dynamic_delay_us: i64 = 0;
			let max_delay_us: i64 = 10_000;

			loop {
				let res = handle.recv(Some(&mut packet))?;

				if res.address.outbound() {
					handle.send(&res)?;
					continue;
				}

				let Some(flow) = parse_flow(&res.data) else {
					error!("Failed to parse flow from packet: {:?}", &res.data[..20]);
					continue;
				};

				let pid_match = Self::pid_matches(map.clone(), &flow, pid).await;

				if pid_match {
					let now = Instant::now();
					let bytes = res.data.len();

					window.push_back((now, bytes));
					if window.len() > MOV_AVG_WINDOW_SIZE {
						window.pop_front();
					}

					if window.len() > 1 {
						let first = window.front().unwrap().0;
						let last = window.back().unwrap().0;

						let duration = last.duration_since(first).as_secs_f64();
						if duration > 0.0 {
							let total_bytes: usize = window.iter().map(|(_, b)| *b).sum();

							let actual_rate = total_bytes as f64 / duration;

							let error = actual_rate - target_byterate as f64;

							// todo: allow multiplier to be configurable
							// Simple proportional controller
							let kp = 0.02; // higher = more aggressive, lower = smoother but slower response
							dynamic_delay_us += (error * kp) as i64;

							dynamic_delay_us = dynamic_delay_us.clamp(0, max_delay_us);

							if dynamic_delay_us > 0 {
								sleep(Duration::from_micros(dynamic_delay_us as u64)).await;
							}
						}
					}
				}

				if let Err(e) = handle.send(&res) {
					error!("Error returning packet: {}", e);
					break;
				}
			}

			Ok(())
		})
	}

	/// Periodically removes stale flow entries that have not been seen within the specified maximum age.
	///
	/// # Arguments
	/// * `max_age` - The maximum age for flow entries before they are considered stale
	///
	/// # Returns
	/// A `JoinHandle<()>` for the spawned task.
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

/// Parse the flow address (destination IP and port) from a raw packet.
///
/// # Arguments
/// * `packet` - A byte slice representing the raw packet data.
///
/// # Returns
/// An `Option<FlowAddress>` containing the parsed flow address, or `None` if parsing fails.
fn parse_flow(packet: &[u8]) -> Option<FlowAddress> {
	let sliced = SlicedPacket::from_ip(packet).ok()?;

	let ip = match sliced.net? {
		InternetSlice::Ipv4(h) => IpAddr::V4(h.header().destination_addr()),
		InternetSlice::Ipv6(h) => IpAddr::V6(h.header().destination_addr()),
		_ => return None,
	};

	match sliced.transport? {
		TransportSlice::Tcp(tcp) => {
			Some(FlowAddress::new(ip, tcp.destination_port()))
		}
		TransportSlice::Udp(udp) => {
			Some(FlowAddress::new(ip, udp.destination_port()))
		}
		_ => None,
	}
}