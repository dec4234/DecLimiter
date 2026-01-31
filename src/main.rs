//! https://github.com/Rubensei/windivert-rust
//! https://www.reqrypt.org/windivert-doc.html
//! https://www.reqrypt.org/windivert-doc.html#filter_language
//!
//! Missing SYS error? - `sc delete WinDivert`

use derive_new::new;
use log::{Level, debug, error, trace};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Condvar};
use std::time::Duration;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep};
use tokio::{try_join};
use windivert::WinDivert;
use windivert::prelude::WinDivertFlags;

const MOV_AVG_WINDOW_SIZE: usize = 500;
const DELAY_ENABLED: bool = true;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    simple_logger::init_with_level(Level::Trace).unwrap();

    println!("DecLimiter Starting...");

    let limiter = DecLimiter::new();
    try_join!(limiter.start(), limiter.limit_speed_pid(33092, 500_000)).unwrap();

    Ok(())
}

/// The destination of a packet. Used to match connections to PIDs.
#[derive(Debug, Copy, Clone, Hash, PartialEq, new, Eq)]
pub struct FlowAddress {
    ip: IpAddr,
    port: u16,
}

#[derive(Debug, Clone)]
pub struct DecLimiter {
    map: Arc<(Mutex<HashMap<FlowAddress, u32>>, Condvar)>, //todo: expiration
}

impl DecLimiter {
    pub fn new() -> Self {
        let map = Arc::new((Mutex::new(HashMap::new()), Condvar::new()));
        Self { map }
    }

    pub fn start(&self) -> JoinHandle<()> {
        self.map_processid_port()
    }

    /// Get the PID associated with a given flow address.
    ///
    /// # Returns
    /// An `Option<u16>` containing the PID if found, or `None` if not found.
    pub fn pid_from_flow(&self, flow: &FlowAddress) -> Option<u32> {
        let (lock, _) = &*self.map;
        let map_lock = lock.blocking_lock();

        map_lock.get(flow).copied()
    }

    /// Check if the given PID matches the PID associated with the given flow address.
    ///
    /// # Returns
    /// `true` if the PIDs match, `false` if there is no pid mapped or they do not match.
	pub async fn pid_matches(&self, flow: &FlowAddress, pid: u32) -> bool {
        let (lock, _) = &*self.map;
        let map_lock = lock.lock().await;

        match map_lock.get(flow) {
            Some(&mapped_pid) => mapped_pid == pid,
            None => false,
        }
    }

    /// Listens for packets and maps process IDs to their corresponding addresses.
    ///
    /// # Returns
    /// A `JoinHandle<()>` for the spawned task.
    fn map_processid_port(&self) -> JoinHandle<()> {
        let map = self.map.clone();

        tokio::spawn(async move {
            debug!("Starting process ID to port mapping...");

            let handle = WinDivert::flow("tcp or udp", 0, WinDivertFlags::new().set_sniff()).unwrap();
            let mut packet = [0u8; 65535];

            loop {
                let res = handle.recv(Some(&mut packet)).unwrap();

                let pid = res.address.process_id();
                let port = res.address.local_port();

                let flow_info = FlowAddress::new(
                    res.address.local_address(),
                    res.address.local_port(),
                );

                let (lock, cvar) = &*map;

                let mut map_lock = lock.lock().await;

                if !map_lock.contains_key(&flow_info) {
                    trace!("Captured PID: {pid}, Port: {port}, Local Addr: {}", flow_info.ip);
                    map_lock.insert(flow_info, pid);
                    cvar.notify_all();
                }

                drop(map_lock); // Explicitly drop the lock
            }
        })
    }

    /// Limit the download speed for a specific PID using a PID-based speed limiter.
    ///
    /// # Arguments
    /// * `pid` - The process ID to limit.
    /// * `target_byterate` - The target byte rate in bytes per second.
    ///
    /// # Returns
    /// A `JoinHandle<()>` for the spawned task.
    pub fn limit_speed_pid(&self, pid: u32, target_byterate: u64) -> JoinHandle<()> {
        let map = self.map.clone();

        tokio::spawn(async move {
            debug!("Starting speed limiter for PID: {}...", pid);

            // Priority is set to 1 so it doesn't usurp the flow capture. This may not be necessary.
            let handle = WinDivert::network("ip and (tcp or udp)", 1, WinDivertFlags::new().set_fragments()).unwrap();
            let mut packet = [0u8; 65535];

            let mut window: VecDeque<(Instant, usize)> = VecDeque::with_capacity(MOV_AVG_WINDOW_SIZE);

            let mut dynamic_delay_us: i64 = 0;
            let max_delay_us: i64 = 10_000;

            loop {
                let res = handle.recv(Some(&mut packet)).unwrap();

                if res.address.outbound() {
                    handle.send(&res).unwrap();
                    continue;
                }

                let Some(flow) = parse_flow(&res.data) else {
                    error!("Failed to parse flow from packet: {:?}", &res.data[..20]);
                    continue;
                };

                // todo: replace with pid_matches
                let pid_match = {
                    let (lock, _) = &*map;
                    let map_lock = lock.lock().await;
                    map_lock.get(&flow).copied() == Some(pid)
                };

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

                            // Simple proportional controller
                            let kp = 0.0005;
                            dynamic_delay_us += (error * kp) as i64;

                            dynamic_delay_us = dynamic_delay_us
                                .clamp(0, max_delay_us);

                            if dynamic_delay_us > 0 && DELAY_ENABLED {
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
