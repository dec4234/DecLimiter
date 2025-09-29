//! https://github.com/Rubensei/windivert-rust
//! https://www.reqrypt.org/windivert-doc.html

use derive_new::new;
use log::{Level, debug, trace};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Condvar};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep};
use tokio::try_join;
use windivert::WinDivert;
use windivert::prelude::WinDivertFlags;

const MOV_AVG_WINDOW_SIZE: usize = 500;
const DELAY_ENABLED: bool = true;
const FILTER: &str = "ip";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    simple_logger::init_with_level(Level::Trace).unwrap();

    println!("DecLimiter Starting...");

    let limiter = DecLimiter::new();
    try_join!(limiter.start()).unwrap();

    Ok(())
}

async fn execute() {
    // https://www.reqrypt.org/windivert-doc.html#filter_language
    // todo: maybe use flow since it might show PID, must use side-by-side
    let handle = WinDivert::network(FILTER, 0, WinDivertFlags::new().set_fragments()).unwrap();
    let mut packet = [0u8; 65535];

    let mut i: u64 = 0;
    let download_delay_micros = 800; // ADJUST, higher for slower speeds

    let mut window: VecDeque<(Instant, usize)> = VecDeque::with_capacity(100);

    loop {
        let res = handle.recv(Some(&mut packet)).unwrap();

        if !res.address.outbound() && DELAY_ENABLED {
            let target = Instant::now() + Duration::from_micros(download_delay_micros);
            while Instant::now() < target {
                std::hint::spin_loop();
            }
        }

        handle.send(&res).unwrap();

        i += 1;

        // push new sample
        let now = Instant::now();
        let bytes = res.data.len();
        window.push_back((now, bytes));
        if window.len() > MOV_AVG_WINDOW_SIZE {
            window.pop_front();
        }

        // compute moving average bitrate
        if window.len() > 1 {
            let first = window.front().unwrap().0;
            let last = window.back().unwrap().0;
            let duration = last.duration_since(first).as_secs_f64();

            if duration > 0.0 {
                let total_bytes: usize = window.iter().map(|(_, b)| *b).sum();
                let bits_per_sec = (total_bytes as f64 * 8.0) / duration;
                if i % 100 == 0 {
                    println!(
                        "Processed {} packets | Moving avg bitrate: {:.2} kbps",
                        i,
                        bits_per_sec / 1000.0
                    );
                }
            }
        } else if i % 10 == 0 {
            println!("Processed {} packets", i);
        }
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, new, Eq)]
pub struct FlowAddress {
    protocol: u8,
    ip: IpAddr,
    port: u16,
}

#[derive(Debug, Clone)]
pub struct DecLimiter {
    map: Arc<(Mutex<HashMap<FlowAddress, u16>>, Condvar)>, //todo: expiration
}

impl DecLimiter {
    pub fn new() -> Self {
        let map = Arc::new((Mutex::new(HashMap::new()), Condvar::new()));
        Self { map }
    }

    pub fn start(&self) -> JoinHandle<()> {
        self.map_processid_port()
    }

    fn map_processid_port(&self) -> JoinHandle<()> {
        let map = self.map.clone();

        tokio::spawn(async move {
            debug!("Starting process ID to port mapping...");

            let handle = WinDivert::flow("true", 0, WinDivertFlags::new().set_sniff()).unwrap();
            let mut packet = [0u8; 65535];

            loop {
                let res = handle.recv(Some(&mut packet)).unwrap();

                let pid = res.address.process_id();
                let port = res.address.local_port();

                let flow_info = FlowAddress::new(
                    res.address.protocol(),
                    res.address.local_address(),
                    res.address.local_port(),
                );

                let (lock, cvar) = &*map;

                let mut map_lock = lock.lock().await;

                if !map_lock.contains_key(&flow_info) {
                    trace!(
                        "Captured PID: {}, Port: {}, Local Addr: {}, Protocol: {}",
                        pid, port, flow_info.ip, flow_info.protocol
                    );
                    map_lock.insert(flow_info, port);
                    cvar.notify_all();
                }

                drop(map_lock); // Explicitly drop the lock
            }
        })
    }

    // todo
    pub fn limit_speed_pid(&self, pid: u16, target_byterate: u64) -> JoinHandle<()> {
        tokio::spawn(async move {})
    }
}
