//! https://github.com/Rubensei/windivert-rust
//! https://www.reqrypt.org/windivert-doc.html

use std::collections::VecDeque;
use std::time::Duration;
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
    println!("DecLimiter Starting...");

    // execute().await;

    try_join!(flow_capture()).unwrap();

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

fn flow_capture() -> JoinHandle<()> {
    tokio::spawn(async move {
        println!("Starting flow capture...");

        let handle = WinDivert::socket("true", 0, WinDivertFlags::new().set_sniff()).unwrap();

        let mut packet = [0u8; 65535];
        let mut hashset = std::collections::HashSet::new();

        loop {
            let res = handle.recv(Some(&mut packet)).unwrap();

            let pid = res.address.process_id();

            if hashset.contains(&pid) {
                continue;
            } else {
                hashset.insert(pid);
                println!("New PID detected: {}", pid);
            }
        }
    })
}
