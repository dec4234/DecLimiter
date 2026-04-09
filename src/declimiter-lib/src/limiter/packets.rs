use ndisapi::{EthRequest, EthRequestMut, IntermediateBuffer, Ndisapi};
use std::collections::VecDeque;
use std::thread;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::HANDLE;

use super::MOV_AVG_WINDOW_SIZE;

/// Read a single packet from the adapter. Returns true if a packet was read.
pub fn read_packet(driver: &Ndisapi, adapter_handle: HANDLE, packet: &mut IntermediateBuffer) -> bool {
    let mut read_request = EthRequestMut::new(adapter_handle);
    read_request.set_packet(packet);
    driver.read_packet(&mut read_request).is_ok()
}

/// Re-inject a packet: outbound goes to the adapter, inbound goes to MSTCP.
pub fn reinject_packet(driver: &Ndisapi, adapter_handle: HANDLE, packet: &IntermediateBuffer, is_outbound: bool) -> Result<(), windows::core::Error> {
    let mut write_request = EthRequest::new(adapter_handle);
    write_request.set_packet(packet);

    if is_outbound {
        driver.send_packet_to_adapter(&write_request)
    } else {
        driver.send_packet_to_mstcp(&write_request)
    }
}

/// Apply throttling by tracking a moving average window and sleeping to limit throughput.
pub fn throttle_packet(window: &mut VecDeque<(Instant, usize)>, dynamic_delay_us: &mut i64, max_delay_us: i64, target_byterate: u64, bytes: usize) {
    let now = Instant::now();

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

            let kp = 0.02;
            *dynamic_delay_us += (error * kp) as i64;
            *dynamic_delay_us = (*dynamic_delay_us).clamp(0, max_delay_us);

            if *dynamic_delay_us > 0 {
                thread::sleep(Duration::from_micros(*dynamic_delay_us as u64));
            }
        }
    }
}
