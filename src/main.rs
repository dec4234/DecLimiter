//! DecLimiter - Network bandwidth limiter for Windows
//! Uses Windows Packet Filter (ndisapi) for transparent packet interception.
//! Requires WinpkFilter driver to be installed: https://www.ntkernel.com/windows-packet-filter/

mod cli;
mod error;
pub mod config;

use log::{debug, Level};
use crate::cli::{handle_startup};

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(Level::Trace).unwrap();

    debug!("DecLimiter Starting...");

    match handle_startup().await {
        Ok(true) => {
            // GUI was launched and closed — exit cleanly
        }
        Ok(false) => {
            // CLI mode — wait for user before closing console
            wait_for_input();
        }
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("elevated") || err_str.contains("Access") || err_str.contains("failed to load") {
                eprintln!("Error: Access denied or driver not found. Please run DecLimiter as Administrator and ensure WinpkFilter driver is installed.");
            } else {
                eprintln!("Error: {}", err_str);
            }
            wait_for_input();
        }
    }
}

fn wait_for_input() {
    println!("Press Enter to exit...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}

#[ignore]
#[tokio::test]
async fn test_limiter() {
    let limiter = declimiter_lib::limiter::DecLimiter::new().unwrap();
    tokio::try_join!(limiter.start(), limiter.limit_speed_pid(44188, Some(500), None), limiter.garbage_collect_flows(std::time::Duration::from_secs(100))).unwrap();
}