//! https://github.com/Rubensei/windivert-rust
//! https://www.reqrypt.org/windivert-doc.html
//! https://www.reqrypt.org/windivert-doc.html#filter_language
//!
//! Missing SYS error? - `sc delete WinDivert`

mod cli;
mod error;

use log::{debug, Level};
use crate::cli::{handle_startup};

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(Level::Trace).unwrap();

    debug!("DecLimiter Starting...");

    if let Err(e) = handle_startup().await {
        let err_str = e.to_string();
        if err_str.contains("Running without elevated access rights") {
            eprintln!("Error: Access denied. Please run DecLimiter as Administrator.");
        } else {
            eprintln!("Error: {}", err_str);
        }
    }

    wait_for_input();
}

fn wait_for_input() {
    println!("Press Enter to exit...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}

#[ignore]
#[tokio::test]
async fn test_limiter() {
    let limiter = declimiter_lib::limiter::DecLimiter::new();
    tokio::try_join!(limiter.start(), limiter.limit_download_speed_pid(44188, 500), limiter.garbage_collect_flows(std::time::Duration::from_secs(100))).unwrap();
}