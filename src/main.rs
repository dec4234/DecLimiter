//! https://github.com/Rubensei/windivert-rust
//! https://www.reqrypt.org/windivert-doc.html
//! https://www.reqrypt.org/windivert-doc.html#filter_language
//!
//! Missing SYS error? - `sc delete WinDivert`

use std::time::Duration;
use declimiter_lib::limiter::DecLimiter;
use log::Level;
use tokio::try_join;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    simple_logger::init_with_level(Level::Trace).unwrap();

    println!("DecLimiter Starting...");

    let limiter = DecLimiter::new();
    try_join!(limiter.start(), limiter.limit_speed_pid(33092, 500_000), limiter.garbage_collect_flows(Duration::from_secs(100))).unwrap();

    Ok(())
}