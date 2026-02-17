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

    handle_startup().await.unwrap(); // todo: called `Result::unwrap()` on an `Err` value: Open(AccessDenied)
}

#[tokio::test]
async fn test_limiter() {
    let limiter = declimiter_lib::limiter::DecLimiter::new();
    tokio::try_join!(limiter.start(), limiter.limit_speed_pid(44188, 500), limiter.garbage_collect_flows(std::time::Duration::from_secs(100))).unwrap();
}