//! https://github.com/Rubensei/windivert-rust
//! https://www.reqrypt.org/windivert-doc.html
//! https://www.reqrypt.org/windivert-doc.html#filter_language
//!
//! Missing SYS error? - `sc delete WinDivert`

mod cli;
mod error;

use clap::Parser;
use log::{debug, Level};
use crate::cli::{execute, DecLimiterArgs};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    simple_logger::init_with_level(Level::Trace)?;

    debug!("DecLimiter Starting...");

    let args = DecLimiterArgs::parse();
    
    execute(args).await?;

    Ok(())
}

#[tokio::test]
async fn test_limiter() {
    let limiter = declimiter_lib::limiter::DecLimiter::new();
    tokio::try_join!(limiter.start(), limiter.limit_speed_pid(33092, 500_000), limiter.garbage_collect_flows(std::time::Duration::from_secs(100))).unwrap();
}