// src/main.rs
mod packet_processor;
mod rate_limiter;
mod process_tracker;
mod config;

use std::collections::HashMap;
use tokio::sync::Mutex;
use crate::packet_processor::PacketProcessor;
use crate::process_tracker::ProcessTracker;
use crate::config::LimiterConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Windows NetLimiter Clone Starting...");

    // Load configuration
    let config = LimiterConfig::load("config.json").unwrap_or_default();

    // Initialize components
    let process_tracker = ProcessTracker::new();
    let rate_limiter = RateLimiter::new(config.global_limits);

    // Start packet processing
    let packet_processor = PacketProcessor::new(process_tracker, rate_limiter).await?;
    packet_processor.start().await?;

    Ok(())
}