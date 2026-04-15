use ndisapi::{EthRequest, EthRequestMut, IntermediateBuffer, Ndisapi};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::HANDLE;

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

/// Token-bucket rate limiter for a single direction (download or upload).
///
/// Tokens represent bytes. The bucket refills at `rate` bytes/sec up to
/// `capacity`. When a packet arrives, its size is deducted from the bucket.
/// If the bucket goes negative, the packet must be delayed until enough
/// tokens have accumulated — the returned `Duration` tells the caller how
/// long to defer reinjection.
pub struct TokenBucket {
    tokens: f64,
    capacity: f64,
    rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(rate: u64) -> Self {
        let rate_f = rate as f64;
        // Allow ~50ms of burst.  Enough to absorb normal jitter without
        // letting large bursts blow past the limit.
        let capacity = (rate_f * 0.05).max(1500.0);
        Self {
            tokens: capacity,
            capacity,
            rate: rate_f,
            last_refill: Instant::now(),
        }
    }

    /// Consume `bytes` from the bucket, returning the delay before the packet
    /// should be reinjected.  Returns `Duration::ZERO` when tokens are
    /// available (no throttling needed).
    pub fn consume(&mut self, bytes: usize) -> Duration {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;

        self.tokens -= bytes as f64;

        if self.tokens >= 0.0 {
            Duration::ZERO
        } else {
            // Time until the bucket refills back to zero.
            Duration::from_secs_f64((-self.tokens) / self.rate)
        }
    }

    /// Update the target rate.  Keeps current token level (clamped to the new
    /// capacity) so the transition is smooth.
    pub fn set_rate(&mut self, rate: u64) {
        let rate_f = rate as f64;
        self.rate = rate_f;
        self.capacity = (rate_f * 0.05).max(1500.0);
        self.tokens = self.tokens.min(self.capacity);
    }
}
