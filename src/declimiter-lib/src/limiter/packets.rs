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

    /// The target rate in bytes per second.
    pub fn rate(&self) -> u64 {
        self.rate as u64
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

#[cfg(test)]
mod tests {
    use super::TokenBucket;
    use std::time::Duration;

    #[test]
    fn capacity_is_fifty_ms_of_rate_with_a_minimum_of_one_frame() {
        // A slow rate gets the minimum capacity of one full frame.
        let slow = TokenBucket::new(1_000);
        assert_eq!(slow.capacity, 1500.0);
        assert_eq!(slow.tokens, 1500.0);

        // A fast rate gets 50 ms of burst.
        let fast = TokenBucket::new(1_000_000);
        assert_eq!(fast.capacity, 50_000.0);
        assert_eq!(fast.tokens, 50_000.0);
        assert_eq!(fast.rate, 1_000_000.0);
    }

    #[test]
    fn consume_within_capacity_has_no_delay() {
        let mut bucket = TokenBucket::new(1_000_000);
        assert_eq!(bucket.consume(1500), Duration::ZERO);
        assert_eq!(bucket.consume(40_000), Duration::ZERO);
    }

    #[test]
    fn consume_past_capacity_gives_delay_for_the_debt() {
        let mut bucket = TokenBucket::new(1_000);
        // 1500 tokens are in the bucket. A request for 2500 bytes leaves a
        // debt of approximately 1000 bytes, which at 1000 B/s is 1 second.
        let delay = bucket.consume(2_500);
        assert!(delay > Duration::from_millis(900), "delay too short: {delay:?}");
        assert!(delay <= Duration::from_secs(1), "delay too long: {delay:?}");
    }

    #[test]
    fn debt_accumulates_over_consecutive_packets() {
        let mut bucket = TokenBucket::new(10_000);
        bucket.consume(1500);
        let first = bucket.consume(1000);
        let second = bucket.consume(1000);
        assert!(first > Duration::ZERO);
        assert!(second > first, "second delay {second:?} must be longer than first {first:?}");
    }

    #[test]
    fn bucket_refills_with_time_but_not_past_capacity() {
        let mut bucket = TokenBucket::new(100_000);
        // Empty the bucket (capacity is 5000).
        bucket.consume(5_000);
        std::thread::sleep(Duration::from_millis(30));
        // 30 ms at 100 KB/s refills approximately 3000 tokens.
        assert_eq!(bucket.consume(2_000), Duration::ZERO);

        let mut idle = TokenBucket::new(100_000);
        std::thread::sleep(Duration::from_millis(20));
        idle.consume(0);
        assert_eq!(idle.tokens, idle.capacity, "tokens must not go above the capacity");
    }

    #[test]
    fn set_rate_changes_rate_and_clamps_tokens() {
        let mut bucket = TokenBucket::new(1_000_000);
        assert_eq!(bucket.tokens, 50_000.0);

        bucket.set_rate(1_000);
        assert_eq!(bucket.rate, 1_000.0);
        assert_eq!(bucket.rate(), 1_000);
        assert_eq!(bucket.capacity, 1500.0);
        assert_eq!(bucket.tokens, 1500.0);

        // An increase of the rate does not add tokens.
        bucket.set_rate(10_000_000);
        assert_eq!(bucket.capacity, 500_000.0);
        assert_eq!(bucket.tokens, 1500.0);
    }
}
