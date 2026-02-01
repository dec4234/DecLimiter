use std::net::IpAddr;
use derive_new::new;
use tokio::time::Instant;

/// The destination of a packet. Used to match connections to PIDs.
#[derive(Debug, Copy, Clone, Hash, PartialEq, new, Eq)]
pub struct FlowAddress {
	pub ip: IpAddr,
	pub port: u16,
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct FlowEntry {
	pub pid: u32,
	pub last_seen: Instant,
}

impl FlowEntry {
	pub fn new(pid: u32) -> Self {
		Self {
			pid,
			last_seen: Instant::now(),
		}
	}
	
	pub fn update_last_seen(&mut self) {
		self.last_seen = Instant::now();
	}
}