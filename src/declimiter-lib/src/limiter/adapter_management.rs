use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForMultipleObjects};
use ndisapi::{DirectionFlags, FilterFlags, IntermediateBuffer, Ndisapi};
use tokio::sync::RwLock;
use log::{debug, error};
use crate::error::DecLimiterError;
use crate::limiter::{network, DecLimiter, ETHERNET_HEADER_LEN};
use crate::limiter::network::{FlowAddress, FlowEntry};
use crate::limiter::packets::{read_packet, reinject_packet, TokenBucket};

/// Initialize tunnel mode on all adapters and return their handles and events.
pub fn setup_adapters(driver: &Ndisapi) -> Result<(Vec<HANDLE>, Vec<HANDLE>), DecLimiterError> {
	let adapters = driver.get_tcpip_bound_adapters_info().map_err(DecLimiterError::WindowsError)?;

	if adapters.is_empty() {
		return Err(DecLimiterError::NoAdapterFound);
	}

	let mut adapter_handles: Vec<HANDLE> = Vec::new();
	let mut events: Vec<HANDLE> = Vec::new();

	for (i, adapter) in adapters.iter().enumerate() {
		let handle = adapter.get_handle();
		let event = create_win32_event()?;

		driver.set_packet_event(handle, event).map_err(DecLimiterError::WindowsError)?;
		driver.set_adapter_mode(handle, FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL).map_err(DecLimiterError::WindowsError)?;

		debug!("Intercepting on adapter [{}]: {}", i, adapter.get_name());
		adapter_handles.push(handle);
		events.push(event);
	}

	Ok((adapter_handles, events))
}

/// A packet whose reinjection has been deferred to enforce a rate limit.
pub struct DelayedPacket {
	pub buffer: IntermediateBuffer,
	pub adapter_handle: HANDLE,
	pub is_outbound: bool,
	pub release_at: Instant,
	/// Full Ethernet frame length, stored so traffic can be counted at
	/// reinjection time rather than interception time.
	pub frame_len: usize,
	/// PID that owns this packet (if resolved), for per-process traffic counting.
	pub pid: Option<u32>,
}

/// Metadata for a packet that was just reinjected from the delay queue,
/// so the caller can update traffic counters at delivery time.
pub struct ReinjectedInfo {
	pub is_outbound: bool,
	pub frame_len: usize,
	pub pid: Option<u32>,
}

/// Drain the delay queue, reinjecting any packets whose release time has passed.
/// Pushes `ReinjectedInfo` into `reinjected` for each delivered packet so the
/// caller can count traffic at delivery time.
pub fn flush_delayed(driver: &Ndisapi, queue: &mut VecDeque<DelayedPacket>, reinjected: &mut Vec<ReinjectedInfo>) {
	let now = Instant::now();
	while let Some(front) = queue.front() {
		if front.release_at <= now {
			let pkt = queue.pop_front().unwrap();
			if let Err(e) = reinject_packet(driver, pkt.adapter_handle, &pkt.buffer, pkt.is_outbound) {
				error!("Error re-injecting delayed packet: {}", e);
			} else {
				reinjected.push(ReinjectedInfo {
					is_outbound: pkt.is_outbound,
					frame_len: pkt.frame_len,
					pid: pkt.pid,
				});
			}
		} else {
			return;
		}
	}
}

/// Read and process all pending packets for a single adapter, applying throttling as needed.
/// Throttled packets are pushed onto `delay_queue` for deferred reinjection instead of
/// blocking the processing thread.
pub fn process_adapter_packets(
	driver: &Ndisapi,
	adapter_handle: HANDLE,
	adapter_idx: usize,
	packet: &mut IntermediateBuffer,
	map: &Arc<RwLock<HashMap<FlowAddress, FlowEntry>>>,
	pid: u32,
	dl_bucket: &mut Option<TokenBucket>,
	ul_bucket: &mut Option<TokenBucket>,
	delay_queue: &mut VecDeque<DelayedPacket>,
) {
	while read_packet(driver, adapter_handle, packet) {
		let is_outbound = packet.get_device_flags() == DirectionFlags::PACKET_FLAG_ON_SEND;
		let data = packet.get_data();
		let mut delay = Duration::ZERO;

		if data.len() > ETHERNET_HEADER_LEN {
			let ip_data = &data[ETHERNET_HEADER_LEN..];

			let flow = if is_outbound {
				network::parse_flow_source(ip_data)
			} else {
				network::parse_flow_dest(ip_data)
			};

			if let Some(flow) = flow {
				if DecLimiter::pid_matches_blocking(map, &flow, pid) {
					// Use full frame length for rate limiting.
					let frame_len = data.len();
					if is_outbound {
						if let Some(bucket) = ul_bucket.as_mut() {
							delay = bucket.consume(frame_len);
						}
					} else if let Some(bucket) = dl_bucket.as_mut() {
						delay = bucket.consume(frame_len);
					}
				}
			}
		}

		if delay > Duration::ZERO {
			// Defer reinjection — take the buffer and replace with a fresh one.
			let frame_len = packet.get_data().len();
			let deferred = std::mem::take(packet);
			delay_queue.push_back(DelayedPacket {
				buffer: deferred,
				adapter_handle,
				is_outbound,
				release_at: Instant::now() + delay,
				frame_len,
				pid: Some(pid),
			});
		} else {
			if let Err(e) = reinject_packet(driver, adapter_handle, packet, is_outbound) {
				error!("Error re-injecting packet on adapter [{}]: {}", adapter_idx, e);
			}
		}
	}
}

/// Create a manual-reset Win32 event for packet notification.
fn create_win32_event() -> Result<HANDLE, DecLimiterError> {
	// Safety: CreateEventW with null security attributes and no name is safe.
	unsafe { CreateEventW(None, true, false, None).map_err(DecLimiterError::WindowsError) }
}

/// Block the current thread until any of the events is signalled.
pub fn wait_for_any_event(events: &[HANDLE]) {
	// Safety: all events are valid handles created by create_win32_event.
	unsafe {
		WaitForMultipleObjects(events, false, u32::MAX);
	}
}

/// Block the current thread until any event is signalled or the timeout expires.
/// A timeout of 0 polls without blocking.
pub fn wait_for_any_event_timeout(events: &[HANDLE], timeout_ms: u32) {
	// Safety: all events are valid handles created by create_win32_event.
	unsafe {
		WaitForMultipleObjects(events, false, timeout_ms);
	}
}

/// Reset the event to non-signalled state.
pub fn reset_event(event: HANDLE) {
	// Safety: event is a valid handle created by create_win32_event.
	unsafe {
		let _ = ResetEvent(event);
	}
}