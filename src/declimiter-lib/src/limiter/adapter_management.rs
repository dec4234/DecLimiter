use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForMultipleObjects};
use ndisapi::{DirectionFlags, FilterFlags, IntermediateBuffer, Ndisapi};
use tokio::sync::Mutex;
use log::{debug, error};
use crate::error::DecLimiterError;
use crate::limiter::{network, DecLimiter, ETHERNET_HEADER_LEN};
use crate::limiter::network::{FlowAddress, FlowEntry};
use crate::limiter::packets::{read_packet, reinject_packet, throttle_packet};

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

/// Read and process all pending packets for a single adapter, applying throttling as needed.
pub fn process_adapter_packets(
	driver: &Ndisapi,
	adapter_handle: HANDLE,
	adapter_idx: usize,
	packet: &mut IntermediateBuffer,
	map: &Arc<Mutex<HashMap<FlowAddress, FlowEntry>>>,
	pid: u32,
	download_byterate: Option<u64>,
	upload_byterate: Option<u64>,
	dl_window: &mut VecDeque<(Instant, usize)>,
	ul_window: &mut VecDeque<(Instant, usize)>,
	dl_delay_us: &mut i64,
	ul_delay_us: &mut i64,
	dl_integral: &mut f64,
	ul_integral: &mut f64,
	max_delay_us: i64,
) {
	while read_packet(driver, adapter_handle, packet) {
		let is_outbound = packet.get_device_flags() == DirectionFlags::PACKET_FLAG_ON_SEND;
		let data = packet.get_data();

		if data.len() > ETHERNET_HEADER_LEN {
			let ip_data = &data[ETHERNET_HEADER_LEN..];

			let flow = if is_outbound {
				network::parse_flow_source(ip_data)
			} else {
				network::parse_flow_dest(ip_data)
			};

			if let Some(flow) = flow {
				if DecLimiter::pid_matches_blocking(map, &flow, pid) {
					if is_outbound {
						if let Some(rate) = upload_byterate {
							throttle_packet(ul_window, ul_delay_us, ul_integral, max_delay_us, rate, ip_data.len());
						}
					} else if let Some(rate) = download_byterate {
						throttle_packet(dl_window, dl_delay_us, dl_integral, max_delay_us, rate, ip_data.len());
					}
				}
			}
		}

		if let Err(e) = reinject_packet(driver, adapter_handle, packet, is_outbound) {
			error!("Error re-injecting packet on adapter [{}]: {}", adapter_idx, e);
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

/// Reset the event to non-signalled state.
pub fn reset_event(event: HANDLE) {
	// Safety: event is a valid handle created by create_win32_event.
	unsafe {
		let _ = ResetEvent(event);
	}
}