use derive_new::new;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;
use windows::Win32::NetworkManagement::IpHelper::{
	GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPTABLE_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::AF_INET;

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
		Self { pid, last_seen: Instant::now() }
	}

	pub fn update_last_seen(&mut self) {
		self.last_seen = Instant::now();
	}
}

// ---------------------------------------------------------------------------
// Packet parsing utilities
// ---------------------------------------------------------------------------

/// Extract the IP address from a raw IP packet's network header.
fn extract_ip(sliced: &SlicedPacket, use_source: bool) -> Option<IpAddr> {
	match sliced.net.as_ref()? {
		InternetSlice::Ipv4(h) => {
			let addr = if use_source { h.header().source_addr() } else { h.header().destination_addr() };
			Some(IpAddr::V4(addr))
		}
		InternetSlice::Ipv6(h) => {
			let addr = if use_source { h.header().source_addr() } else { h.header().destination_addr() };
			Some(IpAddr::V6(addr))
		}
		_ => None,
	}
}

/// Extract the port from a raw IP packet's transport header.
fn extract_port(sliced: &SlicedPacket, use_source: bool) -> Option<u16> {
	match sliced.transport.as_ref()? {
		TransportSlice::Tcp(tcp) => Some(if use_source { tcp.source_port() } else { tcp.destination_port() }),
		TransportSlice::Udp(udp) => Some(if use_source { udp.source_port() } else { udp.destination_port() }),
		_ => None,
	}
}

/// Parse a FlowAddress from a raw IP packet using either source or destination fields.
fn parse_flow(packet: &[u8], use_source: bool) -> Option<FlowAddress> {
	let sliced = SlicedPacket::from_ip(packet).ok()?;
	let ip = extract_ip(&sliced, use_source)?;
	let port = extract_port(&sliced, use_source)?;
	Some(FlowAddress::new(ip, port))
}

/// Parse the flow address (destination IP and port) from a raw IP packet.
pub fn parse_flow_dest(packet: &[u8]) -> Option<FlowAddress> {
	parse_flow(packet, false)
}

/// Parse the flow address (source IP and port) from a raw IP packet.
/// Used for matching outbound packets to their originating process.
pub fn parse_flow_source(packet: &[u8]) -> Option<FlowAddress> {
	parse_flow(packet, true)
}

// ---------------------------------------------------------------------------
// Windows connection table queries
// ---------------------------------------------------------------------------

/// Convert a raw network-byte-order u32 address to an IpAddr.
fn ipv4_from_raw(raw: u32) -> IpAddr {
	let b = raw.to_ne_bytes();
	IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
}

/// Convert a raw network-byte-order port (stored in a u32) to a host-order u16.
fn port_from_raw(raw: u32) -> u16 {
	u16::from_be((raw & 0xFFFF) as u16)
}

/// Query the Windows TCP and UDP connection tables to get (local_ip, local_port, pid) mappings.
pub fn get_pid_port_mappings() -> Vec<(IpAddr, u16, u32)> {
	let mut result = Vec::new();
	query_tcp_table(&mut result);
	query_udp_table(&mut result);
	result
}

fn query_tcp_table(result: &mut Vec<(IpAddr, u16, u32)>) {
	let mut size: u32 = 0;

	// Safety: First call with null buffer to get required size. Second call reads into
	// an appropriately-sized buffer. The MIB_TCPTABLE_OWNER_PID layout is well-defined
	// by the Windows SDK and the pointer arithmetic stays within the buffer bounds
	// guarded by dwNumEntries.
	unsafe {
		let _ = GetExtendedTcpTable(None, &mut size, false.into(), AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0);

		if size == 0 {
			return;
		}

		let mut buffer = vec![0u8; size as usize];
		let ret = GetExtendedTcpTable(Some(buffer.as_mut_ptr() as *mut _), &mut size, false.into(), AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0);

		if ret != 0 {
			return;
		}

		let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
		for i in 0..table.dwNumEntries as usize {
			let row = &*table.table.as_ptr().add(i);
			result.push((ipv4_from_raw(row.dwLocalAddr), port_from_raw(row.dwLocalPort), row.dwOwningPid));
		}
	}
}

fn query_udp_table(result: &mut Vec<(IpAddr, u16, u32)>) {
	let mut size: u32 = 0;

	// Safety: Same pattern as query_tcp_table — two-pass size query then read.
	unsafe {
		let _ = GetExtendedUdpTable(None, &mut size, false.into(), AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0);

		if size == 0 {
			return;
		}

		let mut buffer = vec![0u8; size as usize];
		let ret = GetExtendedUdpTable(Some(buffer.as_mut_ptr() as *mut _), &mut size, false.into(), AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0);

		if ret != 0 {
			return;
		}

		let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
		for i in 0..table.dwNumEntries as usize {
			let row = &*table.table.as_ptr().add(i);
			result.push((ipv4_from_raw(row.dwLocalAddr), port_from_raw(row.dwLocalPort), row.dwOwningPid));
		}
	}
}
