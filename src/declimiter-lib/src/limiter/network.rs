use derive_new::new;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;
use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows::Win32::NetworkManagement::IpHelper::{
	GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
	MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

/// The transport protocol of a flow. TCP and UDP have separate port spaces,
/// thus the same local address and port can belong to two processes.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum FlowProtocol {
	Tcp,
	Udp,
}

/// The local end of a packet. Used to match connections to PIDs.
#[derive(Debug, Copy, Clone, Hash, PartialEq, new, Eq)]
pub struct FlowAddress {
	pub protocol: FlowProtocol,
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

/// Extract the protocol and the port from a raw IP packet's transport header.
fn extract_port(sliced: &SlicedPacket, use_source: bool) -> Option<(FlowProtocol, u16)> {
	match sliced.transport.as_ref()? {
		TransportSlice::Tcp(tcp) => Some((FlowProtocol::Tcp, if use_source { tcp.source_port() } else { tcp.destination_port() })),
		TransportSlice::Udp(udp) => Some((FlowProtocol::Udp, if use_source { udp.source_port() } else { udp.destination_port() })),
		_ => None,
	}
}

/// Parse a FlowAddress from a raw IP packet using either source or destination fields.
fn parse_flow(packet: &[u8], use_source: bool) -> Option<FlowAddress> {
	let sliced = SlicedPacket::from_ip(packet).ok()?;
	let ip = extract_ip(&sliced, use_source)?;
	let (protocol, port) = extract_port(&sliced, use_source)?;
	Some(FlowAddress::new(protocol, ip, port))
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

/// Find the PID that owns a flow.
///
/// A socket bound to INADDR_ANY (0.0.0.0 / ::) appears in the connection table
/// with a wildcard IP, but its packets carry the specific IP of the machine.
/// Thus, if there is no exact match, try the wildcard address of the same
/// family. A dual-stack IPv6 socket bound to :: also receives IPv4 packets, so
/// an IPv4 flow tries the IPv6 wildcard last.
pub fn lookup_pid(map: &HashMap<FlowAddress, FlowEntry>, flow: &FlowAddress) -> Option<u32> {
	let wildcard = |ip: IpAddr| map.get(&FlowAddress::new(flow.protocol, ip, flow.port)).map(|e| e.pid);

	map.get(flow).map(|e| e.pid).or_else(|| match flow.ip {
		IpAddr::V4(_) => wildcard(IpAddr::V4(Ipv4Addr::UNSPECIFIED)).or_else(|| wildcard(IpAddr::V6(Ipv6Addr::UNSPECIFIED))),
		IpAddr::V6(_) => wildcard(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
	})
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

/// Convert a raw IPv6 address to an IpAddr. An IPv4-mapped address
/// (::ffff:a.b.c.d) becomes an IPv4 address, because the packets of such a
/// connection are IPv4 packets.
fn ipv6_from_raw(raw: [u8; 16]) -> IpAddr {
	let addr = Ipv6Addr::from(raw);
	addr.to_ipv4_mapped().map_or(IpAddr::V6(addr), IpAddr::V4)
}

/// Query the Windows TCP and UDP connection tables (IPv4 and IPv6) to get
/// (local flow address, pid) mappings.
pub fn get_pid_port_mappings() -> Vec<(FlowAddress, u32)> {
	let mut result = Vec::new();
	query_tcp_table(&mut result);
	query_tcp6_table(&mut result);
	query_udp_table(&mut result);
	query_udp6_table(&mut result);
	result
}

/// Read a connection table into a buffer. `query` gets the buffer pointer and
/// the buffer size, and returns the Win32 status.
///
/// The buffer holds u32 values so that it has the alignment that the table
/// structures need.
fn read_table(query: impl Fn(Option<*mut c_void>, &mut u32) -> u32) -> Option<Vec<u32>> {
	let mut size: u32 = 0;
	query(None, &mut size);

	// The table can grow between the size query and the read, so try again
	// with the new size if the buffer was too small.
	for _ in 0..3 {
		if size == 0 {
			return None;
		}

		let mut buffer = vec![0u32; (size as usize).div_ceil(size_of::<u32>())];
		let ret = query(Some(buffer.as_mut_ptr() as *mut c_void), &mut size);

		if ret == 0 {
			return Some(buffer);
		}
		if ret != ERROR_INSUFFICIENT_BUFFER.0 {
			return None;
		}
	}

	None
}

fn query_tcp_table(result: &mut Vec<(FlowAddress, u32)>) {
	// Safety: read_table gives a buffer that Windows filled with a
	// MIB_TCPTABLE_OWNER_PID. The layout is well-defined by the Windows SDK and
	// the row slice stays within the buffer bounds guarded by dwNumEntries.
	unsafe {
		let Some(buffer) = read_table(|table, size| GetExtendedTcpTable(table, size, false.into(), AF_INET.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0)) else {
			return;
		};

		let table = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
		let rows = std::slice::from_raw_parts(&raw const (*table).table as *const MIB_TCPROW_OWNER_PID, (*table).dwNumEntries as usize);
		for row in rows {
			result.push((FlowAddress::new(FlowProtocol::Tcp, ipv4_from_raw(row.dwLocalAddr), port_from_raw(row.dwLocalPort)), row.dwOwningPid));
		}
	}
}

fn query_tcp6_table(result: &mut Vec<(FlowAddress, u32)>) {
	// Safety: Same pattern as query_tcp_table, with the IPv6 table layout.
	unsafe {
		let Some(buffer) = read_table(|table, size| GetExtendedTcpTable(table, size, false.into(), AF_INET6.0 as u32, TCP_TABLE_OWNER_PID_ALL, 0)) else {
			return;
		};

		let table = buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
		let rows = std::slice::from_raw_parts(&raw const (*table).table as *const MIB_TCP6ROW_OWNER_PID, (*table).dwNumEntries as usize);
		for row in rows {
			result.push((FlowAddress::new(FlowProtocol::Tcp, ipv6_from_raw(row.ucLocalAddr), port_from_raw(row.dwLocalPort)), row.dwOwningPid));
		}
	}
}

fn query_udp_table(result: &mut Vec<(FlowAddress, u32)>) {
	// Safety: Same pattern as query_tcp_table, with the UDP table layout.
	unsafe {
		let Some(buffer) = read_table(|table, size| GetExtendedUdpTable(table, size, false.into(), AF_INET.0 as u32, UDP_TABLE_OWNER_PID, 0)) else {
			return;
		};

		let table = buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
		let rows = std::slice::from_raw_parts(&raw const (*table).table as *const MIB_UDPROW_OWNER_PID, (*table).dwNumEntries as usize);
		for row in rows {
			result.push((FlowAddress::new(FlowProtocol::Udp, ipv4_from_raw(row.dwLocalAddr), port_from_raw(row.dwLocalPort)), row.dwOwningPid));
		}
	}
}

fn query_udp6_table(result: &mut Vec<(FlowAddress, u32)>) {
	// Safety: Same pattern as query_tcp_table, with the IPv6 UDP table layout.
	unsafe {
		let Some(buffer) = read_table(|table, size| GetExtendedUdpTable(table, size, false.into(), AF_INET6.0 as u32, UDP_TABLE_OWNER_PID, 0)) else {
			return;
		};

		let table = buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
		let rows = std::slice::from_raw_parts(&raw const (*table).table as *const MIB_UDP6ROW_OWNER_PID, (*table).dwNumEntries as usize);
		for row in rows {
			result.push((FlowAddress::new(FlowProtocol::Udp, ipv6_from_raw(row.ucLocalAddr), port_from_raw(row.dwLocalPort)), row.dwOwningPid));
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn flow(protocol: FlowProtocol, ip: &str, port: u16) -> FlowAddress {
		FlowAddress::new(protocol, ip.parse().unwrap(), port)
	}

	#[test]
	fn lookup_keeps_tcp_and_udp_apart() {
		let mut map = HashMap::new();
		map.insert(flow(FlowProtocol::Tcp, "10.0.0.2", 5000), FlowEntry::new(1));
		map.insert(flow(FlowProtocol::Udp, "10.0.0.2", 5000), FlowEntry::new(2));

		assert_eq!(lookup_pid(&map, &flow(FlowProtocol::Tcp, "10.0.0.2", 5000)), Some(1));
		assert_eq!(lookup_pid(&map, &flow(FlowProtocol::Udp, "10.0.0.2", 5000)), Some(2));
	}

	#[test]
	fn lookup_uses_wildcards() {
		let mut map = HashMap::new();
		map.insert(flow(FlowProtocol::Udp, "0.0.0.0", 53), FlowEntry::new(1));
		map.insert(flow(FlowProtocol::Udp, "::", 53), FlowEntry::new(2));
		map.insert(flow(FlowProtocol::Udp, "::", 443), FlowEntry::new(3));

		// The wildcard of the same family has priority.
		assert_eq!(lookup_pid(&map, &flow(FlowProtocol::Udp, "10.0.0.2", 53)), Some(1));
		assert_eq!(lookup_pid(&map, &flow(FlowProtocol::Udp, "2001:db8::1", 53)), Some(2));
		// An IPv4 packet to a dual-stack socket.
		assert_eq!(lookup_pid(&map, &flow(FlowProtocol::Udp, "10.0.0.2", 443)), Some(3));
		assert_eq!(lookup_pid(&map, &flow(FlowProtocol::Tcp, "10.0.0.2", 443)), None);
	}

	#[test]
	fn ipv4_mapped_address_becomes_ipv4() {
		let mapped: Ipv6Addr = "::ffff:192.168.1.5".parse().unwrap();
		assert_eq!(ipv6_from_raw(mapped.octets()), "192.168.1.5".parse::<IpAddr>().unwrap());
	}

	/// The tables of this machine must have a minimum of one entry for each
	/// protocol and address family.
	#[test]
	fn tables_contain_all_families() {
		let mappings = get_pid_port_mappings();
		for protocol in [FlowProtocol::Tcp, FlowProtocol::Udp] {
			assert!(mappings.iter().any(|(f, _)| f.protocol == protocol && f.ip.is_ipv4()), "no IPv4 {protocol:?} entry");
			assert!(mappings.iter().any(|(f, _)| f.protocol == protocol && f.ip.is_ipv6()), "no IPv6 {protocol:?} entry");
		}
	}
}
