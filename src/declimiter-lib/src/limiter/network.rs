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

	use etherparse::PacketBuilder;

	const V4_SRC: [u8; 4] = [192, 168, 1, 10];
	const V4_DST: [u8; 4] = [93, 184, 216, 34];
	const V6_SRC: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
	const V6_DST: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

	fn ipv4_tcp(src_port: u16, dst_port: u16) -> Vec<u8> {
		let mut out = Vec::new();
		PacketBuilder::ipv4(V4_SRC, V4_DST, 64).tcp(src_port, dst_port, 1, 1024).write(&mut out, b"payload").unwrap();
		out
	}

	fn ipv4_udp(src_port: u16, dst_port: u16) -> Vec<u8> {
		let mut out = Vec::new();
		PacketBuilder::ipv4(V4_SRC, V4_DST, 64).udp(src_port, dst_port).write(&mut out, b"payload").unwrap();
		out
	}

	fn ipv6_tcp(src_port: u16, dst_port: u16) -> Vec<u8> {
		let mut out = Vec::new();
		PacketBuilder::ipv6(V6_SRC, V6_DST, 64).tcp(src_port, dst_port, 1, 1024).write(&mut out, b"payload").unwrap();
		out
	}

	fn ipv6_udp(src_port: u16, dst_port: u16) -> Vec<u8> {
		let mut out = Vec::new();
		PacketBuilder::ipv6(V6_SRC, V6_DST, 64).udp(src_port, dst_port).write(&mut out, b"payload").unwrap();
		out
	}

	#[test]
	fn parses_ipv4_tcp_source_and_destination() {
		let packet = ipv4_tcp(50000, 443);
		assert_eq!(parse_flow_source(&packet), Some(flow(FlowProtocol::Tcp, "192.168.1.10", 50000)));
		assert_eq!(parse_flow_dest(&packet), Some(flow(FlowProtocol::Tcp, "93.184.216.34", 443)));
	}

	#[test]
	fn parses_ipv4_udp_source_and_destination() {
		let packet = ipv4_udp(5353, 53);
		assert_eq!(parse_flow_source(&packet), Some(flow(FlowProtocol::Udp, "192.168.1.10", 5353)));
		assert_eq!(parse_flow_dest(&packet), Some(flow(FlowProtocol::Udp, "93.184.216.34", 53)));
	}

	#[test]
	fn parses_ipv6_tcp_source_and_destination() {
		let packet = ipv6_tcp(50001, 80);
		assert_eq!(parse_flow_source(&packet), Some(flow(FlowProtocol::Tcp, "2001:db8::1", 50001)));
		assert_eq!(parse_flow_dest(&packet), Some(flow(FlowProtocol::Tcp, "2001:db8::2", 80)));
	}

	#[test]
	fn parses_ipv6_udp_source_and_destination() {
		let packet = ipv6_udp(40000, 443);
		assert_eq!(parse_flow_source(&packet), Some(flow(FlowProtocol::Udp, "2001:db8::1", 40000)));
		assert_eq!(parse_flow_dest(&packet), Some(flow(FlowProtocol::Udp, "2001:db8::2", 443)));
	}

	#[test]
	fn packet_without_tcp_or_udp_gives_no_flow() {
		let mut packet = Vec::new();
		PacketBuilder::ipv4(V4_SRC, V4_DST, 64).icmpv4_echo_request(1, 1).write(&mut packet, b"ping").unwrap();
		assert_eq!(parse_flow_source(&packet), None);
		assert_eq!(parse_flow_dest(&packet), None);
	}

	#[test]
	fn invalid_data_gives_no_flow() {
		assert_eq!(parse_flow_source(&[]), None);
		assert_eq!(parse_flow_dest(&[0xFF; 3]), None);
		// IP version 0 is not valid.
		assert_eq!(parse_flow_dest(&[0x00; 40]), None);

		// A packet cut inside the transport header.
		let packet = ipv4_tcp(1, 2);
		assert_eq!(parse_flow_dest(&packet[..22]), None);
	}

	#[test]
	fn lookup_prefers_exact_match_over_wildcard() {
		let mut map = HashMap::new();
		map.insert(flow(FlowProtocol::Tcp, "0.0.0.0", 8080), FlowEntry::new(1));
		map.insert(flow(FlowProtocol::Tcp, "10.0.0.2", 8080), FlowEntry::new(2));
		map.insert(flow(FlowProtocol::Tcp, "::", 9090), FlowEntry::new(3));
		map.insert(flow(FlowProtocol::Tcp, "2001:db8::5", 9090), FlowEntry::new(4));

		assert_eq!(lookup_pid(&map, &flow(FlowProtocol::Tcp, "10.0.0.2", 8080)), Some(2));
		assert_eq!(lookup_pid(&map, &flow(FlowProtocol::Tcp, "10.0.0.3", 8080)), Some(1));
		assert_eq!(lookup_pid(&map, &flow(FlowProtocol::Tcp, "2001:db8::5", 9090)), Some(4));
		assert_eq!(lookup_pid(&map, &flow(FlowProtocol::Tcp, "2001:db8::6", 9090)), Some(3));
	}

	#[test]
	fn ipv6_flow_does_not_use_the_ipv4_wildcard() {
		let mut map = HashMap::new();
		map.insert(flow(FlowProtocol::Udp, "0.0.0.0", 53), FlowEntry::new(1));

		assert_eq!(lookup_pid(&map, &flow(FlowProtocol::Udp, "2001:db8::1", 53)), None);
	}

	#[test]
	fn lookup_needs_the_same_port() {
		let mut map = HashMap::new();
		map.insert(flow(FlowProtocol::Tcp, "10.0.0.2", 80), FlowEntry::new(1));
		map.insert(flow(FlowProtocol::Tcp, "0.0.0.0", 81), FlowEntry::new(2));

		assert_eq!(lookup_pid(&map, &flow(FlowProtocol::Tcp, "10.0.0.2", 8080)), None);
		assert_eq!(lookup_pid(&HashMap::new(), &flow(FlowProtocol::Tcp, "10.0.0.2", 80)), None);
	}

	#[test]
	fn flow_entry_update_moves_last_seen_forward() {
		let mut entry = FlowEntry::new(7);
		let before = entry.last_seen;
		std::thread::sleep(std::time::Duration::from_millis(2));
		entry.update_last_seen();
		assert_eq!(entry.pid, 7);
		assert!(entry.last_seen > before);
	}

	#[test]
	fn raw_ipv4_is_in_network_byte_order() {
		// Windows keeps 192.168.1.5 as the bytes C0 A8 01 05 in memory.
		let raw = u32::from_ne_bytes([192, 168, 1, 5]);
		assert_eq!(ipv4_from_raw(raw), "192.168.1.5".parse::<IpAddr>().unwrap());
		assert_eq!(ipv4_from_raw(0), "0.0.0.0".parse::<IpAddr>().unwrap());
	}

	#[test]
	fn raw_port_is_in_network_byte_order() {
		// Port 443 (0x01BB) in network byte order, in the low 16 bits.
		let raw = u16::from_ne_bytes(443u16.to_be_bytes()) as u32;
		assert_eq!(port_from_raw(raw), 443);
		// The upper 16 bits are not part of the port.
		assert_eq!(port_from_raw(raw | 0xABCD_0000), 443);
	}

	#[test]
	fn plain_ipv6_address_stays_ipv6() {
		let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
		assert_eq!(ipv6_from_raw(addr.octets()), IpAddr::V6(addr));
		assert_eq!(ipv6_from_raw([0; 16]), IpAddr::V6(Ipv6Addr::UNSPECIFIED));
	}

	#[test]
	fn read_table_returns_none_when_size_is_zero() {
		let calls = std::cell::Cell::new(0);
		let result = read_table(|_, _| {
			calls.set(calls.get() + 1);
			0
		});
		assert!(result.is_none());
		assert_eq!(calls.get(), 1, "only the size query must run");
	}

	#[test]
	fn read_table_returns_the_filled_buffer() {
		let result = read_table(|table, size| match table {
			None => {
				*size = 10;
				ERROR_INSUFFICIENT_BUFFER.0
			}
			Some(ptr) => {
				// The buffer must hold at least the requested number of bytes.
				unsafe { std::ptr::write_bytes(ptr as *mut u8, 0xAB, *size as usize) };
				0
			}
		})
		.expect("the read must succeed");

		// 10 bytes round up to 3 u32 values.
		assert_eq!(result.len(), 3);
		assert_eq!(result[0], 0xABAB_ABAB);
	}

	#[test]
	fn read_table_retries_when_the_table_grows() {
		let calls = std::cell::Cell::new(0);
		let result = read_table(|table, size| {
			calls.set(calls.get() + 1);
			match (table, calls.get()) {
				(None, _) => {
					*size = 4;
					ERROR_INSUFFICIENT_BUFFER.0
				}
				// The first read finds a larger table.
				(Some(_), 2) => {
					*size = 16;
					ERROR_INSUFFICIENT_BUFFER.0
				}
				(Some(_), _) => 0,
			}
		})
		.expect("the second read must succeed");

		assert_eq!(calls.get(), 3);
		assert_eq!(result.len(), 4);
	}

	#[test]
	fn read_table_gives_up_after_three_attempts() {
		let calls = std::cell::Cell::new(0);
		let result = read_table(|_, size| {
			calls.set(calls.get() + 1);
			*size += 4;
			ERROR_INSUFFICIENT_BUFFER.0
		});
		assert!(result.is_none());
		assert_eq!(calls.get(), 4, "one size query and three reads");
	}

	#[test]
	fn read_table_stops_on_a_different_error() {
		let calls = std::cell::Cell::new(0);
		let result = read_table(|table, size| {
			calls.set(calls.get() + 1);
			match table {
				None => {
					*size = 8;
					ERROR_INSUFFICIENT_BUFFER.0
				}
				// ERROR_INVALID_PARAMETER
				Some(_) => 87,
			}
		});
		assert!(result.is_none());
		assert_eq!(calls.get(), 2);
	}

	/// The current process opens two sockets. Their ports must appear in the
	/// tables with the PID of the current process.
	#[test]
	fn mappings_contain_the_sockets_of_this_process() {
		let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
		let pid = std::process::id();

		let mappings = get_pid_port_mappings();
		let tcp_flow = flow(FlowProtocol::Tcp, "127.0.0.1", tcp.local_addr().unwrap().port());
		let udp_flow = flow(FlowProtocol::Udp, "127.0.0.1", udp.local_addr().unwrap().port());

		assert!(mappings.contains(&(tcp_flow, pid)), "TCP listener {tcp_flow:?} not mapped to PID {pid}");
		assert!(mappings.contains(&(udp_flow, pid)), "UDP socket {udp_flow:?} not mapped to PID {pid}");
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
