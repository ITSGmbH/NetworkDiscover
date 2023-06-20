
use std::convert::{From, TryFrom};
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use pcap::Packet;

#[derive(Debug, Clone, PartialEq)]
pub enum Services {
	DHCP,
}
impl Display for Services {
	fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
		write!(f, "{}", self.value())
	}
}
impl Services {
	pub fn value(&self) -> Protocol {
		match *self {
			Self::DHCP => Protocol::UDP(68),
		}
	}
}

#[derive(Debug, Clone)]
pub enum Protocol {
	UNKNOWN,
	TCP(u16),
	UDP(u16)
}
impl Display for Protocol {
	fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
		match self {
			Self::UNKNOWN => write!(f, "UNKNOWN"),
			Self::TCP(p) => write!(f, "TCP/{}", p),
			Self::UDP(p) => write!(f, "UDP/{}", p),
		}
	}
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct UdpPacket<T> {
	pub src_mac: [u8; 6],
	pub dst_mac: [u8; 6],
	pub src_ip: IpAddr,
	pub dst_ip: IpAddr,
	pub src_port: u16,
	pub dst_port: u16,
	pub len: u16,
	pub data: Option<T>,
}
impl<T> Default for UdpPacket<T> {
	fn default() -> UdpPacket<T> {
		Self {
			src_mac: [0,0,0,0,0,0],
			dst_mac: [0,0,0,0,0,0],
			src_ip: IpAddr::from([0, 0, 0, 0]),
			dst_ip: IpAddr::from([0, 0, 0, 0]),
			src_port: 0,
			dst_port: 0,
			len: 0,
			data: None,
		}
	}
}
impl TryFrom<Packet<'_>> for UdpPacket<DhcpData> {
	type Error = String;

	fn try_from(source: Packet) -> Result<Self, Self::Error> {
		let data = &source.data[2..];
		let src_mac: [u8; 6] = data[0..6].try_into().unwrap_or_default();
		let dst_mac: [u8; 6] = data[6..12].try_into().unwrap_or_default();
		let ip_type: u16 = (u16::from(data[12]) << 8) + u16::from(data[13]);

		let (src_ip, dst_ip, proto, offset) = match ip_type {
			// IPv4
			0x0800 => {
				let ip_header = &data[14..34];
				let ihl: u8 = (ip_header[0] << 4) >> 4; // Second quadrupel, the first quadruple is the version
				let proto: u8 = ip_header[9];
				let src: [u8; 4] = ip_header[12..16].try_into().unwrap_or_default();
				let dst: [u8; 4] = ip_header[16..20].try_into().unwrap_or_default();
				(IpAddr::from(src), IpAddr::from(dst), proto, (14 + (ihl * 4)) as usize)
			},

			// IPv6
			0x86DD => return Err("No IPv6 parsing yet".to_string()),

			// ARP
			0x0806 => return Err("No ARP parsing yet".to_string()),

			// LLDP
			0x88cc => return Err("No LLDP parsing yet".to_string()),

			// No other types (yet?)
			_ => return Err(format!("Unknown Layer-3 Type: {}", ip_type).to_string())
		};

		// No UDP-17 (TCP-6)
		if proto != 17 {
			return Err(format!("Package-type {} cannot be parsed with UdpPackage (17)", proto));
		}

		let udp_header = &data[offset..];
		Ok(UdpPacket {
			src_mac, dst_mac,
			src_ip, dst_ip,
			src_port: (u16::from(udp_header[0]) << 8) + u16::from(udp_header[1]),
			dst_port: (u16::from(udp_header[2]) << 8) + u16::from(udp_header[3]),
			len: (u16::from(udp_header[4]) << 8) + u16::from(udp_header[5]) - 8,
			data: DhcpData::try_from(&data[(offset + 8)..]).ok(),
		})
	}
}

#[derive(Debug, Default, PartialEq)]
pub enum DhcpMessageType {
	#[default]
	Unknown = 0,
	Discover = 1,
	Offer = 2,
	Request = 3,
	Decline = 4,
	Pack = 5,
	Nak = 6,
	Release = 7,
	Inform = 8,
	ForceRenew = 9,
	LeaseQuery = 10,
	LeaseUnassigned = 11,
	LeaseUnknown = 12,
	LeaseActive = 13,
	BulkLeaseQuery = 14,
	LeaseQueryDone = 15,
	ActiveLeaseQuery = 16,
	LeaseQueryStatus = 17,
	TLS = 18,
}
impl From<u8> for DhcpMessageType {
	fn from(val: u8) -> Self {
		match val {
			0 => DhcpMessageType::Unknown,
			1 => DhcpMessageType::Discover,
			2 => DhcpMessageType::Offer,
			3 => DhcpMessageType::Request,
			4 => DhcpMessageType::Decline,
			5 => DhcpMessageType::Pack,
			6 => DhcpMessageType::Nak,
			7 => DhcpMessageType::Release,
			8 => DhcpMessageType::Inform,
			9 => DhcpMessageType::ForceRenew,
			10 => DhcpMessageType::LeaseQuery,
			11 => DhcpMessageType::LeaseUnassigned,
			12 => DhcpMessageType::LeaseUnknown,
			13 => DhcpMessageType::LeaseActive,
			14 => DhcpMessageType::BulkLeaseQuery,
			15 => DhcpMessageType::LeaseQueryDone,
			16 => DhcpMessageType::ActiveLeaseQuery,
			17 => DhcpMessageType::LeaseQueryStatus,
			18 => DhcpMessageType::TLS,
			_ => DhcpMessageType::Unknown
		}
	}
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct DhcpData {
	pub msg_type: DhcpMessageType,
	pub hw_type: u8,
	pub hw_addr_len: u8,
	pub hops: u8,
	pub transaction_id: u32,
	pub seconds: u16,
	pub flags: u16,
	pub client_addr: IpAddr, // Client IP Address
	pub your_addr: IpAddr, // Your IP Address
	pub server_addr: IpAddr, // Server IP Address
	pub relay_addr: IpAddr, // gateway IP Address
	pub hw_addr: [u8; 16], // client Hardware Address
	// 192 * u8 filled with '0'
	pub magic_cookie: u32,
	// Options: type(u8), num_octets(u8), value(num_octets)
	pub options: Vec<DhcpOption>,
}
impl TryFrom<&[u8]> for DhcpData {
	type Error = String;

	fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
		let mut options = vec![];
		let mut option_start: usize = 240;
		while data.len() > option_start {
			let options_data = &data[option_start..];
			let option = DhcpOption::try_from(options_data).unwrap_or(DhcpOption::Invalid(0));
			if option == DhcpOption::End || options_data.len() < 2 {
				break;
			}
			options.push(option);
			option_start += 2 + options_data[1] as usize;
		}

		Ok(DhcpData {
			msg_type: data[0].into(),
			hw_type: data[1],
			hw_addr_len: data[2],
			hops: data[3],
			transaction_id: u32::from_le_bytes(data[4..8].try_into().unwrap_or_default()),
			seconds: u16::from_le_bytes(data[8..10].try_into().unwrap_or_default()),
			flags: u16::from_be_bytes(data[10..12].try_into().unwrap_or_default()), // BigEndian to have the bin-structure as is
			client_addr: {
				let val: [u8; 4] = data[12..16].try_into().unwrap_or_default();
				IpAddr::from(val)
			},
			your_addr: {
				let val: [u8; 4] = data[16..20].try_into().unwrap_or_default();
				IpAddr::from(val)
			},
			server_addr: {
				let val: [u8; 4] = data[20..24].try_into().unwrap_or_default();
				IpAddr::from(val)
			},
			relay_addr: {
				let val: [u8; 4] = data[24..28].try_into().unwrap_or_default();
				IpAddr::from(val)
			},
			hw_addr: data[28..44].try_into().unwrap_or_default(), // client Hardware Address
			// 192 * u8 filled with '0'
			magic_cookie: u32::from_le_bytes(data[236..240].try_into().unwrap_or_default()),
			options,
		})
	}
}

#[derive(Debug, PartialEq)]
pub enum DhcpOption {
	Invalid(u8),
	Unknown(u8, Vec<u8>),
	Netmask(IpAddr), // 1
	Router(Vec<IpAddr>), // 3
	DnsServer(Vec<IpAddr>), // 6
	HostName(String), // 12
	DomainName(String), // 15
	RequestedIpAddress(IpAddr), // 50
	LeaseTime(u32), // 51
	MessageType(DhcpMessageType), // 53
	DhcpServer(IpAddr), // 54
	VendorIdentifier(String), // 60
	End, // 255
}
impl TryFrom<&[u8]> for DhcpOption {
	type Error = String;

	fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
		if data.len() < 1 { return Ok(Self::Invalid(0)); }
		if data.len() < 2 { return Ok(Self::Invalid(data[0])); }
		let code: u8 = data[0];
		let len: usize = data[1] as usize;

		if data.len() < (len + 2) { return Ok(Self::Invalid(data[0])); }
		let parse: &[u8] = &data[2..(len + 2)];

		Ok(match code {
			// Subnet Mask
			1 => {
				let val: [u8; 4] = parse[0..4].try_into().unwrap_or_default();
				Self::Netmask(IpAddr::from(val))
			},
			// Router and DNS-Server
			3 | 6 => {
				let mut list: Vec<IpAddr> = vec![];
				let mut pos: usize = 0;
				while pos < len && pos + 4 <= len {
					let val: [u8; 4] = parse[pos..(pos + 4)].try_into().unwrap_or_default();
					list.push(IpAddr::from(val));
					pos += 4;
				}
				if code  == 3 {
					Self::Router(list)
				} else {
					Self::DnsServer(list)
				}
			},
			// HostName
			12 => Self::HostName(std::str::from_utf8(parse).unwrap_or_default().to_string()),
			// DomainName
			15 => Self::DomainName(std::str::from_utf8(parse).unwrap_or_default().to_string()),
			// Requested IP-Address
			50 => {
				let val: [u8; 4] = parse[0..4].try_into().unwrap_or_default();
				Self::RequestedIpAddress(IpAddr::from(val))
			},
			// LeaseTime
			51 => Self::LeaseTime(u32::from_le_bytes(parse[0..4].try_into().unwrap_or_default())),
			// MessageType
			53 => Self::MessageType(DhcpMessageType::from(parse[0])),
			// DHCP-Server IP-Address
			54 => {
				let val: [u8; 4] = parse[0..4].try_into().unwrap_or_default();
				Self::DhcpServer(IpAddr::from(val))
			},
			// DomainName
			60 => Self::VendorIdentifier(std::str::from_utf8(parse).unwrap_or_default().to_string()),
			// End
			255 => Self::End,
			// Anything else not now
			_ => Self::Unknown(code, Vec::from(parse)),
		})
	}
}
