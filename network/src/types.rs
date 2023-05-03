
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use pcap::Packet;

#[derive(Debug, Clone)]
pub enum Services {
	DHCP,
	DNS,
}
impl Services {
	pub fn value(&self) -> Protocol {
		match *self {
			Self::DHCP => Protocol::UDP(68),
			Self::DNS => Protocol::UDP(53),
		}
	}
}
impl Display for Services {
	fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
		write!(f, "{}", self.value())
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

#[derive(Debug)]
pub struct UdpPacket<T> {
	src_mac: [u8; 6],
	dst_mac: [u8; 6],
	src_ip: IpAddr,
	dst_ip: IpAddr,
	src_port: u16,
	dst_port: u16,
	len: u16,
	data: Option<T>,
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

		// No UDP-17 / TCP-6
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
			data: Some(DhcpData::try_from(&data[(offset + 8)..]).unwrap_or_default()),
			..Default::default()
		})
	}
}

#[derive(Debug, Default)]
pub struct DhcpData {
	raw: Vec<u8>,
}
impl TryFrom<&[u8]> for DhcpData {
	type Error = String;

	fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
		Ok(DhcpData {
			raw: Vec::from(data)
		})
	}
}

