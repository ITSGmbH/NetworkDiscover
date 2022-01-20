
use std::net::IpAddr;

#[derive(Debug)]	
pub enum Protocol { UNKNOWN, TCP, UDP }

#[derive(Debug)]
pub enum State { UNKNOWN, OPEN, FILTER, CLOSE }

#[derive(Debug)]
pub struct Host {
	pub ip: Option<IpAddr>,
	pub ports: Vec<Service>,
	pub hops: Vec<IpAddr>,
	pub services: Vec<Service>,
}
impl Default for Host {
	fn default() -> Self {
		Host {
			ip: None,
			ports: vec![],
			hops: vec![],
			services: vec![],
		}
	}
}

#[derive(Debug)]
pub struct Service {
	pub port: u16,
	pub protocol: Protocol,
	pub state: State,
	pub service: String,
	pub product: String,
	pub version: String,
	pub vulns: Vec<Vulnerability>,
}
impl Default for Service {
	fn default() -> Self {
		Service {
			port: 0,
			protocol: Protocol::UNKNOWN,
			state: State::UNKNOWN,
			service: String::from(""),
			product: String::from(""),
			version: String::from(""),
			vulns: vec![],
		}
	}
}

#[derive(Debug)]
pub struct Vulnerability {
	pub database: String,
	pub id: String,
	pub cvss: f32,
	pub exploit: bool,
}
impl Default for Vulnerability {
	fn default() -> Self {
		Vulnerability {
			database: String::from(""),
			id: String::from(""),
			cvss: 0.0,
			exploit: false,
		}
	}
}
