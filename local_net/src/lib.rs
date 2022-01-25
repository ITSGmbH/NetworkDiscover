
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug)]
pub struct Route {
	network: Option<IpAddr>,
	netmask: u16,
	device: String,
	is_default: bool,
	router: Option<IpAddr>,
}

impl Default for Route {
	fn default() -> Self {
		Route {
			network: None,
			netmask: 0,
			device: String::from(""),
			is_default: false,
			router: None,
		}
	}
}

#[derive(Debug)]
pub struct LocalNet {
	ipv4_addr: Option<IpAddr>,
	ipv4_net: u16,
	ipv6_addr: Option<IpAddr>,
	ipv6_net: u16,
	routes: Vec<Route>,
}
impl Default for LocalNet {
	fn default() -> Self {
		LocalNet {
			ipv4_addr: None,
			ipv4_net: 31,
			ipv6_addr: None,
			ipv6_net: 127,
			routes: vec![],
		}
	}
}
impl LocalNet {
	pub fn host_str(&self) -> String {
		let nwsep = "/";
		if self.ipv4_addr.is_some() {
			let mut ip: String = self.ipv4_addr.unwrap().to_string().to_owned();
			let nw = self.ipv4_net.to_string();
			ip.push_str(&nwsep);
			ip.push_str(&nw);
			return ip;
		}
		if self.ipv6_addr.is_some() {
			let mut ip: String = self.ipv6_addr.unwrap().to_string().to_owned();
			let nw = self.ipv6_net.to_string();
			ip.push_str(&nwsep);
			ip.push_str(&nw);
			return ip;
		} 
		return String::from("127.0.0.1/31");
	}
	
	pub fn host(&self) -> IpAddr {
		return self.ipv4_addr
			.or(self.ipv6_addr)
			.unwrap_or(IpAddr::from_str("127.0.0.1").unwrap());
	}
	
	pub fn networks(&self, sep: &str) -> String {
		let nwsep = "/";
		return self.routes.iter()
			.filter(|r| r.network.is_some())
			.map(|r| {
				let mut ip: String = r.network.unwrap().to_string().to_owned();
				let nw = r.netmask.to_string();
				ip.push_str(&nwsep);
				ip.push_str(&nw);
				ip
			})
			.reduce(|pref, curr| {
				let mut nw: String = pref.to_owned();
				nw.push_str(&sep);
				nw.push_str(&curr);
				nw
			})
			.unwrap_or(String::from("127.0.0.0/31"));
	}
}

pub fn discover(device: &Option<String>) -> LocalNet {
	return discover_impl::discover(device);
}

mod discover_impl {
	use super::{LocalNet, Route};
	
	use log::{info, debug};
	use std::process::Command;
	use std::net::IpAddr;
	use std::str::FromStr;
	
	pub fn discover(device: &Option<String>) -> LocalNet {
		info!("LocalNet discovery: Starting");
		let mut result: LocalNet = LocalNet::default();
		
		result = discover_host_information(result, device);
		result = discover_routing_information(result, device);
		log_result("IPv4", result.ipv4_addr, result.ipv4_net);
		log_result("IPv6", result.ipv6_addr, result.ipv6_net);
		log_routes("Routes", &result.routes);
		
		info!("LocalNet discovery: End");
		return result;
	}
	
	fn log_result(label: &str, ip: Option<IpAddr>, net: u16) {
		match ip {
			Some(ip_addr) => debug!("  {}: {:?}/{:?}", label, ip_addr, net),
			None => debug!("  {}: none", label),
		}
	}

	fn log_routes(label: &str, routes: &Vec<Route>) {
		debug!("  {}:", label);
		for route in routes {
			if route.is_default {
				debug!("    default via {:?} dev {}", route.router.unwrap(), route.device);
			} else {
				debug!("    {:?}/{:?} via {:?} dev {}", route.network.unwrap(), route.netmask, route.router.unwrap(), route.device);
			}
		}
	}

	fn discover_host_information(mut result: LocalNet, device: &Option<String>) -> LocalNet {
		let mut cmd = Command::new("ip");
		cmd.arg("address").arg("show");

		// If a device is given, only grab that information
		if device.is_some() {
			cmd.arg(device.as_ref().unwrap());
		}

		// Parse each line
		let output = cmd.output();
		if output.is_ok() {
			let lines = String::from_utf8(output.unwrap().stdout).unwrap();
			debug!("{:?}", lines);
			
			for line in lines.lines() {
				let mut parts = line.trim().split_whitespace();
				let first_part = parts.next().unwrap_or("");
				if first_part == "inet" {
					let mut addr_parts = parts.next().unwrap_or("").split('/');
					result.ipv4_addr = Some( IpAddr::from_str( addr_parts.next().unwrap_or("127.0.0.1") ).unwrap() );
					result.ipv4_net = addr_parts.last().unwrap_or("32").parse::<u16>().unwrap();

				} else if first_part == "inet6" {
					let mut addr_parts = parts.next().unwrap_or("").split('/');
					result.ipv6_addr = Some( IpAddr::from_str( addr_parts.next().unwrap_or("::1") ).unwrap() );
					result.ipv6_net = addr_parts.last().unwrap_or("32").parse::<u16>().unwrap();
				}
			}
		}
		return result;
	}
	
	fn discover_routing_information(mut result: LocalNet, device: &Option<String>) -> LocalNet {
		let mut cmd = Command::new("ip");
		cmd.arg("route").arg("show");
		
		// If a device is given, only grab that information
		if device.is_some() {
			cmd.arg("dev").arg(device.as_ref().unwrap());
		}

		// Parse each line
		let output = cmd.output();
		if output.is_ok() {
			let lines = String::from_utf8(output.unwrap().stdout).unwrap();
			debug!("{:?}", lines);
			
			for line in lines.lines() {
				let parts: Vec<&str> = line.trim().split_whitespace().collect();
				let network: Vec<&str> = parts[0].split("/").collect();
				let is_default = network[0] == "default";
				
				result.routes.push(Route {
					network: if is_default { None } else { Some(IpAddr::from_str(network[0]).unwrap()) },
					netmask: if is_default { 31 } else { network[1].parse::<u16>().unwrap() },
					device: String::from( if is_default { parts[4] } else { parts[2] } ),
					is_default,
					router: Some(IpAddr::from_str(if is_default { parts[2] } else { parts[8] } ).unwrap()),
				});
			}
		}
		return result;
	}
	
}
