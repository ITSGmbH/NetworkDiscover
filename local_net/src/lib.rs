
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct Route {
	network: Option<IpAddr>,
	netmask: u16,
	metric: u16,
	device: String,
	is_default: bool,
	router: Option<IpAddr>,
	link: Option<IpAddr>,
}

impl Default for Route {
	fn default() -> Self {
		Route {
			network: None,
			netmask: 0,
			metric: 0,
			device: String::from(""),
			is_default: false,
			router: None,
			link: None,
		}
	}
}

impl Route {
	pub fn to_string(&self) -> String {
		let mut ip = self.network.unwrap().to_string().to_owned();
		ip.push_str("/");
		ip.push_str(&self.netmask.to_string());
		ip
	}
}


#[derive(Debug, Clone)]
pub struct LocalNetworkData {
	ipaddr: Option<IpAddr>,
	network: u16,
	routes: Vec<Route>,
}

impl Default for LocalNetworkData {
	fn default() -> Self {
		LocalNetworkData {
			ipaddr: None,
			network: 0,
			routes: vec![],
		}
	}
}

impl LocalNetworkData {
	pub fn to_string(&self) -> String {
		let mut ip = self.ipaddr.unwrap().to_string().to_owned();
		ip.push_str("/");
		ip.push_str(&self.network.to_string());
		ip
	}

	pub fn default_route(&self) -> Result<&Route, &str> {
		self.routes.iter()
			.filter(|route| route.is_default)
			.next()
			.map_or(Err::<&Route, &str>("No default route"), |route| Ok(route))
	}
}


#[derive(Debug)]
pub struct LocalNet {
	networks: Vec<LocalNetworkData>
}

impl LocalNet {
	pub fn default_network(&self) -> Result<&LocalNetworkData, &str> {
		for nw in self.networks.iter() {
			if nw.routes.iter().find(|route| route.is_default).is_some() {
				return Ok(nw);
			}
		}
		Err("No default route found")
	}
	
	pub fn get_ip_for_network(&self, network: &String) -> Result<IpAddr, ()> {
		for local in self.networks.iter() {
			for nw in local.routes.iter() {
				if &nw.to_string() == network {
					return Ok(local.ipaddr.unwrap().clone());
				}
			}
		}
		Err(())
	}
}

pub fn discover(device: &Option<String>) -> LocalNet {
	return discover_impl::discover(device);
}

mod discover_impl {
	use super::{LocalNet, LocalNetworkData, Route};
	
	use log::{info, debug};
	use std::process::Command;
	use std::net::IpAddr;
	use std::str::FromStr;
	
	pub fn discover(device: &Option<String>) -> LocalNet {
		info!("LocalNet discovery: Starting");
		let routings = get_routing_information(device);
		let local_ips = get_local_ip_addresses(device, &routings);

		log_addresses("IPs", &local_ips);
		log_routes("Routes", &routings);
		
		info!("LocalNet discovery: End");
		LocalNet { networks: local_ips }
	}
	
	fn log_addresses(label: &str, ips: &Vec<LocalNetworkData>) {
		for ip in ips {
			debug!("  {}: {:?}/{:?}", label, ip.ipaddr, ip.network)
		}
	}

	fn log_routes(label: &str, routes: &Vec<Route>) {
		debug!("  {}:", label);
		for route in routes {
			if route.is_default {
				debug!("    default via {:?} dev {} and ip {:?}", route.router.unwrap(), route.device, route.link);
			} else {
				debug!("    {:?}/{:?} via {:?} dev {} and ip {:?}", route.network.unwrap(), route.netmask, route.router.unwrap(), route.device, route.link);
			}
		}
	}

	fn get_local_ip_addresses(device: &Option<String>, routings: &Vec<Route>) -> Vec<LocalNetworkData> {
		let mut result: Vec<LocalNetworkData> = vec![];
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
				if first_part.starts_with("inet") {
					let mut addr_parts = parts.next().unwrap_or("").split('/');
					let mut data = LocalNetworkData {
						ipaddr: Some( IpAddr::from_str( addr_parts.next().unwrap_or("127.0.0.1") ).unwrap() ),
						network: addr_parts.last().unwrap_or("32").parse::<u16>().unwrap(),
						routes: vec![],
					};

					// Filter routes and assign
					routings.iter()
						.filter(|route| route.link.unwrap() == data.ipaddr.unwrap() && route.netmask == data.network)
						.for_each(|route| {
							data.routes.push(route.clone());
						});

					result.push(data);
				}
			}
		}

		result
	}
	
	fn get_routing_information(device: &Option<String>) -> Vec<Route> {
		let mut result: Vec<Route> = vec![];
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

			let default_routes: Vec<Vec<&str>> = lines.lines().filter(|line| line.starts_with("default")).map(|line| line.trim().split_whitespace().collect()).collect();
			let direct_routes = lines.lines().filter(|line| !line.starts_with("default"));
			
			for line in direct_routes {
				let parts_vec = line.trim().split_whitespace().collect::<Vec<&str>>();
				let mut parts = parts_vec.iter();
				let mut next_parts = parts.next();
				let nw_vec = next_parts.unwrap().split("/").collect::<Vec<&str>>();
				let mut network = nw_vec.iter();

				let mut route: Route = Default::default();
				route.network = Some(IpAddr::from_str(network.next().unwrap()).unwrap());
				route.netmask = network.next().unwrap().parse::<u16>().unwrap();

				while let Some(part) = parts.next() {
					next_parts = parts.next();
					match part {
						&"dev" => { route.device = String::from(*next_parts.unwrap()); }
						&"via" => { route.router = Some(IpAddr::from_str(*parts.next().unwrap()).unwrap()); }
						&"metric" => { route.metric = parts.next().unwrap().parse::<u16>().unwrap(); }
						&"src" => {
							let cur = *parts.next().unwrap();
							route.link = Some(IpAddr::from_str(cur).unwrap());
							route.is_default = false;

							for r in &default_routes {
								let mut via = "";
								let mut defs = r.iter();
								while let Some(def) = defs.next() {
									if def == &"via" { via = *defs.next().unwrap(); }
									else if def == &"src" && via != "" && defs.next().unwrap() == &cur {
										route.router = Some(IpAddr::from_str(via).unwrap());
										route.is_default = true;
									}
								}
							}
						}
						_ => {}
					}
				}

				result.push(route);
			}
		}

		result
	}
	
}
