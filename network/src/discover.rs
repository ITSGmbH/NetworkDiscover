
use local_net::LocalNet;
use log::info;

pub fn start(network: &LocalNet) {
	let hosts = discover_impl::discover(network);
	
	info!("{:?}", hosts);
}

mod discover_impl {
	use crate::hosts::{Host, Service, Vulnerability, Protocol, State};
	
	use local_net::LocalNet;
	
	use log::{info, debug};
	use std::process::Command;
	use std::net::IpAddr;
	use std::str::FromStr;
	use xml::reader::{EventReader, XmlEvent};
	
	pub fn discover(network: &LocalNet) -> Vec<Host> {
		let mut result: Vec<Host> = vec![];
		
		info!("HostDiscovery: start");
		info!("Network: {}", network.networks(","));
		
		let mut cmd = Command::new("nmap");
		cmd.arg("-sn")
			.arg("-oX")
			.arg("/dev/stderr")
			.arg(network.networks(","));
		
		let output = cmd.output();
		if output.is_ok() {
			let lines = String::from_utf8(output.unwrap().stderr).unwrap();
			let parser = EventReader::from_str(&lines);
			for ev in parser {
				match ev {
					Ok(XmlEvent::StartElement { name, attributes, .. }) => {
						if name.local_name == "address" {
							let mut host = Host::default();
							host.ip = Some(
								attributes.iter()
									.filter(|a| a.name.local_name == "addr")
									.map(|a| String::from(&a.value))
									.inspect(|ip| debug!("  found: {:?}", ip))
									.map(|ip| IpAddr::from_str(&ip))
									.take(1).next()
									.unwrap_or(IpAddr::from_str("127.0.0.1"))
									.unwrap()
								);
							
							// Add the scanning host as a hop and trace the others
							host.hops.push(network.host());
							traceroute(&mut host);
							
							// Find open Ports
							portscan(&mut host, true);
							
							result.push(host);
						}
					},
					_ => {},
				}
			}
			info!("Found: {:?} hosts", result.len());
		}
		info!("HostDiscovery: end");
		return result;
	}
	
	pub fn traceroute(host: &mut Host) {
		if host.ip.is_some() && !host.hops.iter().any(|hop| host.ip.unwrap().to_string() == hop.to_string()) {
			let ip = host.ip.unwrap().to_string();
			debug!("  trace: {:?}", ip);
			
			let mut cmd = Command::new("traceroute");
			cmd.arg("-n")   // no name lookup
				.arg("-q 1")  // only one query
				.arg("-m 30") // max hops
				.arg(ip);
			
			let output = cmd.output();
			if output.is_ok() {
				let lines = String::from_utf8(output.unwrap().stdout).unwrap();
				
				for line in lines.lines() {
					let mut parts = line.trim().split_whitespace();
					if parts.next().unwrap_or("none").parse::<u16>().is_ok() {
						match IpAddr::from_str(parts.next().unwrap()) {
							Ok(ip) => host.hops.push(ip),
							_ => {},
						}
					}
				}
			}
			
			// In case the host is not traceable, add it as the last hop
			if !host.hops.contains(&host.ip.unwrap()) {
				host.hops.push(host.ip.unwrap());
			}
			debug!("  trace-path: {:?}", host.hops);
		} else {
			debug!("  no trace: {:?}", host.ip);
		}
	}
	
	pub fn portscan(host: &mut Host, fullscan: bool) {
		if host.ip.is_some() {
			let ip = host.ip.unwrap().to_string();
			debug!("  portscan: {:?}", ip);
			
			let mut cmd = Command::new("nmap");
			cmd.arg("-O")
				.arg("-sT")
				.arg("-sV");
			if fullscan {
				cmd.arg("--script=vulners.nse");
			}
			cmd.arg("-oX")
				.arg("/dev/stderr")
				.arg(ip);
			
			let output = cmd.output();
			if output.is_ok() {
				let mut service: Service = Service::default();
				let mut vulners: bool = false;
				
				let lines = String::from_utf8(output.unwrap().stderr).unwrap();
				info!("{:?}", lines);
				
				let parser = EventReader::from_str(&lines);
				for ev in parser {
					match ev {
						Ok(XmlEvent::StartElement { name, attributes, .. }) => {
							if name.local_name == "port" {
								service.port = attributes.iter()
									.filter(|a| a.name.local_name == "portid")
									.map(|a| a.value.parse::<u16>().unwrap_or(0u16))
									.take(1).next().unwrap_or(0u16);
								service.protocol = attributes.iter()
									.filter(|a| a.name.local_name == "protocol")
									.map(|a| {
										if a.value == "tcp" { return Protocol::TCP; }
										else if a.value == "udp" { return Protocol::UDP; }
										Protocol::UNKNOWN
									}).take(1).next().unwrap_or(Protocol::UNKNOWN);
								
							} else if name.local_name == "state" {
								service.state = attributes.iter()
									.filter(|a| a.name.local_name == "state")
									.map(|a| {
										if a.value == "open" { return State::OPEN; }
										else if a.value == "filter" { return State::FILTER; }
										else if a.value == "close" { return State::CLOSE; }
										State::UNKNOWN
									}).take(1).next().unwrap_or(State::UNKNOWN);
								
							} else if name.local_name == "service" {
								service.name = attributes.iter()
									.filter(|a| a.name.local_name == "name")
									.map(|a| String::from(&a.value))
									.take(1).next().unwrap_or(String::from(""));
									
								service.product = attributes.iter()
									.filter(|a| a.name.local_name == "product")
									.map(|a| String::from(&a.value))
									.take(1).next().unwrap_or(String::from(""));
									
								service.version = attributes.iter()
									.filter(|a| a.name.local_name == "version")
									.map(|a| String::from(&a.value))
									.take(1).next().unwrap_or(String::from(""));
								
							} else if name.local_name == "osmatch" {
								host.os = attributes.iter()
									.filter(|a| a.name.local_name == "name")
									.map(|a| String::from(&a.value))
									.take(1).next();
									
							} else if name.local_name == "script"
								&& attributes.iter()
									.filter(|a| a.name.local_name == "id")
									.map(|a| String::from(&a.value))
									.take(1).next().unwrap_or(String::from("")) == "vulners" {
									vulners = true;
									
							} else if vulners && name.local_name == "elem" {
								service.version = attributes.iter()
									.filter(|a| a.name.local_name == "version")
									.map(|a| String::from(&a.value))
									.take(1).next().unwrap_or(String::from(""));
							}
						},
						Ok(XmlEvent::EndElement { name }) => {
							if name.local_name == "port" {
								debug!("  service: {:?}", service);
								host.services.push(service);
								service = Service::default();
								
							} else if (vulners && name.local_name == "script") {
								vulners = false;
							}
						},
						_ => {}
					}
				}
				debug!("  ports: {:?}", host.services);
			}
		}
	}
	
}
