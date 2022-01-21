
use local_net::LocalNet;
use log::info;

pub fn start(network: &LocalNet) {
	let hosts = discover_impl::discover(network);
	
	info!("{:?}", hosts);
}

mod discover_impl {
	use crate::hosts::Host;
	
	use local_net::LocalNet;
	
	use log::{info, debug};
	use std::process::Command;
	use std::net::IpAddr;
	use std::str::FromStr;
	use xml::reader::{EventReader, XmlEvent};
	
	pub fn discover(network: &LocalNet) -> Vec<Host> {
		let mut result: Vec<Host> = vec![];
		
		info!("HostDiscovery: start");
		info!("Network: {}", network.network());
		
		let mut cmd = Command::new("nmap");
		cmd.arg("-sn")
			.arg("-oX")
			.arg("/dev/stderr")
			.arg(network.network());
		
		let output = cmd.output();
		if output.is_ok() {
			let lines = String::from_utf8(output.unwrap().stderr).unwrap();
			debug!("Output: {:?}", lines);
			
			let parser = EventReader::from_str(&lines);
			for ev in parser {
				match ev {
					Ok(XmlEvent::StartElement { name, attributes, .. }) => {
						if name.local_name == "address" {
							let mut host = Host::default();
							host.ip = Some( IpAddr::from_str(
								&attributes.iter()
									.filter(|a| a.name.local_name == "addr")
									.map(|a| String::from(&a.value))
									.take(1)
									.next()
									.unwrap_or(String::from("127.0.0.1"))
								).unwrap() );
							result.push(host);
						}
					}
					_ => {}
				}
			}
			info!("Found: {:?} hosts", result.len());
		}
		info!("HostDiscovery: end");
		return result;
	}
	
}
