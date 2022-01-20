
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
	use roxmltree;
	
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
			
			let root: roxmltree::Document = match roxmltree::Document::parse(&lines) {
				Ok(doc) => doc,
				Err(err) => {
					info!("Error {:?}", err);
					roxmltree::Document::parse("<error/>").unwrap()
				}
			};
			
			// XML-Struct: nmaprun -> host -> address
			result = root.descendants()
				.filter(|node| node.is_element() && node.tag_name().name() == "nmaprun")
				.flat_map(|node| node.children())
				.filter(|node| node.is_element() && node.tag_name().name() == "host")
				.flat_map(|node| node.children())
				.filter(|node| node.is_element() && node.tag_name().name() == "address")
				.map(|node| {
					let mut host = Host::default();
					host.ip = Some( IpAddr::from_str( node.attribute("addr").unwrap_or("127.0.0.1") ).unwrap() );
					return host;
				})
				.collect();
				info!("Found: {:?} hosts", result.len());
		}
		info!("HostDiscovery: end");
		return result;
	}
	
}
