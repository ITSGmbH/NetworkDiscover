
use local_net::LocalNet;
use log::info;

pub fn start(db: &mut sqlite::Database, local: &LocalNet, targets: &Vec<config::DiscoverStruct>, num_threads: &u32) {
	let hosts = discover_impl::discover(db, local, targets, num_threads);
	info!("Found hosts: {:?}", hosts.len());
}

mod discover_impl {
	use crate::hosts::{Host, Service, Vulnerability, Protocol, State};
	
	use local_net::LocalNet;
	
	use log::{info, debug};
	use std::process::Command;
	use std::net::IpAddr;
	use std::str::FromStr;
	use std::env::temp_dir;
	use std::path::PathBuf;
	use std::fs::File;
	use std::thread;
	use std::io::prelude::*;
	use xml::reader::{EventReader, XmlEvent};
	use uuid::Uuid;

	pub fn discover(db: &mut sqlite::Database, local: &LocalNet, targets: &Vec<config::DiscoverStruct>, num_threads: &u32) -> Vec<Host> {
		let mut result: Vec<Host> = vec![];
		let mut result_chunks: Vec<Vec<Host>> = vec![];
		for _ in 0..*num_threads {
			result_chunks.push(vec![]);
		}

		info!("HostDiscovery: start");
		debug!("Threads: {}", num_threads);

		let mut count = 0;
		for target in targets {
			for host in discover_network(db, local, &target) {
				let chunk = result_chunks.get_mut((count % num_threads) as usize);
				chunk.unwrap().push(host);
				count += 1;
			}
		}

		// Portscan in threads
		let mut handles = vec![];
		for chunk in result_chunks {
			let handle = thread::spawn(move || {
				debug!("Thread {:?} started", thread::current().id());
				let mut res: Vec<Host> = vec![];
				for mut host in chunk {
					portscan(&mut host);
					res.push(host.clone());
				}
				res
			});
			handles.push(handle);
		}

		// Join and wait till every thread is finished
		for handle in handles {
			let thread_id = &handle.thread().id();
			let mut res: Vec<Host> = handle.join().unwrap();
			debug!("Thread joined: {:?}", thread_id);

			for host in &res {
				host.update_host_information(db);
				host.save_services_to_db(db);
			}
			result.append(&mut res);
		}

		info!("HostDiscovery: ended");
		return result;
	}

	fn get_tmp_file() -> PathBuf {
		let mut tmp_dir = temp_dir();
		let tmp_name = format!("{}.xml", Uuid::new_v4());
		tmp_dir.push(tmp_name);
		tmp_dir
	}

	fn get_file_content_and_cleanup(path: &PathBuf) -> String {
		let file = File::open(path);
		if file.is_ok() {
			let mut f = file.unwrap();
			let mut lines = String::new();
			f.read_to_string(&mut lines).unwrap();
			std::fs::remove_file(path).unwrap_or_default();
			return lines;
		}
		String::new()
	}

	fn discover_network(db: &mut sqlite::Database, local: &LocalNet, target: &config::DiscoverStruct) -> Vec<Host> {
		let mut result: Vec<Host> = vec![];
		let default_network = local.default_network()
			.unwrap()
			.default_route()
			.unwrap()
			.to_string();
		let network = &target.target.as_ref()
			.unwrap()
			.get_network_string()
			.unwrap_or(default_network);
		info!("Network: {}", network);

		let tmp_file = get_tmp_file();
		let mut cmd = Command::new("sudo");
		cmd.arg("nmap")
			.arg("-sn")
			.arg("-oX")
			.arg(&tmp_file)
			.arg(&network);
		debug!("Command: {:?}", cmd);

		let output = cmd.output();
		if output.is_ok() {
			let lines = get_file_content_and_cleanup(&tmp_file);
			let parser = EventReader::from_str(&lines);

			for ev in parser {
				match ev {
					Ok(XmlEvent::StartElement { name, attributes, .. }) => {
						if name.local_name == "address" {
							let is_ip_tag = attributes.iter()
								.filter(|a| a.name.local_name == "addrtype" && (a.value == "ipv4" || a.value == "ipv6"))
								.map(|_| true)
								.take(1).next()
								.unwrap_or(false);
							if is_ip_tag {
								let mut host = Host::default();
								host.network = String::from(network);
								host.extended_scan = target.extended.unwrap_or(true);
								host.ip = Some(
									attributes.iter()
										.filter(|a| a.name.local_name == "addr")
										.map(|a| String::from(&a.value))
										.inspect(|ip| debug!("  found: {}", ip))
										.map(|ip| IpAddr::from_str(&ip))
										.take(1).next()
										.unwrap_or(IpAddr::from_str("127.0.0.1"))
										.unwrap()
									);

								// Add the scanning host as a hop and trace the others
								host.hops.push(local.get_ip_for_network(&network).unwrap_or(IpAddr::from_str("127.0.0.1").unwrap()));
								traceroute(&mut host, &target.max_hops.unwrap_or(10));
								host.save_to_db(db);
								result.push(host);
							}
						}
					},
					_ => {},
				}
			}
			info!("Found: {:?} hosts", result.len());
		}
		return result;
	}

	pub fn traceroute(host: &mut Host, hops: &u16) {
		if host.ip.is_some() && !host.hops.iter().any(|hop| host.ip.unwrap().to_string() == hop.to_string()) {
			let ip = host.ip.unwrap().to_string();
			debug!("  traceroute: {:?}", ip);
			
			let mut cmd = Command::new("traceroute");
			cmd.arg("-n")   // no name lookup
				.arg("-q 1")  // only one query
				.arg("-m").arg(hops.to_string()) // max hops
				.arg(ip);
			debug!("Command: {:?}", cmd);
			
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
			debug!("  found route: {:?}", host.hops);
		} else {
			debug!("  no route to: {:?}", host.ip);
		}
	}
	
	pub fn portscan(host: &mut Host) {
		if host.ip.is_some() {
			let ip = host.ip.unwrap().to_string();
			debug!("  portscan: {:?}", ip);
			
			let tmp_file = get_tmp_file();
			let mut cmd = Command::new("sudo");
			cmd.arg("nmap")
				.arg("-O")
				.arg("-sT")
				.arg("-sV");
			if host.extended_scan {
				cmd.arg("--script=vulners.nse");
			}
			cmd.arg("-oX")
				.arg(&tmp_file)
				.arg(ip);
			debug!("[{:?}] Command: {:?}", thread::current().id(), cmd);
			
			let output = cmd.output();
			if output.is_ok() {
				let mut service = Service::default();
				let mut vulners = Vulnerability::default();

				let mut is_vulners = false;
				let mut vulners_key = String::from("");
				
				let lines = get_file_content_and_cleanup(&tmp_file);
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
									is_vulners = true;
									
							} else if is_vulners && name.local_name == "elem" {
								vulners_key = attributes.iter()
									.map(|a| String::from(&a.value))
									.take(1).next()
									.unwrap_or(String::from(""));
							}
						},

						Ok(XmlEvent::Characters(value)) => {
							if is_vulners && !vulners_key.is_empty() {
								match vulners_key.as_str() {
									"id" => vulners.id = value,
									"type" => vulners.database = value,
									"is_exploit" => vulners.exploit = value.parse::<bool>().unwrap_or(false),
									"cvss" => vulners.cvss = value.parse::<f32>().unwrap_or(0f32),
									_ => {}
								};
							}
						},

						Ok(XmlEvent::EndElement { name }) => {
							if name.local_name == "port" {
								debug!("[{:?}] Service: {:?}", thread::current().id(), &service);
								host.services.push(service);
								service = Service::default();

							} else if is_vulners && name.local_name == "table" && !vulners.id.is_empty() {
								service.vulns.push(vulners.clone());
								vulners = Vulnerability::default();

							} else if is_vulners && name.local_name == "script" {
								is_vulners = false;
							}
						},
						_ => {}
					}
				}

			}
		}
	}
	
}
