
use crate::hosts::Host;
use local_net::LocalNet;
use log::info;

const MAX_TRACEROUTE_HOPS: u16 = 15;

/// Scan for all hosts from the given target networks, scan them for services, vulnerabilities and windows information.
/// The result is saved into the database and is not returned.
///
/// # Arguments
///
/// * `db` - Database connection used to save all information with
/// * `local` - The local network configuration
/// * `targets` - A List of target networks to scan for online hosts
/// * `num_threads` - Number of threads to use in parallel for scanning
///
/// # Example
///
/// ```
/// start(&db, local, targets, 5);
/// ```
pub fn start(db: &mut sqlite::Database, local: &LocalNet, targets: &Vec<config::DiscoverStruct>, num_threads: &u32) {
	info!("HostDiscovery: start");
	let host_chunks = discover_impl::find_hosts_chunked(local, targets, num_threads);
	let hosts = scan_hosts(db, host_chunks);
	info!("Scanned {} hosts", hosts.len());
	info!("HostDiscovery: ended");
}

/// Scan and return a list of hosts, grouped in sublists, for services, vulnerabilities and windows information.
///
/// # Arguments
///
/// * `db` - Database connection used to save all information with
/// * `grouped_hosts` - Hosts grouped into chunks of Hosts to scan in parallel
///
/// # Example
///
/// ```
/// let grouped: Vec<Vec<Host>> = vec![];
/// let scanned = scanned_hosts(&db, grouped);
/// ```
pub fn scan_hosts(db: &mut sqlite::Database, grouped_hosts: Vec<Vec<Host>>) -> Vec<Host> {
	let num_threads = grouped_hosts.len();
	let scanned_hosts = discover_impl::scan_hosts(db, grouped_hosts);
	discover_impl::enummerate_windows(db, scanned_hosts.clone(), num_threads);

	info!("DEBUG: {}", scanned_hosts.len());
	scanned_hosts
}

mod discover_impl {
	use crate::hosts::{Host, Service, Vulnerability, Protocol, State};
	use local_net::LocalNet;
	use log::{info, debug, trace};

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

	/// Scans the Network for Hosts and returns a list a given number of grouped hosts.
	///
	/// # Arguments
	///
	/// * `local` - Local network configuration
	/// * `targets` - List of targets and/or Networks to find Hosts on and scan
	/// * `num_chunks` - The numebr of groups to separate the hosts in
	///
	/// # Example
	///
	/// ```
	/// let chunks = find_hosts_chunked(lcoal, targest, 5);
	/// let hosts = scan_hosts(&db, chunks);
	/// ```
	pub(crate) fn find_hosts_chunked(local: &LocalNet, targets: &Vec<config::DiscoverStruct>, num_chunks: &u32) -> Vec<Vec<Host>> {
		let mut result: Vec<Vec<Host>> = vec![];
		for _ in 0..*num_chunks {
			result.push(vec![]);
		}

		let mut count = 0;
		for target in targets {
			for host in discover_network(local, &target) {
				let chunk = result.get_mut((count % num_chunks) as usize);
				chunk.unwrap().push(host);
				count += 1;
			}
		}
		result
	}

	/// Returns a List of all hosts after they where scanned for services and vulnerabilities.
	/// First routing information are gathered, after each host scanned for services and optionally for vulnerabilities.
	///
	/// # Arguments
	///
	/// * `db` - Database connection to use to save the hosts after all scans are done
	/// * `host_chunks` - List of host-lists; Each List is used in a thread to scan in parallel
	///
	/// # Example
	///
	/// ```
	/// let chunks = find_hosts_chunked(lcoal, targest, 5);
	/// let hosts = scan_hosts(&db, chunks);
	/// ```
	pub(crate) fn scan_hosts(db: &mut sqlite::Database, host_chunks: Vec<Vec<Host>>) -> Vec<Host> {
		let mut result: Vec<Host> = vec![];
		let mut handles = vec![];
		trace!("[Scan] Threads: {}", host_chunks.len());

		for chunk in host_chunks {
			let handle = thread::spawn(move || {
				trace!("[Scan] Thread {:?} started", thread::current().id());
				let mut res: Vec<Host> = vec![];
				for mut host in chunk {
					traceroute(&mut host);
					portscan(&mut host);
					res.push(host.clone());
				}
				res
			});
			handles.push(handle);
		}

		// Join and wait till every thread is finished
		for handle in handles {
			trace!("[Scan] Thread joined: {:?}", &handle.thread().id());
			let mut res: Vec<Host> = handle.join().unwrap();

			for host in &mut res {
				host.save_to_db(db);
				host.update_host_information(db);
				host.save_services_to_db(db);
			}
			result.append(&mut res);
		}
		result
	}

	/// Tries to enummerate windows information on all given hosts in parallel.
	///
	/// The function is blocking until all threads are finished up.
	/// The information is saved for all hosts in a thread after it finished.
	///
	/// # Arguments
	///
	/// * `db` - Database conenction to use to save the hosts after information where enummerated
	/// * `hosts` - List of hosts to try to enummerate windows information
	/// * `num_threads` - Number of threads to split the hosts and scan the hosts simultanously
	///
	/// # Example
	///
	/// ```
	/// enummerate_windows(&db, hosts, 5);
	/// ```
	pub(crate) fn enummerate_windows(db: &mut sqlite::Database, hosts: Vec<Host>, num_threads: usize) {
		let mut host_chunks: Vec<Vec<Host>> = vec![];
		for _ in 0..num_threads {
			host_chunks.push(vec![]);
		}
		hosts.iter().enumerate()
			.for_each(|(k, host)| host_chunks.get_mut(k % num_threads)
				.unwrap()
				.push(host.clone()));

		// Start threads
		trace!("[Windows] Threads: {}", num_threads.len());
		let mut handles = vec![];
		for mut chunk in host_chunks {
			let handle = thread::spawn(move || {
				trace!("[Windows] Thread {:?} started", thread::current().id());
				chunk.iter_mut()
					.filter_map(|host| enumerate_windows_information(host))
					.collect::<Vec<Host>>()
			});
			handles.push(handle);
		}

		// Join and wait till every thread is finished
		for handle in handles {
			trace!("[Windows] Thread joined: {:?}", &handle.thread().id());
			handle.join().unwrap().iter().for_each(|host| host.save_windows_information(db) );
		};
	}

	/// Scan a host for windows services, shares, printers, general information
	///
	/// Based on the configuration if the host, the user, password, workgroup is omitted.
	///
	/// This function creates system commands:
	///
	/// * `sudo NO_COLOR=1 enum4linux IP.AD.DR.ES -A -C -d -oJ TMP_FILE -u USER -w WORKGROUP -p PASSWORD`
	///
	/// # Arguments
	///
	/// * `host` - The Host to scan for windows services
	///
	/// # Example
	///
	/// ```
	/// let windows_host = enumerate_windows_information(&host);
	/// ```
	fn enumerate_windows_information(host: &Host) -> Option<Host> {
		None
	}

	/// Returns a unique XML-Filename as a PathBuf in the systems temp folder.
	/// The File is not created, it's just the filename and path.
	///
	/// # Example
	///
	/// ```
	/// let tmp_file = get_tmp_file();
	/// ```
	fn get_tmp_file() -> PathBuf {
		let mut tmp_dir = temp_dir();
		let tmp_name = format!("{}.xml", Uuid::new_v4());
		tmp_dir.push(tmp_name);
		tmp_dir
	}

	/// Returns the content of a given file as a String and removes the file afterwards.
	///
	/// # Arguments
	///
	/// * `path` - Location of the file to read and remove
	///
	/// # Example
	///
	/// ```
	/// let lines = get_file_content_and_cleanup(&tmp_file);
	/// ```
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

	/// Returns all online hosts from a given network.
	///
	/// This function creates system commands:
	///
	/// * `sudo nmap -sn -oX /tmp/...xml HOST`
	///
	/// # Arguments
	///
	/// * `local` - The local network configuration used to get routing information
	/// * `target` - The target network to search all online hosts
	///
	/// # Example
	///
	/// ```
	/// for host in discover_network(local, &target) {
	///     info!("Found Host: {:?}", host);
	/// }
	/// ```
	fn discover_network(local: &LocalNet, target: &config::DiscoverStruct) -> Vec<Host> {
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
		trace!("[{:?}] Command: {:?}", thread::current().id(), cmd);

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

	/// Traces and fills routing information on the given host object
	///
	/// This function creates system commands:
	///
	/// * `ip route list match IP.AD.DR.ES`
	/// * `traceroute -n -q1 -m IP.AD.DR.ES`
	///
	/// # Arguments
	///
	/// * `host` - Host to trace and find the route to
	///
	/// # Example
	///
	/// ```
	/// traceroute(&mut host);
	/// ```
	/// TODO: Is it more Rust-Style if the host is returned and not modified?
	fn traceroute(host: &mut Host) {
		if host.ip.is_some() && !host.hops.iter().any(|hop| host.ip.unwrap().to_string() == hop.to_string()) {
			let ip = host.ip.unwrap().to_string();
			debug!("Host: {:?}", ip);

			// Default-Gateway to reach the host
			let mut cmd = Command::new("ip");
			cmd.arg("route")
				.arg("list")
				.arg("match")
				.arg(ip.clone());
			trace!("[{:?}] Command: {:?}", thread::current().id(), cmd);

			if let Ok(output) = cmd.output() {
				let mut gateways: Vec<(String, String)> = vec![];
				let mut device: Option<(String, String)> = None;
				let lines = String::from_utf8(output.stdout).unwrap();
				for line in lines.lines() {
					let parts = line.trim().split_whitespace().collect::<Vec<&str>>();
					if parts.get(0).unwrap_or(&"") == &"default" {
						gateways.push( ( String::from(parts.get(2).unwrap_or(&"").to_string()), String::from(parts.get(4).unwrap_or(&"").to_string()) ) );
					} else {
						device = Some( ( String::from(parts.get(2).unwrap_or(&"").to_string()), String::from(parts.get(0).unwrap_or(&"").to_string())  ) );
					}
				}

				// Direct Route -> Get the Gateway and Network based on the the "device"
				let mut gateway = if let Some((ref device, ref network)) = device {
					gateways.clone().into_iter().find_map(|(gw, dev)| if &dev == device {
						host.network = network.clone();
						Some(gw)
					} else {
						None
					} )
				} else { None };

				// If no direct route was found, take the first default gateway
				if gateway.is_none() {
					gateway = Some(gateways.into_iter().next().unwrap_or_default().0)
				}

				// TODO: If no network could be evaluated from the routing table (only possible on direct connected networks), try to calculate

				debug!("  gateway: {:?}", gateway.clone().unwrap_or(String::from("Unknown")));
				if let Some(gateway) = gateway {
					host.hops.push(IpAddr::from_str(gateway.as_str()).unwrap());
				}
			}

			// Traceroute the host
			let mut cmd = Command::new("traceroute");
			cmd.arg("-n")  // no name lookup
				.arg("-q 1") // only one query
				.arg("-m").arg(super::MAX_TRACEROUTE_HOPS.to_string()) // max hops
				.arg(ip.clone());
			trace!("[{:?}] Command: {:?}", thread::current().id(), cmd);

			let output = cmd.output();
			if output.is_ok() {
				let lines = String::from_utf8(output.unwrap().stdout).unwrap();
				for line in lines.lines() {
					let mut parts = line.trim().split_whitespace().collect::<Vec<&str>>();
					// First part has to be a number and the one should not start with a exclamation mark like "!H"
					if parts.get(0).unwrap_or(&"none").parse::<u16>().is_ok() && parts.pop().unwrap_or(&"a").chars().next().unwrap() != '!' {
						// In case of a " * " line, the * was removed above
						match IpAddr::from_str(parts.get(1).unwrap_or(&"*")) {
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
			debug!("  route: {:?}", host.hops);
		} else {
			debug!("  no route to: {:?}", host.ip);
		}
	}
	
	/// Scans a host for open ports and services.
	///
	/// If the host is flagged as `extended_scan`, also a vulnerability scan is performed with the `vulners.nse` nmap script
	///
	/// This function creates system commands:
	///
	/// * `nmap -O -sT -sV --script=vulners.nse`
	///
	/// # Arguments
	///
	/// * `host` - Host to scan for services and vulnerabilities
	///
	/// # Example
	///
	/// ```
	/// portscan(&mut host);
	/// ```
	/// TODO: Is it more Rust-Style if the host is returned and not modified?
	fn portscan(host: &mut Host) {
		if host.ip.is_some() {
			let ip = host.ip.unwrap().to_string();
			debug!("Portscan: {:?}", ip);
			
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
			trace!("[{:?}] Command: {:?}", thread::current().id(), cmd);
			
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
								debug!("  service: {:?}", &service);
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
