
pub mod hosts;
pub mod types;
mod discover;

pub mod scan {
	use super::discover;
	use log::info;
	use local_net::LocalNet;
	use config::AppConfig;

	pub fn full(conf: &AppConfig, network: &LocalNet) -> bool {
		info!("NetworkScan: start");

		let mut db = sqlite::new(conf);
		let mut scan = db::Scan::default();
		if scan.save(&mut db).is_ok() {
			db.current_scan_id = scan.scan;
			discover::start(&mut db, network, &conf.targets, &conf.num_threads);
		}
		let _ = scan.end_scan(&mut db);

		info!("NetworkScan: end");
		return false;
	}

}


pub mod capture {
	use super::discover;
	use crate::types::{Protocol, Services, UdpPacket, DhcpData, DhcpMessageType, DhcpOption};
	use crate::hosts::Host;
	use config::AppConfig;
	use log::{info, error};
	use pcap::{Device, Capture};
	use std::{thread, thread::JoinHandle};
	use std::net::IpAddr;

	pub fn start(config: &AppConfig) {
		let _handle = listen(Services::DHCP, config);
	}

	fn listen(service: Services, config: &AppConfig) -> JoinHandle<()> {
		thread::spawn({
			let conf = config.clone();
			let mut db = sqlite::new(&conf);

			move || {
				let device = Device::from("any");
				let mut capture = Capture::from_device(device).expect(format!("Unable to create Sniffing-Capturer for {}", service).as_str())
					.immediate_mode(true)
					.open().expect(format!("Unable to open Device for Sniffing {}", service).as_str());

				match service.value() {
					Protocol::UDP(port) => capture.filter(format!("udp port {}", port).as_str(), true),
					Protocol::TCP(port) => capture.filter(format!("tcp port {}", port).as_str(), true),
					_ => Ok(())
				}.expect(format!("Unable to apply filter for Sniffing {}", service).as_str());

				loop {
					match capture.next_packet() {
						Ok(packet) => {
							match service {
								Services::DHCP => {
									if let Some(UdpPacket { data: Some( pkg @ _ ), .. }) = UdpPacket::<DhcpData>::try_from(packet).ok() {
										// Try to get the ClientIP
										let client_ip = match pkg.msg_type {
											DhcpMessageType::Offer => Some(&pkg.your_addr),
											DhcpMessageType::Discover => {
												pkg.options.iter().filter_map(|opt| match opt {
													DhcpOption::RequestedIpAddress(ip) => Some(ip),
													_ => None
												}).next()
											},
											_ => None
										};

										// Try to load the host
										if let Some(client_ip) = client_ip {
											let last_scan = db::Scan::last(&mut db);
											db.current_scan_id = last_scan.map_or(1, |s| s.scan);

											info!("DHCP-Initiated Scan");
											let mut host = Host::default();
											host.ip = Some(IpAddr::from(*client_ip));
											discover::scan_hosts(&mut db, vec![vec![host]]);
										}
									}
								},
								// Future: DHCPv6, LLCP
							}
						},
						Err(err) => { error!("Capture Packet while sniffing {} failed: {}", service, err); }
					}
				}
			}
		})
	}

}
