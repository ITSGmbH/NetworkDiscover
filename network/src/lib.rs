
pub mod hosts;
pub mod types;
mod discover;

pub mod scan {
	use super::discover;
	use log::info;
	use local_net::LocalNet;
	use config::AppConfig;

	pub fn full(conf: &AppConfig, network: &LocalNet) -> bool {
		info!("NetworkScan: start full");

		let mut db = sqlite::new(conf);
		let mut scan = db::Scan::default();
		if scan.save(&mut db).is_ok() {
			db.current_scan_id = scan.scan;
			discover::start(&mut db, network, &conf.targets, &conf.num_threads);
		}
		let _ = scan.end_scan(&mut db);

		info!("NetworkScan: end full");
		return false;
	}
	
}


pub mod capture {
	use crate::types::{Protocol, Services, UdpPacket, DhcpData};
	use log::{info, error};
	use pcap::{Device, Capture};

	pub fn start() {
		let _ = listen(Services::DHCP);
	}

	fn listen(service: Services) -> Result<(), std::io::Error> {
		let _ = std::thread::spawn(move || {
			let device = Device::from("any");
			let mut capture = Capture::from_device(device).expect(format!("Unable to create Sniffing-Capturer for {}", service).as_str())
				.immediate_mode(true)
				.open().expect(format!("Unable to open Device for Sniffing {}", service).as_str());

			match service.value() {
				Protocol::UDP(port) => capture.filter(format!("udp port {}", port).as_str(), true),
				Protocol::TCP(port) => capture.filter(format!("tcp port {}", port).as_str(), true),
				_ => Ok(())
			}.expect(format!("Unable to apply filter for shiffing {}", service).as_str());

			loop {
				match capture.next_packet() {
					Ok(packet) => {
						match service {
							Services::DHCP => {
								let _ = UdpPacket::<DhcpData>::try_from(packet).and_then(|p| {
									info!("Got DHCP-Packet ({}): {:?}", service, p);
									Ok(())
								});
							},
							_ => {}
						}
					},
					Err(err) => { error!("Capture Packet while sniffing {} failed: {}", service, err); }
				}
			}
		});
		Ok(())
	}

}
