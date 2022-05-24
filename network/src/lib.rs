
pub mod hosts;
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
