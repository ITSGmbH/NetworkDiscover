
pub mod hosts;
mod discover;

pub mod scan {
	use super::discover;
	use log::info;
	use local_net::LocalNet;
	use config::AppConfig;
	
	pub fn full(conf: &AppConfig, network: &LocalNet) -> bool {
		info!("NetworkScan: start full");
		
		discover::start(network, &conf.targets, &conf.num_threads);
		
		info!("NetworkScan: end full");
		return false;
	}
	
}
