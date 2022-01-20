
pub mod hosts;
mod discover;

pub mod scan {
	use log::{info};
	use super::discover;
	use local_net::LocalNet;
	
	pub fn full(network: &LocalNet) -> bool {
		info!("NetworkScan: start full");
		
		discover::start(network);
		
		info!("NetworkScan: end full");
		return false;
	}
	
}
