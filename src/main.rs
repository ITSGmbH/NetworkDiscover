
mod core;

use crate::core::logger;

use network::scan;
use network::hosts;

fn main() -> Result<(), ()> {
	logger::init();
	
	logger::info!("Starting network_discover...!");

	let name: String = "network_discover".to_string();
	let conf: config::AppConfig = config::get(&name);
	config::save(&name, &conf);

	let local = local_net::discover(&conf.device);
	scan::full(&conf, &local);
	
	logger::info!("Ended network_discover...!");
	Ok(())
}
