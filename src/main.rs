
mod config;
mod core;

use crate::core::logger;

use local_net::local_net;

fn main() -> Result<(), confy::ConfyError> {
	logger::init();
	
    logger::info!("Starting network_discover...!");
    
    let name: String = "network_discover".to_string();
    let conf: self::config::AppConfig = self::config::get(&name);
    
	self::config::save(&name, &conf);
	dbg!(&conf);

	local_net::discover(&conf.device);

	logger::info!("Ended network_discover...!");
    Ok(())
}
