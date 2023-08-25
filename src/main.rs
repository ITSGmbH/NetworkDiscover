pub mod core;

use crate::core::logger;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
	logger::init();
	
	log::info!("Starting network_discover");
	loop {
		let config: config::AppConfig = config::get();
		config::save(&config);

		let res = web::run(config).await;
		if res.is_ok() || res.err().unwrap().kind() != std::io::ErrorKind::ConnectionReset {
			break;
		}
		log::info!("Restarting network_discover");
	}
	log::info!("Ended network_discover");

	Ok(())
}
