mod core;
use crate::core::logger;
use log::info;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
	logger::init();
	
	info!("Starting network_discover");
	loop {
		let config: config::AppConfig = config::get();
		config::save(&config);

		let res = web::run(config).await;
		if res.is_ok() || res.err().unwrap().kind() != std::io::ErrorKind::ConnectionReset {
			break;
		}
		info!("Restarting network_discover");
	}
	info!("Ended network_discover");

	Ok(())
}
