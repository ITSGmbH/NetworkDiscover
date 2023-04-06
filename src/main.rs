//use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};

mod core;
use crate::core::logger;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
	logger::init();
	
	logger::info!("Starting network_discover...!");

	let config: config::AppConfig = config::get("network_discover".to_string());
	config::save(&config);
	if let Err(err) = web::run(config).await {
		logger::error!("{}", err);
	}

	logger::info!("Ended network_discover...!");
	Ok(())
}
