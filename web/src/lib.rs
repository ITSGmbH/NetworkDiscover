
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use std::sync::Mutex;

use std::thread;
use network::scan;

pub async fn run(config: config::AppConfig) -> std::io::Result<()> {
	let running = web::Data::new(Mutex::new(false));
	let web_conf = web::Data::new(config);

	HttpServer::new(move || App::new()
		.app_data(web_conf.clone())
		.app_data(running.clone())
		.service(actix_files::Files::new("/static", "."))
		.service(index)
		.service(scan_start)
	)
	.workers(4)
	.bind((
		"127.0.0.1",
		9090_u16
	))?
	.run()
	.await
}

#[get("/")]
async fn index(config: web::Data<config::AppConfig>) -> String {
	let name = &config.name;
	format!("Welcome to {}", name)
}

#[get("/scan/start")]
async fn scan_start(config: web::Data<config::AppConfig>, running: web::Data<Mutex<bool>>) -> HttpResponse {
	let is_running = *running.lock().unwrap();
	if !is_running {
		thread::spawn(move|| {
			*running.lock().unwrap() = true;
			let local = local_net::discover(&config.device);
			scan::full(&config.clone(), &local);
			*running.lock().unwrap() = false;
		});
		return HttpResponse::Ok().body("started");
	}
	HttpResponse::Ok().body("running")
}
