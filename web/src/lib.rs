
use actix_web::{get, post, web, App, HttpServer, Result, Responder};
use actix_files::{Files, NamedFile};
use std::{path::PathBuf, sync::Mutex};
use serde::Serialize;

use std::thread;
use network::scan;

#[derive(Serialize)]
struct StateResponse {
	network: String,
	state: String,
}

pub async fn run(config: config::AppConfig) -> std::io::Result<()> {
	let running = web::Data::new(Mutex::new(false));
	let web_conf = web::Data::new(config);

	HttpServer::new(move || App::new()
		.app_data(web_conf.clone())
		.app_data(running.clone())
		.service(Files::new("/static", "./static").show_files_listing())
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
async fn index() -> Result<NamedFile> {
	let path: PathBuf = "./static/index.html".parse().unwrap();
	Ok(NamedFile::open(path)?)
}

#[get("/api/networks")]
async fn show_networks(config: web::Data<config::AppConfig>) -> Result<impl Responder> {
	Ok(web::Json(""))
}

#[get("/api/status")]
async fn show_status(config: web::Data<config::AppConfig>, running: web::Data<Mutex<bool>>) -> Result<impl Responder> {
	Ok(web::Json(""))
}

#[get("/api/scans")]
async fn show_scans(config: web::Data<config::AppConfig>) -> Result<impl Responder> {
	Ok(web::Json(""))
}

#[get("/api/network")]
async fn get_network(config: web::Data<config::AppConfig>) -> Result<impl Responder> {
	Ok(web::Json(""))
}

#[get("/api/info")]
async fn get_info(config: web::Data<config::AppConfig>) -> Result<impl Responder> {
	Ok(web::Json(""))
}

#[get("/api/scan_now")]
async fn scan_start(config: web::Data<config::AppConfig>, running: web::Data<Mutex<bool>>) -> Result<impl Responder> {
	let is_running = *running.lock().unwrap();
	let mut message = "running";
	if !is_running {
		let conf = config.clone();
		thread::spawn(move|| {
			*running.lock().unwrap() = true;
			let local = local_net::discover(&conf.device);
			scan::full(&conf, &local);
			*running.lock().unwrap() = false;
		});
		message = "started";
	}

	let response = StateResponse {
		network: String::from(&config.name),
		state: String::from(message),
	};
	Ok(web::Json(response))
}


