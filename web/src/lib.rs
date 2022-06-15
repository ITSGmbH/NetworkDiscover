
use actix_web::{get, web, App, HttpServer, Result, Responder};
use actix_files::{Files, NamedFile};
use std::{path::PathBuf, sync::Mutex};
use serde::{Serialize, Deserialize};

use std::thread;
use network::scan;

#[derive(Serialize)]
struct StateResponse {
	network: String,
	state: String,
}

#[derive(Serialize,Clone,Copy)]
struct ScanStatusResponse {
	running: bool,
	paused: bool,
	triggered: bool,
}

#[derive(Serialize)]
struct SimpleNetwork {
	network: String,
	name: String,
}

#[derive(Deserialize)]
struct ScanRequest {
	network: String,
}

#[derive(Serialize)]
struct ScanResponse {
	network: String,
	scan: i64,
	start: String,
	end: String,
}

#[derive(Deserialize)]
struct NetworkRequest {
	network: String,
	scan: i64,
}

#[derive(Serialize)]
struct NetworkResponse {
	id: i64,
	network: String,
	ip: String,
	os: String,
	nodes: Vec<String>,
}


pub async fn run(config: config::AppConfig) -> std::io::Result<()> {
	let running = web::Data::new(Mutex::new(ScanStatusResponse {
		running: false,
		paused: false,
		triggered: false,
	}));
	let web_conf = web::Data::new(config);

	HttpServer::new(move || App::new()
		.app_data(web_conf.clone())
		.app_data(running.clone())
		.service(Files::new("/static", "./static").show_files_listing())
		.service(index)
		.service(get_networks)
		.service(get_scans)
		.service(get_network)
		.service(show_status)
		.service(scan_start)
	)
	.workers(4)
	.bind(( "0.0.0.0", 9090_u16 ))?
	.run()
	.await
}

#[get("/")]
async fn index() -> Result<NamedFile> {
	let path: PathBuf = "./static/index.html".parse().unwrap();
	Ok(NamedFile::open(path)?)
}

#[get("/api/networks")]
async fn get_networks(config: web::Data<config::AppConfig>) -> Result<impl Responder> {
	let conf = config.clone();
	let mut targets: Vec<SimpleNetwork> = vec![];
	for target in &conf.targets {
		if target.target.is_some() {
			let con = target.target.as_ref().unwrap();
			let name = if con.name.is_some() { con.name.as_ref().unwrap().to_string() } else { "".to_string() };
			let ip = if con.ip.is_some() { con.ip.as_ref().unwrap() } else { "" };
			let mask = if con.mask.is_some() { con.mask.as_ref().unwrap() } else { &0u8 };
			if !ip.is_empty() && mask.ne(&0u8) {
				let mut network = String::from(ip);
				network.push_str("/");
				network.push_str(&mask.to_string());
				targets.push(SimpleNetwork { network, name });
			}
		}
	}
	Ok(web::Json(targets))
}

#[get("/api/scans")]
async fn get_scans(config: web::Data<config::AppConfig>, args: web::Query<ScanRequest>) -> Result<impl Responder> {
	let conf = config.clone();
	let mut db = sqlite::new(&conf);

	let scans = db::Scan::list_from_network(&mut db, &args.network, None, None);
	let response = scans.iter()
		.map(|s| ScanResponse {
			network: args.network.clone(),
			scan: s.scan.clone(),
			start: format!("{}", s.start_time.format("%Y-%m-%d %H:%M:%S")),
			end: format!("{}", s.end_time.format("%Y-%m-%d %H:%M:%S")),
		})
		.collect::<Vec<ScanResponse>>();

	Ok(web::Json(response))
}

#[get("/api/network")]
async fn get_network(config: web::Data<config::AppConfig>, args: web::Query<NetworkRequest>) -> Result<impl Responder> {
	let conf = config.clone();
	let mut db = sqlite::new(&conf);

	let hosts = db::Host::list_from_network(&mut db, &args.network, &args.scan);
	let result = hosts.iter()
		.map(|h| {
			let route = db::Routing::from_host(&mut db, &h.id, &args.scan);
			NetworkResponse {
				id: h.id,
				network: args.network.clone(),
				ip: h.ip.clone(),
				os: h.os.clone(),
				nodes: route.iter()
					.map(|r| r.right.to_string() )
					.collect(),
			}
		})
		.collect::<Vec<NetworkResponse>>();

	Ok(web::Json(result))
}

#[get("/api/status")]
async fn show_status(_config: web::Data<config::AppConfig>, running: web::Data<Mutex<ScanStatusResponse>>) -> Result<impl Responder> {
	let status = running.clone();
	Ok(web::Json(status))
}

#[get("/api/info")]
async fn get_info(config: web::Data<config::AppConfig>) -> Result<impl Responder> {
	Ok(web::Json(""))
}

#[get("/api/scan_now")]
async fn scan_start(config: web::Data<config::AppConfig>, running: web::Data<Mutex<ScanStatusResponse>>) -> Result<impl Responder> {
	let mut message = "running";
	if !(*running.lock().unwrap()).running {
		let conf = config.clone();
		thread::spawn(move|| {
			(*running.lock().unwrap()).running = true;
			let local = local_net::discover(&conf.device);
			scan::full(&conf, &local);
			(*running.lock().unwrap()).running = false;
		});
		message = "started";
	}

	let response = StateResponse {
		network: String::from(&config.name),
		state: String::from(message),
	};
	Ok(web::Json(response))
}


