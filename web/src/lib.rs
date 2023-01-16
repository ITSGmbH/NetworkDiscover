
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

#[derive(Deserialize)]
struct InfoRequest {
	scan: i64,
	info: i64,
}

#[derive(Serialize)]
struct HostInfoResponse {
	id: i64,
	ip: String,
	os: String,
	scan_timestamp: String,
	ports: Vec<PortInfoResponse>,
}

#[derive(Serialize)]
struct PortInfoResponse {
	port: i32,
	protocol: String,
	service: String,
	product: String,
	cves: Vec<CveInfoResponse>,
}

#[derive(Serialize)]
struct CveInfoResponse {
	id: String,
	database: String,
	cvss: f32,
	exploit: bool,
}

pub async fn run(config: config::AppConfig) -> std::io::Result<()> {
	let running = web::Data::new(Mutex::new(ScanStatusResponse {
		running: false,
		paused: true,
		triggered: false,
	}));

	let default_ip = "0.0.0.0".to_owned();
	let default_port = 9090_u16;
	let ip = &config.listen.as_ref().map(|listen| listen.ip.as_ref().unwrap_or(&default_ip) ).unwrap_or(&default_ip).to_owned();
	let port = &config.listen.as_ref().map(|listen| listen.port.as_ref().unwrap_or(&default_port) ).unwrap_or(&default_port).to_owned();
	let web_conf = web::Data::new(config.clone());

	HttpServer::new(move || App::new()
		.app_data(web_conf.clone())
		.app_data(running.clone())
		.service(Files::new("/static", "./static").show_files_listing())
		.service(index)
		.service(get_networks)
		.service(get_scans)
		.service(get_network)
		.service(get_info)
		.service(show_status)
		.service(scan_start)
	)
	.workers(4)
	.bind(( ip.to_owned(), port.to_owned() ))?
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
		.map(|host| {
			let route = db::Routing::from_host(&mut db, &host.hist_id, &args.scan);
			NetworkResponse {
				id: host.hist_id,
				network: args.network.clone(),
				ip: host.ip.clone(),
				os: host.os.clone(),
				nodes: route.iter()
					.map(|route| route.right.to_string() )
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
async fn get_info(config: web::Data<config::AppConfig>, args: web::Query<InfoRequest>) -> Result<impl Responder> {
	let conf = config.clone();
	let mut db = sqlite::new(&conf);

	let scan = db::Scan::load(&mut db, &args.scan).unwrap_or_default();
	let host = db::HostHistory::load(&mut db, &args.info)
		.map(|info| {
			let mut host = db::Host::load(&mut db, &info.host_id).unwrap_or_default();
			host.os = info.os;
			host.hist_id = info.id;
			host
		});
	let ports = db::Port::load(&mut db, &args.info);

	let result = host.map_or(None, |host| Some(HostInfoResponse {
		id: host.id,
		ip: host.ip,
		os: host.os,
		scan_timestamp: scan.start_time.to_string(),
		ports: ports.iter()
			.map(|port| {
				let cves = db::Cve::load(&mut db, &args.info, &port.port);
				PortInfoResponse {
					port: port.port.clone(),
					protocol: port.protocol.clone(),
					service: port.service.clone(),
					product: port.product.clone(),
					cves: cves.iter()
						.map(|cve| CveInfoResponse {
							id: cve.type_id.clone(),
							database: cve.type_name.clone(),
							cvss: cve.cvss.clone(),
							exploit: cve.is_exploit == "true" || cve.is_exploit == "TRUE",
						})
						.collect(),
				}
			})
			.collect(),
	}));

	Ok(web::Json(result))
}

#[get("/api/scan_now")]
async fn scan_start(config: web::Data<config::AppConfig>, running: web::Data<Mutex<ScanStatusResponse>>) -> Result<impl Responder> {
	let mut message = "running";
	if !(*running.lock().unwrap()).running {
		let conf = config.clone();
		thread::spawn(move|| {
			(*running.lock().unwrap()).running = true;
			(*running.lock().unwrap()).paused = false;
			let local = local_net::discover(&conf.device);
			scan::full(&conf, &local);
			(*running.lock().unwrap()).running = false;
			(*running.lock().unwrap()).paused = true;
		});
		message = "started";
	}

	let response = StateResponse {
		network: String::from(&config.name),
		state: String::from(message),
	};
	Ok(web::Json(response))
}




