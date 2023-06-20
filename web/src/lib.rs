use actix_web::{get, post, web, App, HttpServer, Result, Responder, HttpResponse};
use actix_files::{Files, NamedFile};
use serde::{Serialize, Deserialize};
use std::{path::PathBuf, thread, time, io};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use log::info;
use network::{scan, capture};
use export::{pdf::Pdf, csv::Csv, unknown_export};

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
struct VersionResponse {
	installed: String,
	latest: String,
}

enum ScanStatus {
	Started,
	Running,
}
impl From<ScanStatus> for String {
	fn from(val: ScanStatus) -> Self {
		String::from(
			match val {
				ScanStatus::Started => "Started",
				ScanStatus::Running => "Running",
			}
		)
	}
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
	changed: bool,
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
	first_scan: i64,
	changed_scan: i64,
	last_scan: i64,
	is_removed: bool,
	extended: bool,
	has_cve: bool,
}

#[derive(Deserialize)]
struct InfoRequest {
	network: String,
	scan: i64,
	info: i64,
}

#[derive(Serialize)]
struct HostInfoResponse {
	id: i64,
	ip: String,
	os: String,
	scan_timestamp: String,
	scan_history: Vec<ScanResponse>,
	ports: Vec<PortInfoResponse>,
	windows: Option<WindowsResponse>,
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
struct WindowsResponse {
	info: Option<WindowsInfoResponse>,
	domain: Option<WindowsDomainResponse>,
	shares: Vec<WindowsShareResponse>,
	printers: Vec<WindowsPrinterResponse>,
}
#[derive(Serialize)]
struct WindowsInfoResponse {
	native_lan_manager: Option<String>,
	native_os: Option<String>,
	os_name: Option<String>,
	os_build: Option<String>,
	os_release: Option<String>,
	os_version: Option<String>,
	platform: Option<String>,
	server_type: Option<String>,
	server_string: Option<String>,
}
#[derive(Serialize)]
struct WindowsDomainResponse {
	domain: Option<String>,
	dns_domain: Option<String>,
	derived_domain: Option<String>,
	derived_membership: Option<String>,
	fqdn: Option<String>,
	netbios_name: Option<String>,
	netbios_domain: Option<String>,
}
#[derive(Serialize)]
struct WindowsShareResponse {
	name: Option<String>,
	comment: Option<String>,
	share_type: Option<String>,
}
#[derive(Serialize)]
struct WindowsPrinterResponse {
	uri: Option<String>,
	comment: Option<String>,
	description: Option<String>,
	flags: Option<String>,
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
	let stop_handle = web::Data::new(StopHandle::default());

	let default_ip = "0.0.0.0".to_owned();
	let default_port = 9090_u16;
	let ip = &config.listen.as_ref().map(|listen| listen.ip.as_ref().unwrap_or(&default_ip) ).unwrap_or(&default_ip).to_owned();
	let port = &config.listen.as_ref().map(|listen| listen.port.as_ref().unwrap_or(&default_port) ).unwrap_or(&default_port).to_owned();
	let web_conf = web::Data::new(config.clone());

	info!("Starting Webserver: {}:{}", ip, port);

	let server = HttpServer::new({
		let inner_stop_handle = stop_handle.clone();
		let inner_running = running.clone();
		move || App::new()
			.app_data(web_conf.clone())
			.app_data(inner_running.clone())
			.app_data(inner_stop_handle.clone())
			.service(Files::new("/static", "./static").show_files_listing())
			.service(index)
			.service(get_networks)
			.service(get_scans)
			.service(get_network)
			.service(get_info)
			.service(show_status)
			.service(get_version)
			.service(scan_start)
			.service(export_scan)
			.service(load_config)
			.service(save_config)
	})
	.workers(4)
	.bind(( ip.to_owned(), port.to_owned() ))?
	.run();

	// Register the Server in the Stop-handler
	stop_handle.register(server.handle());

	// Start a thread for recurring scans
	let recurring_stop = Arc::new(AtomicBool::new(false));
	let recurring = thread::spawn({
		let recurring_stop = recurring_stop.clone();
		let recurring_sleep = config.repeat as u64 * 3600;
		let recurring_conf = config.clone();
		let recurring_running = running.clone();

		if recurring_sleep <= 0 {
			info!("Recurring scan not enabled, value is '0'");
			recurring_stop.store(true, Ordering::Relaxed);
		}

		move || {
			info!("Start recurring scan every {}s", recurring_sleep);
			let mut cnt = 0;
			loop {
				 if recurring_stop.load(Ordering::Relaxed) {
					 break;
				 }
				cnt += 1;
				thread::sleep(time::Duration::from_secs(1));
				if cnt > recurring_sleep {
					cnt = 0;
					info!("Recurring scan triggered after {}s", recurring_sleep);
					let inner_running = recurring_running.clone();
					let res = start_scan_thread(recurring_conf.clone(), inner_running.into_inner());
					info!("Recurring scan: {}", String::from(res));
				}
			}
			info!("Recurring scan stopped");
		}
	});

	// Start listeners
	capture::start(&config.clone());

	// run the server until it stops
	let res = server.await;

	// If the server has stopped, stop the recurring scans
	recurring_stop.store(true, Ordering::Relaxed);
	let _ = recurring.join();

	// In case the server was stopped gracefully, we restart it in main
	// Otherwise (SIGINT for example) the server is stopped
	let stopped = stop_handle.stopped.lock().unwrap();
	match *stopped {
		true => Err(io::Error::new(
				io::ErrorKind::ConnectionReset,
				"gracefully stopped",
			)),
		_ => res
	}
}

/// Starts a scan in a new thread if there is no scan running at the moment
///
/// # Arguments:
///
/// * `conf` - Application Configuration
/// * `running` - Scan-Status Struct
///
/// # Result
///
/// Status if a scan was started or already running
fn start_scan_thread(config: config::AppConfig, running: Arc<Mutex<ScanStatusResponse>>) -> ScanStatus {
	let inner_running = running.clone();
	let res = match (*inner_running.lock().unwrap()).running {
		true => ScanStatus::Running,
		false => {
			thread::spawn(move|| {
				let inner_running = running.clone();
				let conf = config.clone();
				(*inner_running.lock().unwrap()).running = true;
				(*inner_running.lock().unwrap()).paused = false;
				let local = local_net::discover(&conf.device);
				scan::full(&conf, &local);
				(*inner_running.lock().unwrap()).running = false;
				(*inner_running.lock().unwrap()).paused = true;
			});
			ScanStatus::Started
		}
	};
	res
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
			changed: s.changed,
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
	let removed = db::Host::list_removed_from_network(&mut db, &args.network, &args.scan);
	let mut result = hosts.iter()
		.map(|host| map_network_db_results(&mut db, &host, &args.scan, false))
		.collect::<Vec<NetworkResponse>>();
	result.extend(
			removed.iter()
				.map(|host| map_network_db_results(&mut db, &host, &(args.scan - 1), true))
				.collect::<Vec<NetworkResponse>>()
		);
	Ok(web::Json(result))
}

fn map_network_db_results(db: &mut sqlite::Database, host: &db::Host, scan: &i64, removed: bool) -> NetworkResponse {
	let last = db::Host::find_last_emerge(db, &host.ip);
	let first = db::Host::find_first_emerge(db, &host.ip);
	let change = db::Host::find_last_change(db, &host.ip, scan);
	let route = db::Routing::from_host(db, &host.hist_id, scan);
	let extended = db::Windows::load(db, &host.hist_id);
	let cve = db::Cve::from_host_hist(db, &host.hist_id);
	NetworkResponse {
		id: host.hist_id,
		network: host.network.clone(),
		ip: host.ip.clone(),
		os: host.os.clone(),
		nodes: route.iter()
			.map(|route| route.right.to_string() )
			.collect(),
		first_scan: first.map_or(0, |hist| hist.scan),
		changed_scan: change.map_or(0, |hist| hist.scan),
		last_scan: last.map_or(0, |hist| hist.scan),
		is_removed: removed,
		extended: extended.is_some(),
		has_cve: cve.len() > 0,
	}
}

#[get("/api/status")]
async fn show_status(_config: web::Data<config::AppConfig>, running: web::Data<Mutex<ScanStatusResponse>>) -> Result<impl Responder> {
	let status = running.clone();
	Ok(web::Json(status))
}

#[get("/api/version")]
async fn get_version(_config: web::Data<config::AppConfig>) -> Result<impl Responder> {
	let status = VersionResponse {
		installed: "0.2.0".to_string(),
		latest: "0.2.0".to_string(),
	};
	Ok(web::Json(status))
}

#[get("/api/info")]
async fn get_info(config: web::Data<config::AppConfig>, args: web::Query<InfoRequest>) -> Result<impl Responder> {
	let conf = config.clone();
	let mut db = sqlite::new(&conf);

	let scan = db::Scan::load(&mut db, &args.scan).unwrap_or_default();
	let scan_hist = db::HostHistory::scan_history(&mut db, &args.info);
	let host = db::HostHistory::load(&mut db, &args.info)
		.map(|info| {
			let mut host = db::Host::load(&mut db, &info.host_id).unwrap_or_default();
			host.os = info.os;
			host.hist_id = info.id;
			host
		});
	let ports = db::Port::load(&mut db, &args.info);
	let windows = db::Windows::load(&mut db, &args.info)
		.map(|win| {
			WindowsResponse {
				info: db::WindowsInfo::load(&mut db, &win.id).map(|info| WindowsInfoResponse {
					native_lan_manager: if info.native_lan_manager.is_empty() { None } else { Some(String::from(&info.native_lan_manager)) },
					native_os: if info.native_os.is_empty() { None } else { Some(String::from(&info.native_os)) },
					os_name: if info.os_name.is_empty() { None } else { Some(String::from(&info.os_name)) },
					os_build: if info.os_build.is_empty() { None } else { Some(String::from(&info.os_build)) },
					os_release: if info.os_release.is_empty() { None } else { Some(String::from(&info.os_release)) },
					os_version: if info.os_version.is_empty() { None } else { Some(String::from(&info.os_version)) },
					platform: if info.platform.is_empty() { None } else { Some(String::from(&info.platform)) },
					server_type: if info.server_type.is_empty() { None } else { Some(String::from(&info.server_type)) },
					server_string: if info.server_string.is_empty() { None } else { Some(String::from(&info.server_string)) },
				}),
				domain: db::WindowsDomain::load(&mut db, &win.id).map(|domain| WindowsDomainResponse {
					domain: if domain.domain.is_empty() { None } else { Some(String::from(&domain.domain)) },
					dns_domain: if domain.dns_domain.is_empty() { None } else { Some(String::from(&domain.dns_domain)) },
					derived_domain: if domain.derived_domain.is_empty() { None } else { Some(String::from(&domain.derived_domain)) },
					derived_membership: if domain.derived_membership.is_empty() { None } else { Some(String::from(&domain.derived_membership)) },
					fqdn: if domain.fqdn.is_empty() { None } else { Some(String::from(&domain.fqdn)) },
					netbios_name: if domain.netbios_name.is_empty() { None } else { Some(String::from(&domain.netbios_name)) },
					netbios_domain: if domain.netbios_domain.is_empty() { None } else { Some(String::from(&domain.netbios_domain)) },
				}),
				shares: db::WindowsShare::load(&mut db, &win.id).iter().map(|share| WindowsShareResponse {
					name: if share.name.is_empty() { None } else { Some(String::from(&share.name)) },
					comment: if share.comment.is_empty() { None } else { Some(String::from(&share.comment)) },
					share_type: if share.share_type.is_empty() { None } else { Some(String::from(&share.share_type)) },
				}).collect(),
				printers: db::WindowsPrinter::load(&mut db, &win.id).iter().map(|printer| WindowsPrinterResponse {
					uri: if printer.uri.is_empty() { None } else { Some(String::from(&printer.uri)) },
					comment: if printer.comment.is_empty() { None } else { Some(String::from(&printer.comment)) },
					description: if printer.description.is_empty() { None } else { Some(String::from(&printer.description)) },
					flags: if printer.flags.is_empty() { None } else { Some(String::from(&printer.flags)) },
				}).collect(),
			}
		});

	let result = host.map_or(None, |host| Some(HostInfoResponse {
		id: host.id,
		ip: host.ip,
		os: host.os,
		scan_timestamp: scan.start_time.to_string(),
		scan_history: scan_hist.iter().map(|scan| {
			ScanResponse {
				network: args.network.clone(),
				scan: scan.scan.clone(),
				changed: scan.changed,
				start: scan.start_time.to_string(),
				end: scan.end_time.to_string(),
			}
		}).collect(),
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
							cvss: cve.cvss,
							exploit: cve.is_exploit == "true" || cve.is_exploit == "TRUE",
						})
						.collect(),
				}
			})
			.collect(),
		windows,
	}));
	Ok(web::Json(result))
}

#[get("/api/scan_now")]
async fn scan_start(config: web::Data<config::AppConfig>, running: web::Data<Mutex<ScanStatusResponse>>) -> Result<impl Responder> {
	let res = start_scan_thread(config.get_ref().clone(), running.into_inner());
	let res = String::from(res);
	info!("Scan triggered: {}", String::from(&res));

	Ok(web::Json(StateResponse {
		network: String::from(&config.name),
		state: res,
	}))
}

#[get("/export/{export}")]
async fn export_scan(config: web::Data<config::AppConfig>, export: web::Path<String>, args: web::Query<NetworkRequest>) -> Result<impl Responder> {
	let conf = config.clone();
	let mut db = sqlite::new(&conf);
	let export_type = export.into_inner().to_lowercase();
	let content = match export_type.as_ref() {
		"pdf" => {
			Pdf::export(&mut db, String::from(&args.network), args.scan)
		},
		"csv" => {
			Csv::export(&mut db, String::from(&args.network), args.scan)
		},
		_ => {
			unknown_export()
		},
	};

	let result = HttpResponse::Ok()
		.content_type(if export_type == "pdf" { "application/pdf" } else if export_type == "csv" { "text/csv" } else { "text/plain" })
		.body(content);
	Ok(result)
}


#[get("/api/config")]
async fn load_config(config: web::Data<config::AppConfig>) -> Result<impl Responder> {
	let conf = config.clone();
	// TODO: Windows-Password security: Clear passwords
	Ok(web::Json(conf))
}

#[post("/api/config")]
async fn save_config(payload: web::Json<config::SaveConfig>, stop_handle: web::Data<StopHandle>) -> HttpResponse {
	// TODO: Windows-Password security: Copy over from the original config if None
	let conf = config::AppConfig::from(payload.0);
	config::save(&conf);
	stop_handle.stop(true);
	HttpResponse::Ok().body("reload")
}

/// Holds a Serverhandler in a Mutex to stop the HttpServer gracefully
#[derive(Default)]
struct StopHandle {
	inner: Arc<Mutex<Option<actix_web::dev::ServerHandle>>>,
	stopped: Arc<Mutex<bool>>,
}
impl StopHandle {
	/// Register the StopHandle as a ServerHandler
	pub(crate) fn register(&self, handle: actix_web::dev::ServerHandle) {
		*self.inner.lock().unwrap() = Some(handle);
		*self.stopped.lock().unwrap() = false;
	}

	/// Sends the Stop-Signal to the ServerHandler
	pub(crate) fn stop(&self, graceful: bool) {
		#[allow(clippy::let_underscore_future)]
		let _ = self.inner.lock().unwrap().as_ref().unwrap().stop(graceful);
		*self.stopped.lock().unwrap() = true;
	}
}

