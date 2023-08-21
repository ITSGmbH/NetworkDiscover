use actix_web::{get, post, web, App, HttpServer, Result, Responder, HttpResponse, http::StatusCode};
use actix_files::Files;

use serde::{Serialize, Deserialize};
use minreq;
use base64::Engine;

use std::{fs, path, io::{self, Write}, ffi::OsStr, thread, time};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use log::{info, error};
use network::{scan, capture};
use export::{pdf::Pdf, csv::Csv, unknown_export};

/// Holds the status of the current scan status
#[derive(Serialize,Clone,Copy)]
struct ScanStatusResponse {
	running: bool,
	paused: bool,
	triggered: bool,
}

/// Structure to response for a version check
#[derive(Serialize)]
struct VersionResponse {
	installed: String,
	latest: String,
}

/// Representaiton of the current scan status
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

/// Slim representation of a network
#[derive(Serialize)]
struct SimpleNetwork {
	network: String,
	name: String,
}

/// Request scan information from a network
#[derive(Deserialize)]
struct ScanRequest {
	network: String,
}

/// Represents a scan with it's most important data
#[derive(Serialize)]
struct ScanResponse {
	network: String,
	scan: i64,
	changed: bool,
	start: String,
	end: String,
}

/// Request to get information about a network and a scan
#[derive(Deserialize)]
struct NetworkRequest {
	network: String,
	scan: i64,
}

/// Detailed information about a network
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

/// Request detailed information about a host
#[derive(Deserialize)]
struct InfoRequest {
	network: String,
	scan: i64,
	host: i64,
}

/// Detailed information about a host
#[derive(Serialize)]
struct HostInfoResponse {
	id: i64,
	ip: String,
	os: String,
	scan_timestamp: String,
	scan_history: Vec<ScanResponse>,
	ports: Vec<PortInfoResponse>,
	windows: Option<WindowsResponse>,
	scripts: Vec<ScriptsResponse>,
}

/// Detailed information about one specisic port
#[derive(Serialize)]
struct PortInfoResponse {
	port: i32,
	protocol: String,
	service: String,
	product: String,
	cves: Vec<CveInfoResponse>,
}

/// Data Container for a Script-Scan Response
#[derive(Serialize)]
struct ScriptsResponse {
	name: Option<String>,
	data: Vec<ScriptDataResponse>,
}

/// Data Entry from a Script-Scan
#[derive(Serialize)]
struct ScriptDataResponse {
	key: String,
	value: String,
}

/// Detailed information about a windows scan
#[derive(Serialize)]
struct WindowsResponse {
	info: Option<WindowsInfoResponse>,
	domain: Option<WindowsDomainResponse>,
	shares: Vec<WindowsShareResponse>,
	printers: Vec<WindowsPrinterResponse>,
}

/// Windows Data about a host
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

/// Windows Domain Information
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

/// Windows Shares
#[derive(Serialize)]
struct WindowsShareResponse {
	name: Option<String>,
	comment: Option<String>,
	share_type: Option<String>,
}

/// Windows Printers
#[derive(Serialize)]
struct WindowsPrinterResponse {
	uri: Option<String>,
	comment: Option<String>,
	description: Option<String>,
	flags: Option<String>,
}

/// CVE Information about a host and a Port/Service
#[derive(Serialize)]
struct CveInfoResponse {
	id: String,
	database: String,
	cvss: f32,
	exploit: bool,
}

/// This is the main function to start the Webserver and additional listeners
///
/// This is a blocking function which returns as soon as all web listeners and others are stopped.
///
/// # Arguments:
///
/// * `config` - The main Application Configuration to use
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
			.service(load_scripts)
			.service(upload_script)
			.service(load_script_content)
			.service(activate_script)
			.service(delete_script)
			.service(load_settings)
			.service(save_settings)
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
	return res;
}

/// Handles requests for the root
/// The main html page is parsed and some variables are replaced for white labeling
/// This function has to be registered in the main HttpServer App
///
/// # Arguments:
///
/// * `config` - The main Application Configuration
///
/// # Result
///
/// An HTML HttpResponse
#[get("/")]
async fn index(config: web::Data<config::AppConfig>) -> Result<impl Responder> {
	let logo = match &config.whitelabel {
		Some(wl) if wl.logo_data.is_some() => String::from(wl.logo_data.clone().unwrap()),
		_ => String::from("/static/img/its_logo.png"),
	};
	let tagline = match &config.whitelabel {
		Some(wl) if wl.tagline.is_some() => String::from(wl.tagline.clone().unwrap()),
		_ => String::from("NetworkDiscover"),
	};
	let base_color = match &config.whitelabel {
		Some(wl) if wl.color.is_some() => String::from(wl.color.clone().unwrap()),
		_ => String::from("#3e8ed0"),
	};
	let version = String::from(config::NWD_VERSION);

	Ok(HttpResponse::build(StatusCode::OK)
		.content_type("text/html; charset=utf-8")
		.body(
			fs::read_to_string("./static/index.html")
				.unwrap_or(String::from("No index file found..."))
				.replace("{logo}", &logo)
				.replace("{tagline}", &tagline)
				.replace("{version}", &version)
				.replace("{base_color}", &base_color)
				.replace("{base_color_r}", &u8::from_str_radix(&base_color[1..3], 16).unwrap_or(62).to_string())
				.replace("{base_color_g}", &u8::from_str_radix(&base_color[3..5], 16).unwrap_or(142).to_string())
				.replace("{base_color_b}", &u8::from_str_radix(&base_color[5..7], 16).unwrap_or(208).to_string())
		))
}

/// Handles requests to get all networks.
/// This function has to be registered in the main HttpServer App
///
/// # Arguments:
///
/// * `config` - The main Application Configuration
///
/// # Result
///
/// An JSON HttpResponse
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

/// Handles requests to get all scans from a network.
/// This function has to be registered in the main HttpServer App
///
/// # Arguments:
///
/// * `config` - The main Application Configuration
/// * `args` - ScanRequest Request Arguments
///
/// # Result
///
/// An JSON HttpResponse
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

/// Handles requests to get information about a single network.
/// This function has to be registered in the main HttpServer App
///
/// # Arguments:
///
/// * `config` - The main Application Configuration
/// * `args` - NetworkRequest Request Arguments
///
/// # Result
///
/// An JSON HttpResponse
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

/// Handles requests to get the current status of the server.
/// This function has to be registered in the main HttpServer App
///
/// # Arguments:
///
/// * `config` - The main Application Configuration, not used
/// * `running` - A globally mutex of the ScanStatusResponse
///
/// # Result
///
/// An JSON HttpResponse
#[get("/api/status")]
async fn show_status(_config: web::Data<config::AppConfig>, running: web::Data<Mutex<ScanStatusResponse>>) -> Result<impl Responder> {
	let status = running.clone();
	Ok(web::Json(status))
}

/// Handles requests to initiate a new scan.
/// This function has to be registered in the main HttpServer App
///
/// # Arguments:
///
/// * `config` - The main Application Configuration
/// * `running` - A globally mutex of the ScanStatusResponse
///
/// # Result
///
/// An JSON HttpResponse
#[get("/api/scan_now")]
async fn scan_start(config: web::Data<config::AppConfig>, running: web::Data<Mutex<ScanStatusResponse>>) -> Result<impl Responder> {
	let res = start_scan_thread(config.get_ref().clone(), running.clone().into_inner());
	let status = running.clone();
	info!("Scan triggered: {}", String::from(res));
	Ok(web::Json(status))
}

/// Handles requests to check for a new version on github or any other configured URI.
/// This function has to be registered in the main HttpServer App
///
/// # Arguments:
///
/// * `config` - The main Application Configuration
///
/// # Result
///
/// An JSON HttpResponse
#[get("/api/version")]
async fn get_version(config: web::Data<config::AppConfig>) -> Result<impl Responder> {
	let mut latest = config::NWD_VERSION.to_string();
	let mut url = "https://api.github.com/repos/ITSGmbH/NetworkDiscover/releases/latest";
	if let Some(wl) = config.whitelabel.as_ref() {
		if let Some(check) = wl.update_check.as_ref() {
			url = &check;
		}
	}
	info!("Check for update: {}", url);

	match minreq::get(url)
		.with_header("User-Agent", "NetworkDiscover")
		.send() {
			Ok(resp) => {
				let response = resp.as_str().unwrap_or_default();
				let mut version = "";
				if let Some(pos) = response.find("tag_name") {
					version = &response[(pos+11)..(pos+30)];
					if let Some(pos) = version.find('"') {
						version = &version[..pos];
					}
				}
				match version.chars().next() {
					Some(v) if v == 'v' => {
						info!("Latest Version: {}", version);
						latest = String::from(&version[1..]);
					},
					_ => error!("Could not fetch latest version from: {}", url)
				}
			},
			Err(e) => error!("{}", e),
	}

	let status = VersionResponse {
		installed: config::NWD_VERSION.to_string(),
		latest: latest.to_string(),
	};
	Ok(web::Json(status))
}

/// Handles requests to get information about a given Host.
/// This function has to be registered in the main HttpServer App
///
/// # Arguments:
///
/// * `config` - The main Application Configuration
/// * `args` - InfoRequest Request Arguments
///
/// # Result
///
/// An JSON HttpResponse
#[get("/api/info")]
async fn get_info(config: web::Data<config::AppConfig>, args: web::Query<InfoRequest>) -> Result<impl Responder> {
	let conf = config.clone();
	let mut db = sqlite::new(&conf);

	let scan = db::Scan::load(&mut db, &args.scan).unwrap_or_default();
	let scan_hist = db::HostHistory::scan_history(&mut db, &args.host);
	let host = db::HostHistory::load(&mut db, &args.host)
		.map(|info| {
			let mut host = db::Host::load(&mut db, &info.host_id).unwrap_or_default();
			host.os = info.os;
			host.hist_id = info.id;
			host
		});
	let ports = db::Port::load(&mut db, &args.host);
	let windows = db::Windows::load(&mut db, &args.host)
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

	let scripts = db::ScriptScan::load(&mut db, &args.host).iter()
		.map(|script| ScriptsResponse {
			name: if script.script_id.is_empty() { None } else { Some(String::from(&script.script_id)) },
			data: db::ScriptResult::load(&mut db, &script.id).iter().map(|res| ScriptDataResponse {
				key: String::from(&res.key),
				value: String::from(&res.value),
			}).collect()
		}).collect();

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
				let cves = db::Cve::load(&mut db, &args.host, &port.port);
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
		scripts,
	}));
	Ok(web::Json(result))
}

/// Handles requests to export and download information about a scan.
/// This function has to be registered in the main HttpServer App
///
/// # Arguments:
///
/// * `config` - The main Application Configuration
/// * `export` - Export type (PDF or CSV)
/// * `args` - InfoRequest Request Arguments
///
/// # Result
///
/// An JSON HttpResponse
#[get("/export/{export}")]
async fn export_scan(config: web::Data<config::AppConfig>, export: web::Path<String>, args: web::Query<NetworkRequest>) -> Result<impl Responder> {
	let conf = config.clone();
	let mut db = sqlite::new(&conf);
	let export_type = export.into_inner().to_lowercase();
	let content = match export_type.as_ref() {
		"pdf" => Pdf::export(&mut db, String::from(&args.network), args.scan),
		"csv" => Csv::export(&mut db, String::from(&args.network), args.scan),
		_ => unknown_export(),
	};

	let result = HttpResponse::Ok()
		.content_type(if export_type == "pdf" { "application/pdf" } else if export_type == "csv" { "text/csv" } else { "text/plain" })
		.body(content);
	Ok(result)
}

/// Handles requests to get the system configuration.
/// This function has to be registered in the main HttpServer App
///
/// # Arguments:
///
/// * `config` - The main Application Configuration
///
/// # Result
///
/// An JSON HttpResponse
#[get("/api/config")]
async fn load_config(config: web::Data<config::AppConfig>) -> Result<impl Responder> {
	let conf = config.clone();
	// TODO: Windows-Password security: Clear passwords
	Ok(web::Json(conf))
}

/// Handles requests to save a new configuration.
/// This function has to be registered in the main HttpServer App
///
/// After this call, the network-discover will restart.
///
/// # Arguments:
///
/// * `payload` - The new configuration to save
/// * `stop_handle` - Global registered listener to restart the NetworkDiscover
///
/// # Result
///
/// An JSON HttpResponse
#[post("/api/config")]
async fn save_config(payload: web::Json<config::SaveConfig>, stop_handle: web::Data<StopHandle>) -> Result<impl Responder> {
	// TODO: Windows-Password security: Copy over from the original config if None
	let mut conf = config::AppConfig::from(payload.0);

	if let Some(wl) = conf.whitelabel.as_mut() {
		// The Logo is submitted as a base64 image string: 'data:image/jpeg;base64,/9j/4AAQS...
		// Only images are accepted (data:image/...;base64,)
		if let Some(logo) = &wl.logo_data {
			if logo.len() > 11 && &logo[..11] != "data:image/" {
				wl.logo_data = None;
			}
		}
		// Color-Picker have black as default
		if let Some(color) = &wl.color {
			if color == "#000000" {
				wl.color = None;
			}
		}
	}

	config::save(&conf);
	stop_handle.stop(true);
	Ok(web::Json("reload"))
}

/// Handles requests to get the operating system configuration.
/// This function has to be registered in the main HttpServer App
///
/// # Result
///
/// An JSON HttpResponse
#[get("/api/settings")]
async fn load_settings() -> Result<impl Responder> {
	Ok(web::Json(config::system::SystemSettings::load()))
}

/// Handles requests to save the operation system configuration.
/// This function has to be registered in the main HttpServer App
///
/// After this call, the network-discover may restart.
/// After this call, the whole system may restart.
///
/// # Arguments:
///
/// * `payload` - The new configuration to save
/// * `stop_handle` - Global registered listener to restart the NetworkDiscover
///
/// # Result
///
/// An JSON HttpResponse
#[post("/api/settings")]
async fn save_settings(payload: web::Json<config::system::SystemSettings>, stop_handle: web::Data<StopHandle>) -> Result<impl Responder> {
	if let Some(network) = &payload.network {
		network.apply();
	}

	if let Some(wlan) = &payload.wireless {
		wlan.apply();
	}

	if let Some(system) = &payload.system {
		if system.restart {
			stop_handle.stop(true);
		}
		if system.shutdown {
			config::system::SystemSettings::shutdown();
		}
		if system.reboot {
			config::system::SystemSettings::reboot();
		}
		if system.reload_network {
			config::system::SystemSettings::reload();
		}
		if system.reset {
			config::system::SystemSettings::reset_config();
		}
	}
	Ok(web::Json(true))
}

/// Handles requests to get a list of all NSE-Scripts.
/// This function has to be registered in the main HttpServer App
///
/// # Arguments:
///
/// * `config` - The main Application Configuration
///
/// # Result
///
/// An JSON HttpResponse
#[get("/api/script/list")]
async fn load_scripts(_config: web::Data<config::AppConfig>) -> Result<impl Responder> {
	let mut list: Vec<String> = vec![];

	let mut file_path = path::PathBuf::new();
	file_path.push("scripts");

	if let Ok(dir) = fs::read_dir(file_path) {
		dir.filter(|entry| entry.is_ok())
			.map(|entry| entry.unwrap().path())
			.map(|entry| String::from(entry.file_name().unwrap_or_default().to_str().unwrap_or_default()))
			.filter(|name| name.len() > 4 && &name[(name.len()-4)..] == ".nse")
			.for_each(|file| list.push(file));
	}

	Ok(web::Json(list))
}


/// Clean up a file name from any kind of path traversal stuff
///
/// # Arguments:
///
/// * `file_name` - The filename to clean up
///
/// # Return
///
/// The file name only from the given string
fn clean_script_name(file_name: &str) -> &str {
	path::Path::new(file_name).file_name().unwrap_or(OsStr::new("unknown.nse")).to_str().unwrap_or("unknown.nse")
}

/// Handles requests to load and return the content of an NSE-Script..
/// This function has to be registered in the main HttpServer App
///
/// # Arguments:
///
/// * `config` - The main Application Configuration
/// * `args` - ScriptRequest Request Arguments
///
/// # Result
///
/// An JSON HttpResponse
#[get("/api/script/load")]
async fn load_script_content(_config: web::Data<config::AppConfig>, args: web::Query<ScriptRequest>) -> Result<impl Responder> {
	let mut script = ScriptResponse {
		script: String::from(clean_script_name(&args.script)),
		content: None,
		active: true,
	};

	let mut file_path = path::PathBuf::new();
	file_path.push("scripts");
	file_path.push(&script.script);

	if let Ok(content) = fs::read_to_string(file_path) {
		script.content = Some(content);
	}

	Ok(web::Json(script))
}

/// Handles requests to upload a new NSE-Script
/// This function has to be registered in the main HttpServer App
///
/// # Arguments:
///
/// * `config` - The main Application Configuration
/// * `args` - ScriptRequest Request Arguments
///
/// # Result
///
/// An JSON HttpResponse
#[post("/api/script/upload")]
async fn upload_script(_config: web::Data<config::AppConfig>, args: web::Json<ScriptRequest>) -> Result<impl Responder> {
	let mut script = ScriptResponse {
		script: String::from(clean_script_name(&args.script)),
		content: None,
		active: false,
	};

	let mut file_path = path::PathBuf::new();
	file_path.push("scripts");

	match fs::create_dir_all(&file_path) {
		Err(e) => error!("Could not create Directory for scripts: {}", e),
		_ => {
			// The script is submitted as a base64 string: 'data:application/octet-stream;base64,/9j/4AAQS...
			// First get the optional content, subtract the prefix, base64-decode it and convert it to a string
			if let Some(content) = &args.content {
				if let Some(pos) = content.find(',') {
					if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&content[pos+1..]) {
						if let Ok(content) = String::from_utf8(decoded) {
							script.content = Some(content);
							script.active = true;
						}
					}
				}
			}
		},
	};

	// Write the file
	if script.active {
		let mut script_file = path::PathBuf::from(file_path);
		script_file.push(String::from(&script.script));
		if let Ok(mut file) = fs::File::create(script_file) {
			match file.write_all(script.content.clone().unwrap_or_default().as_bytes()) {
				Err(e) => error!("Could not write to file: {}", e),
				_ => {}
			}
		}
	}

	Ok(web::Json(script))
}

/// Handles requests to Activate/Deactivate a script from being used during an extended scan.
/// This function has to be registered in the main HttpServer App
///
/// # Arguments:
///
/// * `config` - The main Application Configuration
/// * `args` - ScriptRequest Request Arguments
///
/// # Result
///
/// An JSON HttpResponse
#[get("/api/script/activate")]
async fn activate_script(_config: web::Data<config::AppConfig>, args: web::Query<ScriptRequest>) -> Result<impl Responder> {
	let status = true;
	// TODO: Implement
	let _script_file = clean_script_name(&args.script);
	Ok(web::Json(status))
}


/// Handles requests to Delete a NSE-Script.
/// This function has to be registered in the main HttpServer App
///
/// # Arguments:
///
/// * `config` - The main Application Configuration
/// * `args` - ScriptRequest Request Arguments
///
/// # Result
///
/// An JSON HttpResponse
#[get("/api/script/delete")]
async fn delete_script(_config: web::Data<config::AppConfig>, args: web::Query<ScriptRequest>) -> Result<impl Responder> {
	let mut file_path = path::PathBuf::new();
	file_path.push("scripts");
	file_path.push(clean_script_name(&args.script));

	Ok(web::Json(
		match fs::remove_file(file_path) {
			Ok(_) => true,
			_ => false,
		}
	))
}

/// Data format for requesting something for/from a script.
/// Also used to upload a new script.
#[derive(Deserialize)]
struct ScriptRequest {
	script: String,
	content: Option<String>,
}

/// Response to any kind of a script request.
/// The Content is optinal to not send too much data anytime.
#[derive(Serialize)]
struct ScriptResponse {
	script: String,
	content: Option<String>,
	active: bool,
}
