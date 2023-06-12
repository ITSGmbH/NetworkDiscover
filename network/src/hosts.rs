
use std::net::IpAddr;
use std::str::FromStr;
use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result};

#[derive(Debug, Default, Clone)]
pub enum Protocol {
	#[default]
	UNKNOWN,
	TCP,
	UDP
}
impl Display for Protocol {
	fn fmt(&self, f: &mut Formatter) -> Result {
		match self {
			Protocol::UNKNOWN => write!(f, "UNKNOWN"),
			Protocol::TCP => write!(f, "TCP"),
			Protocol::UDP => write!(f, "UDP"),
		}
	}
}
impl FromStr for Protocol {
	type Err = String;
	fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
		match s {
			"UNKNOWN" => Ok(Self::UNKNOWN),
			"TCP" => Ok(Self::TCP),
			"UDP" => Ok(Self::UDP),
			_ => Err(format!("Unknown protocol: {}", s)),
		}
	}
}

#[derive(Debug, Default, Clone)]
pub enum State {
	#[default]
	UNKNOWN,
	OPEN,
	FILTER,
	CLOSE
}
impl Display for State {
	fn fmt(&self, f: &mut Formatter) -> Result {
		match self {
			State::UNKNOWN => write!(f, "UNKNOWN"),
			State::OPEN => write!(f, "OPEN"),
			State::FILTER => write!(f, "FILTER"),
			State::CLOSE => write!(f, "CLOSE"),
		}
	}
}
impl FromStr for State {
	type Err = String;
	fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
		match s {
			"UNKNOWN" => Ok(Self::UNKNOWN),
			"FILTER" => Ok(Self::FILTER),
			"CLOSE" => Ok(Self::CLOSE),
			"OPEN" => Ok(Self::OPEN),
			_ => Err(format!("Unknown state: {}", s)),
		}
	}
}


#[derive(Debug, Default, Clone)]
pub struct Host {
	pub network: String,
	pub ip: Option<IpAddr>,
	pub hops: Vec<IpAddr>,
	pub services: Vec<Service>,
	pub os: Option<String>,
	pub windows: Option<Windows>,
	pub extended_scan: bool,
	db_id: i64,
	db_hist_id: i64,
}
impl Host {
	/// Save this host-information to the database and stores some internal IDs.
	///
	/// Here only the host and routig information are stored. For additional data
	/// like the ports and exploits, use the `save_service_to_db(...)` method.
	///
	/// # Arguments
	///
	/// * `db` - Database instance to save to
	///
	pub(crate) fn save_to_db(&mut self, db: &mut sqlite::Database) {
		let host = if self.db_id > 0 {
			db::Host::load(db, &self.db_id)
		} else {
			None
		}.unwrap_or({
			let ip = self.ip.unwrap_or(IpAddr::from_str("127.0.0.1").unwrap());
			db::Host::load_by_ip(db, &ip.to_string())
				.unwrap_or(db::Host::default())
		});

		// create the host object if it does not exist
		self.db_id = if host.id > 0 {
			host.id
		} else {
			let ip = self.ip.unwrap_or(IpAddr::from_str("127.0.0.1").unwrap());
			self.create_host(db, &ip.to_string())
		};

		// host history
		let scan_id = db.current_scan_id;
		let hist_id = db::HostHistory::load_from_scan_and_host(db, &scan_id, &host.ip)
			.map_or_else(|| self.create_host_hist(db, &self.db_id), |hist| hist.id);
		self.db_hist_id = hist_id;

		// routing based on the host history
		for hop in &self.hops {
			if hop.to_string().eq(&host.ip) { continue; }
			let _res = db::HostHistory::load_from_scan_and_host(db, &scan_id, &hop.to_string())
				.map_or_else(|| {
					// If no HostHistory is found, check if a Host already exist
					let hop_host = db::Host::load_by_ip(db, &hop.to_string());
					let host_id = hop_host.map_or_else(|| self.create_host(db, &hop.to_string()), |host| host.id);
					Some(self.create_host_hist(db, &host_id))
				}, |hist| Some(hist.id))
				.filter(|id| *id != self.db_hist_id)
				.map(|id| db::Routing {
					scan: scan_id,
					left: self.db_hist_id,
					right: id,
					comment: "".to_string(),
				})
				.map(|mut h| h.save(db))
				.unwrap_or(Err("Unknown Error".to_string()));
		}
	}

	/// Create a new HostHostory in the database for the given host and scan
	///
	/// Returns the new id from the database
	///
	/// # Arguments
	///
	/// * `db` - Database instance to save to
	/// * `host_id` - ID of the host
	///
	fn create_host_hist(&self, db: &mut sqlite::Database, host_id: &i64) -> i64 {
		let mut hist = db::HostHistory {
			id: 0,
			host_id: *host_id,
			os: if self.os.is_some() { String::from(self.os.as_ref().unwrap()) } else { "Unknown".to_string() },
			scan: db.current_scan_id,
		};
		let _ = hist.save(db);
		hist.id
	}

	/// Create a new Host in the database with the given IP
	///
	/// Returns the new id from the database
	///
	/// # Arguments
	///
	/// * `db` - Database instance to save to
	/// * `ip` - IP-Address of the host
	///
	fn create_host(&self, db: &mut sqlite::Database, ip: &str) -> i64 {
		let mut host = db::Host::default();
		host.ip = ip.to_string();
		host.network = String::from(&self.network);
		host.comment = format!("First seen on {}", chrono::Utc::now());
		let _ = host.save(db);
		host.id
	}

	/// Updates all information from this host in the database.
	///
	/// The Host has to exist and be loaded correctly.
	///
	/// # Arguments
	///
	/// * `db` - Database instance to save to
	///
	pub(crate) fn update_host_information(&self, db: &mut sqlite::Database) {
		if self.db_hist_id > 0 {
			match db::HostHistory::load(db, &self.db_hist_id) {
				Some(mut hist) => {
					hist.os = if self.os.is_some() { String::from(self.os.as_ref().unwrap()) } else { "Unknown".to_string() };
					let _ = hist.save(db);
				}
				_ => {}
			}
		}
	}

	/// Saves all additional information like Ports and Exploits on them do the database.
	///
	/// The host has to be saved already manually by the `save_to_db(...)`
	///
	/// # Arguments
	///
	/// * `db` - Database instance to save to
	///
	pub(crate) fn save_services_to_db(&self, db: &mut sqlite::Database) {
		if self.db_hist_id > 0 {
			for service in &self.services {
				let mut port = db::Port {
					host_history_id: self.db_hist_id,
					port: service.port as i32,
					protocol: service.protocol.to_string(),
					state: service.state.to_string(),
					service: format!("{} {}", service.name, service.version),
					product: String::from(&service.product),
					comment: "".to_string(),
				};
				let _ = port.save(db);

				for vuln in &service.vulns {
					let mut cve = db::Cve {
						host_history_id: self.db_hist_id,
						scan: db.current_scan_id,
						port: port.port,
						type_name: String::from(&vuln.database),
						type_id: String::from(&vuln.id),
						cvss: vuln.cvss,
						is_exploit: if vuln.exploit { "true" } else { "false" }.to_string(),
						comment: "".to_string(),
					};
					let _ = cve.save(db);
				}
			}
		}
	}

	pub(crate) fn save_windows_information(&self, db: &mut sqlite::Database) {
		if self.db_hist_id > 0 && self.windows.is_some() {
			let windows = self.windows.as_ref().unwrap();
			let mut win = db::Windows {
				id: 0,
				scan: db.current_scan_id,
				hist_id: self.db_hist_id,
			};
			let _ = win.save(db);

			if let Some(info) = &windows.info {
				let db_info = db::WindowsInfo {
					windows_id: win.id,
					native_lan_manager: String::from(info.native_lan_manager.as_ref().unwrap_or(&String::from(""))),
					native_os: String::from(info.native_os.as_ref().unwrap_or(&String::from(""))),
					os_name: String::from(info.os_name.as_ref().unwrap_or(&String::from(""))),
					os_build: String::from(info.os_build.as_ref().unwrap_or(&String::from(""))),
					os_release: String::from(info.os_release.as_ref().unwrap_or(&String::from(""))),
					os_version: String::from(info.os_version.as_ref().unwrap_or(&String::from(""))),
					platform: String::from(info.platform.as_ref().unwrap_or(&String::from(""))),
					server_type: String::from(info.server_type.as_ref().unwrap_or(&String::from(""))),
					server_string: String::from(info.server_string.as_ref().unwrap_or(&String::from(""))),
				};
				let _ = db_info.save(db);
			}

			if let Some(domain) = &windows.domain {
				let db_domain = db::WindowsDomain {
					windows_id: win.id,
					domain: String::from(domain.domain.as_ref().unwrap_or(&String::from(""))),
					dns_domain: String::from(domain.dns_domain.as_ref().unwrap_or(&String::from(""))),
					derived_domain: String::from(domain.derived_domain.as_ref().unwrap_or(&String::from(""))),
					derived_membership: String::from(domain.derived_membership.as_ref().unwrap_or(&String::from(""))),
					fqdn: String::from(domain.fqdn.as_ref().unwrap_or(&String::from(""))),
					netbios_name: String::from(domain.netbios_name.as_ref().unwrap_or(&String::from(""))),
					netbios_domain: String::from(domain.netbios_domain.as_ref().unwrap_or(&String::from(""))),
				};
				let _ = db_domain.save(db);
			}

			windows.shares.iter().for_each(|share| {
				let db_share = db::WindowsShare {
					windows_id: win.id,
					name: String::from(share.name.as_ref().unwrap_or(&String::from(""))),
					comment: String::from(share.comment.as_ref().unwrap_or(&String::from(""))),
					share_type: String::from(share.share_type.as_ref().unwrap_or(&String::from(""))),
				};
				let _ = db_share.save(db);
			});

			windows.printers.iter().for_each(|printer| {
				let db_printer = db::WindowsPrinter {
					windows_id: win.id,
					uri: String::from(printer.uri.as_ref().unwrap_or(&String::from(""))),
					comment: String::from(printer.comment.as_ref().unwrap_or(&String::from(""))),
					description: String::from(printer.description.as_ref().unwrap_or(&String::from(""))),
					flags: String::from(printer.flags.as_ref().unwrap_or(&String::from(""))),
				};
				let _ = db_printer.save(db);
			});
		}
	}
}

#[derive(Debug, Default, Clone)]
pub struct Windows {
	pub info: Option<WindowsInfo>,
	pub domain: Option<WindowsDomain>,
	pub shares: Vec<WindowsShare>,
	pub printers: Vec<WindowsPrinter>,
}
#[derive(Debug, Default, Clone)]
pub struct WindowsInfo {
	pub native_lan_manager: Option<String>,
	pub native_os: Option<String>,
	pub os_name: Option<String>,
	pub os_build: Option<String>,
	pub os_release: Option<String>,
	pub os_version: Option<String>,
	pub platform: Option<String>,
	pub server_type: Option<String>,
	pub server_string: Option<String>,
}
#[derive(Debug, Default, Clone)]
pub struct WindowsDomain {
	pub domain: Option<String>,
	pub dns_domain: Option<String>,
	pub derived_domain: Option<String>,
	pub derived_membership: Option<String>,
	pub fqdn: Option<String>,
	pub netbios_name: Option<String>,
	pub netbios_domain: Option<String>,
}
#[derive(Debug, Default, Clone)]
pub struct WindowsShare {
	pub name: Option<String>,
	pub comment: Option<String>,
	pub share_type: Option<String>,
	pub access: HashMap<String, String>,
}
#[derive(Debug, Default, Clone)]
pub struct WindowsPrinter {
	pub uri: Option<String>,
	pub comment: Option<String>,
	pub description: Option<String>,
	pub flags: Option<String>,
}


#[derive(Debug, Default, Clone)]
pub struct Service {
	pub port: u16,
	pub protocol: Protocol,
	pub state: State,
	pub name: String,
	pub product: String,
	pub version: String,
	pub vulns: Vec<Vulnerability>,
}

#[derive(Debug, Default, Clone)]
pub struct Vulnerability {
	pub database: String,
	pub id: String,
	pub cvss: f32,
	pub exploit: bool,
}
