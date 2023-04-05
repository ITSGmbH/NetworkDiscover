
use std::net::IpAddr;
use std::str::FromStr;
use std::fmt::{Display, Formatter, Result};

#[derive(Debug,Clone)]
pub enum Protocol { UNKNOWN, TCP, UDP }
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

#[derive(Debug,Clone)]
pub enum State { UNKNOWN, OPEN, FILTER, CLOSE }
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


#[derive(Debug,Clone)]
pub struct Host {
	pub network: String,
	pub ip: Option<IpAddr>,
	pub hops: Vec<IpAddr>,
	pub services: Vec<Service>,
	pub os: Option<String>,
	pub extended_scan: bool,
	db_id: i64,
	db_hist_id: i64,
}
impl Default for Host {
	fn default() -> Self {
		Host {
			network: "".to_string(),
			ip: None,
			hops: vec![],
			services: vec![],
			os: None,
			extended_scan: false,
			db_id: 0,
			db_hist_id: 0,
		}
	}
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
}

#[derive(Debug,Clone)]
pub struct Service {
	pub port: u16,
	pub protocol: Protocol,
	pub state: State,
	pub name: String,
	pub product: String,
	pub version: String,
	pub vulns: Vec<Vulnerability>,
}
impl Default for Service {
	fn default() -> Self {
		Service {
			port: 0,
			protocol: Protocol::UNKNOWN,
			state: State::UNKNOWN,
			name: String::from(""),
			product: String::from(""),
			version: String::from(""),
			vulns: vec![],
		}
	}
}

#[derive(Debug,Clone)]
pub struct Vulnerability {
	pub database: String,
	pub id: String,
	pub cvss: f32,
	pub exploit: bool,
}
impl Default for Vulnerability {
	fn default() -> Self {
		Vulnerability {
			database: String::from(""),
			id: String::from(""),
			cvss: 0.0,
			exploit: false,
		}
	}
}
