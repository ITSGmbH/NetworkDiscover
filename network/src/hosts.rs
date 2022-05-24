
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug,Clone)]
pub enum Protocol { UNKNOWN, TCP, UDP }

#[derive(Debug,Clone)]
pub enum State { UNKNOWN, OPEN, FILTER, CLOSE }

#[derive(Debug,Clone)]
pub struct Host {
	pub ip: Option<IpAddr>,
	pub hops: Vec<IpAddr>,
	pub services: Vec<Service>,
	pub os: Option<String>,
	db_id: i64,
}
impl Default for Host {
	fn default() -> Self {
		Host {
			ip: None,
			hops: vec![],
			services: vec![],
			os: None,
			db_id: 0,
		}
	}
}
impl Host {
	pub(crate) fn save_to_db(&mut self, db: &mut sqlite::Database) {
		let mut host = if self.db_id > 0 {
			db::Host::load(db, self.db_id)
		} else {
			None
		}.unwrap_or({
			let ip = self.ip.unwrap_or(IpAddr::from_str("127.0.0.1").unwrap());
			db::Host::load_by_ip(db, ip.to_string()).unwrap_or(db::Host::default())
		});

		if host.id <= 0 {
			host.ip = self.ip.unwrap_or(IpAddr::from_str("127.0.0.1").unwrap()).to_string();
			host.comment = format!("First seen on {}", chrono::Utc::now());
			let _ = host.save(db);
			self.db_id = host.id;
		}

		for hop in &self.hops {
			let _res = db::Host::load_by_ip(db, hop.to_string())
				.or_else(|| {
					let mut right = db::Host::default();
					right.ip = hop.to_string();
					right.comment = format!("Traceroute on {}", chrono::Utc::now());
					let _ = right.save(db);
					Some(right)
				})
				.map(|h| db::Routing {
					scan: db.current_scan_id,
					left: host.id,
					right: h.id,
					comment: "".to_string(),
				})
				.map(|mut h| h.save(db))
				.unwrap_or(Err("Unknown Error".to_string()));
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
