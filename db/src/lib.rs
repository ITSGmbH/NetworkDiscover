
use sqlx::{Row, ValueRef, Value, FromRow, query, query_as};
use chrono::{NaiveDateTime, NaiveDate};

/// Gets the next numeric value (id) from a field in a table.
///
/// # Arguments
///
/// * `pool` - The DB-Pool to connect and run the query on
/// * `id_field` - Field to check for the highest value from and increase
/// * `table` - Table to check on
///
/// # Returns
///
/// An integer which is the one bigger than the max value found
pub(crate) fn next_id(pool: &sqlx::Pool<sqlx::Sqlite>, id_field: &str, table: &str) -> i64 {
	let sql = format!("SELECT MAX({}) AS next_id FROM {}", id_field, table); // Can't bind with sqlx::Query.bind it's not working for the table and for the aggregate function
	let query = query(&sql).fetch_one(pool);
	let result = futures::executor::block_on(query);
	if result.is_ok() {
		let row = result.ok().unwrap();
		let val = row.try_get_raw("next_id");
		let max_id = val.map(|x| x.to_owned().try_decode::<i64>()).unwrap_or(Ok(0_i64));
		return max_id.map(|x| x + 1).unwrap_or(1_i64);
	}
	0
}

#[derive(FromRow, Debug)]
pub struct Scan {
	pub scan: i64,
	pub start_time: NaiveDateTime,
	pub end_time: NaiveDateTime,
}
impl Default for Scan {
	fn default() -> Self {
		Scan {
			scan: 0,
			start_time: chrono::Utc::now().naive_utc(),
			end_time: NaiveDate::from_ymd(9999, 12, 31).and_hms(23, 59, 59),
		}
	}
}
impl Scan {
	/// Loads an instance from the Database.
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `id` - ID of the dataset to load
	///
	/// # Returns
	///
	/// An Optional instance or None in case it could not be loaded.
	pub fn load(db: &mut sqlite::Database, id: i64) -> Option<Scan> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, Scan>("SELECT * FROM scans WHERE scan=?")
				.bind(id)
				.fetch_one(pool);
			let result = futures::executor::block_on(query);
			if result.is_ok() {
				return Some(result.ok().unwrap());
			}
		}
		None
	}

	/// Loads all instances in between a given date range
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `start` - Optional naive date which symbolizes the start
	/// * `end` - Optional naive date which symbolizes the end
	///
	/// # Returns
	///
	/// A List with instances in the given range
	pub fn list(db: &mut sqlite::Database, start: Option<NaiveDateTime>, end: Option<NaiveDateTime>) -> Vec<Scan> {
		let mut list = vec![];
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			// naive::MIN_DATETIME, naive::MAX_DATETIME does not work :(
			let param_start = if start.is_none() { NaiveDate::from_ymd(1900, 1, 1).and_hms(0, 0, 0) } else { start.unwrap() };
			let param_end = if end.is_none() { NaiveDate::from_ymd(9999, 12, 31).and_hms(23, 59, 59) } else { end.unwrap() };
			let query = query_as::<_, Scan>("SELECT * FROM scans WHERE start_time >= ? AND end_time <= ?")
				.bind(&param_start)
				.bind(&param_end)
				.fetch_all(pool);
			let result = futures::executor::block_on(query);
			if result.is_ok() {
				list.append(&mut result.ok().unwrap());
			} else {
				log::error!("DB: Load Scan Error: {}", result.err().unwrap());
			}
		}
		return list;
	}

	/// Saves the instance
	///
	/// # Arguments
	///
	/// * `self` - Only callable on a reference, mutable
	/// * `db` - Mutable reference to the database connection object
	pub fn save(&mut self, db: &mut sqlite::Database) -> Result<(), String> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = if self.scan <= 0 {
				self.scan = next_id(pool, "scan", "scans");
				query("INSERT INTO scans (scan,start_time,end_time) VALUES(?,?,?)")
					.bind(self.scan)
					.bind(self.start_time)
					.bind(self.end_time)
					.execute(pool)
			} else {
				query("UPDATE scans SET start_time = ?, end_time = ? WHERE scan = ?")
					.bind(self.start_time)
					.bind(self.end_time)
					.bind(self.scan)
					.execute(pool)
			};
			let result = futures::executor::block_on(query);
			if result.is_err() {
				let err = result.err().unwrap();
				return Err(format!("DB: Save Scan Error: {}", &err));
			}
		}
		Ok(())
	}

	/// Updates the end_scan field and saves itself.
	///
	/// # Arguments
	///
	/// * `self` - Only callable on a reference, mutable
	/// * `db` - Mutable reference to the database connection object
	pub fn end_scan(&mut self, db: &mut sqlite::Database) -> Result<(), String> {
		self.end_time = chrono::Utc::now().naive_utc();
		self.save(db)
	}
}


#[derive(FromRow, Debug)]
pub struct Log {
	pub log_time: NaiveDateTime,
	pub scan: i64,
	pub severity: String,
	pub origin: String,
	pub log: String,
}
impl Log {
	/// Saves the instance
	///
	/// # Arguments
	///
	/// * `self` - Only callable on a reference, mutable
	/// * `db` - Mutable reference to the database connection object
	pub fn save(&mut self, db: &mut sqlite::Database) -> Result<(), String> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query("INSERT INTO log (log_time,scan,severity,origin,log) VALUES(?,?,?,?,?)")
				.bind(self.log_time)
				.bind(self.scan)
				.bind(&self.severity)
				.bind(&self.origin)
				.bind(&self.log)
				.execute(pool);
			let result = futures::executor::block_on(query);
			if result.is_err() {
				let err = result.err().unwrap();
				return Err(format!("DB: Save Log Error: {}", &err));
			}
		}
		Ok(())
	}
}


#[derive(FromRow, Debug)]
pub struct Host {
	pub id: i64,
	pub ip: String,
	pub ignore: bool,
	pub comment: String,
}
impl Default for Host {
	fn default() -> Self {
		Host {
			id:0,
			ip: "".to_string(),
			ignore: false,
			comment: "".to_string(),
		}
	}
}
impl Host {
	/// Loads an instance from the Database.
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `id` - ID of the dataset to load
	///
	/// # Returns
	///
	/// An Optional instance or None in case it could not be loaded.
	pub fn load(db: &mut sqlite::Database, id: i64) -> Option<Host> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, Host>("SELECT * FROM hosts WHERE id=?")
				.bind(id)
				.fetch_one(pool);
			let result = futures::executor::block_on(query);
			if result.is_ok() {
				return Some(result.ok().unwrap());
			}
		}
		None
	}

	/// Loads an instance from the Database based on he IP-Address.
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `ip` - IP-Address to try to load a host from
	///
	/// # Returns
	///
	/// An Optional instance or None in case it could not be loaded.
	pub fn load_by_ip(db: &mut sqlite::Database, ip: String) -> Option<Host> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, Host>("SELECT * FROM hosts WHERE ip=?")
				.bind(ip)
				.fetch_one(pool);
			let result = futures::executor::block_on(query);
			if result.is_ok() {
				return Some(result.ok().unwrap());
			}
		}
		None
	}

	/// Loads all instances found in a scan
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `scan` - ID of the scan to load the hosts from
	///
	/// # Returns
	///
	/// An Optional instance or None in case it could not be loaded.
	pub fn list(db: &mut sqlite::Database, scan: i64) -> Vec<Host> {
		let mut list = vec![];
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, Host>("SELECT hosts.* FROM hosts,hosts_history WHERE hosts_history.scan = ? AND hosts_history.host_id=host.id")
				.bind(scan)
				.fetch_all(pool);
			let result = futures::executor::block_on(query);
			if result.is_ok() {
				list.append(&mut result.ok().unwrap());
			} else {
				log::error!("DB: Load Hosts Error: {}", result.err().unwrap());
			}
		}
		return list;
	}

	/// Saves the instance
	///
	/// # Arguments
	///
	/// * `self` - Only callable on a reference, mutable
	/// * `db` - Mutable reference to the database connection object
	pub fn save(&mut self, db: &mut sqlite::Database) -> Result<(), String> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = if self.id <= 0 {
				self.id = next_id(pool, "id", "hosts");
				query("INSERT INTO hosts (id,ip,ignore,comment) VALUES(?,?,?,?)")
					.bind(self.id)
					.bind(&self.ip)
					.bind(self.ignore)
					.bind(&self.comment)
					.execute(pool)
			} else {
				query("UPDATE hosts SET ip = ?, ignore = ?, comment = ? WHERE id=?")
					.bind(&self.ip)
					.bind(self.ignore)
					.bind(&self.comment)
					.bind(self.id)
					.execute(pool)
			};
			let result = futures::executor::block_on(query);
			if result.is_err() {
				let err = result.err().unwrap();
				return Err(format!("DB: Save Host Error: {}", &err));
			}
		}
		Ok(())
	}
}


#[derive(FromRow, Debug)]
pub struct HostHistory {
	pub id: i64,
	pub host_id: i64,
	pub os: String,
	pub scan: i64,
}
impl HostHistory {
	/// Loads an instance from the Database.
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `id` - ID of the dataset to load
	///
	/// # Returns
	///
	/// An Optional instance or None in case it could not be loaded.
	pub fn load(db: &mut sqlite::Database, id: i64) -> Option<HostHistory> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, HostHistory>("SELECT * FROM hosts_history WHERE id=?")
				.bind(id)
				.fetch_one(pool);
			let result = futures::executor::block_on(query);
			if result.is_ok() {
				return Some(result.ok().unwrap());
			}
		}
		None
	}

	/// Loads all instances from a given host or scan. If the host parameter is given, the host is used for the query, otherwise the scan.
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `scan` - Scan-ID to load host informations from
	/// * `host` - Host-ID to load host informations from
	///
	/// # Returns
	///
	/// A List of host information
	pub fn list(db: &mut sqlite::Database, scan: Option<i64>, host: Option<i64>) -> Vec<HostHistory> {
		let mut list = vec![];
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = if host.is_some() {
					query_as::<_, HostHistory>("SELECT * FROM hosts_history WHERE host_id = ?")
				} else {
					query_as::<_, HostHistory>("SELECT * FROM hosts_history WHERE scan = ?")
				}
				.bind(host.unwrap_or( scan.unwrap_or(0) ))
				.fetch_all(pool);
			let result = futures::executor::block_on(query);
			if result.is_ok() {
				list.append(&mut result.ok().unwrap());
			} else {
				log::error!("DB: Load HostHistories Error: {}", result.err().unwrap());
			}
		}
		return list;
	}

	/// Saves the instance
	///
	/// # Arguments
	///
	/// * `self` - Only callable on a reference, mutable
	/// * `db` - Mutable reference to the database connection object
	pub fn save(&mut self, db: &mut sqlite::Database) -> Result<(), String> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = if self.id <= 0 {
				self.id = next_id(pool, "id", "hosts_history");
				query("INSERT INTO hosts_history (id,host_id,os,scan) VALUES(?,?,?,?)")
					.bind(self.id)
					.bind(self.host_id)
					.bind(&self.os)
					.bind(self.scan)
					.execute(pool)
			} else {
				query("UPDATE hosts_history SET host_id = ?, os = ?, scan = ? WHERE id = ?")
					.bind(self.host_id)
					.bind(&self.os)
					.bind(self.scan)
					.bind(self.id)
					.execute(pool)
			};
			let result = futures::executor::block_on(query);
			if result.is_err() {
				let err = result.err().unwrap();
				return Err(format!("DB: Save HostHistory Error: {}", &err));
			}
		}
		Ok(())
	}
}


#[derive(FromRow, Debug)]
pub struct Routing {
	pub scan: i64,
	pub left: i64,
	pub right: i64,
	pub comment: String,
}
impl Routing {
	/// Loads all instances where the host is on the source (left).
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `host` - ID of the dataset to load
	///
	/// # Returns
	///
	/// An Optional instance or None in case it could not be loaded.
	pub fn from_host(db: &mut sqlite::Database, host: i64) -> Vec<Routing> {
		Routing::load(db, host, true)
	}

	/// Loads all instances where the host is the destination (right).
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `host` - ID of the dataset to load
	///
	/// # Returns
	///
	/// An Optional instance or None in case it could not be loaded.
	pub fn to_host(db: &mut sqlite::Database, host: i64) -> Vec<Routing> {
		Routing::load(db, host, false)
	}

	/// Loads an instance from the Database.
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `host` - Host-ID to load, even in the left or right field
	/// * `left` - Host-ID is on the left: Load all follow up hosts (right hosts) or vice versa
	///
	/// # Returns
	///
	/// A list with instances
	fn load(db: &mut sqlite::Database, host: i64, left: bool) -> Vec<Routing> {
		let mut list = vec![];
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = if left { query_as::<_, Routing>("SELECT * FROM routing WHERE left = ?") } else { query_as::<_, Routing>("SELECT * FROM routing WHERE right = ?") }
				.bind(host)
				.fetch_all(pool);
			let result = futures::executor::block_on(query);
			if result.is_ok() {
				list.append(&mut result.ok().unwrap());
			} else {
				log::error!("DB: Load Routing Error: {}", result.err().unwrap());
			}
		}
		return list;
	}

	/// Saves the instance
	///
	/// # Arguments
	///
	/// * `self` - Only callable on a reference, mutable
	/// * `db` - Mutable reference to the database connection object
	pub fn save(&mut self, db: &mut sqlite::Database) -> Result<(), String> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query("INSERT INTO routing (scan,left,right,comment) VALUES(?,?,?,?)")
				.bind(self.scan)
				.bind(self.left)
				.bind(self.right)
				.bind(&self.comment)
				.execute(pool);
			let result = futures::executor::block_on(query);
			if result.is_err() {
				let err = result.err().unwrap();
				return Err(format!("DB: Save Routing Error: {}", &err));
			}
		}
		Ok(())
	}
}


#[derive(FromRow, Debug)]
pub struct Port {
	pub host_history_id: i64,
	pub port: i32,
	pub protocol: String,
	pub state: String,
	pub service: String,
	pub product: String,
	pub comment: String,
}
impl Port {
	/// Loads a list of instances where the host history id is a reference to.
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `id` - Host-History-ID of the dataset to load
	///
	/// # Returns
	///
	/// An Optional instance or None in case it could not be loaded.
	pub fn load(db: &mut sqlite::Database, id: i64) -> Vec<Port> {
		let mut list = vec![];
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, Port>("SELECT * FROM ports WHERE host_history_id = ?")
				.bind(id)
				.fetch_all(pool);
			let result = futures::executor::block_on(query);
			if result.is_ok() {
				list.append(&mut result.ok().unwrap());
			} else {
				log::error!("DB: Load Ports Error: {}", result.err().unwrap());
			}
		}
		return list;
	}

	/// Saves the instance
	///
	/// # Arguments
	///
	/// * `self` - Only callable on a reference, mutable
	/// * `db` - Mutable reference to the database connection object
	pub fn save(&mut self, db: &mut sqlite::Database) -> Result<(), String> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query("INSERT INTO scans (host_history_id,port,protocol,state,service,product,comment) VALUES(?,?,?,?,?,?,?)")
				.bind(self.host_history_id)
				.bind(self.port)
				.bind(&self.protocol)
				.bind(&self.state)
				.bind(&self.service)
				.bind(&self.product)
				.bind(&self.comment)
				.execute(pool);
			let result = futures::executor::block_on(query);
			if result.is_err() {
				let err = result.err().unwrap();
				return Err(format!("DB: Save Port Error: {}", &err));
			}
		}
		Ok(())
	}
}


#[derive(FromRow, Debug)]
pub struct Cve {
	pub host_history_id: i64,
	pub port: i64,
	#[sqlx(rename = "type")]
	pub type_name: String,
	pub type_id: String,
	pub cvss: f32,
	pub is_exploit: String,
	pub scan: i64,
	pub comment: String,
}
impl Cve {
	/// Loads a list of all CVEs which are referenced to a port on a given host in a scan.
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `id` - Host-History-ID of the dataset to load
	/// * `port` - Port to get the CVEs from
	///
	/// # Returns
	///
	/// A List with all CVEs
	pub fn load(db: &mut sqlite::Database, id: i64, port: i64) -> Vec<Cve> {
		let mut list = vec![];
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, Cve>("SELECT * FROM cves WHERE host_history_id = ? AND port = ?")
				.bind(id)
				.bind(port)
				.fetch_all(pool);
			let result = futures::executor::block_on(query);
			if result.is_ok() {
				list.append(&mut result.ok().unwrap());
			} else {
				log::error!("DB: Load Cves Error: {}", result.err().unwrap());
			}
		}
		return list;
	}

	/// Loads a list of all CVEs which are found in a given scan.
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `scan` - Scan-ID of the dataset to load
	///
	/// # Returns
	///
	/// A List with all CVEs
	pub fn from_scan(db: &mut sqlite::Database, scan: i64) -> Vec<Cve> {
		let mut list = vec![];
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, Cve>("SELECT * FROM cves WHERE scan = ?")
				.bind(scan)
				.fetch_all(pool);
			let result = futures::executor::block_on(query);
			if result.is_ok() {
				list.append(&mut result.ok().unwrap());
			} else {
				log::error!("DB: Load Cves Error: {}", result.err().unwrap());
			}
		}
		return list;
	}

	/// Saves the instance
	///
	/// # Arguments
	///
	/// * `self` - Only callable on a reference, mutable
	/// * `db` - Mutable reference to the database connection object
	pub fn save(&mut self, db: &mut sqlite::Database) -> Result<(), String> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query("INSERT INTO cves (scan,host_history_id,port,type,type_id,cvss,is_exploit,comment) VALUES(?,?,?,?,?,?,?,?)")
				.bind(self.scan)
				.bind(self.host_history_id)
				.bind(self.port)
				.bind(&self.type_name)
				.bind(&self.type_id)
				.bind(self.cvss)
				.bind(&self.is_exploit)
				.bind(&self.comment)
				.execute(pool);
			let result = futures::executor::block_on(query);
			if result.is_err() {
				let err = result.err().unwrap();
				return Err(format!("DB: Save Cve Error: {}", &err));
			}
		}
		Ok(())
	}
}

