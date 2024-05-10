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
	pub changed: bool,
}
impl Default for Scan {
	fn default() -> Self {
		Scan {
			scan: 0,
			start_time: chrono::Utc::now().naive_utc(),
			end_time: NaiveDate::from_ymd_opt(9999, 12, 31).unwrap().and_hms_opt(23, 59, 59).unwrap(),
			changed: true,
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
	pub fn load(db: &mut sqlite::Database, id: &i64) -> Option<Scan> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, Scan>("SELECT *,false AS changed FROM scans WHERE scan=?")
				.bind(id)
				.fetch_one(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => Some(result),
				Err(err) => match err {
					sqlx::Error::RowNotFound => None,
					_ => {
						log::error!("[DB] Entity: 'Scan'; Load failed: {}", err);
						return None;
					}
				}
			}
		}
		None
	}

	/// Loads all instances in between a given date range from a network
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `network` - The Network (IP/MASK) name to load the scans from
	/// * `start` - Optional naive date which symbolizes the start
	/// * `end` - Optional naive date which symbolizes the end
	///
	/// # Returns
	///
	/// A List with instances in the given range
	pub fn list_from_network(db: &mut sqlite::Database, network: &String, start: Option<NaiveDateTime>, end: Option<NaiveDateTime>) -> Vec<Scan> {
		let mut list = vec![];
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			// naive::MIN_DATETIME, naive::MAX_DATETIME does not work :(
			let param_start = if start.is_none() { NaiveDate::from_ymd_opt(1900, 1, 1).unwrap().and_hms_opt(0, 0, 0).unwrap() } else { start.unwrap() };
			let param_end = if end.is_none() { NaiveDate::from_ymd_opt(9999, 12, 31).unwrap().and_hms_opt(23, 59, 59).unwrap() } else { end.unwrap() };
			// let query = query_as::<_, Scan>("SELECT DISTINCT s.*,true AS changed FROM scans AS s,hosts AS h,hosts_history AS hist LEFT JOIN cves as c ON hist.id = c.host_history_id WHERE h.network = ? AND h.id=hist.host_id AND hist.scan=s.scan AND s.start_time >= ? AND s.end_time <= ? ORDER BY c.cvss DESC, CAST(substr(h.ip, 13) AS NUMERIC) ASC")

			let query = query_as::<_, Scan>("SELECT DISTINCT s.*,true AS changed FROM scans AS s,hosts AS h,hosts_history AS hist LEFT JOIN cves as c ON hist.id = c.host_history_id WHERE h.network = ? AND h.id=hist.host_id AND hist.scan=s.scan AND s.start_time >= ? AND s.end_time <= ? ORDER BY s.start_time DESC, c.cvss DESC, CAST(substr(h.ip, 13) AS NUMERIC) ASC LIMIT 21")
				.bind(network)
				.bind(&param_start)
				.bind(&param_end)
				.fetch_all(pool);
			let result = futures::executor::block_on(query);
			if result.is_ok() {
				list.append(&mut result.ok().unwrap());
			} else {
				log::error!("[DB] Entity: 'Scan'; List from Network Failed: {}", result.err().unwrap());
			}

			// Check if there is a change between the scans
			let mut first = true;
			list.iter_mut().for_each(|scan| {
				let mut changed = false;
				let pool1 = con.unwrap();
				let query = query_as::<_, Host>("SELECT h.*,hist.os AS os,hist.id AS hist_id FROM hosts AS h,hosts_history AS hist WHERE hist.scan = ? AND hist.host_id=h.id AND h.network = ? AND h.id NOT IN ( SELECT h1.id FROM hosts AS h1,hosts_history AS hist1 WHERE hist1.scan = ? AND hist1.host_id=h1.id AND h1.network = ? )")
					.bind(scan.scan - 1)
					.bind(network)
					.bind(scan.scan)
					.bind(network)
					.fetch_all(pool1);
				let result = futures::executor::block_on(query);
				if result.is_ok() {
					changed = result.ok().unwrap().len() > 0;
				}
				scan.changed = first || changed;
				first = false;
			});
		}
		return list;
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
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			// naive::MIN_DATETIME, naive::MAX_DATETIME does not work :(
			let param_start = if start.is_none() { NaiveDate::from_ymd_opt(1900, 1, 1).unwrap().and_hms_opt(0, 0, 0).unwrap() } else { start.unwrap() };
			let param_end = if end.is_none() { NaiveDate::from_ymd_opt(9999, 12, 31).unwrap().and_hms_opt(23, 59, 59).unwrap() } else { end.unwrap() };
			let query = query_as::<_, Scan>("SELECT *,false AS changed FROM scans WHERE start_time >= ? AND end_time <= ?")
				.bind(&param_start)
				.bind(&param_end)
				.fetch_all(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => result.into_iter().collect(),
				Err(err) => {
					match err {
						sqlx::Error::RowNotFound => {},
						_ => { log::error!("[DB] Entity: 'Scan'; List failed: {}", err); }
					}
					return vec![];
				}
			}
		}
		return vec![];
	}

	/// Loads the last scan instance
	///
	/// # Arguments:
	///
	/// * `db` - Mutable reference to the database connection object
	///
	/// # Returns
	///
	/// Option to the latest scan
	pub fn last(db: &mut sqlite::Database) -> Option<Scan> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, Scan>("SELECT *,false AS changed FROM scans ORDER BY scan DESC LIMIT 1").fetch_one(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => Some(result),
				Err(err) => match err {
					sqlx::Error::RowNotFound => None,
					_ => {
						log::error!("[DB] Entity: 'Scan'; Load Last failed: {}", err);
						return None;
					}
				}
			}
		}
		None
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
			return futures::executor::block_on(query)
				.map_or_else(
					|err| Err(format!("[DB] Entity: 'Scan'; Save failed: {}", err)),
					|_|  Ok(())
				);
		}
		Err(format!("[DB] Entity: 'Scan'; No Connection available."))
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


#[derive(FromRow, Default, Debug)]
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
			return futures::executor::block_on(query)
				.map_or_else(
					|err| Err(format!("[DB] Entity: 'Log'; Save failed: {}", err)),
					|_|  Ok(())
				);
		}
		Err(format!("[DB] Entity: 'Log'; No Connection available."))
	}
}


#[derive(FromRow, Default, Debug)]
pub struct Host {
	pub id: i64,
	pub hist_id: i64,
	pub network: String,
	pub ipnet: String,
	pub hostname: String,
	pub ip: String,
	pub os: String,
	pub ignore: bool,
	pub comment: String,
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
	pub fn load(db: &mut sqlite::Database, id: &i64) -> Option<Host> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, Host>("SELECT *, 0 AS hist_id,'' AS os FROM hosts WHERE id=?")
				.bind(id)
				.fetch_one(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => Some(result),
				Err(err) => match err {
					sqlx::Error::RowNotFound => None,
					_ => {
						log::error!("[DB] Entity: 'Host'; Load failed: {}", err);
						return None;
					}
				}
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
	pub fn load_by_ip(db: &mut sqlite::Database, ip: &str) -> Option<Host> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, Host>("SELECT *, 0 AS hist_id,'' AS os FROM hosts WHERE ip=?")
				.bind(ip)
				.fetch_one(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => Some(result),
				Err(err) => match err {
					sqlx::Error::RowNotFound => None,
					_ => {
						log::error!("[DB] Entity: 'Host'; Load by IP failed: {}", err);
						return None;
					}
				}
			}
		}
		None
	}

	/// Finds the first instance of a host/ip
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `ip` - IP-Address to find the first instance of
	///
	/// # Returns
	///
	/// An Optional instance of a HostHistory.
	pub fn find_first_emerge(db: &mut sqlite::Database, ip: &str) -> Option<HostHistory> {
		let con = db.connection();
		con.map(|pool| {
			let query = query_as::<_, HostHistory>("SELECT hist.* FROM hosts AS h,hosts_history AS hist WHERE h.ip = ? AND hist.host_id=h.id ORDER BY hist.scan ASC")
				.bind(ip)
				.fetch_one(pool);
			let result = futures::executor::block_on(query);
			if result.is_ok() {
				return result.ok();
			}
			None
		}).unwrap_or(None)
	}

	/// Finds the last instance of a host/ip
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `ip` - IP-Address to find the first instance of
	///
	/// # Returns
	///
	/// An Optional instance of a HostHistory.
	pub fn find_last_emerge(db: &mut sqlite::Database, ip: &str) -> Option<HostHistory> {
		let con = db.connection();
		con.map(|pool| {
			let query = query_as::<_, HostHistory>("SELECT hist.* FROM hosts AS h,hosts_history AS hist WHERE h.ip = ? AND hist.host_id=h.id ORDER BY hist.scan DESC")
				.bind(ip)
				.fetch_one(pool);
			let result = futures::executor::block_on(query);
			if result.is_ok() {
				return result.ok();
			}
			None
		}).unwrap_or(None)
	}

	/// Finds the latest host which changed before the given scan.
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `ip` - IP-Address to find the first instance of
	/// * `scan` - ID of the latest scan
	///
	/// # Returns
	///
	/// An Optional instance of a HostHistory.
	pub fn find_last_change(db: &mut sqlite::Database, ip: &str, scan: &i64) -> Option<HostHistory> {
		let con = db.connection();
		con.map(|pool| {
			let query = query_as::<_, HostHistory>("SELECT hist.* FROM hosts AS h,hosts_history AS hist WHERE h.ip = ? AND hist.host_id=h.id AND hist.scan <= ? ORDER BY hist.scan DESC")
				.bind(ip)
				.bind(scan)
				.fetch_all(pool);
			let result = futures::executor::block_on(query);
			if result.is_ok() {
				let mut last = "".to_string();
				for cur in result.ok().unwrap() {
					if !last.is_empty() && last != cur.os {
						return Some(cur);
					}
					last = String::from(&cur.os);
				}
			}
			None
		}).unwrap_or(None)
	}

	/// Loads all instances found in a scan
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `network` - Network to load the hosts from
	/// * `scan` - ID of the scan to load the hosts from
	///
	/// # Returns
	///
	/// A vector of Hosts.
	pub fn list_from_network(db: &mut sqlite::Database, network: &str, scan: &i64) -> Vec<Host> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			// let query = query_as::<_, Host>("SELECT h.*,hist.os AS os,hist.id AS hist_id FROM hosts AS h,hosts_history AS hist LEFT JOIN cves as c ON hist.id = c.host_history_id WHERE hist.scan = ? AND hist.host_id=h.id AND h.network = ? ORDER BY c.cvss DESC, CAST(substr(h.ip, 13) AS NUMERIC) ASC")
			let query = query_as::<_, Host>("SELECT DISTINCT h.*,hist.os AS os,hist.id AS hist_id, c.* FROM hosts AS h,hosts_history AS hist LEFT JOIN cves as c ON hist.id = c.host_history_id WHERE hist.scan = ? AND hist.host_id=h.id AND h.network = ? GROUP BY h.ip ORDER BY c.cvss DESC, CAST(substr(h.ip, 13) AS NUMERIC) ASC")
			//let query = query_as::<_, Host>("SELECT DISTINCT s.*,true AS changed FROM scans AS s,hosts AS h,hosts_history AS hist LEFT JOIN cves as c ON hist.id = c.host_history_id WHERE h.network = ? AND h.id=hist.host_id AND hist.scan=s.scan AND s.start_time >= ? AND s.end_time <= ? ORDER BY s.start_time DESC, c.cvss DESC, CAST(substr(h.ip, 13) AS NUMERIC) ASC")
				.bind(scan)
				.bind(network)
				.fetch_all(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => result.into_iter().collect(),
				Err(err) => {
					match err {
						sqlx::Error::RowNotFound => {},
						_ => { log::error!("[DB] Entity: 'Host'; Load from Network failed: {}", err); }
					}
					return vec![];
				}
			}
		}
		return vec![];
	}

	/// Loads all instances not found anymore in a scan since last time
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `network` - Network to load the hosts from
	/// * `scan` - ID of the scan to load the hosts from
	///
	/// # Returns
	///
	/// A vector of Hosts.
	pub fn list_removed_from_network(db: &mut sqlite::Database, network: &str, scan: &i64) -> Vec<Host> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, Host>("SELECT h.*, hist.os AS os, hist.id AS hist_id FROM hosts AS h, hosts_history AS hist WHERE hist.scan = ? AND hist.host_id=h.id AND h.network = ? AND h.id NOT IN ( SELECT h.id FROM hosts AS h, hosts_history AS hist WHERE hist.scan = ? AND hist.host_id=h.id AND h.network = ? )")
				.bind(scan - 1)
				.bind(network)
				.bind(scan)
				.bind(network)
				.fetch_all(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => result.into_iter().collect(),
				Err(err) => {
					match err {
						sqlx::Error::RowNotFound => {},
						_ => { log::error!("[DB] Entity: 'host'; Load Removed from Network failed: {}", err); }
					}
					return vec![];
				}
			}
		}
		return vec![];
	}

	/// Loads the gateway the requested Host is connected to
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `host` - ID of the host to load the gateway from
	/// * `scan` - ID of the scan to load the hosts from
	///
	/// # Returns
	///
	/// A vector of Hosts.
	pub fn get_gateway(db: &mut sqlite::Database, host: &i64, scan: &i64) -> Option<Host> {
		let con = db.connection();
		con.map(|pool| {
			let query = query_as::<_, Host>("SELECT h.*,hist.os AS os,hist.id AS hist_id FROM hosts AS h,hosts_history AS hist WHERE hist.scan = ? AND hist.host_id=h.id AND hist.id = ( SELECT hi.id FROM hosts_history AS hi, routing AS ro WHERE ro.left=? AND ro.right=hi.id )")
				.bind(scan)
				.bind(host)
				.fetch_one(pool);
			let result = futures::executor::block_on(query);
			if result.is_ok() {
				return result.ok();
			}
			None
		}).unwrap_or(None)
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
				query("INSERT INTO hosts (id,network,ipnet,hostname,ip,ignore,comment) VALUES(?,?,?,?,?,?,?)")
					.bind(self.id)
					.bind(&self.network)
					.bind(&self.ipnet)
					.bind(&self.hostname)
					.bind(&self.ip)
					.bind(self.ignore)
					.bind(&self.comment)
					.execute(pool)
			} else {
				query("UPDATE hosts SET network = ?, ipnet = ?, hostname = ?, ip = ?, ignore = ?, comment = ? WHERE id=?")
					.bind(&self.network)
					.bind(&self.ipnet)
					.bind(&self.hostname)
					.bind(&self.ip)
					.bind(self.ignore)
					.bind(&self.comment)
					.bind(self.id)
					.execute(pool)
			};
			return futures::executor::block_on(query)
				.map_or_else(
					|err| Err(format!("[DB] Entity: 'Host'; Save failed: {}", err)),
					|_|  Ok(())
				);
		}
		Err(format!("[DB] Entity: 'Host'; No Connection available."))
	}
}


#[derive(FromRow, Default, Debug)]
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
	pub fn load(db: &mut sqlite::Database, id: &i64) -> Option<HostHistory> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, HostHistory>("SELECT * FROM hosts_history WHERE id=?")
				.bind(id)
				.fetch_one(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => Some(result),
				Err(err) => match err {
					sqlx::Error::RowNotFound => None,
					_ => {
						log::error!("[DB] Entity: 'HostHistory'; Load failed: {}", err);
						return None;
					}
				}
			}
		}
		None
	}

	/// Loads an instance from the Database.
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `id` - ID of the Host-History which is the base
	///
	/// # Returns
	///
	/// List with all scans in which the host appeared.
	pub fn scan_history(db: &mut sqlite::Database, id: &i64) -> Vec<Scan> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, Scan>("SELECT s.*,false AS changed FROM scans AS s, hosts_history AS hist WHERE hist.scan=s.scan AND hist.host_id IN ( SELECT host_id FROM hosts_history WHERE id = ? )")
				.bind(id)
				.fetch_all(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => result.into_iter().collect(),
				Err(err) => {
					match err {
						sqlx::Error::RowNotFound => {},
						_ => { log::error!("[DB] Entity: 'HostHistory'; List Scan-History failed: {}", err); }
					}
					return vec![];
				}
			}
		}
		return vec![];
	}

	/// Loads an instance from the Database.
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `scan` - Scan-ID to load the host history from
	/// * `ip` - IP-Address of the host to load the hostory from
	///
	/// # Returns
	///
	/// An Optional instance or None in case it could not be loaded.
	pub fn load_from_scan_and_host(db: &mut sqlite::Database, scan: &i64, ip: &str) -> Option<HostHistory> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, HostHistory>("SELECT hist.* FROM hosts_history AS hist, hosts AS h WHERE hist.scan=? AND hist.host_id=h.id AND h.ip=?")
				.bind(scan)
				.bind(ip)
				.fetch_one(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => Some(result),
				Err(err) => match err {
					sqlx::Error::RowNotFound => None,
					_ => {
						log::error!("[DB] Entity: 'hostHistory'; Load from Scan failed: {}", err);
						return None;
					}
				}
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
			return match futures::executor::block_on(query) {
				Ok(result) => result.into_iter().collect(),
				Err(err) => {
					match err {
						sqlx::Error::RowNotFound => {},
						_ => { log::error!("[DB] Entity: 'HostHistory'; List failed: {}", err); }
					}
					return vec![];
				}
			}
		}
		return vec![];
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
			return futures::executor::block_on(query)
				.map_or_else(
					|err| Err(format!("[DB] Entity: 'HostHistory'; Save failed: {}", err)),
					|_|  Ok(())
				);
		}
		Err(format!("[DB] Entity: 'HostHistory'; No Connection available."))
	}
}


#[derive(FromRow, Default, Debug)]
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
	/// * `scan` - ID of the scan to load the routing from
	///
	/// # Returns
	///
	/// An Optional instance or None in case it could not be loaded.
	pub fn from_host(db: &mut sqlite::Database, host: &i64, scan: &i64) -> Vec<Routing> {
		Routing::load(db, host, scan, true)
	}

	/// Loads all instances where the host is the destination (right).
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `host` - ID of the dataset to load
	/// * `scan` - ID of the scan to load the routing from
	///
	/// # Returns
	///
	/// An Optional instance or None in case it could not be loaded.
	pub fn to_host(db: &mut sqlite::Database, host: &i64, scan: &i64) -> Vec<Routing> {
		Routing::load(db, host, scan, false)
	}

	/// Loads an instance from the Database.
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `host` - Host-ID to load, even in the left or right field
	/// * `scan` - ID of the scan to load the routing from
	/// * `left` - Host-ID is on the left: Load all follow up hosts (right hosts) or vice versa
	///
	/// # Returns
	///
	/// A list with instances
	fn load(db: &mut sqlite::Database, host: &i64, scan: &i64, left: bool) -> Vec<Routing> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = if left { query_as::<_, Routing>("SELECT * FROM routing WHERE left = ? AND scan = ?") } else { query_as::<_, Routing>("SELECT * FROM routing WHERE right = ? AND scan = ?") }
				.bind(host)
				.bind(scan)
				.fetch_all(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => result.into_iter().collect(),
				Err(err) => {
					match err {
						sqlx::Error::RowNotFound => {},
						_ => { log::error!("[DB] Entity: 'Routing'; List failed: {}", err); }
					}
					return vec![];
				}
			}
		}
		return vec![];
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
			return futures::executor::block_on(query)
				.map_or_else(
					|err| Err(format!("[DB] Entity: 'Routing'; Save failed: {}", err)),
					|_|  Ok(())
				);
		}
		Err(format!("[DB] Entity: 'Routing'; No Connection available."))
	}
}


#[derive(FromRow, Default, Debug)]
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
	/// * `hist_id` - Host-History-ID of the dataset to load
	///
	/// # Returns
	///
	/// An Optional instance or None in case it could not be loaded.
	pub fn load(db: &mut sqlite::Database, hist_id: &i64) -> Vec<Port> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, Port>("SELECT * FROM ports WHERE host_history_id = ?")
				.bind(hist_id)
				.fetch_all(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => result.into_iter().collect(),
				Err(err) => {
					match err {
						sqlx::Error::RowNotFound => {},
						_ => { log::error!("[DB] Entity: 'Port'; List failed: {}", err); }
					}
					return vec![];
				}
			}
		}
		return vec![];
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
			let query = query("INSERT INTO ports (host_history_id,port,protocol,state,service,product,comment) VALUES(?,?,?,?,?,?,?)")
				.bind(self.host_history_id)
				.bind(self.port)
				.bind(&self.protocol)
				.bind(&self.state)
				.bind(&self.service)
				.bind(&self.product)
				.bind(&self.comment)
				.execute(pool);
			return futures::executor::block_on(query)
				.map_or_else(
					|err| Err(format!("[DB] Entity: 'Port'; Save failed: {}", err)),
					|_|  Ok(())
				);
		}
		Err(format!("[DB] Entity: 'Port'; No Connection available."))
	}
}


#[derive(FromRow, Default, Debug)]
pub struct Cve {
	pub host_history_id: i64,
	pub port: i32,
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
	/// * `hist_id` - Host-History-ID of the dataset to load
	/// * `port` - Port to get the CVEs from
	///
	/// # Returns
	///
	/// A List with all CVEs
	pub fn load(db: &mut sqlite::Database, hist_id: &i64, port: &i32) -> Vec<Cve> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, Cve>("SELECT * FROM cves WHERE host_history_id = ? AND port = ?")
				.bind(hist_id)
				.bind(port)
				.fetch_all(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => result.into_iter().collect(),
				Err(err) => {
					match err {
						sqlx::Error::RowNotFound => {},
						_ => { log::error!("[DB] Entity: 'Cve'; List failed: {}", err); }
					}
					return vec![];
				}
			}
		}
		return vec![];
	}

	/// Loads a list of all CVEs which are referenced to a host in a scan.
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `hist_id` - Host-History-ID of the dataset to load
	///
	/// # Returns
	///
	/// A List with all CVEs
	pub fn from_host_hist(db: &mut sqlite::Database, hist_id: &i64) -> Vec<Cve> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, Cve>("SELECT * FROM cves WHERE host_history_id = ? ORDER BY cvss DESC, port ASC")
				.bind(hist_id)
				.fetch_all(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => result.into_iter().collect(),
				Err(err) => {
					match err {
						sqlx::Error::RowNotFound => {},
						_ => { log::error!("[DB] Entity: 'Cve'; List from HostHistory failed: {}", err); }
					}
					return vec![];
				}
			}
		}
		return vec![];
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
	pub fn from_scan(db: &mut sqlite::Database, scan: &i64) -> Vec<Cve> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, Cve>("SELECT * FROM cves WHERE scan = ?")
				.bind(scan)
				.fetch_all(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => result.into_iter().collect(),
				Err(err) => {
					match err {
						sqlx::Error::RowNotFound => {},
						_ => { log::error!("[DB] Entity: 'Cve'; List from Scan failed: {}", err); }
					}
					return vec![];
				}
			}
		}
		return vec![];
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
			return futures::executor::block_on(query)
				.map_or_else(
					|err| Err(format!("[DB] Entity: 'Cve'; Save failed: {}", err)),
					|_|  Ok(())
				);
		}
		Err(format!("[DB] Entity: 'Cve'; No Connection available."))
	}
}

#[derive(FromRow, Default, Debug)]
pub struct Windows {
	pub id: i64,
	pub scan: i64,
	pub hist_id: i64,
}
impl Windows {
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
			if self.id <= 0 {
				self.id = next_id(pool, "id", "windows");
				let query = query("INSERT INTO windows (id,scan,hist_id) VALUES(?,?,?)")
					.bind(self.id)
					.bind(self.scan)
					.bind(self.hist_id)
					.execute(pool);
				return futures::executor::block_on(query)
					.map_or_else(
						|err| Err(format!("[DB] Entity: 'Windows'; Save failed: {}", err)),
						|_|  Ok(())
					);
			}
			return Err(format!("[DB] Entity: 'Windows' can not be changed."));
		}
		Err(format!("[DB] Entity: 'Windows'; No Connection available."))
	}

	/// Loads all windows scan information from a host and scan (defined by the Host-History ID)
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `hist_id` - Host-History-ID of the dataset to load
	///
	/// # Returns
	///
	/// Windows-Scan Information if any
	pub fn load(db: &mut sqlite::Database, hist_id: &i64) -> Option<Windows> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, Windows>("SELECT * FROM windows WHERE hist_id=?")
				.bind(hist_id)
				.fetch_one(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => Some(result),
				Err(err) => match err {
					sqlx::Error::RowNotFound => None,
					_ => {
						log::error!("[DB] Entity: 'Windows'; Load failed: {}", err);
						return None;
					}
				}
			}
		}
		None
	}
}


#[derive(FromRow, Default, Debug)]
pub struct WindowsInfo {
	pub windows_id: i64,
	pub native_lan_manager: String,
	pub native_os: String,
	pub os_name: String,
	pub os_build: String,
	pub os_release: String,
	pub os_version: String,
	pub platform: String,
	pub server_type: String,
	pub server_string: String,
}
impl WindowsInfo {
	/// Saves the instance
	///
	/// # Arguments
	///
	/// * `self` - Only callable on a reference, mutable
	/// * `db` - Mutable reference to the database connection object
	pub fn save(&self, db: &mut sqlite::Database) -> Result<(), String> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query("INSERT INTO windows_info (windows_id,native_lan_manager,native_os,os_name,os_build,os_release,os_version,platform,server_type,server_string) VALUES(?,?,?,?,?,?,?,?,?,?)")
				.bind(self.windows_id)
				.bind(&self.native_lan_manager)
				.bind(&self.native_os)
				.bind(&self.os_name)
				.bind(&self.os_build)
				.bind(&self.os_release)
				.bind(&self.os_version)
				.bind(&self.platform)
				.bind(&self.server_type)
				.bind(&self.server_string)
				.execute(pool);
			return futures::executor::block_on(query)
				.map_or_else(
					|err| Err(format!("[DB] Entity: 'WindowsInfo'; Save failed: {}", err)),
					|_|  Ok(())
				);
		}
		Err(format!("[DB] Entity: 'WindowsInfo'; No Connection available."))
	}

	/// Returns teh Windows-Scan Information from the given Windows-Scan
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `win_id` - Windows-Scan-ID of the dataset to load
	///
	/// # Returns
	///
	/// All collected Windows-Information if any
	pub fn load(db: &mut sqlite::Database, win_id: &i64) -> Option<WindowsInfo> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, WindowsInfo>("SELECT * FROM windows_info WHERE windows_id=?")
				.bind(win_id)
				.fetch_one(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => Some(result),
				Err(err) => match err {
					sqlx::Error::RowNotFound => None,
					_ => {
						log::error!("[DB] Entity: 'WindowsInfo'; Load failed: {}", err);
						return None;
					}
				}
			}
		}
		None
	}
}


#[derive(FromRow, Default, Debug)]
pub struct WindowsDomain {
	pub windows_id: i64,
	pub domain: String,
	pub dns_domain: String,
	pub derived_domain: String,
	pub derived_membership: String,
	pub fqdn: String,
	pub netbios_name: String,
	pub netbios_domain: String,
}
impl WindowsDomain {
	/// Saves the instance
	///
	/// # Arguments
	///
	/// * `self` - Only callable on a reference, mutable
	/// * `db` - Mutable reference to the database connection object
	pub fn save(&self, db: &mut sqlite::Database) -> Result<(), String> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query("INSERT INTO windows_domain (windows_id,domain,fqdn,dns_domain,derived_domain,derived_membership,netbios_name,netbios_domain) VALUES(?,?,?,?,?,?,?,?)")
				.bind(self.windows_id)
				.bind(&self.domain)
				.bind(&self.dns_domain)
				.bind(&self.derived_domain)
				.bind(&self.derived_membership)
				.bind(&self.fqdn)
				.bind(&self.netbios_name)
				.bind(&self.netbios_domain)
				.execute(pool);
			return futures::executor::block_on(query)
				.map_or_else(
					|err| Err(format!("[DB] Entity: 'WindowsDomain'; Save failed: {}", err)),
					|_|  Ok(())
				);
		}
		Err(format!("[DB] Entity: 'WindowsDomain'; No Connection available."))
	}

	/// Returns teh Windows-Scan DomainData from the given Windows-Scan
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `win_id` - Windows-Scan-ID of the dataset to load
	///
	/// # Returns
	///
	/// All collected Windows-DomainData if any
	pub fn load(db: &mut sqlite::Database, win_id: &i64) -> Option<WindowsDomain> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, WindowsDomain>("SELECT * FROM windows_domain WHERE windows_id=?")
				.bind(win_id)
				.fetch_one(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => Some(result),
				Err(err) => match err {
					sqlx::Error::RowNotFound => None,
					_ => {
						log::error!("[DB] Entity: 'WindowsDomain'; Load failed: {}", err);
						return None;
					}
				}
			}
		}
		None
	}
}


#[derive(FromRow, Default, Debug)]
pub struct WindowsShare {
	pub windows_id: i64,
	pub name: String,
	pub comment: String,
	#[sqlx(rename = "type")]
	pub share_type: String,
}
impl WindowsShare {
	/// Saves the instance
	///
	/// # Arguments
	///
	/// * `self` - Only callable on a reference, mutable
	/// * `db` - Mutable reference to the database connection object
	pub fn save(&self, db: &mut sqlite::Database) -> Result<(), String> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query("INSERT INTO windows_share (windows_id,name,type,comment) VALUES(?,?,?,?)")
				.bind(self.windows_id)
				.bind(&self.name)
				.bind(&self.share_type)
				.bind(&self.comment)
				.execute(pool);
			return futures::executor::block_on(query)
				.map_or_else(
					|err| Err(format!("[DB] Entity: 'WindowsShare'; Save failed: {}", err)),
					|_|  Ok(())
				);
		}
		Err(format!("[DB] Entity: 'WindowsShare'; No Connection available."))
	}

	/// Loads a list of all shares found during a windows scan
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `win_id` - Windows Scan-ID of the dataset to load
	///
	/// # Returns
	///
	/// A List with windows share information
	pub fn load(db: &mut sqlite::Database, win_id: &i64) -> Vec<WindowsShare> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, WindowsShare>("SELECT * FROM windows_share WHERE windows_id = ?")
				.bind(win_id)
				.fetch_all(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => result.into_iter().collect(),
				Err(err) => {
					match err {
						sqlx::Error::RowNotFound => {},
						_ => { log::error!("[DB] Entity: 'WindowsShare'; Load failed: {}", err); }
					}
					return vec![];
				}
			}
		}
		return vec![];
	}
}


#[derive(FromRow, Default, Debug)]
pub struct WindowsPrinter {
	pub windows_id: i64,
	pub uri: String,
	pub comment: String,
	pub description: String,
	pub flags: String,
}
impl WindowsPrinter {
	/// Saves the instance
	///
	/// # Arguments
	///
	/// * `self` - Only callable on a reference, mutable
	/// * `db` - Mutable reference to the database connection object
	pub fn save(&self, db: &mut sqlite::Database) -> Result<(), String> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query("INSERT INTO windows_printer (windows_id,uri,flags,description,comment) VALUES(?,?,?,?,?)")
				.bind(self.windows_id)
				.bind(&self.uri)
				.bind(&self.flags)
				.bind(&self.description)
				.bind(&self.comment)
				.execute(pool);
			return futures::executor::block_on(query)
				.map_or_else(
					|err| Err(format!("[DB] Entity: 'WindowsPrinter'; Save failed: {}", err)),
					|_|  Ok(())
				);
		}
		Err(format!("[DB] Entity: 'WindowsPrinter'; No Connection available."))
	}

	/// Loads a list of all printers found during a windows scan
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `win_id` - Windows Scan-ID of the dataset to load
	///
	/// # Returns
	///
	/// A List with windows prinetr information
	pub fn load(db: &mut sqlite::Database, win_id: &i64) -> Vec<WindowsPrinter> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, WindowsPrinter>("SELECT * FROM windows_printer WHERE windows_id = ?")
				.bind(win_id)
				.fetch_all(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => result.into_iter().collect(),
				Err(err) => {
					match err {
						sqlx::Error::RowNotFound => {},
						_ => { log::error!("[DB] Entity: 'WindowsPrinter'; Load failed: {}", err); }
					}
					return vec![];
				}
			}
		}
		return vec![];
	}
}


#[derive(FromRow, Default, Debug)]
pub struct ScriptScan {
	pub id: i64,
	pub scan: i64,
	pub hist_id: i64,
	pub script_id: String,
}
impl ScriptScan {
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
			if self.id <= 0 {
				self.id = next_id(pool, "id", "script_scan");
				let query = query("INSERT INTO script_scan (id,scan,hist_id,script_id) VALUES(?,?,?,?)")
					.bind(self.id)
					.bind(self.scan)
					.bind(self.hist_id)
					.bind(&self.script_id)
					.execute(pool);
				return futures::executor::block_on(query)
					.map_or_else(
						|err| Err(format!("[DB] Entity: 'ScriptScan'; Save failed: {}", err)),
						|_|  Ok(())
					);
			}
			return Err(format!("[DB] Entity: 'ScriptScan' can not be changed."));
		}
		Err(format!("[DB] Entity: 'ScriptScan'; No Connection available."))
	}

	/// Loads a list of all scripts which where run during a scan and produced some output
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `hist_id` - Host-History-ID of the dataset to load
	///
	/// # Returns
	///
	/// A List with scripts
	pub fn load(db: &mut sqlite::Database, hist_id: &i64) -> Vec<ScriptScan> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, ScriptScan>("SELECT * FROM script_scan WHERE hist_id=? ORDER BY script_id ASC")
				.bind(hist_id)
				.fetch_all(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => result.into_iter().collect(),
				Err(err) => {
					match err {
						sqlx::Error::RowNotFound => {},
						_ => { log::error!("[DB] Entity: 'ScriptScan'; Load failed: {}", err); }
					}
					return vec![];
				}
			}
		}
		return vec![];
	}
}


#[derive(FromRow, Default, Debug)]
pub struct ScriptResult {
	pub script_id: i64,
	pub key: String,
	pub value: String,
}
impl ScriptResult {
	/// Saves the instance
	///
	/// # Arguments
	///
	/// * `self` - Only callable on a reference, mutable
	/// * `db` - Mutable reference to the database connection object
	pub fn save(&self, db: &mut sqlite::Database) -> Result<(), String> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query("INSERT INTO script_result (script_id,key,value) VALUES(?,?,?)")
				.bind(self.script_id)
				.bind(&self.key)
				.bind(&self.value)
				.execute(pool);
			return futures::executor::block_on(query)
				.map_or_else(
					|err| Err(format!("[DB] Entity: 'ScriptResult'; Save failed: {}", err)),
					|_|  Ok(())
				);
		}
		Err(format!("[DB] Entity: 'ScriptResult'; No Connection available."))
	}

	/// Loads a list of all script results found during a scan
	///
	/// # Arguments
	///
	/// * `db` - Mutable reference to the database connection object
	/// * `script_scan_id` - ScriptScan-ID of the dataset to load
	///
	/// # Returns
	///
	/// A List with script results
	pub fn load(db: &mut sqlite::Database, script_scan_id: &i64) -> Vec<ScriptResult> {
		let con = db.connection();
		if con.is_some() {
			let pool = con.unwrap();
			let query = query_as::<_, ScriptResult>("SELECT * FROM script_result WHERE script_id=? ORDER BY key ASC")
				.bind(script_scan_id)
				.fetch_all(pool);
			return match futures::executor::block_on(query) {
				Ok(result) => result.into_iter().collect(),
				Err(err) => {
					match err {
						sqlx::Error::RowNotFound => {},
						_ => { log::error!("[DB] Entity: 'ScriptResult'; Load failed: {}", err); }
					}
					return vec![];
				}
			}
		}
		return vec![];
	}
}
