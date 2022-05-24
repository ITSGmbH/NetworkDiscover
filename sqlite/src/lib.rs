
use sqlx::{
	sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
	Pool, Sqlite,
};
use std::time::{Duration, Instant};
use std::{format, str::FromStr};

use config::AppConfig;

pub struct Database {
	pub current_scan_id: i64,
	pub(crate) db_file: String,
	pub(crate) db_url: Option<String>,
	pool: Option<Pool<Sqlite>>,
}

pub fn new(conf: &AppConfig) -> Database {
	let db_conf = conf.sqlite.as_ref();
	if db_conf.is_some() {
		Database {
			current_scan_id: 0,
			db_file: String::from(&db_conf.unwrap().file),
			db_url: if db_conf.unwrap().url.is_empty() { None } else { Some(String::from(&db_conf.unwrap().url)) },
			pool: None,
		}
	} else {
		Database {
			current_scan_id: 0,
			db_file: "scan.sqlite".to_string(),
			db_url: None,
			pool: None,
		}
	}
}

impl Database {
	pub fn connect(&mut self) {
		if self.pool.is_none() {
			let connect_timeout = Duration::from_secs(60);
			let db_url = if self.db_url.is_some() { String::from(self.db_url.as_ref().unwrap()) } else { format!("sqlite://{}", self.db_file) };
			let connect_options = SqliteConnectOptions::from_str(&db_url)
				.unwrap()
				.create_if_missing(true)
				.journal_mode(SqliteJournalMode::Wal)
				.synchronous(SqliteSynchronous::Normal)
				.busy_timeout(connect_timeout);

			self.pool = Some(
				SqlitePoolOptions::new()
					.max_connections(10)
					.connect_timeout(connect_timeout)
					.connect_lazy_with(connect_options)
			);

			let start = Instant::now();
			let mig = sqlx::migrate!("../db/migrate").run(self.pool.as_ref().unwrap());
			let res = futures::executor::block_on(mig);
			log::info!("DB-Update duration: {}", start.elapsed().as_secs_f32());

			if res.is_err() {
				let err = res.err().unwrap();
				log::error!("DB-Update Error: {}", &err);
			}
		}
	}

	pub fn connection(&mut self) -> Option<&Pool<Sqlite>> {
		self.connect();
		if self.pool.is_none() {
			return None;
		}
		return self.pool.as_ref();
	}
}

