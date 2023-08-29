
use sqlx::{
	sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
	Pool, Sqlite,
};
use std::time::{Duration, Instant};
use std::{format, str::FromStr};

use config::AppConfig;

use std::sync::atomic::{AtomicBool, Ordering};
static DB_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub struct Database {
	pub current_scan_id: i64,
	pub(crate) db_file: Option<String>,
	pub(crate) db_url: Option<String>,
	pool: Option<Pool<Sqlite>>,
}

pub fn new(conf: &AppConfig) -> Database {
	let db_conf = conf.sqlite.as_ref();
	if db_conf.is_some() {
		Database {
			current_scan_id: 0,
			db_file: db_conf.unwrap().file.as_ref().map_or_else(|| None, |s| if s.is_empty() { None } else { Some(String::from(s)) } ),
			db_url: db_conf.unwrap().url.as_ref().map_or_else(|| None, |s| if s.is_empty() { None } else { Some(String::from(s)) } ),
			pool: None,
		}
	} else {
		let std_conf = ::config::DbStruct::default();
		Database {
			current_scan_id: 0,
			db_file: std_conf.file,
			db_url: None,
			pool: None,
		}
	}
}

impl Database {
	pub fn connect(&mut self) {
		if self.pool.is_none() {
			let connect_timeout = Duration::from_secs(60);
			let db_url = if self.db_url.is_some() {
				String::from(self.db_url.as_ref().unwrap())
			} else {
				format!("sqlite://{}", self.db_file.as_ref().unwrap())
			};
			let connect_options = SqliteConnectOptions::from_str(&db_url)
				.unwrap()
				.create_if_missing(true)
				.journal_mode(SqliteJournalMode::Wal)
				.synchronous(SqliteSynchronous::Normal)
				.busy_timeout(connect_timeout);

			self.pool = Some(
				SqlitePoolOptions::new()
					.max_connections(10)
					.connect_lazy_with(connect_options)
			);

			if !DB_INITIALIZED.load(Ordering::Relaxed) {
				let start = Instant::now();
				let mig = sqlx::migrate!("../db/migrate").run(self.pool.as_ref().unwrap());
				let res = futures::executor::block_on(mig);
				log::info!("DB-Update duration: {}", start.elapsed().as_secs_f32());

				if res.is_err() {
					let err = res.err().unwrap();
					log::error!("DB-Update Error: {}", &err);
				} else {
					DB_INITIALIZED.store(true, Ordering::Relaxed);
				}
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

