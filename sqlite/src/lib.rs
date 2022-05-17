
use sqlx::{
	sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
	Pool, Sqlite,
};
use std::time::{Duration, Instant};
use std::{fs, str::FromStr};

use config::AppConfig;

pub struct Database {
	pub(crate) db_file: String,
	pub(crate) db_url: Option<String>,
	pool: Option<Pool<Sqlite>>,
}

pub fn new(conf: &AppConfig) -> Database {
	let db_conf = conf.sqlite.as_ref();
	if db_conf.is_some() {
		Database {
			db_file: String::from(&db_conf.unwrap().file),
			db_url: if db_conf.unwrap().url.is_empty() { None } else { Some(String::from(&db_conf.unwrap().url)) },
			pool: None,
		}
	} else {
		Database {
			db_file: "scan.sqlite".to_string(),
			db_url: None,
			pool: None,
		}
	}
}

impl Database {
	pub async fn connect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
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
					.connect_with(connect_options)
					.await?
			);
		}

		let start = Instant::now();
		sqlx::migrate!("../db/migrate").run(self.pool.as_ref().unwrap()).await?;
		log::info!("DB-Update duration: {}", start.elapsed().as_secs_f32());

		Ok(())
	}

	pub async fn insert() -> Result<(), Box<dyn std::error::Error>> {

		Ok(())
	}
}

