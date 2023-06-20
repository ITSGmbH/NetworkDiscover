
use chrono::Local;
use std::io::Write;
use env_logger;
use log::LevelFilter;

pub use log::{info, warn, debug, error, trace};

pub fn init() {
	env_logger::Builder::new()
		.target(env_logger::Target::Stdout)
		.format(|buf, record| {
			writeln!(buf, 
				"{} [{}] - {}",
				Local::now().format("%Y-%m-%dT%H:%M:%S"),
				record.level(),
				record.args()
			)
		})
		.filter(None, LevelFilter::Debug)
		.filter(Some("sqlx"), LevelFilter::Error)
		.init();
}
