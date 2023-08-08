
use chrono::Local;
use std::io::Write;
use env_logger;
use env_logger::Env;
use log::LevelFilter;

pub use log::{info, warn, debug, error, trace};

pub fn init() {
	env_logger::Builder::from_env(Env::default().default_filter_or("debug"))
		.target(env_logger::Target::Stdout)
		.format(|buf, record| {
			writeln!(buf, 
				"{} [{}] - {}",
				Local::now().format("%Y-%m-%dT%H:%M:%S"),
				record.level(),
				record.args()
			)
		})
		.filter(Some("sqlx"), LevelFilter::Error)
		.init();
}
