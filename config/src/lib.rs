
use log::{info, warn};
use confy;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppConfig {
	pub name: String,
	pub repeat: u32,
	pub num_threads: u32,
	pub device: Option<String>,
	pub listen: Option<ConnectionStruct>,
	pub syslog: Option<ConnectionStruct>,
	pub sqlite: Option<DbStruct>,
	pub targets: Vec<DiscoverStruct>,
}

impl Default for AppConfig {
	fn default() -> Self {
		AppConfig {
			name: String::from("LocalNet"),
			repeat: 0,
			num_threads: 10,
			device: None,
			listen: Default::default(),
			syslog: Default::default(),
			sqlite: Default::default(),
			targets: vec![],
		}
	}
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DbStruct {
	pub file: String,
	pub url: String,
}
impl Default for DbStruct {
	fn default() -> Self {
		DbStruct{
			file: "".to_string(),
			url: "".to_string(),
		}
	}
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiscoverStruct {
	pub extended: Option<bool>,
	pub max_hops: Option<u16>,
	pub target: Option<ConnectionStruct>,
}
impl Default for DiscoverStruct {
	fn default() -> Self {
		DiscoverStruct {
			extended: None,
			max_hops: None,
			target: None,
		}
	}
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum NetworkProtocol {
	TCP,
	UDP,
	ICMP,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConnectionStruct {
	pub ip: Option<String>,
	pub mask: Option<u8>,
	pub port: Option<u16>,
	pub protocol: Option<NetworkProtocol>,
}
impl Default for ConnectionStruct {
	fn default() -> Self {
		ConnectionStruct {
			ip: None,
			mask: None,
			port: None,
			protocol: None,
		}
	}
}

pub fn get(name: &String) -> AppConfig {
	info!("Loading configuration {:?}", name);
	let cfg: AppConfig = match confy::load(name.as_str()) {
		Ok(v) => v,
		Err(e) => {
			warn!("No configuration found for {:?}: {:?}", name, e);
			Default::default()
		}
	};
	return cfg;
}

pub fn save(name: &String, conf: &AppConfig) {
	match confy::store(name.as_str(), conf) {
		Ok(_) => {},
		Err(e) => warn!("Could not save configuration {:?}: {:?}", name, e)
	}
}
