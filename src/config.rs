
use log::{info, warn};
use confy;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppConfig {
	pub name: String,
	pub device: Option<String>,
	pub listen: Option<ConnectionStruct>,
	pub syslog: Option<ConnectionStruct>,
	pub targets: Vec<DiscoverStruct>,
}

impl Default for AppConfig {
	fn default() -> Self {
		AppConfig {
			name: String::from("LocalNet"),
			device: None,
			listen: Default::default(),
			syslog: Default::default(),
			targets: vec![],
		}
	}
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiscoverStruct {
	pub targets: Option<ConnectionStruct>,
	pub extended: Option<bool>,
	pub max_hops: Option<u16>,
}
impl Default for DiscoverStruct {
	fn default() -> Self {
		DiscoverStruct {
			targets: None,
			extended: None,
			max_hops: None
		}
	}
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConnectionStruct {
	pub ip: Option<String>,
	pub port: Option<u16>,
	pub mask: Option<u8>,
}
impl Default for ConnectionStruct {
	fn default() -> Self {
		ConnectionStruct {
			ip: None,
			port: None,
			mask: None,
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
