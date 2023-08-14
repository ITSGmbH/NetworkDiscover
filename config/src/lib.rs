pub mod system;

use log::{info, warn};
use confy;
use serde::{Serialize, Deserialize};
use std::{env, convert::From, str::FromStr};
use std::path::PathBuf;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SaveConfig {
	pub repeat: Option<u32>,
	pub num_threads: Option<u32>,
	pub device: Option<String>,
	pub script_args: Option<String>,
	pub listen: Option<ConnectionStruct>,
	pub sqlite: Option<DbStruct>,
	pub targets: Option<Vec<DiscoverStruct>>,
	pub whitelabel: Option<WhiteLabel>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppConfig {
	pub repeat: u32,
	pub num_threads: u32,
	pub device: Option<String>,
	pub script_args: Option<String>,
	pub listen: Option<ConnectionStruct>,
	pub sqlite: Option<DbStruct>,
	pub targets: Vec<DiscoverStruct>,
	pub whitelabel: Option<WhiteLabel>,
}
impl Default for AppConfig {
	fn default() -> Self {
		AppConfig {
			repeat: 0,
			num_threads: 10,
			device: None,
			script_args: None,
			listen: Default::default(),
			sqlite: Default::default(),
			targets: vec![],
			whitelabel: None,
		}
	}
}
impl From<SaveConfig> for AppConfig {
	fn from(item: SaveConfig) -> Self {
		AppConfig {
			repeat: item.repeat.unwrap_or_default(),
			num_threads: item.num_threads.unwrap_or(10),
			device: item.device,
			script_args: item.script_args,
			listen: item.listen,
			sqlite: item.sqlite,
			targets: item.targets.unwrap_or_default(),
			whitelabel: item.whitelabel,
		}
	}
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WhiteLabel {
	pub logo: Option<String>,
	pub logo_data: Option<String>,
	pub color: Option<String>,
	pub tagline: Option<String>,
	pub update_check: Option<String>,
}
impl Default for WhiteLabel {
	fn default() -> Self {
		WhiteLabel {
			logo: None,
			logo_data: None,
			color: None,
			tagline: None,
			update_check: None,
		}
	}
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DbStruct {
	pub file: Option<String>,
	pub url: Option<String>,
}
impl Default for DbStruct {
	fn default() -> Self {
		DbStruct{
			file: {
				let mut path = env::var("DATA_DIR").unwrap_or_else(|_| String::from("."));
				let path_buf = env::current_exe().unwrap_or(PathBuf::from("db"));
				let name = path_buf.file_name().unwrap_or(std::ffi::OsStr::new("db")).to_str().unwrap_or("db");
				path.push(std::path::MAIN_SEPARATOR);
				path.push_str(name);
				path.push_str(".sqlite");
				Some(path)
			},
			url: None,
		}
	}
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiscoverStruct {
	pub extended: Option<bool>,
	pub version_check: Option<bool>,
	pub target: Option<ConnectionStruct>,
	pub windows: Option<WindowsStruct>,
}
impl Default for DiscoverStruct {
	fn default() -> Self {
		DiscoverStruct {
			extended: Some(true),
			version_check: Some(true),
			target: None,
			windows: None,
		}
	}
}
impl DiscoverStruct {
	pub fn is_responsible_for(&self, ip: IpAddr) -> bool {
		if let Some(target) = &self.target {
			let shift: u32 = 32 - (target.mask.unwrap_or(0) as u32);
			return match ip {
				IpAddr::V4(ip) => {
					let network = Ipv4Addr::from_str(target.ip.as_ref().unwrap_or(&"127.0.0.1".to_string())).unwrap().octets();
					let check = ip.octets();
					let mut bin_network: u32 = ((network[0] as u32) << 24) + ((network[1] as u32) << 16) + ((network[2] as u32) << 8) + (network[3] as u32);
					let mut bin_check: u32 = ((check[0] as u32) << 24) + ((check[1] as u32) << 16) + ((check[2] as u32) << 8) + (check[3] as u32);
					bin_network = bin_network >> shift;
					bin_check = bin_check >> shift;

					bin_check == bin_network
				},
				IpAddr::V6(_ip) => { false },
			}
		}
		true
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
	pub name: Option<String>,
	pub ip: Option<String>,
	pub mask: Option<u8>,
	pub port: Option<u16>,
	pub protocol: Option<NetworkProtocol>,
}
impl Default for ConnectionStruct {
	fn default() -> Self {
		ConnectionStruct {
			name: None,
			ip: None,
			mask: None,
			port: None,
			protocol: None,
		}
	}
}
impl ConnectionStruct {
	pub fn get_network_string(&self) -> Option<String> {
		if self.ip.is_some() {
			// In case we have a ":" in the IP-Address we assume it's IPv6
			let mut ip = self.ip.as_ref().unwrap().to_string().to_owned();
			ip.push_str("/");
			ip.push_str(&self.mask.unwrap_or( if ip.contains(":") { 127 } else { 32 } ).to_string());
			Some(ip)
		} else {
			None
		}
	}
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WindowsStruct {
	pub domain: Option<String>,
	pub domain_user: Option<String>,
	pub password: Option<String>,
}
impl Default for WindowsStruct {
	fn default() -> Self {
		WindowsStruct {
			domain: None,
			domain_user: None,
			password: None,
		}
	}
}

fn get_config_file() -> PathBuf {
	let name = env::var("CONFIG_FILE").unwrap_or_else(|_| {
		let dir = env::var("DATA_DIR").unwrap_or_else(|_| String::from("./"));
		let path = PathBuf::from(dir).canonicalize().unwrap_or(PathBuf::from("/tmp"));
		let mut conf = String::from(path.to_str().unwrap());
		conf.push(std::path::MAIN_SEPARATOR);
		conf.push_str("config.toml");
		conf
	});
	[name].iter().collect()
}

pub fn get() -> AppConfig {
	let path = get_config_file();
	info!("Loading configuration {:?}", path);

	let cfg: AppConfig = match confy::load_path(&path) {
		Ok(v) => v,
		Err(e) => {
			warn!("No configuration found for {:?}: {:?}", path, e);
			Default::default()
		}
	};
	return cfg;
}

pub fn save(conf: &AppConfig) {
	let path = get_config_file();
	info!("Save configuration {:?}", path);

	match confy::store_path(&path, conf) {
		Ok(_) => {},
		Err(e) => warn!("Could not save configuration {:?}: {:?}", path, e)
	}
}
