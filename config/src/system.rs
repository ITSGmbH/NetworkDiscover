use serde::{Serialize, Deserialize};
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;

const DEFAULT_CONF_INTERFACE: &str = "end0";
const DEFAULT_CONF_FILE_WPA_SUPPLICANT: &str = "/etc/wpa_supplicant/wpa_supplicant.conf";
const DEFAULT_CONF_FILE_INTERFACES: &str = "/etc/network/interfaces.d/interface";
const DEFAULT_CONF_FILE_DHCPCD: &str = "/etc/dhcpcd.conf";

const NWD_SYSTEM_CONFIG: &str = "NWD_SYSTEM_CONFIG";
const NWD_DHCPCD_CONFIG: &str = "NWD_DHCPCD_CONFIG";
const NWD_CONFIGURE_INTERFACE: &str = "NWD_CONFIGURE_INTERFACE";
const NWD_WPA_SUPPLICANT_FILE: &str = "NWD_WPA_SUPPLICANT_FILE";
const NWD_INTERFACES_FILE: &str = "NWD_INTERFACES_FILE";
const NWD_DHCPCD_FILE: &str = "NWD_DHCPCD_FILE";

/// Check if the System-Configuration should be saved or not
fn is_system_config_enabled() -> bool {
	match env::var(NWD_SYSTEM_CONFIG) {
		Ok(val) => match val.chars().next() {
			Some(first) if first == '1' || first == 't' || first == 'T' => true,
			_ => false,
		},
		_ => true,
	}
}

/// Check if the dhcpcd.conf or NetworkManager elseway should be used
fn is_dhcpcd_conf_enabled() -> bool {
	match env::var(NWD_DHCPCD_CONFIG) {
		Ok(val) => match val.chars().next() {
			Some(first) if first == '1' || first == 't' || first == 'T' => true,
			_ => false,
		},
		_ => false,
	}
}

/// Returns the network interface defined in NWD_CONFIGURE_INTERFACE
fn get_conf_interface() -> String {
	match env::var(NWD_CONFIGURE_INTERFACE) {
		Ok(val) => val,
		_ => String::from(DEFAULT_CONF_INTERFACE),
	}
}

/// Returns the wpa_supplicant configuration file defined in NWD_WPA_SUPPLICANT_FILE
fn get_conf_wpa_file() -> String {
	match env::var(NWD_WPA_SUPPLICANT_FILE) {
		Ok(val) => val,
		_ => String::from(DEFAULT_CONF_FILE_WPA_SUPPLICANT),
	}
}

/// Returns the interface configuration file defined in NWD_INTERFACES_FILE
fn get_conf_ifaces_file() -> String {
	match env::var(NWD_INTERFACES_FILE) {
		Ok(val) => val,
		_ => String::from(DEFAULT_CONF_FILE_INTERFACES),
	}
}

/// Returns the dhcpcd configuration file defined in NWD_DHCPCD_FILE
fn get_conf_dhcpcd_file() -> String {
	match env::var(NWD_DHCPCD_FILE) {
		Ok(val) => val,
		_ => String::from(DEFAULT_CONF_FILE_DHCPCD),
	}
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SystemSettings {
	pub network: Option<SystemNetwork>,
	pub wireless: Option<SystemWireless>,
	pub system: Option<SystemConfig>,
}
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SystemNetwork {
	pub ip: Option<String>,
	pub router: Option<String>,
	pub dns: Option<String>,
}
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SystemWireless {
	pub ssid: Option<String>,
	pub psk: Option<String>,
	pub country: Option<String>,
}
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SystemConfig {
	pub restart: bool,
	pub reboot: bool,
}

/// Implementation to load the configuration
impl SystemSettings {
	/// Loads the configuration
	pub fn load() -> Self {
		Self {
			network: Some(SystemNetwork::load()),
			wireless: Some(SystemWireless::load()),
			system: None
		}
	}
}

/// The Implementation is used to create and save a confiug file
impl SystemNetwork {
	/// Loads the network configuration from the config files
	pub(crate) fn load() -> Self {
		let mut conf = Self::default();
		if is_dhcpcd_conf_enabled() {
			match File::open(get_conf_dhcpcd_file()) {
				Ok(file) => {
					let buf = BufReader::new(file);
					buf.lines().map(|val| val.unwrap_or_default()).for_each(|line| {
						if let Some(_) = line.rfind("static ip_address") {
							conf.ip = line.split('=').last().map(|val| String::from(val));
						}
						if let Some(_) = line.rfind("static routers") {
							conf.router = line.split('=').last().map(|val| String::from(val));
						}
						if let Some(_) = line.rfind("static domain_name_servers") {
							conf.dns = line.split('=').last().map(|val| String::from(val));
						}
					});
				},
				Err(err) => log::error!("{}: {}", get_conf_dhcpcd_file(), err),
			}
		} else {
			match File::open(get_conf_ifaces_file()) {
				Ok(file) => {
					let buf = BufReader::new(file);
					buf.lines().map(|val| val.unwrap_or_default()).for_each(|line| {
						if let Some(_) = line.rfind("address") {
							conf.ip = line.split(' ').last().map(|val| String::from(val).replace("/24", ""));
						}
						if let Some(_) = line.rfind("gateway") {
							conf.router = line.split(' ').last().map(|val| String::from(val));
						}
						if let Some(_) = line.rfind("dns-nameservers") {
							let servers = line.split(' ').skip(1).map(|val| String::from(val)).collect::<Vec<String>>();
							conf.dns = Some(servers.join(" "));
						}
					});
				},
				Err(err) => log::error!("{}: {}", get_conf_dhcpcd_file(), err),
			}
		}

		conf
	}

	/// Creates a new network configuration under /etc/network/interfaces.d/eth0
	/// and patches /etc/dhcpcd.conf to apply the configuration properly
	///
	/// In the end there will be two interfaces, one as DHCP and one with the
	/// given configuration (IP, Router, DNS, VLAN-ID).
	///
	/// # Configuration if dhcp-client uis used
	///
	/// * /etc/network/interfaces.d/interface
	///
	/// ```
	/// # Configuration created/managed by NetworkDiscover
	/// auto eth0.0
	/// iface eth0.0 inet dhcp
	/// vlan-raw-device eth0
	///
	/// auto eth0.1
	/// iface eth0.1 inet manual
	/// vlan-raw-device eth0
	/// ```
	///
	/// * /etc/dhcpcd.conf
	///
	/// ```
	/// # See dhcpcd.conf(5) for details.
	/// # Configuration created/managed by NetworkDiscover
	/// hostname
	/// clientid
	/// persistent
	/// option rapid_commit
	/// option ntp_servers
	/// option domain_name_servers, domain_name, domain_search, host_name
	/// option classless_static_routes
	/// option interface_mtu
	/// require dhcp_server_identifier
	/// slaac private
	///
	/// interface eth0.1
	/// static ip_address=IP-ADDRESS/24
	/// static routers=ROUTER
	/// static domain_name_servers=DNS-SERVERS
	/// ```
	///
	/// # Configuration if NetworkManager is used
	///
	/// * /etc/network/interfaces.d/interface
	///
	/// ```
	/// # Configuration created/managed by NetworkDiscover
	/// auto eth0
	/// iface eth0 inet dhcp
	///
	/// auto eth0:1
	/// iface eth0:1 inet manual
	/// 	address IP-ADDRESS/24
	/// 	gateway ROUTER
	/// 	dns-nameservers DNS-SERVERS
	/// ```
	///
	pub fn apply(&self) {
		if !is_system_config_enabled() {
			log::debug!("System-Configuration is disabled, define {}", NWD_SYSTEM_CONFIG);
			return;
		}

		match File::create(get_conf_ifaces_file()) {
			Ok(mut conf) => {
				let mut conf_string = String::from("# Configuration created/managed by NetworkDiscover\n");

				if is_dhcpcd_conf_enabled() {
					// Configure for DHCP-Client
					conf_string.push_str("auto ");
					conf_string.push_str(&get_conf_interface());
					conf_string.push_str(".0\niface ");
					conf_string.push_str(&get_conf_interface());
					conf_string.push_str(".0 inet dhcp\nvlan-raw-device ");
					conf_string.push_str(&get_conf_interface());
					conf_string.push_str("\n\n");
					conf_string.push_str("auto ");
					conf_string.push_str(&get_conf_interface());
					conf_string.push_str(".1\niface ");
					conf_string.push_str(&get_conf_interface());
					conf_string.push_str(".1 inet manual\nvlan-raw-device ");
					conf_string.push_str(&get_conf_interface());
					conf_string.push_str("\n\n");
				} else {
					// Configure NetworkManager
					conf_string.push_str("auto ");
					conf_string.push_str(&get_conf_interface());
					conf_string.push_str("\niface ");
					conf_string.push_str(&get_conf_interface());
					conf_string.push_str(" inet dhcp");
					conf_string.push_str("\n\n");
					conf_string.push_str("auto ");
					conf_string.push_str(&get_conf_interface());
					conf_string.push_str(":1\niface ");
					conf_string.push_str(&get_conf_interface());
					conf_string.push_str(":1 inet static");
					if let Some(ip) = &self.ip {
						conf_string.push_str("\n\taddress ");
						conf_string.push_str(ip);
						conf_string.push_str("/24");
					}
					if let Some(router) = &self.router {
						conf_string.push_str("\n\tgateway ");
						conf_string.push_str(router);
					}
					if let Some(dns) = &self.dns {
						let servers = String::from(dns).replace(",", " ");
						conf_string.push_str("\n\tdns-nameservers ");
						conf_string.push_str(servers.as_ref());
					}
					conf_string.push_str("\n\n");
				}

				match conf.write_all(conf_string.as_bytes()) {
					Ok(_) => log::info!("Wrote Configuration {} ({})", get_conf_ifaces_file(), NWD_INTERFACES_FILE),
					Err(err) => log::error!("{}: {}", get_conf_ifaces_file(), err),
				}
			},
			Err(err) => log::error!("{}: {}", get_conf_ifaces_file(), err),
		}

		// If no NetworkManager is used, configure the dhcp-client
		if is_dhcpcd_conf_enabled() {
			match File::create(get_conf_dhcpcd_file()) {
				Ok(mut conf) => {
					let mut conf_string = String::from("# See dhcpcd.conf(5) for details.\n# Configuration created/managed by NetworkDiscover\n");
					conf_string.push_str("hostname\nclientid\npersistent\nslaac private\n");
					conf_string.push_str("option rapid_commit\noption ntp_servers\n");
					conf_string.push_str("option domain_name_servers, domain_name, domain_search, host_name\n");
					conf_string.push_str("option classless_static_routes\noption interface_mtu\nrequire dhcp_server_identifier\n");

					if let Some(ip) = &self.ip {
						conf_string.push_str("\ninterface ");
						conf_string.push_str(&get_conf_interface());
						conf_string.push_str(".1\nstatic ip_address=");
						conf_string.push_str(ip);
						conf_string.push_str("/24");

						if let Some(router) = &self.router {
							conf_string.push_str("\nstatic routers=");
							conf_string.push_str(router);
						}
						if let Some(dns) = &self.dns {
							let servers = String::from(dns).replace(",", " ");
							conf_string.push_str("\nstatic domain_name_servers=");
							conf_string.push_str(servers.as_ref());
						}
						conf_string.push_str("\n");
					}

					match conf.write_all(conf_string.as_bytes()) {
						Ok(_) => log::info!("Wrote Configuration {} ({})", get_conf_dhcpcd_file(), NWD_DHCPCD_FILE),
						Err(err) => log::error!("{}: {}", get_conf_dhcpcd_file(), err),
					}
				},
				Err(err) => log::error!("{}: {}", get_conf_dhcpcd_file(), err),
			}
		}
	}

}

/// The Implementation is used to create and save a confiug file
impl SystemWireless {
	/// Loads the network configuration from the config files
	pub(crate) fn load() -> Self {
		let mut conf = Self::default();
		match File::open(get_conf_wpa_file()) {
			Ok(file) => {
				let buf = BufReader::new(file);
				buf.lines().map(|val| val.unwrap_or_default()).for_each(|line| {
					if let Some(_) = line.rfind("country") {
						conf.country = line.split('=').last().map(|val| String::from(val));
					}
					if let Some(_) = line.rfind("ssid") {
						conf.ssid = line.split('=').last().map(|val| String::from(val).replace("\"", ""));
					}
					if let Some(_) = line.rfind("psk") {
						conf.psk = line.split('=').last().map(|val| String::from(val).replace("\"", ""));
					}
				});
			},
			Err(err) => log::error!("{}: {}", get_conf_wpa_file(), err),
		}

		conf
	}

	/// Creates a new /etc/wpa_supplicant/wpa_supplicant.conf file
	///
	/// # Configuration
	///
	/// ```
	/// # Configuration created/managed by NetworkDiscover
	/// ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
	/// update_config=1
	/// country=COUNTRY
	///
	/// network={
	/// 	ssid="SSID"
	/// 	psk="PSK"
	/// 	key_mgmt=WPA-PSK
	/// }
	/// ```
	pub fn apply(&self) {
		if !is_system_config_enabled() {
			log::debug!("System-Configuration is disabled, define {}", NWD_SYSTEM_CONFIG);
			return;
		}

		match File::create(get_conf_wpa_file()) {
			Ok(mut conf) => {
				let mut conf_string = String::from("# Configuration created/managed by NetworkDiscover");
				conf_string.push_str("\nctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev");

				conf_string.push_str("\nupdate_config=1");
				if let Some(country) = &self.country {
					conf_string.push_str("\ncountry=");
					conf_string.push_str(country);
				}

				if let Some(ssid) = &self.ssid {
					conf_string.push_str("\nnetwork = {");
					conf_string.push_str("\n\tssid = \"");
					conf_string.push_str(ssid);
					conf_string.push_str("\"");
					conf_string.push_str("\n\tpsk = \"");
					conf_string.push_str(&self.psk.as_ref().unwrap_or(&String::from("Unknown")));
					conf_string.push_str("\"");
					conf_string.push_str("\n\tkey_mgmt = WPA-PSK");
					conf_string.push_str("\n}\n");
				}

				match conf.write_all(conf_string.as_bytes()) {
					Ok(_) => log::info!("Wrote Configuration {} ({})", get_conf_wpa_file(), NWD_WPA_SUPPLICANT_FILE),
					Err(err) => log::error!("{}: {}", get_conf_wpa_file(), err),
				}
			},
			Err(err) => log::error!("{}: {}", get_conf_wpa_file(), err),
		}
	}

}
