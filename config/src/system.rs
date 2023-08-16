use serde::{Serialize, Deserialize};
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;
use std::process::Command;

const DEFAULT_CONF_INTERFACE: &str = "end0";
const DEFAULT_CONF_FILE_WPA_SUPPLICANT: &str = "/etc/wpa_supplicant/wpa_supplicant.conf";
const DEFAULT_CONF_FILE_INTERFACES: &str = "/etc/network/interfaces.d/interface";
const DEFAULT_CONF_FILE_DHCPCD: &str = "/etc/dhcpcd.conf";
const DEFAULT_CONF_FILE_NM_WIFI: &str = "/etc/NetworkManager/system-connections/NWD-WiFi.nmconnection";
const DEFAULT_CONF_FILE_NM_LAN: &str = "/etc/NetworkManager/system-connections/NWD-LAN.nmconnection";

const NWD_SYSTEM_CONFIG: &str = "NWD_SYSTEM_CONFIG";
const NWD_DHCPCD_CONFIG: &str = "NWD_DHCPCD_CONFIG";
const NWD_CONFIGURE_INTERFACE: &str = "NWD_CONFIGURE_INTERFACE";
const NWD_WPA_SUPPLICANT_FILE: &str = "NWD_WPA_SUPPLICANT_FILE";
const NWD_INTERFACES_FILE: &str = "NWD_INTERFACES_FILE";
const NWD_DHCPCD_FILE: &str = "NWD_DHCPCD_FILE";
const NWD_NM_LAN_FILE: &str = "NWD_NM_LAN_FILE";
const NWD_NM_WIFI_FILE: &str = "NWD_NM_WIFI_FILE";

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

/// Returns the NetworkManager configuration file defined in NWD_NM_LAN_FILE
fn get_conf_nm_lan_file() -> String {
	match env::var(NWD_NM_LAN_FILE) {
		Ok(val) => val,
		_ => String::from(DEFAULT_CONF_FILE_NM_LAN),
	}
}

/// Returns the NetworkManager configuration file defined in NWD_NM_WIFI_FILE
fn get_conf_nm_wifi_file() -> String {
	match env::var(NWD_NM_WIFI_FILE) {
		Ok(val) => val,
		_ => String::from(DEFAULT_CONF_FILE_NM_WIFI),
	}
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SystemSettings {
	pub interfaces: Option<Vec<String>>,
	pub network: Option<SystemNetwork>,
	pub wireless: Option<SystemWireless>,
	pub system: Option<SystemConfig>,
}
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SystemNetwork {
	pub interface: Option<String>,
	pub ip: Option<String>,
	pub router: Option<String>,
	pub dns: Option<String>,
}
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SystemWireless {
	pub interface: Option<String>,
	pub ssid: Option<String>,
	pub psk: Option<String>,
	pub country: Option<String>,
}
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SystemConfig {
	pub reload_network: bool,
	pub restart: bool,
	pub reboot: bool,
	pub shutdown: bool,
}

/// Implementation to load the configuration
impl SystemSettings {
	/// Loads the configuration
	pub fn load() -> Self {
		Self {
			interfaces: Some(Self::load_interfaces()),
			network: Some(SystemNetwork::load()),
			wireless: Some(SystemWireless::load()),
			system: None
		}
	}

	/// Reboot the system
	pub fn reboot() {
		if !is_system_config_enabled() {
			log::debug!("System-Configuration is disabled, define {}", NWD_SYSTEM_CONFIG);
			return;
		}
		let mut cmd = Command::new("sudo");
		cmd.arg("shutdown")
			.arg("-r")
			.arg("now");
		log::trace!("[main] Command: {:?}", cmd);
		let _ = cmd.output();
	}

	/// Shutdown the system
	pub fn shutdown() {
		if !is_system_config_enabled() {
			log::debug!("System-Configuration is disabled, define {}", NWD_SYSTEM_CONFIG);
			return;
		}
		let mut cmd = Command::new("sudo");
		cmd.arg("shutdown")
			.arg("now");
		log::trace!("[main] Command: {:?}", cmd);
		let _ = cmd.output();
	}

	/// Reload the network
	pub fn reload() {
		if !is_system_config_enabled() {
			log::debug!("System-Configuration is disabled, define {}", NWD_SYSTEM_CONFIG);
			return;
		}
		if is_dhcpcd_conf_enabled() {
			let mut cmd = Command::new("sudo");
			cmd.arg("systemctl")
				.arg("restart")
				.arg("networking");
			log::trace!("[main] Command: {:?}", cmd);
			let _ = cmd.output();

		} else {
			let mut cmd = Command::new("sudo");
			cmd.arg("systemctl")
				.arg("restart")
				.arg("NetworkManager");
			log::trace!("[main] Command: {:?}", cmd);
			let _ = cmd.output();

			let mut cmd = Command::new("sudo");
			cmd.arg("nmcli")
				.arg("con")
				.arg("up")
				.arg("NWD-LAN");
			log::trace!("[main] Command: {:?}", cmd);
			let _ = cmd.output();

			let mut cmd = Command::new("sudo");
			cmd.arg("nmcli")
				.arg("con")
				.arg("up")
				.arg("NWD-WiFi");
			log::trace!("[main] Command: {:?}", cmd);
			let _ = cmd.output();
		}
	}

	/// Get a list of all network interfaces
	fn load_interfaces() -> Vec<String> {
		let mut list = vec![];
		let mut cmd = Command::new("ip");
		cmd.arg("link")
			.arg("show");
		log::trace!("[main] Command: {:?}", cmd);

		if let Ok(output) = cmd.output() {
			let lines = String::from_utf8(output.stdout).unwrap();
			for line in lines.lines() {
				let parts = line.trim().split(": ").collect::<Vec<&str>>();
				if parts.len() > 2 {
					list.push(String::from(*parts.get(1).unwrap_or(&&"")));
				}
			}
		}
		list
	}
}

/// The Implementation is used to create and save a confiug file
impl SystemNetwork {
	/// Loads the network configuration from the config files
	pub(crate) fn load() -> Self {
		match is_dhcpcd_conf_enabled() {
			true => Self::load_dhcpcd(),
			false => Self::load_network_manager(),
		}
	}

	/// Load NetworkManager specific data
	fn load_network_manager() -> Self {
		let mut conf = Self::default();
		match File::open(get_conf_nm_lan_file()) {
			Ok(file) => {
				let buf = BufReader::new(file);
				buf.lines().map(|val| val.unwrap_or_default()).for_each(|line| {
					if let Some(_) = line.find("interface-name") {
						let values = line.split('=').skip(1).map(|val| String::from(val)).collect::<Vec<String>>();
						conf.interface = Some(values.join("="));
					}
					if let Some(_) = line.find("address1") {
						let val = line.split('=').skip(1).map(|val| String::from(val)).collect::<Vec<String>>().join(",");
						let mut val = val.split(',');
						conf.ip = match val.next() {
							Some(ip) => {
								let pos: usize = ip.find('/').unwrap_or_default();
								ip.get(..pos).map(|val| String::from(val))
							},
							_ => None,
						};
						conf.router = match val.next() {
							Some(router) => Some(String::from(router)),
							_ => None,
						};
					}
					if let Some(_) = line.rfind("dns") {
						let val = line.split('=').skip(1).map(|val| String::from(val)).collect::<Vec<String>>().join(";");
						let val = val.split(';').map(|val| String::from(val)).collect::<Vec<String>>().join(" ");
						conf.dns = Some(val);
					}
				});
			},
			Err(err) => log::error!("{}: {}", get_conf_nm_lan_file(), err),
		}
		conf
	}

	/// Load DHCPCD specific data
	fn load_dhcpcd() -> Self {
		let mut conf = Self::default();
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
	/// 	dns-nameservers DNS SERVERS
	/// ```
	///
	/// # Configuration for NetworkManager
	///
	/// ```
	/// [connection]
	/// id=NWD-LAN
	/// uuid=a414d407-9193-4ee8-8196-ab6bca788f03
	/// type=ethernet
	/// interface-name=INTERFACE
	///
	/// [ethernet]
	///
	/// [ipv6]
	/// addr-gen-mode=default
	/// method=auto
	///
	/// [proxy]
	///
	/// [ipv4]
	/// method=auto
	/// address1=IP-ADDRESS/24,ROUTER
	/// dns=DNS;SERVERS;
	/// ```
	///
	pub fn apply(&self) {
		if !is_system_config_enabled() {
			log::debug!("System-Configuration is disabled, define {}", NWD_SYSTEM_CONFIG);
			return;
		}
		match is_dhcpcd_conf_enabled() {
			true => self.apply_dhcpcd(),
			false => self.apply_network_manager(),
		}
	}

	/// Write NetworkManager LAN-Configuraiton
	fn apply_network_manager(&self) {
		let interface = match self.interface.as_ref() {
			Some(val) => String::from(val),
			None => get_conf_interface(),
		};

		match File::create(get_conf_nm_lan_file()) {
			Ok(mut conf) => {
				let mut conf_string = String::from("# Configuration created/managed by NetworkDiscover");
				conf_string.push_str("\n[connection]\nid=NWD-LAN");
				conf_string.push_str("\nuuid=a414d407-9193-4ee8-8196-ab6bca788f03");
				conf_string.push_str("\ntype=ethernet\ninterface-name=");
				conf_string.push_str(&interface);
				conf_string.push_str("\n\n[ethernet]\n\n[ipv6]\naddr-gen-mode=default\nmethod=auto\n\n[proxy]\n\n[ipv4]\nmethod=auto\n");

				if let Some(ip) = &self.ip {
					conf_string.push_str("address1=");
					conf_string.push_str(ip);
					conf_string.push_str("/24");
					if let Some(router) = &self.router {
						conf_string.push_str(",");
						conf_string.push_str(router);
					}
					conf_string.push_str("\n");
				}
				if let Some(dns) = &self.dns {
					let servers = String::from(dns).replace(",", " ").replace(" ", ";");
					conf_string.push_str("dns=");
					conf_string.push_str(servers.as_ref());
					conf_string.push_str("\n");
				}

				match conf.write_all(conf_string.as_bytes()) {
					Ok(_) => log::info!("Wrote Configuration {} ({})", get_conf_nm_lan_file(), NWD_NM_LAN_FILE),
					Err(err) => log::error!("{}: {}", get_conf_nm_lan_file(), err),
				}
			},
			Err(err) => log::error!("{}: {}", get_conf_nm_lan_file(), err),
		}
	}

	/// Write DHCPCD LAN-Configuraiton
	fn apply_dhcpcd(&self) {
		let interface = match self.interface.as_ref() {
			Some(val) => String::from(val),
			None => get_conf_interface(),
		};

		match File::create(get_conf_ifaces_file()) {
			Ok(mut conf) => {
				let mut conf_string = String::from("# Configuration created/managed by NetworkDiscover\n");
				conf_string.push_str("auto ");
				conf_string.push_str(&interface);
				conf_string.push_str(".0\niface ");
				conf_string.push_str(&interface);
				conf_string.push_str(".0 inet dhcp\nvlan-raw-device ");
				conf_string.push_str(&interface);
				conf_string.push_str("\n\n");
				conf_string.push_str("auto ");
				conf_string.push_str(&interface);
				conf_string.push_str(".1\niface ");
				conf_string.push_str(&interface);
				conf_string.push_str(".1 inet manual\nvlan-raw-device ");
				conf_string.push_str(&interface);
				conf_string.push_str("\n\n");

				match conf.write_all(conf_string.as_bytes()) {
					Ok(_) => log::info!("Wrote Configuration {} ({})", get_conf_ifaces_file(), NWD_INTERFACES_FILE),
					Err(err) => log::error!("{}: {}", get_conf_ifaces_file(), err),
				}
			},
			Err(err) => log::error!("{}: {}", get_conf_ifaces_file(), err),
		}

		match File::create(get_conf_dhcpcd_file()) {
			Ok(mut conf) => {
				let mut conf_string = String::from("# See dhcpcd.conf(5) for details.\n# Configuration created/managed by NetworkDiscover\n");
				conf_string.push_str("hostname\nclientid\npersistent\nslaac private\n");
				conf_string.push_str("option rapid_commit\noption ntp_servers\n");
				conf_string.push_str("option domain_name_servers, domain_name, domain_search, host_name\n");
				conf_string.push_str("option classless_static_routes\noption interface_mtu\nrequire dhcp_server_identifier\n");

				if let Some(ip) = &self.ip {
					conf_string.push_str("\ninterface ");
					conf_string.push_str(&interface);
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

impl SystemWireless {
	/// Loads the network configuration from the config files
	pub(crate) fn load() -> Self {
		match is_dhcpcd_conf_enabled() {
			true => Self::load_dhcpcd(),
			false => Self::load_network_manager(),
		}
	}

	/// Load NetworkManager specific data
	fn load_network_manager() -> Self {
		let mut conf = Self::default();
		match File::open(get_conf_nm_wifi_file()) {
			Ok(file) => {
				let buf = BufReader::new(file);
				buf.lines().map(|val| val.unwrap_or_default()).for_each(|line| {
					if let Some(_) = line.find("interface-name") {
						let values = line.split('=').skip(1).map(|val| String::from(val)).collect::<Vec<String>>();
						conf.interface = Some(values.join("="));
					}
					if let Some(_) = line.find("ssid") {
						let values = line.split('=').skip(1).map(|val| String::from(val)).collect::<Vec<String>>();
						conf.ssid = Some(values.join("="));
					}
					if let Some(_) = line.find("psk") {
						let values = line.split('=').skip(1).map(|val| String::from(val)).collect::<Vec<String>>();
						conf.psk = Some(values.join("="));
					}
				});
			},
			Err(err) => log::error!("{}: {}", get_conf_nm_wifi_file(), err),
		}
		conf
	}

	/// Load WPA-Supplicant specific data
	fn load_dhcpcd() -> Self {
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

	/// Configure thw WiFi
	///
	/// # Configuration: DHCPCD
	///
	/// Manages the Configuration: /etc/wpa_supplicant/wpa_supplicant.conf file
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
	///
	/// # Configuration: NetworkManager
	///
	/// Manages the Configuration: /etc/NetworkManager/system-connections/NWD-WiFi.nmconnection
	/// ```
	/// [connection]
	/// id=NWD-WiFi
	/// uuid=73f99d6a-a155-400c-a8d8-c484989526ce
	/// type=wifi
	/// interface-name=wlan0
	///
	/// [wifi]
	/// mode=infrastructure
	/// ssid=SSID
	///
	/// [wifi-security]
	/// auth-alg=open
	/// key-mgmt=wpa-psk
	/// psk=PSK
	///
	/// [ipv4]
	/// method=auto
	///
	/// [ipv6]
	/// addr-gen-mode=default
	/// method=auto
	///
	/// [proxy]
	/// ```
	///
	pub fn apply(&self) {
		if !is_system_config_enabled() {
			log::debug!("System-Configuration is disabled, define {}", NWD_SYSTEM_CONFIG);
			return;
		}
		match is_dhcpcd_conf_enabled() {
			true => self.apply_dhcpcd(),
			false => self.apply_network_manager(),
		}
	}

	/// Write NetworkManager Wifi-Configuraiton
	fn apply_network_manager(&self) {
		match File::create(get_conf_nm_wifi_file()) {
			Ok(mut conf) => {
				let mut conf_string = String::from("# Configuration created/managed by NetworkDiscover");
				conf_string.push_str("\n[connection]\nid=NWD-WiFi");
				conf_string.push_str("\nuuid=73f99d6a-a155-400c-a8d8-c484989526ce");
				conf_string.push_str("\ntype=wifi\ninterface-name=");
				if let Some(interface) = &self.interface {
					conf_string.push_str(interface);
				}
				conf_string.push_str("\n\n[wifi]\nmode=infrastructure");
				if let Some(ssid) = &self.ssid {
					conf_string.push_str("\nssid=");
					conf_string.push_str(ssid);
					conf_string.push_str("\n");
				}
				conf_string.push_str("\n[wifi-security]\nauth-alg=open\nkey-mgmt=wpa-psk");
				if let Some(psk) = &self.psk{
					conf_string.push_str("\npsk=");
					conf_string.push_str(psk);
					conf_string.push_str("\n");
				}
				conf_string.push_str("\n[ipv4]\nmethod=auto\n\n[ipv6]\naddr-gen-mode=default\nmethod=auto\n\n[proxy]\n");

				match conf.write_all(conf_string.as_bytes()) {
					Ok(_) => log::info!("Wrote Configuration {} ({})", get_conf_nm_wifi_file(), NWD_NM_WIFI_FILE),
					Err(err) => log::error!("{}: {}", get_conf_nm_wifi_file(), err),
				}
			},
			Err(err) => log::error!("{}: {}", get_conf_nm_wifi_file(), err),
		}
	}

	/// Write WPA-Supplicant Wifi-Configuraiton
	fn apply_dhcpcd(&self) {
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
