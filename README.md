# Network Discover

Network Discover is a lightweight server application which uses `ip`, `nmap` with `vulners.nse` and `traceroute` to discover all hosts in a given network and checks for vulnerabilities.

To be abe to run `nmap` with more privileges, `sudo` is used. Therefore the following file ahst to be created and the User which starts network Discovery must be in the _sudo_ group. Any other configuration is possible too.

_/etc/sudoers.d/nmap_
```
Cmnd_Alias NMAP = /usr/bin/nmap
%sudo ALL=(ALL) NOPASSWD: NMAP
```

## Features

* Discovers all running Hosts on one/multiple networks
* Creates a Network map based on traceroute
* Checks every Host for the running Operating System
* Checks every Host for open and running services
* Checks every running service for known Vulnerabilities (via vulners)
* Scans can run manually or automatically every given timespan
* Detect new Hosts based on DHCP
* CSV Export of a single scan
* PDF Reporting
* Whitelabeling
* Custom NMAP-Scripts upload
* Shows a diff between two scans
* Scan Windows Systems for NetBios and other vulnerabilities (enum4linux-ng)
* Simple Network-Configuration for debian based installation (wpa_supplicant, dhcpcd)

### Planned Features

* Colors in PDF Report (same as online)
* IPv6
* Detect new Hosts based on SLAAC messages
* SNMP information gathering and display
* Scan a host individually (predefined nmap params or individual?)
* Enterprise-Vulners API with `vulners_enterprise.nse` and a custom API-Key
* ...

### Maybe Features

* Smoke-Ping similar connectivity test
* Split it up into Server part and a library to be usable as WASM maybe
* ...

## Run

To be able to sniff the network for DHCP and other packages, the binary must run as root or have set capabilities for `net_raw` and `net_admin`:

```bash
$ sudo setcap cap_net_raw,cap_net_admin+eip target/release/network_discover
```

The following environment variables are available:

* **CONFIG_FILE** *(./config.toml)* Path and name of the config file.
* **DATA_DIR** *(./)* Path where to store the database/sqlite if not configured.
* **NWD_SYSTEM_CONFIG** *(true)* Set to true to be able to configure the network through the UI.
* **NWD_CONFIGURE_INTERFACE** *(eth0)* Network Interface to configure an additional IP.
* **NWD_INTERFACES_FILE** *(/etc/network/interfaces.d/eth0)* Network Configuration to add an additional virtual interface.
* **NWD_WPA_SUPPLICANT_FILE** *(/etc/wpa_supplicant/wpa_supplicant.conf)* WLAN-Configuration.
* **NWD_DHCPCD_FILE** *(/etc/dhcpcd.conf)* DHCPCD Configuration for IP-Configuration.

### Run it locally from source:

```bash
$ cargo run
# or
$ cargo build --release
$ target/release/network_discover
```

Check the `.cargo/config.toml` for environment variables.

### Run it in a container:

```bash
$ podman build -t its-nwd:0.0.1 -f Dockerfile .
$ podman run -v /tmp/nwd:/data  -p 9191:9090 --network podman --name its-nwd --replace localhost/its-nwd:0.0.1
```

Use the Volume */data* to persist the database.
Or configure it via *--env DATA_DIR="/some/other/path"* for the database and *--env CONFIG_FILE="/some/other/path/config.toml"* for the configuration.

### Run it on an embed device:

**For now:** Clone the repository on a RaspberryPi, BananaPi or wherever, install rust and compile it.
Then use the *package/network_discover.service* file to start it via systemd.
Add the `Environment="DATA_PATH=/data CONFIG_FILE=/data/config.toml"` to the `[Service]` section.
Build *Network Discover* via `cargo build --release` and copy the binary `target/release/network_discover` and the folder `static` to `/opt/network_discover/` or change the path in the service-file. Download the *vulners.nse* scripts from [github.com/vulnersCom/nmap-vulners/](https://github.com/vulnersCom/nmap-vulners/raw/master/vulners.nse) and install them manually in */usr/share/nmap/scripts/*.

**Future:** A special image will be provided in the releases for direct install and update.


## Configuration

The Configuration is created automaticall on first start. I is stored under `./config.toml`

```toml
name = 'LocalNet'
repeat = 0
num_threads = 10

[listen]
ip = '0.0.0.0'
mask = 32
port = 9090
protocol = 'UDP'

[[targets]]
extended = false
max_hops = 3

[targets.target]
ip = '192.168.66.0'
name = 'Local LAN'
mask = 24
port = 53
protocol = 'UDP'

[targets.target]
ip = '192.168.55.0'
name = 'Guest WLAN'
mask = 24
port = 53
protocol = 'UDP'
```

### Main Parameters

* **name** _(string)_: Name of the scanner instance
* **repeat** _(int32)_: Number of seconds to pause after a new scan starts
* **num_threads** _(int32)_: Number of Threads used to run nmap scans against found hosts

### Listen Parameters

* **ip** _(string)_: IP-Address to listen on for the Web-Interface
* **port** _(int32)_: Port on which the Webserver should listen on
* **mask** _(int32)_: _(not used)_
* **protocol** _(string)_: _(not used)_

### Targets

* **extended** _(bool)_: If false, only a simple scan is run on the targets, otherwise a full scan
* **max_hops** _(int32)_: Maximum numbers of hops to reach a target host

#### List of Targets

* **ip** _(string)_: The network address to scan
* **name** _(string)_: Name of the network
* **mask** _(int32)_: Netmask as CIDR for the above network address
* **port** _(int32)_: Port to use for check if a host is alive
* **protocol** _(string)_: Protocol (TCP, UDP) to use for check if a host is alive


