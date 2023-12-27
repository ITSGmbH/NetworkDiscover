# Network Discover

Network Discover is a lightweight server application which uses `ip`, `traceroute` and `nmap` with `vulners.nse` to discover all hosts in a given network and checks for vulnerabilities.
If you want to scan windows systems as well, `enum4linux-ng` is used.
This needs the additional packages `nmblookup`, `net`, `rpcclient` and `smbclient`.
These should be available through the package manager and a package named like `smb` or `samba`, ...


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

## Run NetworkDiscover

### Preparation

To be able to run `nmap` as a normal user, `sudo` is used.
Therefore the user has to have sudo-rights with no password, which can be achieved by the following configuration file
After add the user to the group `sudo` or use a special group like `nwd`.

_/etc/sudoers.d/nmap_
```
Cmnd_Alias NMAP = /usr/bin/nmap
%sudo ALL=(ALL) NOPASSWD: NMAP
```

If DHCP Packages should be captured, NetworkDiscover needs the two capabilities `net_raw` and `net_admin`.

```bash
$ sudo setcap cap_net_raw,cap_net_admin+eip target/release/network_discover
```

Alternatively, NetworkDiscover can be started as root, in that case no sudo and no capabilities have to be configured.
But, as always, this may cause security issues.


### Environment

The following environment variables are available:

* **CONFIG_FILE** *(./config.toml)* Path and name of the config file.
* **DATA_DIR** *(./)* Path where to store the database/sqlite if not configured.
* **NWD_SYSTEM_CONFIG** *(true)* Set to true to be able to configure the network through the UI.
* **NWD_DHCPCD_CONFIG** *(false)* Set to true to use **DHCP-Client** `/etc/dhcpcd.conf` instead of **NetworkManager** `/etc/network/interfaces.d/interface`.
* **NWD_CONFIGURE_INTERFACE** *(eth0)* Network Interface to configure an additional IP.
* **NWD_INTERFACES_FILE** *(/etc/network/interfaces.d/eth0)* Network Configuration to add an additional virtual interface.
* **NWD_WPA_SUPPLICANT_FILE** *(/etc/wpa_supplicant/wpa_supplicant.conf)* WLAN-Configuration.
* **NWD_DHCPCD_FILE** *(/etc/dhcpcd.conf)* DHCPCD Configuration for IP-Configuration.

In a default setup, there is no special configuration needed.
Allthough if you run it in a container or locally on a development machine, the ability to configure the network may be disabled or changed.


### Run it from source

Check the `.cargo/config.toml` for environment variables.

```bash
$ cargo build --release
$ target/release/network_discover
```

### Run it in a container

```bash
$ podman build -t its-nwd:0.3.0 -f Dockerfile .
$ podman run -v /tmp/nwd:/data  -p 9191:9090 --network podman --name its-nwd --replace localhost/its-nwd:0.3.0
```

Use the Volume */data* to persist the database.
Or configure it via *--env DATA_DIR="/some/other/path"* for the database and *--env CONFIG_FILE="/some/other/path/config.toml"* for the configuration.


### Run it on an embed device

* **RPI** Install the [latest RaspberryPI OS Lite](https://www.raspberrypi.com/software/) when using a RaspberryPI
   * Use the RaspberryPI Imager for the initial setup
* **BPI** Install the [latest BPI-M2 Ultra Armbian Bookworm](https://wiki.banana-pi.org/Banana_Pi_BPI-M2U#Armbian) when using a BananaPI
   * A screen and keyboard is needed for the initial start and setup

1. Configure the Raspberry Pi OS
2. Install dependencies: *nmap, enum4linux-ng, traceroute, smbclient, python3-ldap3, python3-yaml, python3-impacket*
3. Download [github.com/vulnersCom/nmap-vulners/](https://github.com/vulnersCom/nmap-vulners/raw/master/vulners.nse) and move it to */usr/share/nmap/scripts/*
4. Download and install the [latest enum4Linux-ng](https://github.com/cddmp/enum4linux-ng) and it's prerequisites
5. Download and install the [latest NetworkDiscover](https://github.com/ITSGmbH/NetworkDiscover)

#### For RaspberryPi OS

```bash
# 0. Configure RaspberryPi OS
#   > 2 Network Options -> N3 Network Interface names -> Disable: No
#   > 5 Interfacing Options -> P2 SSH -> Enable: Yes
#   > 7 Advanced Options -> A1 Expand Filesystem
#   > 8 Update
sudo raspi-config
```

#### For Armbian

```bash
# System
#   > SSH: Reconfigure SSH daemon -> Uncheck: Allow root login
# Personal
#   > Hostname -> nwd-xxx ->
# Personal: Keyboard and locales for Switzerland
#   > Keyboard -> Generic 105-key PC -> Other -> German (Switzerland) -> German (Switzerland) -> The default for the keyboard layout -> No compose key
#   > Locales -> After the Keyboard is choosen: Uncheck everything except: en_us.UTF-8
# Network
#   > IP -> end0 -> DHCP
#   > IP -> wlan0 -> DHCP
#   > WiFi -> Connect if wanted
sudo armbian-config
```

#### General for all Systems

```bash
# 1. Upgrade the system
sudo apt update
sudo apt full-upgrade

# 2. Install dependencies
sudo apt install curl wget nmap traceroute python3-ldap3 python3-yaml python3-impacket
sudo apt install smbclient samba
sudo systemctl stop smbd nmbd samba-ad-dc
sudo systemctl disable smbd nmbd samba-ad-dc

# 3. Install vulners nmap script
sudo wget https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse -O /usr/share/nmap/scripts/vulners.nse
sudo wget https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/http-vulners-regex.nse -O /usr/share/nmap/scripts/http-vulners-regex.nse

# 4. Install enum4linux-ng
sudo wget https://raw.githubusercontent.com/cddmp/enum4linux-ng/master/enum4linux-ng.py -O /usr/local/bin/enum4linux-ng
sudo chmod 0755 /usr/local/bin/enum4linux-ng

# 5. Install NetworkDiscover
curl -s https://api.github.com/repos/ITSGmbH/NetworkDiscover/releases/latest | grep "browser_download_url.*armhf.deb" | cut -d '"' -f 4 | wget -O network_discover.deb -qi -
sudo dpkg -i network_discover.deb

# 6. Clean up
rm network_discover.deb
```

## Configuration

### Network Configuration

A simple Network configuration can be done over the Web-Interface.
A Virtual Network-Interface will be added with a given IP.
The main interface will still act as a normal DHCP-Client.
With this, a NetworkDiscover can be preconfigured for a different network and placed there.

As second, the WLAN can be configured with the SSID and a PSK.
WLAN is only working as a DHCP-Client for now.

### NetworkDiscover Configuration

The Configuration is created automatically on first start and should be changed through the Web-Interface.


## Build
```
$ sudo apt install build-essential
```

Normally build with cargo:

```

$ cargo build
$ cargo build --release
```

or with Cross for a different architecture *(musl does not work because libpcap could not be found)*:

```
$ cross build --target armv7-unknown-linux-gnueabihf
$ cross build --release --target armv7-unknown-linux-gnueabihf
```
