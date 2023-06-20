# Installation

## Manually create a package

1. Create a package with the script `create_package.sh`
2. Copy the package `package/network_discover-x.y.z.tar.xz` to the destination
3. Unpack the package as root: `tar -xJf package/network_discover-x.y.z.tar.xz -C /`
4. Enable the service: `systemctl enable network_discover`


## Install deb

The [Releases Page](https://github.com/ITSGmbH/NetworkDiscover/releases) should contain debian packages.
Or one can be built manually with the script used in the previous section.


## Install manually

```bash
$ mkdir -p /opt/network_discover/static
$ cp network_discover /opt/network_discover/
$ cp static/* /opt/network_discover/static/
```

### System.d

```bash
$ cp network_discover.service /etc/systemd/system/
$ chmod -x /etc/systemd/system/network_discover.service
$ systemctl enable network_discover
$ systemctl start network_discover
```

## Latest Release

All Releases can be found on [Github.com](https://github.com/ITSGmbH/NetworkDiscover/releases)

### No Package-Manager

To download and install the latest release, use the following commands:

```
$ curl -s https://api.github.com/repos/ITSGmbH/NetworkDiscover/releases/latest | grep "browser_download_url.*xz" | cut -d '"' -f 4 | wget -O network_discover.tar.xz -qi -
$ sudo systemctl stop network_discover
$ sudo tar -xJf network_discover.tar.xz -C /
$ sudo systemctl start network_discover
```

### DEB-Package

To download and install the latest deb-release, use the following commands:

```
$ curl -s https://api.github.com/repos/ITSGmbH/NetworkDiscover/releases/latest | grep "browser_download_url.*deb" | cut -d '"' -f 4 | wget -O network_discover.deb -qi -
$ sudo dpkg -i network-discover.deb
```
