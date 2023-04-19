# Installation

## Use the package

1. Create a package with the script `create_package.sh`
2. Copy the package `package/network_discover-x.y.z.tar.xz` to the destination
3. Unpack the package as root: `tar -xJf package/network_discover-x.y.z.tar.xz -C /`
4. Enable the service: `systemctl enable network_discover`

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

