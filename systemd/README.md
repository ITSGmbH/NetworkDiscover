# Systemd Services

The script assumes the scanner to be installed under `/opt/network_discover/`

## Install

1. Copy the two `.service` files to `/etc/systemd/system/` or to the global `/lib/systemd/system/`.
2. Make the start script executable

```
$ cp /opt/network_discover/systemd/*.service /etc/systemd/system/
$ chmod +x /opt/network_discover/systemd/network_scanner
```

## Enable and start

After enable and start the services:

```
$ systemd enable network_scanner
$ systemd enable network_scannerui

$ systemd start network_scanner
$ systemd start network_scannerui
```
