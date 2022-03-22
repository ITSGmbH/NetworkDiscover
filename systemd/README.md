# Systemd Services

The script assumes the scanner to be installed under `/opt/network_scanner/`

## Install

Copy the two `.service` files to `/etc/systemd/system/` or to the global `/lib/systemd/system/`.

```
$ cp /opt/network_scanner/systemd/*.service /etc/systemd/system/
```

## Enable and start

After enable and start the services:

```
$ systemd enable network_scanner
$ systemd enable network_scannerui

$ systemd start network_scanner
$ systemd start network_scannerui
```
