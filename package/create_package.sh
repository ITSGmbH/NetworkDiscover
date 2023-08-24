#!/bin/bash

echo "Prepare and Build"
CWD=`dirname $( realpath $0 )`
cd $CWD &>/dev/null

cd .. &>/dev/null
cargo clean
cargo build --release
cd - &>/dev/null

PACKAGE="network_discover"
VERSION=$( grep "^version" ../Cargo.toml | cut -d'"' -f2 )
ARCH=$( uname -m )
if [ "${ARCH::3}" == "arm" ]; then
	ARCH="armhf"
fi
ARCHIVE="${PACKAGE}-${VERSION}_${ARCH}.tar.xz"
DEBIAN="${PACKAGE}-${VERSION}_${ARCH}.deb"


### PREPARE THE PACKAGE

rm -Rf pkg &>/dev/null
mkdir -p pkg/opt/${PACKAGE}/ &>/dev/null
mkdir -p pkg/lib/systemd/system/ &>/dev/null

cp ${PACKAGE}.service pkg/lib/systemd/system/ &>/dev/null
cp ../target/release/${PACKAGE} pkg/opt/${PACKAGE}/ &>/dev/null
cp -R ../static pkg/opt/${PACKAGE}/static &>/dev/null
cp ../LICENSE pkg/opt/${PACKAGE}/ &>/dev/null
cp ../README.md pkg/opt/${PACKAGE}/ &>/dev/null
echo "${VERSION}" > pkg/opt/${PACKAGE}/VERSION

chmod +x pkg/opt/${PACKAGE}/${PACKAGE} &>/dev/null
chmod -x pkg/lib/systemd/system/${PACKAGE}.service &>/dev/null


### BASE PACKAGE

rm ${ARCHIVE} &>/dev/null
tar -cJf ${ARCHIVE} -C pkg . &>/dev/null

echo "Created $CWD/${ARCHIVE}"


### DEBIAN PACKAGE

if [ ! -f /etc/debian_version ]; then
  echo "This is not a debian based system"
  echo "A .deb can be created but with no guarantee to work properly."
  echo "It should work because there is no real linking, although..."
  echo
  echo "press CTRL+C to stop"
  echo "press [anykey] to continue"
  read
fi

rm -Rf deb &>/dev/null
mkdir -p deb &>/dev/null

$( cd pkg; find . -type f | xargs md5sum | sed 's/.\///' > ../deb/md5sums )

cat << EOF > deb/control
Package: ${PACKAGE}
Version: ${VERSION}-1
Architecture: ${ARCH}
Maintainer: Lukas LukyLuke Zurschmiede <${PACKAGE}@ranta.ch>
Depends: nmap ( >= 7.40 )
Section: net
Priority: optional
Homepage: https://github.com/ITSGmbH/NetworkDiscover
Description: Network-Discover and Asset-Scanner
 Discovers and scans networks to get an overview of all
 assets, possible vulnerabilities and NetBIOS Information.
EOF

cat << EOF > deb/copyright
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: ${PACKAGE}
Upstream-Contact: Lukas LukyLuke Zurschmiede <${PACKAGE}@ranta.ch>
Source: https://github.com/ITSGmbH/NetworkDiscover

Files: *
Copyright: 2023 Lukas LukyLuke Zurschmiede <${PACKAGE}@ranta.ch>
License: GPL-3+
 Tis package is free software; you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation; either version 3 of the License, or
 any later version.
EOF

cat << EOF > deb/changelog
${PACKAGE} (0.3.4-1)

 * Use the configured network as the main key and not the real network
 * Add a new field to the host to identify the real ip network

-- Lukas LukyLuke Zurschmiede <${PACKAGE}@ranta.ch>

${PACKAGE} (0.3.3-1)

 * Recurring Scan changed to CRON Syntax
 * UI Enhancements
 * Dynamic amount of networks in configuration UI
 * System as main menu

-- Lukas LukyLuke Zurschmiede <${PACKAGE}@ranta.ch>

${PACKAGE} (0.3.0-1)

 * UI Enhancements
 * Network-Configuration for the underlying Debian/Armbian
 * NMAP-Scripts upload
 * Windows-Scan via enum4linux-ng

-- Lukas LukyLuke Zurschmiede <${PACKAGE}@ranta.ch>

${PACKAGE} (0.2.0-1)

 * Various changes to make it usable for a daily use.

-- Lukas LukyLuke Zurschmiede <${PACKAGE}@ranta.ch>

${PACKAGE} (0.1.0-1)

 * Initial release.

-- Lukas LukyLuke Zurschmiede <${PACKAGE}@ranta.ch>
EOF

cat << EOF > deb/prerm
#!/bin/sh
set -e
invoke-rc.d ${PACKAGE} stop &>/dev/null
systemctl disable ${PACKAGE}
exit 0
EOF

cat << EOF > deb/preinst
#!/bin/sh
set -e
if [ -f /lib/systemd/system/${PACKAGE}.service ]; then
  systemctl stop ${PACKAGE}
fi
exit 0
EOF

cat << EOF > deb/postinst
setcap cap_net_bind_service,cap_net_raw,cap_net_admin+eip /opt/network_discover/network_discover
touch /opt/network_discover/config.toml

systemctl daemon-reload
systemctl enable ${PACKAGE}
systemctl start ${PACKAGE}
exit 0
EOF

cat << EOF > deb/debian-binary
2.0
EOF

chmod +x deb/prerm
chmod +x deb/preinst
chmod +x deb/postinst
tar -cJf deb/control.tar.xz -C deb control md5sums copyright prerm preinst postinst &>/dev/null
cp ${ARCHIVE} deb/data.tar.xz

rm ${DEBIAN} &>/dev/null
$( cd deb ; ar r ../${DEBIAN} debian-binary control.tar.xz data.tar.xz &>/dev/null )

echo "Created ${CWD}/${DEBIAN}"
