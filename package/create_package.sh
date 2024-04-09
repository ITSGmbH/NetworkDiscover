#!/bin/bash

echo "Prepare and Build"
CWD=`dirname $( realpath $0 )`
cd $CWD &>/dev/null

PACKAGE="network_discover"
VERSION=$( grep "^version" ../Cargo.toml | cut -d'"' -f2 )
ARCHLIST=( $( uname -m ) )

### If cross is available, create als an AMRv7 Package
cross version &>/dev/null
if [ $? -eq 0 -a "${ARCHLIST[0]}" == "x86_64" ]; then
  ARCHLIST+=( "armhf" )
fi


### PREPARE THE PACKAGE

rm -Rf pkg &>/dev/null
mkdir -p pkg/opt/${PACKAGE}/ &>/dev/null
mkdir -p pkg/lib/systemd/system/ &>/dev/null

cp -R ../static pkg/opt/${PACKAGE}/static &>/dev/null
cp ../LICENSE pkg/opt/${PACKAGE}/ &>/dev/null
cp ../README.md pkg/opt/${PACKAGE}/ &>/dev/null
echo "${VERSION}" > pkg/opt/${PACKAGE}/VERSION

cat << EOF > pkg/lib/systemd/system/${PACKAGE}.service
[Unit]
Description=Network-Discover by IT-S GmbH
After=network.target

[Service]
Type=simple
Restart=on-failure
WorkingDirectory=/opt/network_discover/
ExecStart=+/opt/network_discover/network_discover
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=
Environment="NWD_SYSTEM_CONFIG=1 NWD_DHCPCD_CONFIG=0"

[Install]
WantedBy=multi-user.target
EOF
chmod -x pkg/lib/systemd/system/${PACKAGE}.service &>/dev/null



### DEBIAN PACKAGE

rm -Rf deb &>/dev/null
mkdir -p deb &>/dev/null

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
${PACKAGE} (0.3.5-1)

 * Use the configured network as the main key and not the real network
 * Add a new field to the host to identify the real ip network
 * Fix problem with DHCP and extended scan

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


### Build all architectures

for ARCH in ${ARCHLIST[*]}; do
  ARCHIVE="${PACKAGE}-${VERSION}_${ARCH}.tar.xz"
  DEBIAN="${PACKAGE}-${VERSION}_${ARCH}.deb"
  rm ${ARCHIVE} &>/dev/null
  rm ${DEBIAN} &>/dev/null

  if [ "${ARCH}" == "armhf" ]; then
    TARGET="armv7-unknown-linux-gnueabihf"
    $( cd .. && rm -Rf target/release && cross build --target=${TARGET} --release )
    cp ../target/${TARGET}/release/${PACKAGE} pkg/opt/${PACKAGE}/ &>/dev/null
  else
    $( cd .. && rm -Rf target/release && cargo build --release )
    cp ../target/release/${PACKAGE} pkg/opt/${PACKAGE}/ &>/dev/null
  fi

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

  tar -cJf ${ARCHIVE} -C pkg . &>/dev/null
  echo "Created $CWD/${ARCHIVE}"

  cp ${ARCHIVE} deb/data.tar.xz
  tar -cJf deb/control.tar.xz -C deb control md5sums copyright prerm preinst postinst &>/dev/null
  $( cd deb ; ar r ../${DEBIAN} debian-binary control.tar.xz data.tar.xz &>/dev/null )

  echo "Created $CWD/${DEBIAN}"
done
