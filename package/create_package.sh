#!/bin/sh

CWD=`dirname $( realpath $0 )`
cd $CWD &>/dev/null

cd .. &>/dev/null
cargo build --release
cd - &>/dev/null

VERSION=$( grep "^version" ../Cargo.toml | cut -d' ' -f3 | tr -d '"' )

rm -Rf pkg &>/dev/null
mkdir -p pkg/opt/network_discover/ &>/dev/null
mkdir -p pkg/etc/systemd/system/ &>/dev/null

cp network_discover.service pkg/etc/systemd/system/ &>/dev/null
cp ../target/release/network_discover pkg/opt/network_discover/ &>/dev/null
cp -R ../static pkg/opt/network_discover/static &>/dev/null
cp ../LICENSE pkg/opt/network_discover/ &>/dev/null
cp ../README.md pkg/opt/network_discover/ &>/dev/null

chmod +x pkg/opt/network_discover/network_discover &>/dev/null
chmod +x pkg/etc/systemd/system/network_discover.service &>/dev/null

ARCHIVE="network_discover-${VERSION}.tar.xz"
rm ${ARCHIVE} &>/dev/null
tar -cJf $ARCHIVE -C pkg . &>/dev/null

echo "Created $CWD/$ARCHIVE"
