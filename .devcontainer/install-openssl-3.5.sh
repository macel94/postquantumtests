#!/usr/bin/env bash
set -euo pipefail

required_version="3.5.0"
install_prefix="/usr/local/openssl-3.5"
source_version="3.5.0"
source_archive="openssl-${source_version}.tar.gz"
source_url="https://www.openssl.org/source/${source_archive}"
build_root="/tmp/openssl-${source_version}-build"

if [[ -x "${install_prefix}/bin/openssl" ]]; then
  installed_version="$(${install_prefix}/bin/openssl version | awk '{print $2}')"
  if dpkg --compare-versions "${installed_version}" ge "${required_version}"; then
    echo "OpenSSL ${installed_version} is already installed at ${install_prefix}."
    sudo sh -c "printf '%s\n' '${install_prefix}/lib' > /etc/ld.so.conf.d/openssl-3.5.conf"
    sudo ldconfig
    exit 0
  fi
fi

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  build-essential \
  ca-certificates \
  curl \
  perl \
  pkg-config

rm -rf "${build_root}"
mkdir -p "${build_root}"
cd "${build_root}"

curl -fsSLO "${source_url}"
tar -xzf "${source_archive}"
cd "openssl-${source_version}"

./Configure linux-x86_64 shared --prefix="${install_prefix}" --openssldir="${install_prefix}/ssl" --libdir=lib
make -j"$(nproc)"
sudo make install_sw

sudo sh -c "printf '%s\n' '${install_prefix}/lib' > /etc/ld.so.conf.d/openssl-3.5.conf"
sudo ldconfig

echo "Installed OpenSSL $(${install_prefix}/bin/openssl version | awk '{print $2}') to ${install_prefix}."