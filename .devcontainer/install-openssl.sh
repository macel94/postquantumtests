#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <openssl-version>" >&2
  echo "Example: $0 3.5.0" >&2
  exit 64
fi

source_version="$1"

if [[ ! "$source_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9]+)*$ ]]; then
  echo "OpenSSL version must be a full source release version such as 3.5.0 or 4.0.0." >&2
  exit 64
fi

version_branch="$(awk -F. '{ print $1 "." $2 }' <<<"$source_version")"
install_prefix="${OPENSSL_INSTALL_PREFIX:-/usr/local/openssl-${version_branch}}"
source_archive="openssl-${source_version}.tar.gz"
build_root="/tmp/openssl-${source_version}-build"

if [[ -x "${install_prefix}/bin/openssl" ]]; then
  installed_version="$(${install_prefix}/bin/openssl version | awk '{print $2}')"
  if [[ "$installed_version" == "$source_version" ]]; then
    echo "OpenSSL ${installed_version} is already installed at ${install_prefix}."
    sudo sh -c "printf '%s\n' '${install_prefix}/lib' > '/etc/ld.so.conf.d/openssl-${version_branch}.conf'"
    sudo ldconfig
    "${install_prefix}/bin/openssl" version
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

rm -rf "$build_root"
mkdir -p "$build_root"
cd "$build_root"

downloaded=false
for source_url in \
  "https://openssl-library.org/source/${source_archive}" \
  "https://openssl-library.org/source/old/${version_branch}/${source_archive}" \
  "https://www.openssl.org/source/${source_archive}" \
  "https://www.openssl.org/source/old/${version_branch}/${source_archive}"; do
  if curl -fsSL --retry 3 --retry-delay 5 -o "$source_archive" "$source_url"; then
    downloaded=true
    break
  fi
done

if [[ "$downloaded" != true ]]; then
  echo "Failed to download ${source_archive}." >&2
  exit 1
fi

tar -xzf "$source_archive"
cd "openssl-${source_version}"

./Configure linux-x86_64 shared --prefix="$install_prefix" --openssldir="${install_prefix}/ssl" --libdir=lib
make -j"$(nproc)"
sudo make install_sw

sudo sh -c "printf '%s\n' '${install_prefix}/lib' > '/etc/ld.so.conf.d/openssl-${version_branch}.conf'"
sudo ldconfig

echo "Installed OpenSSL $(${install_prefix}/bin/openssl version | awk '{print $2}') to ${install_prefix}."