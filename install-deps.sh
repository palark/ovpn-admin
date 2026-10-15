#!/usr/bin/env bash
# Installs the build dependencies of build.sh (Node.js 24 + npm) on Debian/Ubuntu, e.g. in the release workflows.
# Go is expected to be installed already. No C toolchain is needed: the binary is built with CGO_ENABLED=0.
set -e

apt-get update
apt-get install -y curl ca-certificates

curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
apt-get install -y nodejs
