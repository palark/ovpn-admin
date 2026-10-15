#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

image="node:24-alpine"
uid="$(id -u)"
gid="$(id -g)"

run() {
  # npm cache goes to /tmp: the host uid has no writable home in the image
  docker run --rm -u "${uid}:${gid}" -e npm_config_cache=/tmp/.npm -w /app -v "$(pwd):/app" "${image}" "$@"
}

run npm ci
run npm run build
