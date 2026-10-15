#!/usr/bin/env bash
# Kept for compatibility: CGO is not used anymore, so arm64 binaries are cross-compiled by build.sh, e.g.
# GOARCH=arm64 ./build.sh
set -e

if [[ "${GOOS:-linux}" != "linux" ]] || [[ "${GOARCH}" != "arm64" ]]; then
  echo "build_arm.sh: GOOS=linux and GOARCH=arm64 are expected (32-bit arm is not supported) (got GOOS=${GOOS} GOARCH=${GOARCH})" >&2
  exit 1
fi

exec "$(dirname "$0")/build.sh" "$@"
