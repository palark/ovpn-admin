#!/usr/bin/env bash
# Kept for compatibility: arm64 binaries are cross-compiled without CGO, so the dependencies are the same as for install-deps.sh
set -e

exec "$(dirname "$0")/install-deps.sh" "$@"
