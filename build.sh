#!/usr/bin/env bash
# Builds the frontend and a static ovpn-admin binary (no CGO, the frontend and templates are embedded via go:embed).
# Extra arguments are passed to "go build", e.g. ./build.sh -o ovpn-admin-arm64 (with GOARCH=arm64)
set -e

cd frontend && npm ci && npm run build && cd ..

CGO_ENABLED=0 GOOS=${GOOS:-linux} GOARCH=${GOARCH:-amd64} go build -trimpath -ldflags "-s -w" "$@"
