#!/usr/bin/env bash

# See start.sh about 'docker compose' (plugin) vs. standalone 'docker-compose'
./start.sh
docker compose -p openvpn-slave -f docker-compose-slave.yaml up -d
