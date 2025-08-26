#!/usr/bin/env bash

# About 'docker compose' and 'docker-compose'
# We are using Docker Compose in plugin mode with Docker. For more details, see: https://docs.docker.com/compose/install/linux/. If you need to use the standalone Docker Compose, you can modify the command `docker compose` to `docker-compose` accordingly.
docker compose -f docker-compose.yaml up -d --build
