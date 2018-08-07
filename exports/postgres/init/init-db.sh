#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE ROLE `echo $DOCKER_USER` WITH LOGIN PASSWORD '`echo $DOCKER_PASSWORD`';
    CREATE DATABASE idp;
    GRANT ALL PRIVILEGES ON DATABASE idp TO `echo $DOCKER_USER`;

EOSQL

psql -U dockeridp idp < dump.sql