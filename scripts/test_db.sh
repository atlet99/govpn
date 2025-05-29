#!/bin/bash

# Create test database
psql -U postgres -c "DROP DATABASE IF EXISTS govpn_test;"
psql -U postgres -c "CREATE DATABASE govpn_test;"

# Run migrations
psql -U postgres -d govpn_test -f pkg/storage/postgres/migrations/000001_init_test.up.sql

# Run tests
go test -v ./pkg/storage/postgres/...

# Clean up
psql -U postgres -c "DROP DATABASE IF EXISTS govpn_test;" 