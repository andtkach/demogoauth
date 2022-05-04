#!/bin/bash
SERVER_ADDRESS=localhost \
SERVER_PORT=8181 \
DB_USER=root \
DB_PASSWORD=mysqlrootpass \
DB_ADDRESS=localhost \
DB_PORT=3306 \
DB_NAME=bankdb \
go run main.go
