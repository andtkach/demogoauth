#!/bin/bash
SERVER_ADDRESS=localhost \
SERVER_PORT=8181 \
DB_USER=root \
DB_PASSWD=mysqlrootpass \
DB_ADDR=localhost \
DB_PORT=3306 \
DB_NAME=bankdb \
go run main.go
