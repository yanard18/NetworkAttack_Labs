#!/bin/bash

docker exec local-dns-server-10.9.0.53 rndc dumpdb -cache
docker exec local-dns-server-10.9.0.53 cat /var/cache/bind/dump.db
