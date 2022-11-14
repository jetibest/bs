#!/bin/sh

npm install 'ws' 'websocketstream' '@peculiar/webcrypto' 'node-abort-controller'

if [ ! -e tls/key.pem ]
then
	# ensure tls-directory
	mkdir tls 2>/dev/null
	
	# Use this as local SSL certificate for HTTPS requests between this server and HA-proxy of the hosting party
	cd tls && openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem
fi
