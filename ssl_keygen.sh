#!/bin/bash

openssl req -days 365 -new -key server.key -out server.csr -config openssl.cnf
