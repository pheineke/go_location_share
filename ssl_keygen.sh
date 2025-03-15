#!/bin/bash

# Check if server.key exists, if not, generate it
if [ ! -f server.key ]; then
  openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:2048
fi

# Now create the certificate signing request (CSR)
