#!/bin/bash

openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/C=/ST=/L=/O=/OU=/CN="
