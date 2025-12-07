#!/bin/bash

mkdir -p certs
cd certs

# CA
openssl genrsa -out ca.key 2048
openssl req -x509 -new -key ca.key -out ca.crt -subj "/CN=MinhaCA"

# Servidor
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=ServidorChat"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# Cliente Lucas
openssl genrsa -out lucas.key 2048
openssl req -new -key lucas.key -out lucas.csr -subj "/CN=lucas"
openssl x509 -req -in lucas.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out lucas.crt
