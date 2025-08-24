#!/bin/bash

set -e

CERT_DIR="${CERT_DIR:-./certificates}"

echo "Generating certificates..."
mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_DIR/ca-cert.pem" ]; then
    echo "Creating new certificates..."
    
    # Generate CA private key
    openssl genrsa -out "$CERT_DIR/ca-key.pem" 2048
    
    # Generate CA certificate
    openssl req -new -x509 -key "$CERT_DIR/ca-key.pem" \
        -out "$CERT_DIR/ca-cert.pem" -days 365 \
        -subj '/CN=Test CA'
    
    # Generate server private key
    openssl genrsa -out "$CERT_DIR/server-key.pem" 2048
    
    # Generate server certificate request
    openssl req -new -key "$CERT_DIR/server-key.pem" \
        -out "$CERT_DIR/server.csr" \
        -subj '/CN=redproxy'
    
    # Generate server certificate
    openssl x509 -req -in "$CERT_DIR/server.csr" \
        -CA "$CERT_DIR/ca-cert.pem" \
        -CAkey "$CERT_DIR/ca-key.pem" \
        -CAcreateserial \
        -out "$CERT_DIR/server-cert.pem" -days 365
    
    # Generate client private key
    openssl genrsa -out "$CERT_DIR/client-key.pem" 2048
    
    # Generate client certificate request
    openssl req -new -key "$CERT_DIR/client-key.pem" \
        -out "$CERT_DIR/client.csr" \
        -subj '/CN=test-client'
    
    # Generate client certificate
    openssl x509 -req -in "$CERT_DIR/client.csr" \
        -CA "$CERT_DIR/ca-cert.pem" \
        -CAkey "$CERT_DIR/ca-key.pem" \
        -CAcreateserial \
        -out "$CERT_DIR/client-cert.pem" -days 365
    
    # Set proper permissions
    chmod 644 "$CERT_DIR"/*.pem
    
    echo "Certificates generated successfully:"
    ls -la "$CERT_DIR"/
else
    echo "Certificates already exist"
    ls -la "$CERT_DIR"/
fi