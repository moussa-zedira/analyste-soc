#!/usr/bin/env bash
# Genere des certificats self-signed pour l'overlay TLS (dev/staging).
# En prod, remplacer par Let's Encrypt ou ta CA interne.

set -euo pipefail

DIR="${CERTS_DIR:-./certs}"
CN="${TLS_CN:-cyberdef.local}"
DAYS="${TLS_DAYS:-365}"

mkdir -p "$DIR"
chmod 700 "$DIR"

if [ -s "$DIR/server.crt" ] && [ -s "$DIR/server.key" ]; then
    echo "[tls] $DIR/server.{crt,key} already present (skip)"
    exit 0
fi

echo "[tls] generating self-signed cert for CN=$CN (validity=$DAYS days)"

openssl req -x509 -nodes \
    -newkey rsa:4096 \
    -keyout "$DIR/server.key" \
    -out "$DIR/server.crt" \
    -days "$DAYS" \
    -subj "/CN=$CN" \
    -addext "subjectAltName=DNS:$CN,DNS:localhost,IP:127.0.0.1"

chmod 600 "$DIR/server.key"
chmod 644 "$DIR/server.crt"
echo "[tls] OK : $DIR/server.crt + $DIR/server.key"
