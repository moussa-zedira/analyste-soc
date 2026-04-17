#!/usr/bin/env bash
# Télécharge MaxMind GeoLite2-City.mmdb dans /data/geoip/.
# Nécessite la variable d'env MAXMIND_LICENSE_KEY (gratuite sur maxmind.com).
set -euo pipefail

DEST_DIR="${GEOIP_DEST_DIR:-/data/geoip}"
DEST_FILE="${DEST_DIR}/GeoLite2-City.mmdb"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

if [[ -z "${MAXMIND_LICENSE_KEY:-}" ]]; then
    echo "GeoIP DB non disponible — set MAXMIND_LICENSE_KEY (https://www.maxmind.com/en/geolite2/signup)"
    exit 1
fi

mkdir -p "$DEST_DIR"

URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"

echo "[geolite] Downloading GeoLite2-City..."
curl -fsSL "$URL" -o "$TMP_DIR/geolite.tar.gz"

echo "[geolite] Extracting..."
tar -xzf "$TMP_DIR/geolite.tar.gz" -C "$TMP_DIR"

MMDB_PATH=$(find "$TMP_DIR" -name 'GeoLite2-City.mmdb' | head -n1)
if [[ -z "$MMDB_PATH" ]]; then
    echo "[geolite] ERROR: GeoLite2-City.mmdb not found in archive" >&2
    exit 2
fi

mv "$MMDB_PATH" "$DEST_FILE"
echo "[geolite] Installed at $DEST_FILE ($(du -h "$DEST_FILE" | cut -f1))"
