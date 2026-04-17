#!/usr/bin/env bash
# Genere les secrets aleatoires pour ./secrets/*.txt.
# Utilise par l'overlay docker-compose.secrets.yml.

set -euo pipefail

DIR="${SECRETS_DIR:-./secrets}"
mkdir -p "$DIR"
chmod 700 "$DIR"

gen() {
    local name="$1"
    local len="${2:-48}"
    local path="$DIR/$name.txt"
    if [ -s "$path" ]; then
        echo "[secrets] $name already exists (skip) : $path"
        return
    fi
    python3 -c "import secrets; print(secrets.token_urlsafe($len), end='')" > "$path"
    chmod 600 "$path"
    echo "[secrets] wrote $path (len=$len)"
}

gen api_key 32
gen jwt_secret 48
gen postgres_password 24

echo
echo "[secrets] DONE — files in $DIR (mode 600)"
echo "[secrets] add $DIR/ to .gitignore !"
