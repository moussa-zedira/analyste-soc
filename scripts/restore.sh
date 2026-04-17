#!/usr/bin/env bash
# Restore Postgres depuis un dump custom (-Fc) genere par backup.sh.
#
# Usage :
#   ./scripts/restore.sh ./backups/cyberdef-node-20260417T120000Z.dump
#
# IMPORTANT : drop + recreate le schema public. Confirme avant d'executer.

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: $0 <dump-file>"
    exit 64
fi

DUMP="$1"
SERVICE="${PG_SERVICE:-postgres}"

if [ ! -f "$DUMP" ]; then
    echo "[restore] dump file not found: $DUMP"
    exit 1
fi

echo "[restore] target dump : $DUMP"
echo "[restore] WARNING : drops and recreates the public schema."
read -r -p "Continue ? (yes/NO) " ans
[ "$ans" = "yes" ] || { echo "aborted"; exit 1; }

echo "[restore] dropping schema public..."
docker compose exec -T "$SERVICE" \
    sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"'

echo "[restore] streaming dump into pg_restore..."
docker compose exec -T "$SERVICE" \
    sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --no-acl --clean --if-exists' \
    < "$DUMP"

echo "[restore] OK"
echo "[restore] re-run alembic upgrade head if schema changed since dump"
