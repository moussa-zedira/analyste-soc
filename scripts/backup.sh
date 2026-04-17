#!/usr/bin/env bash
# Backup Postgres en format custom (-Fc) — compresse, restaurable selectivement.
#
# Usage :
#   ./scripts/backup.sh                  # vers ./backups/
#   BACKUP_DIR=/var/backups ./scripts/backup.sh
#
# Recupere automatiquement les credentials depuis le service postgres du compose.

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
SERVICE="${PG_SERVICE:-postgres}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"

mkdir -p "$BACKUP_DIR"

TS=$(date -u +%Y%m%dT%H%M%SZ)
HOST=$(hostname -s 2>/dev/null || echo "node")
OUT="${BACKUP_DIR}/cyberdef-${HOST}-${TS}.dump"

echo "[backup] dumping postgres into ${OUT}"

# pg_dump dans le container (evite besoin de psql client local)
docker compose exec -T "$SERVICE" \
    sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc --no-owner --no-acl' \
    > "$OUT"

SIZE=$(du -h "$OUT" | cut -f1)
echo "[backup] OK : $OUT ($SIZE)"

# Rotation : supprime les dumps plus vieux que RETENTION_DAYS
if command -v find >/dev/null 2>&1; then
    DELETED=$(find "$BACKUP_DIR" -name 'cyberdef-*.dump' -mtime +"$RETENTION_DAYS" -delete -print | wc -l)
    if [ "$DELETED" -gt 0 ]; then
        echo "[backup] rotated $DELETED old dump(s) older than $RETENTION_DAYS days"
    fi
fi
