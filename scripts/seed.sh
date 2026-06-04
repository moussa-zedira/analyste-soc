#!/usr/bin/env bash
# Amorce une instance fraîche : reconstruit l'index RAG (vide au 1er boot)
# et synchronise les règles SigmaHQ. Idempotent — relançable sans risque.
set -euo pipefail

API_BASE="${API_BASE:-http://localhost:8000}"
API_KEY="${API_KEY:-dev-insecure-key}"
HDR="X-API-Key: ${API_KEY}"

echo "→ Sync SigmaHQ (${API_BASE}/sigma/sync)"
curl -fsS -X POST "${API_BASE}/sigma/sync" -H "${HDR}" -H "Content-Type: application/json" -d '{}' \
  && echo "  ✓ sigma sync OK" || { echo "  ✗ sigma sync KO"; exit 1; }

echo "→ Rebuild index RAG (${API_BASE}/ai/rag/rebuild)"
curl -fsS -X POST "${API_BASE}/ai/rag/rebuild" -H "${HDR}" -H "Content-Type: application/json" -d '{}' \
  && echo "  ✓ rag rebuild lancé (tâche de fond)" || { echo "  ✗ rag rebuild KO"; exit 1; }

echo "✓ Seed terminé."
