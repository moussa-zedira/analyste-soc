#!/usr/bin/env bash
# GOAD (Game of Active Directory) — lab AD vulnerable pour tester analyste-soc
# Clone GOAD + prepare Vagrantfile + cree engagement "goad-lab" par defaut.
#
# Pre-requis : VMware Workstation / VirtualBox + Vagrant + Ansible.
# Ressources : ~30 Go disque, 16 Go RAM (5 VMs Windows).
#
# Usage : bash scripts/setup_goad.sh [install_dir]
#         Defaut install_dir = ~/labs/GOAD

set -euo pipefail

INSTALL_DIR="${1:-$HOME/labs/GOAD}"
API_URL="${API_URL:-http://localhost:8000}"
API_KEY="${API_KEY:-dev-insecure-key}"

echo "==> GOAD install dir: $INSTALL_DIR"
mkdir -p "$(dirname "$INSTALL_DIR")"

# 1) Clone GOAD si pas deja fait
if [ ! -d "$INSTALL_DIR" ]; then
  echo "==> Cloning Orange-Cyberdefense/GOAD..."
  git clone https://github.com/Orange-Cyberdefense/GOAD.git "$INSTALL_DIR"
else
  echo "==> GOAD deja present, pull..."
  git -C "$INSTALL_DIR" pull --ff-only || true
fi

# 2) Verifie outils
for tool in vagrant ansible-playbook; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "!! $tool manquant. Installe-le avant : https://www.vagrantup.com/ + ansible"
    exit 1
  fi
done

# 3) Affiche les commandes lab a lancer (on ne lance pas auto — 30Go/16Go RAM)
cat <<EOF

==> Pret. Commandes a lancer manuellement :

cd "$INSTALL_DIR"

# Provider VMware Workstation (recommande, plus rapide que VirtualBox)
./goad.sh -t install -l GOAD -p vmware

# ou VirtualBox
./goad.sh -t install -l GOAD -p virtualbox

# Pour eteindre le lab :  ./goad.sh -t stop  -l GOAD
# Pour supprimer :        ./goad.sh -t destroy -l GOAD

EOF

# 4) Cree l'engagement "goad-lab" cote plateforme (scope = range GOAD 192.168.56.0/24)
echo "==> Creation de l'engagement 'goad-lab' sur $API_URL..."
ENG_PAYLOAD=$(cat <<'JSON'
{
  "name": "GOAD Lab",
  "client_name": "SELF / Training",
  "status": "active",
  "scope_targets": ["192.168.56.0/24", "192.168.57.0/24"],
  "excluded_targets": [],
  "notes": "Lab Game of Active Directory (Orange-Cyberdefense) — training / plateforme validation.",
  "mitre_tactics_authorized": ["TA0001","TA0002","TA0003","TA0004","TA0005","TA0006","TA0007","TA0008","TA0009"]
}
JSON
)

set +e
HTTP_CODE=$(curl -s -o /tmp/goad_eng.json -w "%{http_code}" \
  -X POST "$API_URL/redteam/engagements" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d "$ENG_PAYLOAD")
set -e

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
  ENG_ID=$(grep -o '"id"[[:space:]]*:[[:space:]]*"[^"]*"' /tmp/goad_eng.json | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
  echo "==> Engagement cree : $ENG_ID"
  echo "    Utilise-le dans le ChatPanel pour l'assistant pentest."
else
  echo "!! Creation engagement failed (HTTP $HTTP_CODE)."
  echo "   Verifie que l'API tourne ($API_URL) et que API_KEY est bon."
  cat /tmp/goad_eng.json 2>/dev/null || true
fi

echo ""
echo "==> Next steps :"
echo "   1. cd $INSTALL_DIR && ./goad.sh -t install -l GOAD -p vmware"
echo "   2. Dans la plateforme : POST /bloodhound/import (zip genere depuis GOAD)"
echo "   3. Dans le chat : selectionner l'engagement 'GOAD Lab'"
