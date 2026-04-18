# GOAD (Game of Active Directory) — lab AD vulnerable pour tester analyste-soc (Windows PS)
#
# Pre-requis : VMware Workstation / VirtualBox + Vagrant + Ansible (WSL).
# Ressources : ~30 Go disque, 16 Go RAM (5 VMs Windows).
#
# Usage : .\scripts\setup_goad.ps1 [-InstallDir <path>]

param(
    [string]$InstallDir = "$HOME\labs\GOAD",
    [string]$ApiUrl = $(if ($env:API_URL) { $env:API_URL } else { "http://localhost:8000" }),
    [string]$ApiKey = $(if ($env:API_KEY) { $env:API_KEY } else { "dev-insecure-key" })
)

$ErrorActionPreference = "Stop"

Write-Host "==> GOAD install dir: $InstallDir"
New-Item -ItemType Directory -Force -Path (Split-Path $InstallDir) | Out-Null

if (-not (Test-Path $InstallDir)) {
    Write-Host "==> Cloning Orange-Cyberdefense/GOAD..."
    git clone https://github.com/Orange-Cyberdefense/GOAD.git $InstallDir
} else {
    Write-Host "==> GOAD deja present, pull..."
    git -C $InstallDir pull --ff-only
}

foreach ($tool in @("vagrant")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Host "!! $tool manquant. Installe-le avant : https://www.vagrantup.com/"
        exit 1
    }
}

Write-Host ""
Write-Host "==> Pret. Commandes a lancer manuellement :"
Write-Host ""
Write-Host "  cd $InstallDir"
Write-Host "  wsl ./goad.sh -t install -l GOAD -p vmware     # ou -p virtualbox"
Write-Host ""

# Creation engagement plateforme
Write-Host "==> Creation de l'engagement 'goad-lab' sur $ApiUrl..."
$body = @{
    name = "GOAD Lab"
    client_name = "SELF / Training"
    status = "active"
    scope_targets = @("192.168.56.0/24", "192.168.57.0/24")
    excluded_targets = @()
    notes = "Lab Game of Active Directory (Orange-Cyberdefense) — training / plateforme validation."
    mitre_tactics_authorized = @("TA0001","TA0002","TA0003","TA0004","TA0005","TA0006","TA0007","TA0008","TA0009")
} | ConvertTo-Json -Depth 4

try {
    $resp = Invoke-RestMethod -Uri "$ApiUrl/redteam/engagements" `
        -Method Post `
        -Headers @{ "Content-Type" = "application/json"; "X-API-Key" = $ApiKey } `
        -Body $body
    Write-Host "==> Engagement cree : $($resp.id)"
    Write-Host "    Utilise-le dans le ChatPanel pour l'assistant pentest."
} catch {
    Write-Host "!! Creation engagement failed : $_"
    Write-Host "   Verifie que l'API tourne ($ApiUrl) et que ApiKey est bon."
}

Write-Host ""
Write-Host "==> Next steps :"
Write-Host "   1. cd $InstallDir ; wsl ./goad.sh -t install -l GOAD -p vmware"
Write-Host "   2. Dans la plateforme : POST /bloodhound/import (zip genere depuis GOAD)"
Write-Host "   3. Dans le chat : selectionner l'engagement 'GOAD Lab'"
