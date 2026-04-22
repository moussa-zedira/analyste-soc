# =====================================================================
# cyberdef-stealth.ps1 - Toggle mode invisibilite totale
#
# Utilisation :
#   cyberdef-stealth status   Montre l'etat actuel
#   cyberdef-stealth on       Force l'interface courante en Public
#   cyberdef-stealth off      Repasse l'interface courante en Private
#
# Fonctionnement :
#   - Les regles firewall Stealth-Block-* sont scopees Profile Public
#   - Windows applique automatiquement Public en Wi-Fi/cafe/4G
#   - Ce script permet de forcer Public meme sur ton reseau maison
#     (utile pendant un engagement pentest depuis chez toi)
# =====================================================================

param(
    [Parameter(Position=0)]
    [ValidateSet("status", "on", "off", "help")]
    [string]$Action = "status"
)

$ErrorActionPreference = "Stop"

function Show-Status {
    Write-Host ""
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "  CYBERDEF-STEALTH - Status" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host ""

    # Interface active
    $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
    if (-not $defaultRoute) {
        Write-Host "Aucune interface active." -ForegroundColor Red
        return
    }
    $activeIf = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex
    $profile = Get-NetConnectionProfile -InterfaceIndex $activeIf.ifIndex -ErrorAction SilentlyContinue

    Write-Host "Interface active  : $($activeIf.Name)" -ForegroundColor Gray
    Write-Host "Reseau            : $($profile.Name)" -ForegroundColor Gray

    $cat = $profile.NetworkCategory
    $stealthActive = ($cat -eq "Public")
    $color = if ($stealthActive) { "Green" } else { "Yellow" }
    Write-Host "Profil firewall   : $cat" -ForegroundColor $color

    # Regles Stealth-Block-*
    $rules = @(Get-NetFirewallRule -DisplayName "Stealth-Block-*" -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true })
    Write-Host "Regles Block      : $($rules.Count) actives" -ForegroundColor Gray

    # Firewall profiles
    Write-Host ""
    Write-Host "Firewall profiles :" -ForegroundColor Gray
    Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction | Format-Table -AutoSize

    Write-Host "=========================================" -ForegroundColor Cyan
    if ($stealthActive) {
        Write-Host "  MODE INVISIBLE : ACTIF (profil Public)" -ForegroundColor Green
    } else {
        Write-Host "  MODE NORMAL (profil $cat)" -ForegroundColor Yellow
        Write-Host "  Tape 'cyberdef-stealth on' pour forcer invisible." -ForegroundColor Gray
    }
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Require-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "[stealth] Elevation admin requise (UAC)..." -ForegroundColor Yellow
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File",$PSCommandPath,$script:Action
        exit 0
    }
}

function Set-Category {
    param([string]$Category)

    Require-Admin

    $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
    if (-not $defaultRoute) {
        Write-Host "Aucune interface active - abort." -ForegroundColor Red
        Read-Host "Entree pour fermer"
        return
    }

    $activeIf = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex
    $profile = Get-NetConnectionProfile -InterfaceIndex $activeIf.ifIndex

    Write-Host ""
    Write-Host "Interface : $($activeIf.Name)" -ForegroundColor Gray
    Write-Host "Reseau    : $($profile.Name)" -ForegroundColor Gray
    Write-Host "Avant     : $($profile.NetworkCategory)" -ForegroundColor Gray

    try {
        Set-NetConnectionProfile -InterfaceIndex $activeIf.ifIndex -NetworkCategory $Category -ErrorAction Stop
        $newProfile = Get-NetConnectionProfile -InterfaceIndex $activeIf.ifIndex
        Write-Host "Apres     : $($newProfile.NetworkCategory)" -ForegroundColor Green
    } catch {
        Write-Host "ERREUR: $_" -ForegroundColor Red
        Read-Host "Entree pour fermer"
        return
    }

    Write-Host ""
    if ($Category -eq "Public") {
        Write-Host "MODE INVISIBLE ACTIVE - aucun port joignable depuis l'exterieur." -ForegroundColor Green
    } else {
        Write-Host "MODE NORMAL - partage/cast/imprimante retrouves sur le reseau local." -ForegroundColor Green
    }
    Write-Host ""
    Read-Host "Entree pour fermer"
}

switch ($Action) {
    "status" { Show-Status }
    "on"     { Set-Category -Category "Public" }
    "off"    { Set-Category -Category "Private" }
    "help"   {
        Write-Host ""
        Write-Host "Usage: cyberdef-stealth [status|on|off|help]"
        Write-Host ""
        Write-Host "  status  Montre l'etat actuel (profil + regles)"
        Write-Host "  on      Force Public sur l'interface active = invisible"
        Write-Host "  off     Repasse Private = acces reseau local normal"
        Write-Host ""
    }
}
