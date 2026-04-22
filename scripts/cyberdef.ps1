# =====================================================================
# cyberdef.ps1 - Lancement hardening + stack analyste-soc
#
# Actions :
#   1. Auto-elevation UAC si non admin
#   2. Active le firewall Windows (Domain/Private/Public)
#   3. Kill sliver-server.exe daemon natif (doublon du container)
#   4. docker compose up -d --build
#   5. Verifie qu'aucun port projet n'ecoute sur 0.0.0.0
#   6. Rapport stealth final
# =====================================================================

$ErrorActionPreference = "Stop"
$ProjectRoot = "C:\Users\Pa\Documents\analyste-soc"

# --- 1. Auto-elevation ---
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[cyberdef] Elevation admin requise (UAC)..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File",$PSCommandPath
    exit 0
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  CYBERDEF - Stealth launch" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# --- 2. Firewall Windows ---
Write-Host "[1/5] Firewall Windows..." -ForegroundColor Green
try {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction Stop
    $profiles = Get-NetFirewallProfile | Select-Object Name,Enabled
    foreach ($p in $profiles) {
        $color = if ($p.Enabled) { "Green" } else { "Red" }
        Write-Host "      $($p.Name) : $($p.Enabled)" -ForegroundColor $color
    }
} catch {
    Write-Host "      ERREUR firewall : $_" -ForegroundColor Red
}

# --- 3. Kill Sliver natif ---
Write-Host ""
Write-Host "[2/5] Sliver daemon natif..." -ForegroundColor Green
$sliverProcs = Get-Process -Name "sliver-server" -ErrorAction SilentlyContinue
if ($sliverProcs) {
    foreach ($p in $sliverProcs) {
        Write-Host "      Kill PID $($p.Id) ($($p.Path))" -ForegroundColor Yellow
        Stop-Process -Id $p.Id -Force
    }
    Start-Sleep -Seconds 1
} else {
    Write-Host "      Aucune instance native - OK" -ForegroundColor Gray
}

# --- 4. Docker Compose ---
Write-Host ""
Write-Host "[3/5] Docker Compose up..." -ForegroundColor Green
Set-Location $ProjectRoot
& docker compose up -d --build
if ($LASTEXITCODE -ne 0) {
    Write-Host "      ERREUR docker compose (exit $LASTEXITCODE)" -ForegroundColor Red
    Read-Host "Appuie sur Entree pour fermer"
    exit 1
}

# --- 5. Audit exposition ---
Write-Host ""
Write-Host "[4/5] Audit exposition publique..." -ForegroundColor Green
Start-Sleep -Seconds 3

$projectPorts = @(8000, 3001, 5432, 6379, 514, 1514, 31337, 3333)
$leaks = @()

foreach ($port in $projectPorts) {
    $listening = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    foreach ($c in $listening) {
        if ($c.LocalAddress -eq "0.0.0.0" -or $c.LocalAddress -eq "::") {
            $leaks += [PSCustomObject]@{ Port = $port; Address = $c.LocalAddress; PID = $c.OwningProcess }
        }
    }
}

if ($leaks.Count -eq 0) {
    Write-Host "      Aucun port projet expose publiquement - OK" -ForegroundColor Green
} else {
    Write-Host "      FUITE DETECTEE :" -ForegroundColor Red
    $leaks | Format-Table -AutoSize
}

# --- 6. Rapport final ---
Write-Host ""
Write-Host "[5/5] Rapport stealth" -ForegroundColor Green
Write-Host "      API     : http://127.0.0.1:8000  (docs caches)"
Write-Host "      Web     : http://127.0.0.1:3001"
Write-Host "      Syslog  : 127.0.0.1:514 / 1514"
Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
if ($leaks.Count -eq 0) {
    Write-Host "  STEALTH MODE : ACTIF" -ForegroundColor Green
} else {
    Write-Host "  STEALTH MODE : PARTIEL (voir fuites)" -ForegroundColor Yellow
}
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Read-Host "Appuie sur Entree pour fermer"
