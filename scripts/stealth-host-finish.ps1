# =====================================================================
# stealth-host-finish.ps1 - Finition hardening firewall
#
# Desactive les regles Allow par defaut pour SMB/NetBIOS/RPC qui
# restent actives meme en profil Public, puis ajoute des regles
# Block explicites pour etre certain.
# =====================================================================

$ErrorActionPreference = "Stop"

# --- Auto-elevation UAC ---
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[finish] Elevation admin requise (UAC)..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File",$PSCommandPath
    exit 0
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  STEALTH FINISH - Block SMB/NetBIOS/RPC" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# --- 1. Disable all "File and Printer Sharing" allow rules ---
Write-Host "[1/3] Disable Partage de fichiers et imprimantes..." -ForegroundColor Green
$rules = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Where-Object {
    $_.DisplayName -match "Partage de fichiers|File and Printer|NetBIOS|Netbios"
}
foreach ($r in $rules) {
    try {
        Disable-NetFirewallRule -Name $r.Name -ErrorAction Stop
        Write-Host "      DISABLED: $($r.DisplayName)" -ForegroundColor Gray
    } catch {
        Write-Host "      ERREUR $($r.DisplayName): $_" -ForegroundColor Red
    }
}

# --- 2. Block explicites 135/137/138/139/445 sur Any profile ---
Write-Host ""
Write-Host "[2/3] Block explicite 135/137/138/139/445..." -ForegroundColor Green
$blocks = @(
    @{ Name = "Stealth-Block-RPC-135"; Port = 135; Proto = "TCP" },
    @{ Name = "Stealth-Block-NetBIOS-137"; Port = 137; Proto = "UDP" },
    @{ Name = "Stealth-Block-NetBIOS-138"; Port = 138; Proto = "UDP" },
    @{ Name = "Stealth-Block-NetBIOS-139"; Port = 139; Proto = "TCP" },
    @{ Name = "Stealth-Block-SMB-445"; Port = 445; Proto = "TCP" },
    @{ Name = "Stealth-Block-mDNS-5353"; Port = 5353; Proto = "UDP" },
    @{ Name = "Stealth-Block-SSDP-1900"; Port = 1900; Proto = "UDP" }
)
foreach ($b in $blocks) {
    try {
        # Supprime la regle si elle existe deja pour eviter les doublons
        Remove-NetFirewallRule -DisplayName $b.Name -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $b.Name -Direction Inbound -Action Block `
            -Protocol $b.Proto -LocalPort $b.Port -Profile Any `
            -Enabled True -ErrorAction Stop | Out-Null
        Write-Host "      BLOCK $($b.Proto)/$($b.Port) OK" -ForegroundColor Gray
    } catch {
        Write-Host "      ERREUR $($b.Proto)/$($b.Port): $_" -ForegroundColor Red
    }
}

# --- 3. Verification ---
Write-Host ""
Write-Host "[3/3] Verification..." -ForegroundColor Green
$remaining = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Where-Object {
    $_.DisplayName -match "Partage de fichiers|File and Printer|NetBIOS|Netbios"
}
if ($remaining) {
    Write-Host "      Regles Allow SMB/NetBIOS encore actives:" -ForegroundColor Yellow
    $remaining | Select-Object DisplayName,Profile | Format-Table -AutoSize
} else {
    Write-Host "      Zero regle Allow SMB/NetBIOS active - OK" -ForegroundColor Green
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  TERMINE" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Read-Host "Appuie sur Entree pour fermer"
