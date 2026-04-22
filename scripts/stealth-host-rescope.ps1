# =====================================================================
# stealth-host-rescope.ps1 - Scope les blocks au profil Public uniquement
#
# A la maison (profil Private/Domain) tu retrouves :
#   - Partage de fichiers SMB (NAS, autres PC)
#   - Cast AirPlay/Chromecast (mDNS)
#   - Imprimantes reseau
#   - Voisinage reseau / decouverte
#
# En Wi-Fi public (profil Public) = cafe, hotel, aeroport, 4G :
#   - Tout reste bloque comme avant (invisibilite totale)
# =====================================================================

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[rescope] Elevation admin requise (UAC)..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File",$PSCommandPath
    exit 0
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  RESCOPE - Blocks Public only" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

$rules = Get-NetFirewallRule -DisplayName "Stealth-Block-*" -ErrorAction SilentlyContinue
if (-not $rules) {
    Write-Host "Aucune regle Stealth-Block-* trouvee." -ForegroundColor Yellow
    Read-Host "Entree pour fermer"
    exit 0
}

foreach ($r in $rules) {
    try {
        Set-NetFirewallRule -Name $r.Name -Profile Public -ErrorAction Stop
        Write-Host "  $($r.DisplayName) -> Profile Public" -ForegroundColor Gray
    } catch {
        Write-Host "  ERREUR $($r.DisplayName): $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  TERMINE" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "A la maison (Private) : partage/cast/imprimante retrouves."
Write-Host "En exterieur (Public) : invisibilite totale maintenue."
Write-Host ""
Read-Host "Entree pour fermer"
