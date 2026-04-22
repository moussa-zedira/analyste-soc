# =====================================================================
# cyberdef-down.ps1 - Arret de la stack analyste-soc
#
# N'eteint PAS le firewall (volontairement - on reste protege meme
# quand la stack est down).
# =====================================================================

$ErrorActionPreference = "Stop"
$ProjectRoot = "C:\Users\Pa\Documents\analyste-soc"

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  CYBERDEF - Stop stack" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

Set-Location $ProjectRoot
& docker compose down

Write-Host ""
Write-Host "Stack stopped. Firewall still active." -ForegroundColor Green
Write-Host ""
