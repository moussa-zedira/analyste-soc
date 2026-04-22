# =====================================================================
# stealth-host.ps1 - Hardening reseau host Windows (admin requis)
#
# Actions :
#   1. Firewall ON (Domain/Private/Public) + Public = blockinboundalways
#   2. Desactive SMB1
#   3. Desactive NetBIOS sur toutes les interfaces
#   4. Active DNS over HTTPS sur Cloudflare (1.1.1.1 / 1.0.0.1)
#   5. Desactive LLMNR
#   6. Rapport final
# =====================================================================

$ErrorActionPreference = "Stop"

# --- Auto-elevation UAC ---
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[stealth-host] Elevation admin requise (UAC)..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File",$PSCommandPath
    exit 0
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  STEALTH HOST - Windows hardening" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# --- 1. Firewall Windows ---
Write-Host "[1/5] Firewall Windows..." -ForegroundColor Green
try {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
    # Public profile = block inbound always, even if rule says allow
    Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block -DefaultOutboundAction Allow -AllowInboundRules False
    Get-NetFirewallProfile | Format-Table Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules -AutoSize
} catch {
    Write-Host "      ERREUR: $_" -ForegroundColor Red
}

# --- 2. SMB1 ---
Write-Host "[2/5] SMB1 disable..." -ForegroundColor Green
try {
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($smb1 -and $smb1.State -eq "Enabled") {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
        Write-Host "      SMB1 desactive (reboot recommande)" -ForegroundColor Yellow
    } else {
        Write-Host "      SMB1 deja desactive - OK" -ForegroundColor Gray
    }
    # Server config belt + suspenders
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false -Force -ErrorAction SilentlyContinue
    Write-Host "      SMB server: SMB1 off, SMB2/3 actif" -ForegroundColor Gray
} catch {
    Write-Host "      ERREUR: $_" -ForegroundColor Red
}

# --- 3. NetBIOS off on all interfaces ---
Write-Host "[3/5] NetBIOS disable sur toutes les interfaces..." -ForegroundColor Green
try {
    $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
    $count = 0
    foreach ($a in $adapters) {
        # TcpipNetbiosOptions: 0=default, 1=enabled, 2=disabled
        $result = $a.SetTcpipNetbios(2)
        if ($result.ReturnValue -eq 0 -or $result.ReturnValue -eq 1) { $count++ }
    }
    Write-Host "      NetBIOS desactive sur $count adapters" -ForegroundColor Gray
} catch {
    Write-Host "      ERREUR: $_" -ForegroundColor Red
}

# --- 4. DNS over HTTPS (Cloudflare) ---
Write-Host "[4/5] DNS over HTTPS (Cloudflare)..." -ForegroundColor Green
try {
    # Enregistrer les templates DoH pour Cloudflare (Win11 natif)
    $dohServers = @(
        @{ IP = "1.1.1.1"; Template = "https://cloudflare-dns.com/dns-query" },
        @{ IP = "1.0.0.1"; Template = "https://cloudflare-dns.com/dns-query" },
        @{ IP = "2606:4700:4700::1111"; Template = "https://cloudflare-dns.com/dns-query" },
        @{ IP = "2606:4700:4700::1001"; Template = "https://cloudflare-dns.com/dns-query" }
    )
    foreach ($srv in $dohServers) {
        try {
            Add-DnsClientDohServerAddress -ServerAddress $srv.IP -DohTemplate $srv.Template `
                -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue | Out-Null
        } catch { }
    }

    # Appliquer aux adapters actifs (IPv4 + IPv6)
    $activeIf = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -notmatch "vEthernet|Loopback" }
    foreach ($if in $activeIf) {
        Set-DnsClientServerAddress -InterfaceIndex $if.ifIndex `
            -ServerAddresses ("1.1.1.1","1.0.0.1","2606:4700:4700::1111","2606:4700:4700::1001") `
            -ErrorAction SilentlyContinue
        Write-Host "      DNS sur $($if.Name) -> Cloudflare DoH" -ForegroundColor Gray
    }
} catch {
    Write-Host "      ERREUR: $_" -ForegroundColor Red
}

# --- 5. LLMNR off (registry) ---
Write-Host "[5/5] LLMNR disable..." -ForegroundColor Green
try {
    $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    Set-ItemProperty -Path $key -Name "EnableMulticast" -Value 0 -Type DWord -Force
    Write-Host "      LLMNR desactive" -ForegroundColor Gray
} catch {
    Write-Host "      ERREUR: $_" -ForegroundColor Red
}

# --- Rapport final ---
Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  STEALTH HOST - Termine" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Recommande : reboot pour que SMB1 soit retire totalement."
Write-Host ""
Read-Host "Appuie sur Entree pour fermer"
