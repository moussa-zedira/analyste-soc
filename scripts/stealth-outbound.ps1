# =====================================================================
# stealth-outbound.ps1 - Stealth cote sortant (leaks DNS/IPv6/MAC/VPN)
#
# Utilisation :
#   stealth-outbound.ps1 audit                Diagnostic toutes les fuites
#   stealth-outbound.ps1 test                 Tests live (DNS resolver, IPv6)
#   stealth-outbound.ps1 ipv6 off|on          Bloque/restore IPv6 sortant
#   stealth-outbound.ps1 mac random|static    MAC randomization Wi-Fi
#   stealth-outbound.ps1 killswitch install <VpnIfName>
#                                              Firewall rule : tout ce qui
#                                              sort par autre chose que le
#                                              VPN est bloque.
#   stealth-outbound.ps1 killswitch remove    Retire le kill-switch
#   stealth-outbound.ps1 killswitch status    Etat des regles kill-switch
#
# Complemente stealth-host.ps1 (entrant) : ce script s'occupe du sortant
# qui est le vrai trou d'invisibilite.
# =====================================================================

param(
    [Parameter(Position=0, Mandatory=$true)]
    [ValidateSet("audit","test","ipv6","mac","killswitch","help")]
    [string]$Action,

    [Parameter(Position=1)]
    [string]$Arg1,

    [Parameter(Position=2)]
    [string]$Arg2
)

$ErrorActionPreference = "Stop"
$KS_PREFIX = "Stealth-KS-"   # prefix commun aux regles kill-switch

function Require-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "[stealth-outbound] Elevation admin requise (UAC)..." -ForegroundColor Yellow
        $args = @("-NoProfile","-ExecutionPolicy","Bypass","-File",$PSCommandPath,$script:Action)
        if ($script:Arg1) { $args += $script:Arg1 }
        if ($script:Arg2) { $args += $script:Arg2 }
        Start-Process powershell.exe -Verb RunAs -ArgumentList $args
        exit 0
    }
}

function Get-ActiveAdapter {
    $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric | Select-Object -First 1
    if (-not $defaultRoute) { return $null }
    return Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex
}

# ---------------------------------------------------------------------
# AUDIT : diagnostic fuites sans rien modifier
# ---------------------------------------------------------------------
function Invoke-Audit {
    Write-Host ""
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "  STEALTH OUTBOUND - Audit" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host ""

    $adapter = Get-ActiveAdapter
    if (-not $adapter) {
        Write-Host "Aucune interface active." -ForegroundColor Red
        return
    }
    Write-Host "Interface active  : $($adapter.Name) ($($adapter.InterfaceDescription))" -ForegroundColor Gray
    Write-Host ""

    # IPv6 enable-state sur l'interface
    $binding = Get-NetAdapterBinding -InterfaceAlias $adapter.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
    $ipv6On = $binding.Enabled
    $color = if ($ipv6On) { "Yellow" } else { "Green" }
    $label = if ($ipv6On) { "ACTIF (fuite possible si VPN IPv4-only)" } else { "desactive" }
    Write-Host "IPv6              : $label" -ForegroundColor $color

    # MAC randomization Wi-Fi (si applicable)
    if ($adapter.InterfaceDescription -match "Wireless|Wi-?Fi|802\.11") {
        $macRand = Get-NetAdapterAdvancedProperty -Name $adapter.Name `
            -RegistryKeyword "NetworkAddress" -ErrorAction SilentlyContinue
        if ($macRand -and $macRand.RegistryValue) {
            Write-Host "MAC randomization : static MAC force (RegistryValue set)" -ForegroundColor Yellow
        } else {
            Write-Host "MAC randomization : pilote par Windows (check Settings > Wi-Fi)" -ForegroundColor Gray
        }
    }

    # DNS actuels
    $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4
    Write-Host "DNS configures    : $($dns.ServerAddresses -join ', ')" -ForegroundColor Gray

    # Kill-switch installe ?
    $ksRules = @(Get-NetFirewallRule -DisplayName "$KS_PREFIX*" -ErrorAction SilentlyContinue)
    if ($ksRules.Count -gt 0) {
        $enabled = @($ksRules | Where-Object { $_.Enabled -eq $true }).Count
        Write-Host "Kill-switch VPN   : INSTALLE ($enabled/$($ksRules.Count) regles actives)" -ForegroundColor Green
    } else {
        Write-Host "Kill-switch VPN   : absent" -ForegroundColor Yellow
    }

    # Profil firewall (lecture seule)
    $profile = Get-NetConnectionProfile -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue
    Write-Host "Profil firewall   : $($profile.NetworkCategory)" -ForegroundColor Gray

    # IP publique (si online)
    try {
        $pub = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -TimeoutSec 5 -ErrorAction Stop).ip
        Write-Host "IP publique vue   : $pub" -ForegroundColor Gray
    } catch {
        Write-Host "IP publique vue   : n/a (offline ?)" -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "Recommandations :"
    if ($ipv6On) {
        Write-Host "  - 'stealth-outbound ipv6 off' si tu vas utiliser un VPN IPv4-only"
    }
    if ($ksRules.Count -eq 0) {
        Write-Host "  - Active un VPN puis 'stealth-outbound killswitch install <VpnIfName>'"
    }
    Write-Host "  - 'stealth-outbound test' pour un test live DNS + IPv6"
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host ""
}

# ---------------------------------------------------------------------
# TEST : tests live DNS et IPv6 leak
# ---------------------------------------------------------------------
function Invoke-Test {
    Write-Host ""
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host "  STEALTH OUTBOUND - Tests live" -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host ""

    # DNS resolver utilise
    try {
        $res = Resolve-DnsName -Name "whoami.akamai.net" -Type TXT -ErrorAction Stop
        $txt = ($res | Where-Object { $_.Type -eq "TXT" }).Strings
        if ($txt) {
            Write-Host "DNS resolver vu   : $txt" -ForegroundColor Gray
        }
    } catch {
        Write-Host "DNS test          : echec ($_)" -ForegroundColor Red
    }

    # IPv4 vs IPv6 public
    try {
        $v4 = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -TimeoutSec 5).ip
        Write-Host "IPv4 publique     : $v4" -ForegroundColor Gray
    } catch {
        Write-Host "IPv4 publique     : n/a" -ForegroundColor Gray
    }

    try {
        $v6 = (Invoke-RestMethod -Uri "https://api64.ipify.org?format=json" -TimeoutSec 5).ip
        if ($v6 -match ":") {
            Write-Host "IPv6 leak         : OUI - $v6" -ForegroundColor Red
            Write-Host "                    Ton VPN fuit si il est IPv4-only." -ForegroundColor Yellow
        } else {
            Write-Host "IPv6 leak         : non (api64 a repondu en IPv4)" -ForegroundColor Green
        }
    } catch {
        Write-Host "IPv6 leak         : pas d'IPv6 sortant (OK)" -ForegroundColor Green
    }

    Write-Host ""
}

# ---------------------------------------------------------------------
# IPV6 : toggle sur l'interface active
# ---------------------------------------------------------------------
function Set-IPv6State {
    param([string]$State)
    Require-Admin

    $adapter = Get-ActiveAdapter
    if (-not $adapter) {
        Write-Host "Aucune interface active." -ForegroundColor Red
        Read-Host "Entree pour fermer" ; return
    }

    if ($State -eq "off") {
        Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6
        Write-Host "IPv6 desactive sur $($adapter.Name)." -ForegroundColor Green
    } elseif ($State -eq "on") {
        Enable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6
        Write-Host "IPv6 re-active sur $($adapter.Name)." -ForegroundColor Yellow
    } else {
        Write-Host "Usage: stealth-outbound ipv6 off|on" -ForegroundColor Red
    }
    Write-Host ""
    Read-Host "Entree pour fermer"
}

# ---------------------------------------------------------------------
# MAC : toggle randomization Wi-Fi
# ---------------------------------------------------------------------
function Set-MacRandom {
    param([string]$Mode)
    Require-Admin

    $adapter = Get-ActiveAdapter
    if (-not $adapter) { Write-Host "Aucune interface." ; return }
    if ($adapter.InterfaceDescription -notmatch "Wireless|Wi-?Fi|802\.11") {
        Write-Host "Interface active n'est pas du Wi-Fi. MAC randomization ignoree." -ForegroundColor Yellow
        Read-Host "Entree pour fermer" ; return
    }

    if ($Mode -eq "random") {
        # Generer une MAC locally-administered aleatoire (2eme nibble = 2,6,A,E)
        $bytes = 1..6 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }
        # Premier octet : set bit "locally-admin" (0x02), clear bit "multicast" (0x01)
        $bytes[0] = ($bytes[0] -band 0xFE) -bor 0x02
        $mac = ($bytes | ForEach-Object { "{0:X2}" -f $_ }) -join ""
        try {
            Set-NetAdapterAdvancedProperty -Name $adapter.Name `
                -RegistryKeyword "NetworkAddress" -RegistryValue $mac -ErrorAction Stop
            Write-Host "MAC randomisee   : $mac" -ForegroundColor Green
            Write-Host "Disable/Enable adapter pour appliquer :" -ForegroundColor Gray
            Restart-NetAdapter -Name $adapter.Name -Confirm:$false
            Write-Host "OK." -ForegroundColor Green
        } catch {
            Write-Host "ERREUR: MAC spoofing non supporte par ce driver ($_)" -ForegroundColor Red
        }
    } elseif ($Mode -eq "static") {
        try {
            Remove-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "NetworkAddress" -ErrorAction Stop
            Restart-NetAdapter -Name $adapter.Name -Confirm:$false
            Write-Host "MAC restore au default hardware." -ForegroundColor Green
        } catch {
            Write-Host "Note: pas de MAC override a retirer." -ForegroundColor Gray
        }
    } else {
        Write-Host "Usage: stealth-outbound mac random|static" -ForegroundColor Red
    }
    Read-Host "Entree pour fermer"
}

# ---------------------------------------------------------------------
# KILL-SWITCH : bloque tout ce qui ne passe pas par l'interface VPN
# ---------------------------------------------------------------------
function Install-KillSwitch {
    param([string]$VpnIfName)
    Require-Admin

    if (-not $VpnIfName) {
        Write-Host "Indique le nom de l'interface VPN (ex: OpenVPN TAP-Windows Adapter V9)." -ForegroundColor Red
        Write-Host "Liste des interfaces disponibles :" -ForegroundColor Gray
        Get-NetAdapter | Format-Table Name,Status,InterfaceDescription -AutoSize
        Read-Host "Entree pour fermer" ; return
    }

    $vpnAdapter = Get-NetAdapter -Name $VpnIfName -ErrorAction SilentlyContinue
    if (-not $vpnAdapter) {
        Write-Host "Interface '$VpnIfName' introuvable." -ForegroundColor Red
        Read-Host "Entree pour fermer" ; return
    }

    # Remove existing first
    Get-NetFirewallRule -DisplayName "$KS_PREFIX*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

    # 1. Allow loopback
    New-NetFirewallRule -DisplayName "${KS_PREFIX}Loopback-Out" `
        -Direction Outbound -Action Allow -InterfaceAlias "Loopback Pseudo-Interface 1" `
        -Enabled True -Profile Any | Out-Null

    # 2. Allow DHCP (bootstrap reseau)
    New-NetFirewallRule -DisplayName "${KS_PREFIX}DHCP-Out" `
        -Direction Outbound -Action Allow -Protocol UDP -RemotePort 67,68 `
        -Enabled True -Profile Any | Out-Null

    # 3. Allow VPN server reachability (tous protocoles sur interface physique,
    #    mais uniquement vers les IP necessaires pour monter le tunnel)
    #    Pragmatique : on laisse tout sortir EN UDP/TCP vers n'importe quelle
    #    IP mais uniquement pour initier le VPN. L'utilisateur peut raffiner
    #    avec -RemoteAddress <ip-vpn-server>.
    New-NetFirewallRule -DisplayName "${KS_PREFIX}VPN-Tunnel-Out" `
        -Direction Outbound -Action Allow -InterfaceAlias $VpnIfName `
        -Enabled True -Profile Any | Out-Null

    # 4. Block TOUT le reste en sortie
    New-NetFirewallRule -DisplayName "${KS_PREFIX}Block-All-Out" `
        -Direction Outbound -Action Block `
        -Enabled True -Profile Any | Out-Null

    Write-Host ""
    Write-Host "Kill-switch INSTALLE." -ForegroundColor Green
    Write-Host "Si le VPN '$VpnIfName' tombe, tout trafic sortant est bloque." -ForegroundColor Green
    Write-Host "Pour desinstaller : stealth-outbound killswitch remove" -ForegroundColor Gray
    Write-Host ""
    Read-Host "Entree pour fermer"
}

function Remove-KillSwitch {
    Require-Admin
    $rules = @(Get-NetFirewallRule -DisplayName "$KS_PREFIX*" -ErrorAction SilentlyContinue)
    if ($rules.Count -eq 0) {
        Write-Host "Pas de kill-switch installe." -ForegroundColor Gray
    } else {
        $rules | Remove-NetFirewallRule
        Write-Host "Kill-switch retire ($($rules.Count) regles supprimees)." -ForegroundColor Green
    }
    Read-Host "Entree pour fermer"
}

function Show-KillSwitchStatus {
    $rules = @(Get-NetFirewallRule -DisplayName "$KS_PREFIX*" -ErrorAction SilentlyContinue)
    if ($rules.Count -eq 0) {
        Write-Host "Kill-switch : ABSENT" -ForegroundColor Yellow
    } else {
        Write-Host "Kill-switch : INSTALLE ($($rules.Count) regles)" -ForegroundColor Green
        $rules | Format-Table DisplayName,Direction,Action,Enabled -AutoSize
    }
}

# ---------------------------------------------------------------------
# DISPATCH
# ---------------------------------------------------------------------
switch ($Action) {
    "audit"      { Invoke-Audit }
    "test"       { Invoke-Test }
    "ipv6"       { Set-IPv6State -State $Arg1 }
    "mac"        { Set-MacRandom -Mode $Arg1 }
    "killswitch" {
        switch ($Arg1) {
            "install" { Install-KillSwitch -VpnIfName $Arg2 }
            "remove"  { Remove-KillSwitch }
            "status"  { Show-KillSwitchStatus }
            default   {
                Write-Host "Usage: stealth-outbound killswitch install <VpnIfName>|remove|status"
            }
        }
    }
    "help" {
        Write-Host ""
        Write-Host "stealth-outbound.ps1 - stealth cote sortant"
        Write-Host ""
        Write-Host "  audit                           Diagnostic toutes fuites"
        Write-Host "  test                            Tests live DNS + IPv6"
        Write-Host "  ipv6 off|on                     Toggle IPv6 interface"
        Write-Host "  mac random|static               MAC spoofing Wi-Fi"
        Write-Host "  killswitch install <VpnIfName>  Pose le kill-switch"
        Write-Host "  killswitch remove               Retire le kill-switch"
        Write-Host "  killswitch status               Etat kill-switch"
        Write-Host ""
    }
}
