# Télécharge MaxMind GeoLite2-City.mmdb dans le dossier cible.
# Nécessite la variable d'env MAXMIND_LICENSE_KEY (gratuite sur maxmind.com).
[CmdletBinding()]
param(
    [string]$DestDir = $(if ($env:GEOIP_DEST_DIR) { $env:GEOIP_DEST_DIR } else { "C:\data\geoip" })
)

$ErrorActionPreference = "Stop"

if (-not $env:MAXMIND_LICENSE_KEY) {
    Write-Host "GeoIP DB non disponible -- set MAXMIND_LICENSE_KEY (https://www.maxmind.com/en/geolite2/signup)"
    exit 1
}

if (-not (Test-Path $DestDir)) {
    New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("geolite_" + [Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    $url = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=$($env:MAXMIND_LICENSE_KEY)&suffix=tar.gz"
    $archive = Join-Path $tmp "geolite.tar.gz"

    Write-Host "[geolite] Downloading GeoLite2-City..."
    Invoke-WebRequest -Uri $url -OutFile $archive -UseBasicParsing

    Write-Host "[geolite] Extracting..."
    tar -xzf $archive -C $tmp
    if ($LASTEXITCODE -ne 0) {
        throw "tar failed (code $LASTEXITCODE) — install bsdtar/git-tar"
    }

    $mmdb = Get-ChildItem -Path $tmp -Recurse -Filter 'GeoLite2-City.mmdb' | Select-Object -First 1
    if (-not $mmdb) {
        throw "GeoLite2-City.mmdb not found in archive"
    }

    $dest = Join-Path $DestDir 'GeoLite2-City.mmdb'
    Move-Item -Force -Path $mmdb.FullName -Destination $dest
    Write-Host "[geolite] Installed at $dest"
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
