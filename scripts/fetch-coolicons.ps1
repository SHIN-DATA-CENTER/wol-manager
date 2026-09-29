<#
.SYNOPSIS
  Downloads and extracts coolicons v4.1 (CC BY 4.0, by Kryston Schwarze) for building.

.DESCRIPTION
  The icons are third-party material and are never committed to this repository.
  build.rs reads them at build time from COOLICONS_DIR (default: <repo>\coolicons.v4.1).

  The official release zip is downloaded (or taken from -ZipPath), verified against a
  pinned SHA-256, extracted to a staging folder inside .cache and then moved into place.
  Running the script again is a no-op when the icons are already present.

.PARAMETER Destination
  The folder that becomes the coolicons tree (the zip's content goes directly into it, it
  is not a parent folder). Default: <repo>\coolicons.v4.1. It must not exist, be empty, or
  already be a coolicons v4.1 folder: any other existing folder is refused, never deleted.

.PARAMETER ZipPath
  Use an already downloaded coolicons.v4.1.zip (offline builds).

.PARAMETER Force
  Re-download and re-extract even if the icons are present (replaces a coolicons v4.1
  folder at -Destination; other folders are still refused).
#>
[CmdletBinding()]
param(
    [string]$Destination,
    [string]$ZipPath,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is very slow with progress in PS 5.1

$Url    = 'https://github.com/krystonschwarze/coolicons/releases/download/v4.1/coolicons.v4.1.zip'
$Sha256 = '5311B1B44E345B19007902DB55418C3A0B35FAC825A38FBB9038BBF3A077E11C'
$Probe  = 'cooliocns SVG\System\Terminal.svg'   # the release zip misspells the folder

$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Destination) { $Destination = Join-Path $RepoRoot 'coolicons.v4.1' }
$CacheDir = Join-Path $RepoRoot '.cache'

$isCoolicons = Test-Path -LiteralPath (Join-Path $Destination $Probe) -PathType Leaf
if ($isCoolicons -and -not $Force) {
    Write-Host "coolicons already present: $Destination"
    exit 0
}
# The destination is replaced as a whole below: only ever a coolicons tree (or nothing).
if (Test-Path -LiteralPath $Destination) {
    if (-not (Test-Path -LiteralPath $Destination -PathType Container)) {
        throw "-Destination '$Destination' is a file. Pass the folder that should contain the icons."
    }
    $isEmpty = -not (Get-ChildItem -LiteralPath $Destination -Force | Select-Object -First 1)
    if (-not $isCoolicons -and -not $isEmpty) {
        throw ("-Destination '$Destination' exists and is not a coolicons v4.1 folder ('$Probe' " +
            'is missing). It is not deleted: pass a new folder (the icons go directly into it), ' +
            'or remove it yourself.')
    }
}

function Get-Sha256([string]$Path) {
    (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
}

if (-not $ZipPath) {
    $ZipPath = Join-Path $CacheDir 'coolicons.v4.1.zip'
    $needDownload = $Force -or -not (Test-Path -LiteralPath $ZipPath)
    if (-not $needDownload -and (Get-Sha256 $ZipPath) -ne $Sha256) { $needDownload = $true }
    if ($needDownload) {
        New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $part = "$ZipPath.part"
        Write-Host "Downloading $Url"
        Invoke-WebRequest -Uri $Url -OutFile $part -UseBasicParsing
        Move-Item -LiteralPath $part -Destination $ZipPath -Force
    }
}

if (-not (Test-Path -LiteralPath $ZipPath)) { throw "Zip not found: $ZipPath" }
$actual = Get-Sha256 $ZipPath
if ($actual -ne $Sha256) {
    throw "SHA-256 mismatch for $ZipPath`n  expected $Sha256`n  actual   $actual"
}

# Extract next to the destination (same volume) so the final move is a rename.
New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null
$staging = Join-Path $CacheDir ('coolicons-staging-' + [guid]::NewGuid().ToString('N'))
Add-Type -AssemblyName System.IO.Compression.FileSystem
try {
    [IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $staging)
    if (-not (Test-Path -LiteralPath (Join-Path $staging $Probe))) {
        throw "Unexpected archive layout: '$Probe' not found in $ZipPath"
    }
    if (Test-Path -LiteralPath $Destination) {
        # Checked above; checked again right before deleting anything.
        $stillIcons = Test-Path -LiteralPath (Join-Path $Destination $Probe) -PathType Leaf
        $stillEmpty = -not (Get-ChildItem -LiteralPath $Destination -Force | Select-Object -First 1)
        if (-not ($stillIcons -or $stillEmpty)) {
            throw "-Destination '$Destination' is no longer a coolicons folder; it was not changed."
        }
        Remove-Item -LiteralPath $Destination -Recurse -Force
    }
    $parent = Split-Path -Parent $Destination
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    Move-Item -LiteralPath $staging -Destination $Destination
}
finally {
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
}

Write-Host "coolicons v4.1 extracted to $Destination"
Write-Host 'Icons: coolicons by Kryston Schwarze, licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).'
