<#
.SYNOPSIS
  Runs the GUI (default) or the CLI from source with an isolated settings folder and PATH.

.DESCRIPTION
  Sets WOL_MANAGER_CONFIG_DIR to <repo>\.cache\dev-config so development runs never touch
  the real %APPDATA%\wol-manager, and WOL_MANAGER_PATH_BACKEND_FILE to
  <repo>\.cache\dev-path.json so that `-Cli path add` and the GUI's PATH switch edit that
  JSON file instead of the real user PATH (debug builds only: a -Release build ignores the
  variable and changes the real PATH; -RealPath does the same in a debug build).

  cargo runs in the repository root, where it reads .cargo\config.toml (+crt-static,
  /STACK:8000000 against Slint stack overflows in debug builds) and rustup reads
  rust-toolchain.toml, whatever the current folder is.

  The GUI is a single instance per session: while another WoL Manager runs (e.g. the
  installed one in the notification area), the dev build shows a message and exits instead
  of opening that window.

.EXAMPLE
  .\scripts\dev-run.ps1
  .\scripts\dev-run.ps1 -Software
  .\scripts\dev-run.ps1 -Cli list
#>
[CmdletBinding()]
param(
    [switch]$Software,
    [switch]$Cli,
    [switch]$Release,
    [switch]$RealPath,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if ($cargo) { $cargo = $cargo.Source } else { $cargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe' }

$env:WOL_MANAGER_CONFIG_DIR = Join-Path $RepoRoot '.cache\dev-config'
if ($RealPath) {
    Remove-Item Env:\WOL_MANAGER_PATH_BACKEND_FILE -ErrorAction SilentlyContinue
} else {
    $env:WOL_MANAGER_PATH_BACKEND_FILE = Join-Path $RepoRoot '.cache\dev-path.json'
}
if ($Software) { $env:SLINT_BACKEND = 'winit-software' }

$package = if ($Cli) { 'wolm' } else { 'wol-manager' }
$cargoArgs = @('run', '--manifest-path', (Join-Path $RepoRoot 'Cargo.toml'), '-p', $package)
if ($Release) { $cargoArgs += '--release' }
if ($Rest) { $cargoArgs += '--'; $cargoArgs += $Rest }

Write-Host "WOL_MANAGER_CONFIG_DIR=$env:WOL_MANAGER_CONFIG_DIR"
if ($RealPath -or $Release) {
    Write-Warning 'PATH changes (wolm path add|remove, the GUI PATH switch) edit the REAL user PATH in this run.'
} else {
    Write-Host "WOL_MANAGER_PATH_BACKEND_FILE=$env:WOL_MANAGER_PATH_BACKEND_FILE"
}

Push-Location -LiteralPath $RepoRoot
try {
    & $cargo @cargoArgs
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $code
