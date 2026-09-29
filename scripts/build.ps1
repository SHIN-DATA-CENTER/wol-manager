<#
.SYNOPSIS
  Builds the WoL Manager release artifacts: portable ZIP, NSIS installer and SHA-256 files.

.DESCRIPTION
  Runs under Windows PowerShell 5.1 (and pwsh 7), from any working directory: it changes into
  the repository root for the whole run, because cargo reads .cargo\config.toml (+crt-static,
  /STACK) and rustup reads rust-toolchain.toml from the working directory, not from
  --manifest-path. Steps:
    1. Checks prerequisites: no RUSTFLAGS / CARGO_ENCODED_RUSTFLAGS (they would silently replace
       the rustflags in .cargo/config.toml), cargo, rustc = the rust-toolchain.toml channel on
       the x86_64-pc-windows-msvc host, makensis, cargo-about 0.9.2.
    2. Runs scripts\fetch-coolicons.ps1 and reads the version and [workspace.metadata.wol]
       through `cargo metadata` (all workspace members must share one version).
    3. cargo build --release --locked --workspace, then fails when an exe imports the VC++
       runtime (vcruntime*/msvcp*.dll: +crt-static was not in effect).
    4. Stages dist\stage\wol-manager-<ver>-x86_64-pc-windows-msvc\ with wol-manager.exe,
       bin\wolm.exe, LICENSE.txt, THIRD-PARTY-NOTICES.txt and README.txt.
       THIRD-PARTY-NOTICES.txt = packaging\notices\{header,coolicons,slint}.txt + cargo-about
       output (+ NOTICE files of dependencies), UTF-8 with BOM, CRLF.
    5. Creates the ZIP with %SystemRoot%\System32\tar.exe (not Compress-Archive, whose
       Windows PowerShell 5.1 version writes backslash separators).
    6. Builds the installer with makensis /V3 /INPUTCHARSET UTF8 /WX and /D defines.
    7. Writes <artifact>.sha256 files and SHA256SUMS.txt (lowercase hex, two spaces, file name,
       no BOM). PDBs are copied to dist\symbols (never shipped in the ZIP or the installer).

  Output (dist\):
    wol-manager-<ver>-x86_64-pc-windows-msvc.zip (+ .sha256)
    wol-manager-<ver>-setup-x64.exe (+ .sha256)
    SHA256SUMS.txt, symbols\*.pdb, stage\..., obj\...

.PARAMETER SkipInstaller
  Do not build the NSIS installer (makensis is then not required).

.PARAMETER SkipZip
  Do not create the portable ZIP.

.PARAMETER NoNotices
  Skip cargo-about; THIRD-PARTY-NOTICES.txt then lacks the Rust crate section.
  For local test builds only; cannot be combined with building the installer.

.PARAMETER SkipFetch
  Do not run fetch-coolicons.ps1 (also skipped when COOLICONS_DIR is set).

.PARAMETER Clean
  Delete dist\ before building (does not run cargo clean).

.PARAMETER Makensis
  Path to makensis.exe. Default: PATH, then the NSIS registry key, then
  ${env:ProgramFiles(x86)}\NSIS\makensis.exe.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build.ps1
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build.ps1 -SkipInstaller -NoNotices
#>
[CmdletBinding()]
param(
    [switch]$SkipInstaller,
    [switch]$SkipZip,
    [switch]$NoNotices,
    [switch]$SkipFetch,
    [switch]$Clean,
    [string]$Makensis
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Target = 'x86_64-pc-windows-msvc'
$CargoAboutVersion = '0.9.2'
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
$Utf8Bom = New-Object System.Text.UTF8Encoding $true

function Write-Step([string]$Message) {
    Write-Host ''
    Write-Host "==> $Message" -ForegroundColor Cyan
}

# Runs a native program. Output is shown (or returned with -Capture); a non-zero exit code
# throws. stderr is never redirected: Windows PowerShell 5.1 would turn every stderr line
# (cargo progress, cargo-about warnings) into an error record.
function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [switch]$Capture
    )
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        if ($Capture) {
            $out = & $FilePath @ArgumentList
        } else {
            & $FilePath @ArgumentList | Out-Host
        }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prev
    }
    if ($code -ne 0) {
        throw "'$FilePath $($ArgumentList -join ' ')' failed with exit code $code"
    }
    if ($Capture) { return $out }
}

function Read-TextFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing file: $Path" }
    $text = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
    return $text
}

# Normalizes line endings to CRLF and makes sure the text ends with exactly one newline.
function ConvertTo-Crlf([string]$Text) {
    $t = $Text.Replace("`r`n", "`n").Replace("`r", "`n").TrimEnd("`n")
    return $t.Replace("`n", "`r`n") + "`r`n"
}

function Write-TextFile([string]$Path, [string]$Text, [System.Text.Encoding]$Encoding) {
    [IO.File]::WriteAllText($Path, $Text, $Encoding)
}

function Get-Sha256Hex([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Resolve-Cargo {
    $cmd = Get-Command cargo.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    $candidate = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    throw 'cargo not found (PATH or %USERPROFILE%\.cargo\bin). Install Rust from https://rustup.rs/'
}

# rustc as cargo will run it: $env:RUSTC, else the rustup proxy next to cargo.exe, else PATH.
function Resolve-Rustc([string]$CargoBin) {
    if ($env:RUSTC) { return $env:RUSTC }
    $candidate = Join-Path $CargoBin 'rustc.exe'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    $cmd = Get-Command rustc.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    throw 'rustc not found (next to cargo.exe or on PATH).'
}

# Names of the DLLs a PE image imports (import table and delay-load import table).
function Get-PeImportNames([string]$Path) {
    $b = [IO.File]::ReadAllBytes($Path)
    $u16 = { param([int64]$o) [int64][BitConverter]::ToUInt16($b, [int]$o) }
    $u32 = { param([int64]$o) [int64][BitConverter]::ToUInt32($b, [int]$o) }
    if ($b.Length -lt 0x40 -or (& $u16 0) -ne 0x5A4D) { throw "$Path is not a PE image (no MZ header)" }
    $pe = & $u32 0x3C
    if ($pe + 24 -gt $b.Length -or (& $u32 $pe) -ne 0x4550) { throw "$Path is not a PE image (no PE signature)" }
    $sectionCount = & $u16 ($pe + 6)
    $optSize = & $u16 ($pe + 20)
    $opt = $pe + 24
    $magic = & $u16 $opt
    if ($magic -eq 0x20B) { $dirs = $opt + 112 } elseif ($magic -eq 0x10B) { $dirs = $opt + 96 } else {
        throw ("{0}: unknown optional header magic 0x{1:X}" -f $Path, $magic)
    }
    $dirCount = & $u32 ($dirs - 4)
    $sections = @(for ($i = 0; $i -lt $sectionCount; $i++) {
        $s = $opt + $optSize + 40 * $i
        [pscustomobject]@{
            Va = (& $u32 ($s + 12)); Size = [Math]::Max((& $u32 ($s + 8)), (& $u32 ($s + 16))); Raw = (& $u32 ($s + 20))
        }
    })
    $toOffset = {
        param([int64]$Rva)
        foreach ($s in $sections) {
            if ($Rva -ge $s.Va -and $Rva -lt $s.Va + $s.Size) { return $Rva - $s.Va + $s.Raw }
        }
        throw ("{0}: RVA 0x{1:X} is outside every section" -f $Path, $Rva)
    }
    $readName = {
        param([int64]$Rva)
        $o = & $toOffset $Rva
        $end = [Array]::IndexOf($b, [byte]0, [int]$o)
        if ($end -lt 0) { $end = $b.Length }
        [Text.Encoding]::ASCII.GetString($b, [int]$o, [int]($end - $o))
    }
    $names = New-Object System.Collections.Generic.List[string]
    # Data directory 1 = imports (20-byte descriptors, name RVA at +12);
    # 13 = delay-load imports (32-byte descriptors, name RVA at +4).
    foreach ($d in @(@{ Index = 1; Entry = 20; NameAt = 12 }, @{ Index = 13; Entry = 32; NameAt = 4 })) {
        if ($d.Index -ge $dirCount) { continue }
        $rva = & $u32 ($dirs + 8 * $d.Index)
        if ($rva -eq 0) { continue }
        $o = & $toOffset $rva
        while ($o + $d.Entry -le $b.Length) {
            $nameRva = & $u32 ($o + $d.NameAt)
            if ($nameRva -eq 0) { break }
            $names.Add((& $readName $nameRva))
            $o += $d.Entry
        }
    }
    return $names.ToArray()
}

function Resolve-Makensis {
    if ($Makensis) {
        if (Test-Path -LiteralPath $Makensis -PathType Leaf) {
            return (Resolve-Path -LiteralPath $Makensis).Path
        }
        throw "makensis not found at -Makensis '$Makensis'"
    }
    $cmd = Get-Command makensis.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    foreach ($key in @('HKLM:\SOFTWARE\WOW6432Node\NSIS', 'HKLM:\SOFTWARE\NSIS')) {
        $dir = $null
        try { $dir = (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).'(default)' } catch { $dir = $null }
        if ($dir) {
            $candidate = Join-Path $dir 'makensis.exe'
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        }
    }
    $pf86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    if ($pf86) {
        $candidate = Join-Path $pf86 'NSIS\makensis.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    throw 'makensis not found (PATH, HKLM\SOFTWARE\WOW6432Node\NSIS, %ProgramFiles(x86)%\NSIS). Install NSIS 3.12 or later, or use -SkipInstaller.'
}

# ---------------------------------------------------------------------------- 1. prerequisites
Write-Step 'Checking prerequisites'
if ($NoNotices -and -not $SkipInstaller) {
    throw '-NoNotices cannot be combined with building the installer (THIRD-PARTY-NOTICES.txt would be incomplete). Add -SkipInstaller.'
}
foreach ($name in @('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS')) {
    if ([Environment]::GetEnvironmentVariable($name)) {
        throw "$name is set. It silently replaces the rustflags in .cargo\config.toml (+crt-static, /STACK). Unset it and run again."
    }
}
if ([Environment]::GetEnvironmentVariable('CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS')) {
    Write-Warning 'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS is set; make sure it keeps +crt-static.'
}

# Native tools print UTF-8; decode it as such (paths may contain non-ASCII characters).
$savedOutputEncoding = $null
try {
    $savedOutputEncoding = [Console]::OutputEncoding
    [Console]::OutputEncoding = $Utf8NoBom
} catch {
    $savedOutputEncoding = $null
}

$pushedLocation = $false
try {
    # cargo reads .cargo\config.toml (+crt-static, /STACK, COOLICONS_DIR) and rustup reads
    # rust-toolchain.toml from the WORKING DIRECTORY; --manifest-path does not change that.
    Push-Location -LiteralPath $RepoRoot
    $pushedLocation = $true

    $cargo = Resolve-Cargo
    # cargo subcommands (cargo-about) and rustup proxies live next to cargo.exe.
    $cargoBin = Split-Path -Parent $cargo
    if (($env:PATH -split ';') -notcontains $cargoBin) { $env:PATH = "$cargoBin;$env:PATH" }
    Write-Host "cargo:       $cargo"

    # The toolchain must be the one pinned in rust-toolchain.toml (RUSTUP_TOOLCHAIN or a
    # rustup override would replace it) and must build for the x86_64-pc-windows-msvc host:
    # the rustflags in .cargo\config.toml are set for that target only.
    $rustc = Resolve-Rustc $cargoBin
    $rustcInfo = (Invoke-Native -FilePath $rustc -ArgumentList @('-vV') -Capture) -join "`n"
    $rustcRelease = [regex]::Match($rustcInfo, '(?m)^release:\s*(\S+)').Groups[1].Value
    $rustcHost = [regex]::Match($rustcInfo, '(?m)^host:\s*(\S+)').Groups[1].Value
    Write-Host "rustc:       $rustcRelease ($rustcHost)"
    if ($rustcHost -ne $Target) {
        throw "rustc builds for '$rustcHost', but the release must be built for $Target (use the $Target toolchain)."
    }
    $toolchainFile = Join-Path $RepoRoot 'rust-toolchain.toml'
    if (Test-Path -LiteralPath $toolchainFile -PathType Leaf) {
        $channel = [regex]::Match((Read-TextFile $toolchainFile), '(?m)^\s*channel\s*=\s*"([^"]+)"').Groups[1].Value
        $mismatch = ($channel -match '^\d+\.\d+\.\d+$' -and $rustcRelease -ne $channel) -or
                    ($channel -match '^\d+\.\d+$' -and -not $rustcRelease.StartsWith("$channel."))
        if ($mismatch) {
            throw "rustc $rustcRelease is in use, but rust-toolchain.toml pins $channel. Unset RUSTUP_TOOLCHAIN / remove the rustup override (rustup override list), or install it: rustup toolchain install $channel"
        }
    }

    if (-not $NoNotices) {
        $aboutVersionText = $null
        try {
            $aboutVersionText = (Invoke-Native -FilePath $cargo -ArgumentList @('about', '--version') -Capture) -join ' '
        } catch {
            throw "cargo-about is required for THIRD-PARTY-NOTICES.txt. Install it with:`n  cargo install cargo-about --locked --version $CargoAboutVersion --features cli`n(or use -NoNotices -SkipInstaller for a local test build)"
        }
        Write-Host "cargo-about: $aboutVersionText"
        if ($aboutVersionText -notmatch [regex]::Escape($CargoAboutVersion)) {
            Write-Warning "cargo-about $CargoAboutVersion is expected (found '$aboutVersionText')."
        }
    }

    $makensisExe = $null
    if (-not $SkipInstaller) {
        $makensisExe = Resolve-Makensis
        $nsisVersion = (Invoke-Native -FilePath $makensisExe -ArgumentList @('/VERSION') -Capture) -join ' '
        Write-Host "makensis:    $makensisExe ($nsisVersion)"
    }

    # ------------------------------------------------------------------------ 2. inputs
    if ($SkipFetch) {
        Write-Step 'Skipping coolicons fetch (-SkipFetch)'
    } elseif ($env:COOLICONS_DIR) {
        Write-Step "Skipping coolicons fetch (COOLICONS_DIR=$env:COOLICONS_DIR)"
    } else {
        Write-Step 'Fetching coolicons (build-time only, never committed)'
        $powershellExe = Join-Path $PSHOME 'powershell.exe'
        if (-not (Test-Path -LiteralPath $powershellExe -PathType Leaf)) { $powershellExe = Join-Path $PSHOME 'pwsh.exe' }
        Invoke-Native -FilePath $powershellExe -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'fetch-coolicons.ps1'))
    }

    Write-Step 'Reading workspace metadata'
    $manifest = Join-Path $RepoRoot 'Cargo.toml'
    $metaJson = Invoke-Native -FilePath $cargo -ArgumentList @(
        'metadata', '--format-version', '1', '--no-deps', '--locked', '--manifest-path', $manifest) -Capture
    $meta = ($metaJson -join "`n") | ConvertFrom-Json

    $versions = @($meta.packages | ForEach-Object { $_.version } | Sort-Object -Unique)
    if ($versions.Count -ne 1) {
        throw "Workspace members have different versions: $($versions -join ', ') (use version.workspace = true)"
    }
    $Version = [string]$versions[0]
    if ($Version -notmatch '^\d+\.\d+\.\d+([-+].*)?$') { throw "Unexpected version '$Version'" }
    $core = ($Version -split '[-+]', 2)[0]
    $parts = @($core.Split('.'))
    while ($parts.Count -lt 4) { $parts += '0' }
    $VersionNum = ($parts[0..3]) -join '.'

    if (-not $meta.metadata -or -not ($meta.metadata.PSObject.Properties.Name -contains 'wol')) {
        throw '[workspace.metadata.wol] not found in Cargo.toml'
    }
    $wol = $meta.metadata.wol
    function Get-WolValue([string]$Key) {
        $p = $wol.PSObject.Properties[$Key]
        if (-not $p -or -not [string]$p.Value) { throw "[workspace.metadata.wol] $Key is missing" }
        return [string]$p.Value
    }
    $ProductName = Get-WolValue 'product-name'
    $Publisher = Get-WolValue 'publisher'
    $AppDirName = Get-WolValue 'app-dir-name'
    $InstallDirName = Get-WolValue 'install-dir-name'
    $UninstallKey = Get-WolValue 'uninstall-key'
    $GuiExe = Get-WolValue 'gui-exe'
    $CliExe = Get-WolValue 'cli-exe'
    $CliSubdir = Get-WolValue 'cli-subdir'
    $InstalledSentinel = Get-WolValue 'installed-sentinel'
    $GuiMutex = Get-WolValue 'gui-mutex'
    $GuiQuitEvent = Get-WolValue 'gui-quit-event'

    $TargetDir = [string]$meta.target_directory
    $ReleaseDir = Join-Path $TargetDir 'release'
    Write-Host "version:     $Version (VERSION_NUM $VersionNum)"
    Write-Host "target dir:  $TargetDir"

    $BaseName = "$AppDirName-$Version"
    $StageName = "$BaseName-$Target"
    $Dist = Join-Path $RepoRoot 'dist'
    $StageRoot = Join-Path $Dist 'stage'
    $Stage = Join-Path $StageRoot $StageName
    $ObjDir = Join-Path $Dist 'obj'
    $SymbolsDir = Join-Path $Dist 'symbols'
    $ZipPath = Join-Path $Dist "$StageName.zip"
    $SetupPath = Join-Path $Dist "$BaseName-setup-x64.exe"

    if ($Clean -and (Test-Path -LiteralPath $Dist)) {
        Write-Step 'Cleaning dist\'
        Remove-Item -LiteralPath $Dist -Recurse -Force
    }

    # ------------------------------------------------------------------------ 3. build
    Write-Step 'cargo build --release --locked --workspace'
    Invoke-Native -FilePath $cargo -ArgumentList @(
        'build', '--release', '--locked', '--workspace', '--manifest-path', $manifest)

    $guiBuilt = Join-Path $ReleaseDir $GuiExe
    $cliBuilt = Join-Path $ReleaseDir $CliExe
    foreach ($f in @($guiBuilt, $cliBuilt)) {
        if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { throw "Build output not found: $f" }
        # +crt-static check: the exe must not need the VC++ redistributable.
        $imports = @(Get-PeImportNames $f)
        if ($imports.Count -eq 0) { throw "Could not read the import table of $f" }
        $vcRuntime = @($imports | Where-Object { $_ -match '^(vcruntime|msvcp|concrt|vccorlib)\d' })
        if ($vcRuntime.Count -gt 0) {
            throw "$f imports $($vcRuntime -join ', ') (the VC++ runtime): +crt-static from .cargo\config.toml was not in effect (check that file and CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS)."
        }
    }

    # ------------------------------------------------------------------------ 4. stage
    Write-Step "Staging $StageName"
    foreach ($d in @($Dist, $StageRoot, $ObjDir, $SymbolsDir)) {
        New-Item -ItemType Directory -Force -Path $d | Out-Null
    }
    if (Test-Path -LiteralPath $Stage) { Remove-Item -LiteralPath $Stage -Recurse -Force }
    New-Item -ItemType Directory -Force -Path (Join-Path $Stage $CliSubdir) | Out-Null

    Copy-Item -LiteralPath $guiBuilt -Destination (Join-Path $Stage $GuiExe)
    Copy-Item -LiteralPath $cliBuilt -Destination (Join-Path (Join-Path $Stage $CliSubdir) $CliExe)
    Write-TextFile (Join-Path $Stage 'LICENSE.txt') (ConvertTo-Crlf (Read-TextFile (Join-Path $RepoRoot 'LICENSE'))) $Utf8NoBom
    $readme = (Read-TextFile (Join-Path $RepoRoot 'packaging\portable\README.txt')).Replace('{{VERSION}}', $Version)
    Write-TextFile (Join-Path $Stage 'README.txt') (ConvertTo-Crlf $readme) $Utf8Bom

    # rustc names the PDB after the crate: wol-manager.exe -> wol_manager.pdb.
    foreach ($exe in @($GuiExe, $CliExe)) {
        $pdb = [IO.Path]::GetFileNameWithoutExtension($exe).Replace('-', '_') + '.pdb'
        $src = Join-Path $ReleaseDir $pdb
        if (Test-Path -LiteralPath $src -PathType Leaf) {
            Copy-Item -LiteralPath $src -Destination (Join-Path $SymbolsDir $pdb) -Force
        } else {
            Write-Warning "PDB not found: $src"
        }
    }

    # THIRD-PARTY-NOTICES.txt
    $noticesDir = Join-Path $RepoRoot 'packaging\notices'
    $sections = New-Object System.Collections.Generic.List[string]
    $sections.Add((Read-TextFile (Join-Path $noticesDir 'header.txt')).Replace('{{VERSION}}', $Version))
    $sections.Add((Read-TextFile (Join-Path $noticesDir 'coolicons.txt')))
    $sections.Add((Read-TextFile (Join-Path $noticesDir 'slint.txt')))
    if ($NoNotices) {
        Write-Warning '-NoNotices: the Rust crate section is omitted. Do not distribute this build.'
        $sections.Add("==============================================================================`n3. Rust crates`n==============================================================================`n`n(omitted in this local test build: built with -NoNotices)")
    } else {
        Write-Step 'Generating the Rust crate notices (cargo-about)'
        $aboutOut = Join-Path $ObjDir 'cargo-about.txt'
        if (Test-Path -LiteralPath $aboutOut) { Remove-Item -LiteralPath $aboutOut -Force }
        Invoke-Native -FilePath $cargo -ArgumentList @(
            'about', 'generate', '--workspace', '--locked', '--fail',
            '--manifest-path', $manifest,
            '-c', (Join-Path $RepoRoot 'packaging\about.toml'),
            '-o', $aboutOut,
            (Join-Path $RepoRoot 'packaging\about.hbs'))
        $aboutText = Read-TextFile $aboutOut

        # about.hbs ends with one "@@WOL-MANIFEST@@<Cargo.toml path>" line per crate. cargo-about
        # does not collect NOTICE files (Apache-2.0 section 4d), so append them here.
        $marker = '@@WOL-MANIFEST@@'
        $body = New-Object System.Text.StringBuilder
        $manifests = New-Object System.Collections.Generic.List[string]
        foreach ($line in ($aboutText.Replace("`r`n", "`n") -split "`n")) {
            if ($line.StartsWith($marker)) {
                $manifests.Add($line.Substring($marker.Length).Trim())
            } else {
                [void]$body.Append($line).Append("`n")
            }
        }
        if ($manifests.Count -eq 0) { throw "cargo-about output has no $marker lines (packaging\about.hbs changed?)" }
        $noticeText = New-Object System.Text.StringBuilder
        foreach ($m in ($manifests | Sort-Object -Unique)) {
            $crateDir = Split-Path -Parent $m
            if (-not (Test-Path -LiteralPath $crateDir -PathType Container)) { continue }
            $files = @(Get-ChildItem -LiteralPath $crateDir -File | Where-Object { $_.Name -match '^NOTICE([.-].*)?$' } | Sort-Object Name)
            foreach ($nf in $files) {
                $crateName = Split-Path -Leaf $crateDir
                [void]$noticeText.Append("`n------------------------------------------------------------------------------`n")
                [void]$noticeText.Append("NOTICE file of $crateName ($($nf.Name))`n")
                [void]$noticeText.Append("------------------------------------------------------------------------------`n`n")
                [void]$noticeText.Append((Read-TextFile $nf.FullName).TrimEnd()).Append("`n")
            }
        }
        $crateSection = $body.ToString().TrimEnd()
        if ($noticeText.Length -gt 0) {
            $crateSection += "`n`nNOTICE files of the crates above:`n" + $noticeText.ToString()
        }
        $sections.Add($crateSection)
    }
    $notices = ($sections | ForEach-Object { $_.Replace("`r`n", "`n").TrimEnd("`n") }) -join "`n`n"
    Write-TextFile (Join-Path $Stage 'THIRD-PARTY-NOTICES.txt') (ConvertTo-Crlf $notices) $Utf8Bom

    # Installer icon: generated by the GUI build script inside its OUT_DIR (never committed).
    $icon = Get-ChildItem -LiteralPath (Join-Path $ReleaseDir 'build') -Directory -Filter "$AppDirName-*" -ErrorAction SilentlyContinue |
        ForEach-Object { Join-Path $_.FullName 'out\gen\art\app.ico' } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        ForEach-Object { Get-Item -LiteralPath $_ } |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if (-not $icon) { throw "app.ico not found under $ReleaseDir\build\$AppDirName-*\out\gen\art" }
    $appIcon = Join-Path $ObjDir 'app.ico'
    Copy-Item -LiteralPath $icon.FullName -Destination $appIcon -Force

    $artifacts = New-Object System.Collections.Generic.List[string]

    # ------------------------------------------------------------------------ 5. zip
    if ($SkipZip) {
        Write-Step 'Skipping the ZIP (-SkipZip)'
    } else {
        Write-Step "Creating $(Split-Path -Leaf $ZipPath)"
        if (Test-Path -LiteralPath $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }
        $tar = Join-Path $env:SystemRoot 'System32\tar.exe'
        if (-not (Test-Path -LiteralPath $tar -PathType Leaf)) { throw "tar.exe not found: $tar (Windows 10 1803 or later is required)" }
        Invoke-Native -FilePath $tar -ArgumentList @('-a', '-c', '-f', $ZipPath, '-C', $StageRoot, $StageName)
        $artifacts.Add($ZipPath)
    }

    # ------------------------------------------------------------------------ 6. installer
    if ($SkipInstaller) {
        Write-Step 'Skipping the installer (-SkipInstaller)'
    } else {
        Write-Step "Building $(Split-Path -Leaf $SetupPath)"
        if (Test-Path -LiteralPath $SetupPath) { Remove-Item -LiteralPath $SetupPath -Force }
        # /D options must come before the script. No value may end with a backslash.
        $nsisArgs = @(
            '/V3', '/INPUTCHARSET', 'UTF8', '/WX',
            "/DVERSION=$Version",
            "/DVERSION_NUM=$VersionNum",
            "/DSTAGE_DIR=$Stage",
            "/DOUTFILE=$SetupPath",
            "/DAPP_ICON=$appIcon",
            "/DMUTEX_NAME=$GuiMutex",
            "/DQUIT_EVENT=$GuiQuitEvent",
            "/DAPPDATA_DIRNAME=$AppDirName",
            "/DUNINST_KEY_NAME=$UninstallKey",
            "/DPRODUCT_NAME=$ProductName",
            "/DPUBLISHER=$Publisher",
            "/DINSTALL_DIR_NAME=$InstallDirName",
            "/DGUI_EXE=$GuiExe",
            "/DCLI_EXE=$CliExe",
            "/DCLI_SUBDIR=$CliSubdir",
            # The uninstaller's name is what marks an installed copy for the app.
            "/DUNINSTALLER_EXE=$InstalledSentinel",
            (Join-Path $RepoRoot 'installer\wol-manager.nsi'))
        Invoke-Native -FilePath $makensisExe -ArgumentList $nsisArgs
        if (-not (Test-Path -LiteralPath $SetupPath -PathType Leaf)) { throw "makensis did not create $SetupPath" }
        $artifacts.Add($SetupPath)
    }

    # ------------------------------------------------------------------------ 7. checksums
    Write-Step 'Writing SHA-256 checksums'
    $sums = New-Object System.Text.StringBuilder
    foreach ($a in $artifacts) {
        $leaf = Split-Path -Leaf $a
        $line = "$(Get-Sha256Hex $a)  $leaf`n"
        Write-TextFile "$a.sha256" $line $Utf8NoBom
        [void]$sums.Append($line)
    }
    $sumsPath = Join-Path $Dist 'SHA256SUMS.txt'
    if ($artifacts.Count -gt 0) {
        Write-TextFile $sumsPath $sums.ToString() $Utf8NoBom
    } elseif (Test-Path -LiteralPath $sumsPath) {
        Remove-Item -LiteralPath $sumsPath -Force
    }

    Write-Step 'Done'
    Write-Host "stage:     $Stage"
    foreach ($a in $artifacts) { Write-Host "artifact:  $a" }
    if ($artifacts.Count -gt 0) { Write-Host "checksums: $sumsPath" }
} finally {
    if ($pushedLocation) { Pop-Location }
    if ($null -ne $savedOutputEncoding) {
        try { [Console]::OutputEncoding = $savedOutputEncoding } catch { }
    }
}
