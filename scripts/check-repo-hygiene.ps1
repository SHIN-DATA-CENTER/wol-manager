<#
.SYNOPSIS
  Fails when coolicons data (or anything derived from it) or build output would be committed.

.DESCRIPTION
  Checks the set of files that `git add -A` would commit (tracked + untracked-not-ignored):
    - no image / font / icon files: by extension (also with ".svg" anywhere in the name,
      e.g. "x.svg.txt") and by content (PNG / GIF / JPEG / BMP / ICO / WebP / font
      signatures), whatever the extension
    - nothing under coolicons.v4.1/, target/, dist/, .cache/
    - no generated Slint icon files
    - every text file, whatever its extension (binary = contains a NUL byte), is scanned for
      inline SVG markup, data: images, currentColor strokes, SVG path data (a moveto with
      at least 4 drawing commands) and long base64 runs that decode to any of these or to
      an image. The build helper's crates/wol-build/src/icon.rs and coolicons.rs (and this
      script) may mention the markup tokens, but may not contain path data with more than 8
      commands (their test shapes are tiny).
    - when the coolicons folder is present (-CooliconsDir, else COOLICONS_DIR, else
      <repo>\coolicons.v4.1; CI runs this again after fetching it): no file may contain the
      path data of any icon or be byte-identical to any file of the package, also inside a
      base64 run
    - .gitignore itself is not ignored and ignores the folders above
    - the installer does not use nsExec::ExecToLog (crashes Unicode installers in NSIS <= 3.12)
  Exit code 0 = clean, 1 = violations found.

.PARAMETER CooliconsDir
  The coolicons v4.1 folder to compare against. Default: COOLICONS_DIR, else
  <repo>\coolicons.v4.1. That comparison is skipped (with a note) when the folder is missing.
#>
[CmdletBinding()]
param(
    [string]$CooliconsDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot

$git = (Get-Command git -ErrorAction SilentlyContinue)
if ($git) { $git = $git.Source } else { $git = 'C:\Program Files\Git\cmd\git.exe' }
if (-not (Test-Path -LiteralPath $git)) { throw 'git not found' }

function Invoke-Git {
    $out = & $git -C $RepoRoot -c core.quotepath=off @args
    if ($LASTEXITCODE -gt 1) { throw "git $args failed ($LASTEXITCODE)" }
    $out
}

$violations = New-Object System.Collections.Generic.List[string]
$files = @(Invoke-Git ls-files --cached --others --exclude-standard) | Where-Object { $_ }

$forbiddenExt  = '\.(svg|svgz|ico|icns|cur|png|apng|bmp|gif|jpe?g|webp|avif|tiff?|ttf|otf|woff2?|eot|iconjar)$'
$svgInName     = '\.svgz?(\.[^/]*)?$'
$forbiddenDirs = '^(coolicons[^/]*|target|dist|\.cache)/'
$forbiddenName = '(^|/)(coolicons-gen\.slint|icons\.slint)$'

foreach ($f in $files) {
    if ($f -match $forbiddenExt)  { $violations.Add("binary/icon file would be committed: $f") }
    elseif ($f -match $svgInName) { $violations.Add("SVG file (renamed) would be committed: $f") }
    if ($f -match $forbiddenDirs) { $violations.Add("build output or coolicons folder would be committed: $f") }
    if ($f -match $forbiddenName) { $violations.Add("generated icon Slint file would be committed: $f") }
}

# ------------------------------------------------------------------ content helpers
# Files that legitimately mention the markup tokens (production code of the icon renderer and
# its synthetic test shapes, and this script). Path data is still limited there.
$markupAllowed = @(
    'crates/wol-build/src/icon.rs',
    'crates/wol-build/src/coolicons.rs',
    'scripts/check-repo-hygiene.ps1'
)
$markupPatterns = @('(?i)<svg\b', '(?i)data:image/', '(?i)stroke\s*=\s*"currentColor"')
# SVG path data: a moveto followed by path-alphabet characters only.
$pathRun = New-Object System.Text.RegularExpressions.Regex('[Mm][\s,]*-?\.?\d[0-9MmLlHhVvCcSsQqTtAaZz\s,.\-]{8,}')
$base64Run = New-Object System.Text.RegularExpressions.Regex('[A-Za-z0-9+/]{120,}={0,2}')
$utf8 = New-Object System.Text.UTF8Encoding($false, $false)
$sha = [System.Security.Cryptography.SHA256]::Create()

function Get-CommandCount([string]$Path) {
    ([regex]::Matches($Path, '[MmLlHhVvCcSsQqTtAaZz]')).Count
}

# Image / font signatures at the start of a byte array.
function Test-ImageBytes([byte[]]$b) {
    if ($b.Length -lt 4) { return $false }
    $h = [BitConverter]::ToString($b, 0, [Math]::Min(12, $b.Length))
    return ($h.StartsWith('89-50-4E-47') -or $h.StartsWith('47-49-46-38') -or $h.StartsWith('FF-D8-FF') -or
        $h.StartsWith('00-00-01-00') -or $h.StartsWith('00-00-02-00') -or $h.StartsWith('42-4D') -or
        $h.StartsWith('77-4F-46-46') -or $h.StartsWith('77-4F-46-32') -or $h.StartsWith('4F-54-54-4F') -or
        $h.StartsWith('00-01-00-00') -or ($h.StartsWith('52-49-46-46') -and $b.Length -ge 12 -and
            [Text.Encoding]::ASCII.GetString($b, 8, 4) -eq 'WEBP'))
}

function Get-Sha256Hex([byte[]]$b) {
    [BitConverter]::ToString($sha.ComputeHash($b)).Replace('-', '')
}

# ------------------------------------------------------------------ the real icon data
if (-not $CooliconsDir) {
    $CooliconsDir = if ($env:COOLICONS_DIR) { $env:COOLICONS_DIR } else { Join-Path $RepoRoot 'coolicons.v4.1' }
}
if (-not [IO.Path]::IsPathRooted($CooliconsDir)) { $CooliconsDir = Join-Path $RepoRoot $CooliconsDir }
$iconPaths = New-Object 'System.Collections.Generic.HashSet[string]'
$iconHashes = New-Object 'System.Collections.Generic.HashSet[string]'
$deep = Test-Path -LiteralPath $CooliconsDir -PathType Container
if ($deep) {
    foreach ($item in Get-ChildItem -LiteralPath $CooliconsDir -Recurse -File -Force) {
        $bytes = [IO.File]::ReadAllBytes($item.FullName)
        if ($bytes.Length -gt 0) { [void]$iconHashes.Add((Get-Sha256Hex $bytes)) }
        if ($item.Extension -eq '.svg') {
            foreach ($m in [regex]::Matches($utf8.GetString($bytes), '\sd="([^"]+)"')) {
                $p = $m.Groups[1].Value.Trim()
                if ($p.Length -ge 16) { [void]$iconPaths.Add($p) }
            }
        }
    }
    Write-Host "Comparing with $($iconHashes.Count) coolicons files and $($iconPaths.Count) icon paths in $CooliconsDir"
} else {
    Write-Host "Note: $CooliconsDir not found; the comparison with the real icon data is skipped."
}

# $true when $Text contains (a run of) the path data of a coolicons icon.
function Test-IconPath([string]$Text) {
    if (-not $deep) { return $false }
    foreach ($m in $pathRun.Matches($Text)) {
        $run = $m.Value.Trim()
        if ($run.Length -lt 16) { continue }
        if ($iconPaths.Contains($run)) { return $true }
        foreach ($p in $iconPaths) {
            if ($run.Contains($p) -or ($run.Length -ge 24 -and $p.Contains($run))) { return $true }
        }
    }
    return $false
}

# Violations for one piece of text ($Where names it). $Limit = most path commands allowed.
function Test-Text([string]$Text, [string]$Where, [bool]$MarkupOk, [int]$Limit) {
    if (-not $MarkupOk) {
        foreach ($p in $markupPatterns) {
            if ($Text -match $p) { $violations.Add("icon data pattern '$p' found in $Where") }
        }
    }
    foreach ($m in $pathRun.Matches($Text)) {
        $n = Get-CommandCount $m.Value
        $digits = ([regex]::Matches($m.Value, '\d')).Count
        if ($n -gt $Limit -and $digits -ge 4) {
            $violations.Add("SVG path data ($n commands) found in ${Where}: $($m.Value.Substring(0, [Math]::Min(40, $m.Value.Length)))...")
            break
        }
    }
    if (Test-IconPath $Text) { $violations.Add("coolicons path data found in $Where") }
}

# ------------------------------------------------------------------ scan every file
foreach ($f in $files) {
    $path = Join-Path $RepoRoot $f
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($deep -and $bytes.Length -gt 0 -and $iconHashes.Contains((Get-Sha256Hex $bytes))) {
        $violations.Add("file is a copy of a coolicons file: $f")
    }
    if ([Array]::IndexOf($bytes, [byte]0) -ge 0) {
        # Binary: only its signature can be checked.
        if (Test-ImageBytes $bytes) { $violations.Add("image / font data would be committed: $f") }
        continue
    }
    $text = $utf8.GetString($bytes)
    $allowed = $markupAllowed -contains $f
    Test-Text $text $f $allowed $(if ($allowed) { 8 } else { 3 })
    if ($f -match '\.slint$' -and $text -match 'commands\s*:') {
        $violations.Add("inline Path commands found in $f (icons must come from coolicons at build time)")
    }
    if ($f -match '^installer/' -and $text -match 'ExecToLog') {
        $violations.Add("nsExec::ExecToLog used in $f (use ExecToStack)")
    }
    # Base64 without a data: prefix.
    foreach ($m in $base64Run.Matches($text)) {
        $s = $m.Value.TrimEnd('=')
        $s = $s.Substring(0, $s.Length - ($s.Length % 4))
        try { $decoded = [Convert]::FromBase64String($s) } catch { continue }
        $where = "base64 data in $f"
        if (Test-ImageBytes $decoded) { $violations.Add("image data in $where"); continue }
        if ($deep -and $iconHashes.Contains((Get-Sha256Hex $decoded))) { $violations.Add("a coolicons file in $where"); continue }
        Test-Text $utf8.GetString($decoded) $where $false 3
    }
}

# .gitignore must be committable and must ignore the sensitive folders.
& $git -C $RepoRoot check-ignore -q .gitignore
if ($LASTEXITCODE -eq 0) { $violations.Add('.gitignore ignores itself; it must be committed') }
foreach ($p in @('coolicons.v4.1/x.svg', 'target/x', 'dist/x', '.cache/x')) {
    & $git -C $RepoRoot check-ignore -q --no-index $p
    if ($LASTEXITCODE -ne 0) { $violations.Add("'$p' is not ignored by .gitignore") }
}

if ($violations.Count -gt 0) {
    Write-Host 'Repository hygiene check FAILED:' -ForegroundColor Red
    $violations | Select-Object -Unique | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host "Repository hygiene check passed ($($files.Count) files checked)."
exit 0
