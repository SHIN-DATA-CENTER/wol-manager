<#
.SYNOPSIS
  Fails when a GUI string has no Japanese translation (CI check, no gettext tools needed).

.DESCRIPTION
  1. Extracts a fresh .pot from crates\wol-manager\ui\**\*.slint with
     `slint-tr-extractor --no-default-translation-context` (the same setting as build.rs:
     DefaultTranslationContext::None) into a temporary file.
  2. Every message of that .pot (msgctxt + msgid) must exist in
     crates\wol-manager\lang\ja\LC_MESSAGES\wol-manager.po with a non-empty msgstr (all
     msgstr[n] for plurals) and without the "fuzzy" flag. Otherwise Slint silently shows the
     English source text.
  3. The .po header must declare "Plural-Forms: nplurals=1; plural=0;".
  4. When crates\wol-manager\lang\wol-manager.pot is committed, its message set must match the
     fresh extraction (dates and "#:" source references are ignored).
  Entries of the .po that are no longer used are reported as warnings.

  Exit code: 0 = complete, 1 = problems found, 2 = could not run.

.PARAMETER Extractor
  Path to slint-tr-extractor. Default: PATH, then %USERPROFILE%\.cargo\bin.
  Install: cargo install slint-tr-extractor --version 1.18.1 --locked
#>
[CmdletBinding()]
param(
    [string]$Extractor
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$CrateDir = Join-Path $RepoRoot 'crates\wol-manager'
$UiDir = Join-Path $CrateDir 'ui'
$PoPath = Join-Path $CrateDir 'lang\ja\LC_MESSAGES\wol-manager.po'
$PotPath = Join-Path $CrateDir 'lang\wol-manager.pot'
$Eot = [string][char]4   # gettext's msgctxt/msgid separator

function Resolve-Extractor {
    if ($Extractor) {
        if (Test-Path -LiteralPath $Extractor -PathType Leaf) { return (Resolve-Path -LiteralPath $Extractor).Path }
        throw "slint-tr-extractor not found at '$Extractor'"
    }
    $cmd = Get-Command slint-tr-extractor.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    $candidate = Join-Path $env:USERPROFILE '.cargo\bin\slint-tr-extractor.exe'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    throw 'slint-tr-extractor not found. Install it with: cargo install slint-tr-extractor --version 1.18.1 --locked'
}

function ConvertFrom-PoString([string]$Quoted) {
    # Body of a "..." token without the quotes, with C escapes resolved.
    $s = $Quoted.Trim()
    if ($s.Length -lt 2 -or $s[0] -ne '"' -or $s[$s.Length - 1] -ne '"') { throw "Malformed PO string: $Quoted" }
    $body = $s.Substring(1, $s.Length - 2)
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $body.Length; $i++) {
        $c = $body[$i]
        if ($c -eq '\' -and $i + 1 -lt $body.Length) {
            $i++
            switch ($body[$i]) {
                'n' { [void]$sb.Append("`n") }
                't' { [void]$sb.Append("`t") }
                'r' { [void]$sb.Append("`r") }
                '"' { [void]$sb.Append('"') }
                '\' { [void]$sb.Append('\') }
                default { [void]$sb.Append('\').Append($body[$i]) }
            }
        } else {
            [void]$sb.Append($c)
        }
    }
    return $sb.ToString()
}

# Parses a .po/.pot file into a list of entries:
#   Key (ctxt EOT id, or id), Id, Ctxt, HasCtxt, Plural, Strs (list), Fuzzy, Obsolete, Line
function Read-PoFile([string]$Path) {
    $lines = [IO.File]::ReadAllLines($Path, [Text.Encoding]::UTF8)
    $entries = New-Object System.Collections.Generic.List[object]
    $cur = $null
    $field = $null
    $pendingFuzzy = $false
    $lineNo = 0

    $newEntry = {
        param($fuzzy, $obsolete, $line)
        return [pscustomobject]@{
            Key = $null; Id = $null; Ctxt = $null; HasCtxt = $false; Plural = $null
            Strs = New-Object System.Collections.Generic.List[string]
            Fuzzy = $fuzzy; Obsolete = $obsolete; Line = $line; Field = $null; StrIndex = -1
        }
    }
    $flush = {
        if ($null -ne $cur -and $null -ne $cur.Id) {
            $cur.Key = if ($cur.HasCtxt) { $cur.Ctxt + $Eot + $cur.Id } else { $cur.Id }
            $entries.Add($cur)
        }
    }

    foreach ($raw in $lines) {
        $lineNo++
        $line = $raw.Trim()
        if ($lineNo -eq 1 -and $line.Length -gt 0 -and $line[0] -eq [char]0xFEFF) { $line = $line.Substring(1) }
        if ($line -eq '') {
            . $flush
            $cur = $null; $field = $null; $pendingFuzzy = $false
            continue
        }
        $obsolete = $false
        if ($line.StartsWith('#~')) {
            $obsolete = $true
            $line = $line.Substring(2).Trim()
            if ($line -eq '') { continue }
        } elseif ($line.StartsWith('#')) {
            if ($line.StartsWith('#,') -and $line -match '\bfuzzy\b') { $pendingFuzzy = $true }
            continue
        }

        $m = [regex]::Match($line, '^(msgctxt|msgid_plural|msgid|msgstr(?:\[(\d+)\])?)\s+(".*")$')
        if ($m.Success) {
            $kw = $m.Groups[1].Value
            $value = ConvertFrom-PoString $m.Groups[3].Value
            if ($kw -eq 'msgctxt' -or ($kw -eq 'msgid' -and $null -ne $cur -and $null -ne $cur.Id)) {
                # A new entry starts (entries are not always separated by blank lines).
                . $flush
                $cur = $null
            }
            if ($null -eq $cur) { $cur = & $newEntry $pendingFuzzy $obsolete $lineNo; $pendingFuzzy = $false }
            if ($obsolete) { $cur.Obsolete = $true }
            switch -Regex ($kw) {
                '^msgctxt$' { $cur.Ctxt = $value; $cur.HasCtxt = $true; $field = 'ctxt' }
                '^msgid$' { $cur.Id = $value; $field = 'id' }
                '^msgid_plural$' { $cur.Plural = $value; $field = 'plural' }
                '^msgstr' { $cur.Strs.Add($value); $cur.StrIndex = $cur.Strs.Count - 1; $field = 'str' }
            }
            continue
        }
        if ($line.StartsWith('"')) {
            if ($null -eq $cur -or $null -eq $field) { throw "${Path}:${lineNo}: continuation line without a keyword" }
            $value = ConvertFrom-PoString $line
            switch ($field) {
                'ctxt' { $cur.Ctxt += $value }
                'id' { $cur.Id += $value }
                'plural' { $cur.Plural += $value }
                'str' { $cur.Strs[$cur.StrIndex] = $cur.Strs[$cur.StrIndex] + $value }
            }
            continue
        }
        throw "${Path}:${lineNo}: cannot parse line: $raw"
    }
    . $flush
    return $entries
}

function Format-Key([string]$Key) {
    $parts = $Key.Split([char]4)
    if ($parts.Count -eq 2) { return "[$($parts[0])] `"$($parts[1])`"" }
    return "`"$Key`""
}

# ---------------------------------------------------------------------------- main
# Message texts are reported verbatim; print them as UTF-8 (CI logs, redirected output).
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false } catch { }

try {
    if (-not (Test-Path -LiteralPath $UiDir -PathType Container)) { throw "UI folder not found: $UiDir" }
    if (-not (Test-Path -LiteralPath $PoPath -PathType Leaf)) { throw "Japanese catalog not found: $PoPath" }
    $exe = Resolve-Extractor
} catch {
    Write-Host "check-translations: $_"
    exit 2
}

$problems = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]
$tempPot = Join-Path ([IO.Path]::GetTempPath()) ('wol-manager-' + [guid]::NewGuid().ToString('N') + '.pot')

try {
    # Relative paths (from the crate folder) keep the "#:" references stable across machines.
    $files = @(Get-ChildItem -LiteralPath $UiDir -Recurse -File -Filter '*.slint' | Sort-Object FullName |
        ForEach-Object { $_.FullName.Substring($CrateDir.Length + 1).Replace('\', '/') })
    if ($files.Count -eq 0) { throw "No .slint files under $UiDir" }

    Push-Location -LiteralPath $CrateDir
    try {
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & $exe --no-default-translation-context -o $tempPot @files | Out-Host
        $code = $LASTEXITCODE
        $ErrorActionPreference = $prev
        if ($code -ne 0) { throw "slint-tr-extractor failed with exit code $code" }
    } finally {
        Pop-Location
    }

    $fresh = @(Read-PoFile $tempPot | Where-Object { $_.Id -ne '' -and -not $_.Obsolete })
    $po = @(Read-PoFile $PoPath)
    $poByKey = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    foreach ($e in $po) { if (-not $e.Obsolete -and $e.Id -ne '') { $poByKey[$e.Key] = $e } }

    # Header
    $header = $po | Where-Object { $_.Id -eq '' -and -not $_.HasCtxt } | Select-Object -First 1
    if (-not $header -or $header.Strs.Count -eq 0 -or $header.Strs[0] -notmatch 'Plural-Forms:\s*nplurals=1;\s*plural=0;') {
        $problems.Add("wol-manager.po: header must contain 'Plural-Forms: nplurals=1; plural=0;'")
    }

    # Every extracted message must be translated.
    foreach ($e in $fresh) {
        $t = $null
        [void]$poByKey.TryGetValue($e.Key, [ref]$t)
        $label = Format-Key $e.Key
        if ($null -eq $t) { $problems.Add("missing in ja .po: $label"); continue }
        if ($t.Fuzzy) { $problems.Add("fuzzy in ja .po (line $($t.Line)): $label") }
        if ($t.Strs.Count -eq 0 -or @($t.Strs | Where-Object { $_ -eq '' }).Count -gt 0) {
            $problems.Add("empty msgstr in ja .po (line $($t.Line)): $label")
        }
        if ($null -ne $e.Plural -and $null -eq $t.Plural) { $problems.Add("ja .po entry is not a plural entry (line $($t.Line)): $label") }
    }

    # Unused translations (not an error: they may belong to strings removed on purpose).
    $freshKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($e in $fresh) { [void]$freshKeys.Add($e.Key) }
    foreach ($k in $poByKey.Keys) {
        if (-not $freshKeys.Contains($k)) { $warnings.Add("unused entry in ja .po: $(Format-Key $k)") }
    }

    # Committed template must be current.
    if (Test-Path -LiteralPath $PotPath -PathType Leaf) {
        $committedKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($e in (Read-PoFile $PotPath)) {
            if ($e.Id -ne '' -and -not $e.Obsolete) { [void]$committedKeys.Add($e.Key) }
        }
        foreach ($k in $freshKeys) {
            if (-not $committedKeys.Contains($k)) {
                $problems.Add("missing from lang/wol-manager.pot: $(Format-Key $k) (re-extract with slint-tr-extractor)")
            }
        }
        foreach ($k in $committedKeys) {
            if (-not $freshKeys.Contains($k)) {
                $problems.Add("stale in lang/wol-manager.pot: $(Format-Key $k) (re-extract with slint-tr-extractor)")
            }
        }
    } else {
        $warnings.Add('lang/wol-manager.pot is not committed; skipped the template freshness check')
    }

    Write-Host "Extracted $($fresh.Count) message(s) from $($files.Count) .slint file(s); ja .po has $($poByKey.Count) entr(y/ies)."
} catch {
    Write-Host "check-translations: $_"
    exit 2
} finally {
    Remove-Item -LiteralPath $tempPot -Force -ErrorAction SilentlyContinue
}

foreach ($w in $warnings) { Write-Warning $w }
if ($problems.Count -gt 0) {
    Write-Host 'Translation check FAILED:' -ForegroundColor Red
    foreach ($p in $problems) { Write-Host "  - $p" }
    exit 1
}
Write-Host 'Translation check passed.'
exit 0
