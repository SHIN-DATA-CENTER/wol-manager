<#
.SYNOPSIS
  Silent end-to-end tests of the WoL Manager NSIS installer and uninstaller.

.DESCRIPTION
  THIS SCRIPT REALLY INSTALLS AND UNINSTALLS WoL Manager ON THIS MACHINE and changes the
  user (and, when elevated, the machine) PATH through the installer. It is meant for CI runners
  and test VMs. Outside GitHub Actions it refuses to run unless -AllowMachineChanges is given.
  It also refuses to run when WoL Manager is already installed (it would remove that copy).
  Existing %APPDATA%\wol-manager and %LOCALAPPDATA%\wol-manager folders are renamed to a
  backup name for the duration of the test and restored afterwards.

  Cases (implementation plan, section 11, items 6-8):
    A  per-user install (/S /CurrentUser): files, HKCU uninstall key, PathEntryAdded=1,
       user PATH, Start menu shortcut, `wolm --version` from a NEW process
    B  upgrade in place (/S without a scope switch)
    C  other scope already installed (/S /AllUsers with a per-user install) -> exit 4
    D  bin\wolm.exe locked -> exit 3, installation untouched
    E  running GUI (simulated mutex + quit event) is asked to quit, then the upgrade succeeds
    F  running GUI that does not quit -> exit 3
    G  uninstall through QuietUninstallString: files, key, shortcut and PATH entry removed,
       PATH value byte-identical to before, settings kept
    H  /PURGE: settings removed
    I  /D=<dir with spaces> /NoPath /DesktopShortcut
    J  /ElevatedChild without elevation -> exit 740 (only when not elevated)
    K  all users (only when elevated): HKLM (64-bit view), Program Files, machine PATH,
       common Start menu, other scope -> exit 4, uninstall and cleanup
    L  an upgrade follows PATH changes made outside the installer (wolm path add after
       /NoPath, as the GUI's PATH switch does; wolm path remove after a PATH install)
    M  upgrade with /D= naming another folder -> exit 2, nothing installed there; the same
       folder spelled differently (case, trailing backslash) upgrades in place
    N  /S /AllUsers /D=<folder outside Program Files> without /AllowOutsideProgramFiles
       -> exit 2, nothing installed
  Every case cleans up after itself, and a final sweep uninstalls anything left behind
  (in a finally block, also after a failure).
  Not covered: a non-elevated "All users" installation (UAC prompt, elevated child, passing
  on its exit code). Test it by hand (plan section 11, item 7).

  Exit code: 0 = all cases passed, 1 = at least one failure, 2 = could not run.

.PARAMETER Setup
  Installer to test. Default: the newest dist\wol-manager-*-setup-x64.exe.

.PARAMETER AllowMachineChanges
  Required outside GitHub Actions (see above).

.PARAMETER SkipAllUsers
  Skip case K even when running elevated.

.PARAMETER TimeoutSeconds
  Maximum time for one installer / uninstaller run.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\smoke-installer.ps1 -AllowMachineChanges
#>
[CmdletBinding()]
param(
    [string]$Setup,
    [switch]$AllowMachineChanges,
    [switch]$SkipAllUsers,
    [int]$TimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot

# ---------------------------------------------------------------------------- configuration
function Get-WolMetadata([string]$Key) {
    # Minimal reader for [workspace.metadata.wol] in Cargo.toml (no cargo needed).
    $text = [IO.File]::ReadAllText((Join-Path $RepoRoot 'Cargo.toml'), [Text.Encoding]::UTF8)
    $section = [regex]::Match($text, '(?ms)^\[workspace\.metadata\.wol\]\s*$(.*?)(^\[|\z)')
    if (-not $section.Success) { throw '[workspace.metadata.wol] not found in Cargo.toml' }
    $m = [regex]::Match($section.Groups[1].Value, '(?m)^\s*' + [regex]::Escape($Key) + '\s*=\s*([''"])(.*?)\1\s*$')
    if (-not $m.Success) { throw "[workspace.metadata.wol] $Key not found" }
    return $m.Groups[2].Value
}

$UninstallKeyName = Get-WolMetadata 'uninstall-key'
$InstallDirName = Get-WolMetadata 'install-dir-name'
$AppDirName = Get-WolMetadata 'app-dir-name'
$MutexName = Get-WolMetadata 'gui-mutex'
$QuitEventName = Get-WolMetadata 'gui-quit-event'
$GuiExe = Get-WolMetadata 'gui-exe'
$CliExe = Get-WolMetadata 'cli-exe'
$CliSubdir = Get-WolMetadata 'cli-subdir'
$ShortcutName = (Get-WolMetadata 'product-name') + '.lnk'
$UninstallSubKey = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$UninstallKeyName"

if (-not $Setup) {
    $candidate = Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'dist') -Filter '*-setup-x64.exe' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if (-not $candidate) { Write-Host 'No installer found in dist\. Run scripts\build.ps1 first or pass -Setup.'; exit 2 }
    $Setup = $candidate.FullName
}
$Setup = (Resolve-Path -LiteralPath $Setup).Path
$verMatch = [regex]::Match((Split-Path -Leaf $Setup), '^.+?-(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?)-setup-x64\.exe$')
if (-not $verMatch.Success) { Write-Host "Cannot read the version from '$Setup'."; exit 2 }
$Version = $verMatch.Groups[1].Value

$IsCi = ($env:GITHUB_ACTIONS -eq 'true')
$IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsCi -and -not $AllowMachineChanges) {
    Write-Host 'This script installs and uninstalls WoL Manager on THIS machine and changes PATH.'
    Write-Host 'Run it on a CI runner or a test VM, with -AllowMachineChanges.'
    exit 2
}

$UserDefaultDir = Join-Path $env:LOCALAPPDATA "Programs\$InstallDirName"
$MachineDefaultDir = Join-Path $env:ProgramW6432 $InstallDirName
$TempRoot = Join-Path ([IO.Path]::GetTempPath()) ('wol-smoke-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null

# ---------------------------------------------------------------------------- helpers
function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "ASSERT: $Message" }
}

function Open-HiveKey([string]$Scope, [string]$SubKey, [bool]$Writable = $false) {
    $hive = if ($Scope -eq 'AllUsers') { [Microsoft.Win32.RegistryHive]::LocalMachine } else { [Microsoft.Win32.RegistryHive]::CurrentUser }
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, [Microsoft.Win32.RegistryView]::Registry64)
    try { return $base.OpenSubKey($SubKey, $Writable) } finally { $base.Close() }
}

# Values of the Add/Remove Programs entry, or $null.
function Get-Arp([string]$Scope) {
    $k = Open-HiveKey $Scope $UninstallSubKey
    if (-not $k) { return $null }
    try {
        $h = @{}
        foreach ($n in $k.GetValueNames()) { $h[$n] = $k.GetValue($n) }
        return $h
    } finally { $k.Close() }
}

function Get-RawPath([string]$Scope) {
    $sub = if ($Scope -eq 'AllUsers') { 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment' } else { 'Environment' }
    $k = Open-HiveKey $Scope $sub
    try {
        if (-not $k -or -not (@($k.GetValueNames()) -contains 'Path')) {
            return [pscustomobject]@{ Exists = $false; Value = ''; Kind = 'None' }
        }
        return [pscustomobject]@{
            Exists = $true
            Value  = [string]$k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            Kind   = [string]$k.GetValueKind('Path')
        }
    } finally { if ($k) { $k.Close() } }
}

function ConvertTo-NormalPath([string]$Entry) {
    $e = [Environment]::ExpandEnvironmentVariables($Entry.Trim().Trim('"')).TrimEnd('\')
    return $e
}

function Get-PathEntryCount([string]$RawPath, [string]$Dir) {
    $want = ConvertTo-NormalPath $Dir
    return @($RawPath -split ';' | Where-Object { $_ -and ((ConvertTo-NormalPath $_) -ieq $want) }).Count
}

function Wait-ExitCode([System.Diagnostics.Process]$Process, [string]$What) {
    if (-not $Process.WaitForExit($TimeoutSeconds * 1000)) {
        try { $Process.Kill() } catch { }
        throw "$What did not finish within $TimeoutSeconds s"
    }
    return $Process.ExitCode
}

# Runs the installer with a raw argument string (/D= must be last and unquoted).
function Invoke-Setup([string]$Arguments) {
    Write-Host "    setup $Arguments"
    $p = Start-Process -FilePath $Setup -ArgumentList $Arguments -PassThru
    $null = $p.Handle   # PS 5.1: keeps ExitCode available after exit
    $code = Wait-ExitCode $p 'setup'
    Write-Host "    -> exit $code"
    return $code
}

# Runs a copy of <InstDir>\uninstall.exe with _?=<InstDir> so that it runs in place, can be
# waited for and returns its exit code (the uninstall.exe in InstDir is still deleted).
function Invoke-UninstallCopy([string]$InstDir, [string]$Arguments) {
    $src = Join-Path $InstDir 'uninstall.exe'
    Assert (Test-Path -LiteralPath $src -PathType Leaf) "uninstaller missing: $src"
    $copy = Join-Path $TempRoot ('uninst-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.exe')
    Copy-Item -LiteralPath $src -Destination $copy
    try {
        $argLine = "$Arguments _?=$InstDir"
        Write-Host "    uninstall $argLine"
        $p = Start-Process -FilePath $copy -ArgumentList $argLine -PassThru
        $null = $p.Handle   # PS 5.1: keeps ExitCode available after exit
        $code = Wait-ExitCode $p 'uninstaller'
        Write-Host "    -> exit $code"
        return $code
    } finally {
        Remove-Item -LiteralPath $copy -Force -ErrorAction SilentlyContinue
    }
}

# Runs an installed wolm.exe (e.g. "path add"), like the GUI's PATH switch would change PATH
# without the installer. Returns its exit code.
function Invoke-Wolm([string]$Exe, [string[]]$Arguments) {
    Write-Host "    wolm $($Arguments -join ' ')"
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'   # PS 5.1: stderr lines of native programs are not errors
    try {
        & $Exe @Arguments | Out-Host
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prev
    }
    Write-Host "    -> exit $code"
    return $code
}

# Runs QuietUninstallString like "Apps & Features" would. The uninstaller stub re-launches
# itself from %TEMP% and exits at once, so completion is detected from the machine state.
function Invoke-QuietUninstallString([string]$Scope) {
    $arp = Get-Arp $Scope
    Assert ($null -ne $arp) "no uninstall entry for $Scope"
    $cmd = [string]$arp['QuietUninstallString']
    $m = [regex]::Match($cmd, '^"([^"]+)"\s*(.*)$')
    Assert $m.Success "unexpected QuietUninstallString: $cmd"
    $exe = $m.Groups[1].Value
    Write-Host "    $cmd"
    $p = Start-Process -FilePath $exe -ArgumentList $m.Groups[2].Value -PassThru
    $null = $p.Handle   # PS 5.1: keeps ExitCode available after exit
    $code = Wait-ExitCode $p 'uninstaller stub'
    Assert ($code -eq 0) "uninstaller stub exit code $code"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-Arp $Scope) -and -not (Test-Path -LiteralPath $exe)) { return }
        Start-Sleep -Milliseconds 500
    }
    throw "uninstall through QuietUninstallString did not finish within $TimeoutSeconds s"
}

# Runs a command in a NEW process whose PATH is rebuilt from the registry, like a newly
# opened terminal (the PATH of this process does not see the installer's change).
function Invoke-NewShell([string]$CommandLine) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $psi.Arguments = "/d /c $CommandLine"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $psi.EnvironmentVariables['PATH'] = (@($machine, $user) | Where-Object { $_ }) -join ';'
    $p = [System.Diagnostics.Process]::Start($psi)
    $stdout = $p.StandardOutput.ReadToEnd()
    $null = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    return [pscustomobject]@{ ExitCode = $p.ExitCode; Output = $stdout.Trim() }
}

function Assert-Installed([string]$Scope, [string]$Dir, [bool]$ExpectPath) {
    foreach ($f in @($GuiExe, 'uninstall.exe', 'LICENSE.txt', 'THIRD-PARTY-NOTICES.txt', "$CliSubdir\$CliExe")) {
        Assert (Test-Path -LiteralPath (Join-Path $Dir $f) -PathType Leaf) "missing file $Dir\$f"
    }
    $arp = Get-Arp $Scope
    Assert ($null -ne $arp) "uninstall key missing ($Scope)"
    Assert ([string]$arp['DisplayVersion'] -eq $Version) "DisplayVersion '$($arp['DisplayVersion'])' <> '$Version'"
    Assert ([string]$arp['InstallLocation'] -ieq $Dir) "InstallLocation '$($arp['InstallLocation'])' <> '$Dir'"
    Assert ([string]$arp['InstallMode'] -eq $Scope) "InstallMode '$($arp['InstallMode'])' <> '$Scope'"
    Assert ([string]$arp['UninstallString'] -eq "`"$Dir\uninstall.exe`" /$Scope") "UninstallString '$($arp['UninstallString'])'"
    Assert ([string]$arp['QuietUninstallString'] -eq "`"$Dir\uninstall.exe`" /$Scope /S") "QuietUninstallString '$($arp['QuietUninstallString'])'"
    foreach ($n in @('DisplayName', 'Publisher', 'DisplayIcon', 'URLInfoAbout')) {
        Assert ([string]$arp[$n] -ne '') "$n is empty"
    }
    Assert ([int]$arp['EstimatedSize'] -gt 0) 'EstimatedSize missing'
    Assert ([int]$arp['NoModify'] -eq 1 -and [int]$arp['NoRepair'] -eq 1) 'NoModify/NoRepair not set'
    Assert ($arp.ContainsKey('VersionMajor') -and $arp.ContainsKey('VersionMinor')) 'VersionMajor/VersionMinor missing'
    $flag = if ($arp.ContainsKey('PathEntryAdded')) { [int]$arp['PathEntryAdded'] } else { -1 }
    $raw = Get-RawPath $Scope
    $bin = Join-Path $Dir $CliSubdir
    if ($ExpectPath) {
        Assert ($flag -eq 1) "PathEntryAdded is $flag, expected 1"
        Assert ((Get-PathEntryCount $raw.Value $bin) -eq 1) "$bin is not on the $Scope PATH exactly once"
        $where = Invoke-NewShell "where $CliExe"
        Assert (@($where.Output -split "`r?`n" | Where-Object { $_ -ieq (Join-Path $bin $CliExe) }).Count -eq 1) "new shell: 'where $CliExe' did not find $bin\$CliExe (got: $($where.Output))"
        $ver = Invoke-NewShell "$([IO.Path]::GetFileNameWithoutExtension($CliExe)) --version"
        Assert ($ver.ExitCode -eq 0 -and $ver.Output.Contains($Version)) "new shell: 'wolm --version' -> exit $($ver.ExitCode), '$($ver.Output)'"
    } else {
        Assert ($flag -eq 0) "PathEntryAdded is $flag, expected 0"
        Assert ((Get-PathEntryCount $raw.Value $bin) -eq 0) "$bin is on the $Scope PATH although /NoPath was given"
    }
}

function Assert-Removed([string]$Scope, [string]$Dir) {
    Assert ($null -eq (Get-Arp $Scope)) "uninstall key still present ($Scope)"
    Assert (-not (Test-Path -LiteralPath $Dir)) "install folder still present: $Dir"
    $raw = Get-RawPath $Scope
    Assert ((Get-PathEntryCount $raw.Value (Join-Path $Dir $CliSubdir)) -eq 0) "PATH entry still present ($Scope)"
}

function Assert-PathUnchanged([string]$Scope, $Before) {
    $after = Get-RawPath $Scope
    if (-not $Before.Exists) {
        Assert (-not $after.Exists -or $after.Value -eq '') "$Scope PATH did not exist before but is now '$($after.Value)'"
        return
    }
    Assert ($after.Kind -eq $Before.Kind) "$Scope PATH value type changed: $($Before.Kind) -> $($after.Kind)"
    Assert ($after.Value -ceq $Before.Value) "$Scope PATH differs from before the test:`n  before: $($Before.Value)`n  after:  $($after.Value)"
}

function Get-ShortcutPath([string]$Folder) {
    return Join-Path ([Environment]::GetFolderPath($Folder)) $ShortcutName
}

function New-SettingsSentinels {
    foreach ($d in @((Join-Path $env:APPDATA $AppDirName), (Join-Path $env:LOCALAPPDATA $AppDirName))) {
        New-Item -ItemType Directory -Force -Path $d | Out-Null
        [IO.File]::WriteAllText((Join-Path $d 'smoke-sentinel.txt'), 'smoke test')
    }
}

function Test-SettingsSentinels {
    return (Test-Path -LiteralPath (Join-Path (Join-Path $env:APPDATA $AppDirName) 'smoke-sentinel.txt')) -and
           (Test-Path -LiteralPath (Join-Path (Join-Path $env:LOCALAPPDATA $AppDirName) 'smoke-sentinel.txt'))
}

# Uninstalls whatever this script may have left behind (best effort, never throws).
function Remove-Leftovers {
    foreach ($scope in @('CurrentUser', 'AllUsers')) {
        try {
            $arp = Get-Arp $scope
            if (-not $arp) { continue }
            $dir = [string]$arp['InstallLocation']
            if ($scope -eq 'AllUsers' -and -not $IsElevated) {
                Write-Warning "An all-users installation is left in $dir; uninstall it from an elevated shell."
                continue
            }
            if ($dir -and (Test-Path -LiteralPath (Join-Path $dir 'uninstall.exe'))) {
                Write-Host "  cleanup: uninstalling $scope copy in $dir"
                $null = Invoke-UninstallCopy $dir "/S /$scope"
            }
        } catch {
            Write-Warning "cleanup of $scope failed: $_"
        }
    }
}

# ---------------------------------------------------------------------------- test driver
$results = New-Object System.Collections.Generic.List[object]
function Invoke-Case([string]$Id, [string]$Title, [scriptblock]$Body) {
    Write-Host ''
    Write-Host "[$Id] $Title" -ForegroundColor Cyan
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        & $Body
        $results.Add([pscustomobject]@{ Id = $Id; Title = $Title; Result = 'PASS'; Detail = '' })
        Write-Host "[$Id] PASS ($([int]$sw.Elapsed.TotalSeconds) s)" -ForegroundColor Green
    } catch {
        $results.Add([pscustomobject]@{ Id = $Id; Title = $Title; Result = 'FAIL'; Detail = "$_" })
        Write-Host "[$Id] FAIL: $_" -ForegroundColor Red
        if ($IsCi) {
            # GitHub annotation (visible on the run page without opening the log).
            $msg = ("[$Id] $Title -- $_") -replace '%', '%25' -replace "`r", '%0D' -replace "`n", '%0A'
            Write-Host "::error title=Installer smoke test::$msg"
        }
        Remove-Leftovers
    }
}
function Skip-Case([string]$Id, [string]$Title, [string]$Reason) {
    Write-Host ''
    Write-Host "[$Id] $Title - SKIPPED: $Reason" -ForegroundColor Yellow
    $results.Add([pscustomobject]@{ Id = $Id; Title = $Title; Result = 'SKIP'; Detail = $Reason })
}

# ---------------------------------------------------------------------------- pre-flight
Write-Host "Installer: $Setup"
Write-Host "Version:   $Version"
Write-Host "Elevated:  $IsElevated"
foreach ($scope in @('CurrentUser', 'AllUsers')) {
    $arp = Get-Arp $scope
    if ($arp) {
        Write-Host "WoL Manager is already installed ($scope, $($arp['InstallLocation'])). Uninstall it first; this test would remove it."
        exit 2
    }
}
foreach ($d in @($UserDefaultDir, $MachineDefaultDir)) {
    if (Test-Path -LiteralPath $d) { Write-Host "Folder already exists: $d. Remove it first."; exit 2 }
}

$userPathBefore = Get-RawPath 'CurrentUser'
$machinePathBefore = Get-RawPath 'AllUsers'
$settingsBackups = @{}

try {
    # Keep real settings out of harm's way (they are renamed, never deleted).
    foreach ($d in @((Join-Path $env:APPDATA $AppDirName), (Join-Path $env:LOCALAPPDATA $AppDirName))) {
        if (Test-Path -LiteralPath $d) {
            $backup = "$d.smoke-backup-" + (Get-Date -Format 'yyyyMMddHHmmss')
            Rename-Item -LiteralPath $d -NewName (Split-Path -Leaf $backup)
            $settingsBackups[$d] = $backup
            Write-Host "Settings folder moved aside: $d -> $backup"
        } else {
            $settingsBackups[$d] = $null
        }
    }

    Invoke-Case 'A' 'Per-user install (/S /CurrentUser)' {
        Assert ((Invoke-Setup '/S /CurrentUser') -eq 0) 'exit code'
        Assert-Installed 'CurrentUser' $UserDefaultDir $true
        Assert (Test-Path -LiteralPath (Get-ShortcutPath 'Programs')) 'Start menu shortcut missing'
        $after = Get-RawPath 'CurrentUser'
        if ($userPathBefore.Exists) { Assert ($after.Kind -eq $userPathBefore.Kind) "user PATH type changed: $($userPathBefore.Kind) -> $($after.Kind)" }
    }

    Invoke-Case 'B' 'Upgrade in place (/S, scope from the existing installation)' {
        if (-not (Get-Arp 'CurrentUser')) { Assert ((Invoke-Setup '/S /CurrentUser') -eq 0) 'setup for B' }
        Assert ((Invoke-Setup '/S') -eq 0) 'exit code'
        Assert-Installed 'CurrentUser' $UserDefaultDir $true
    }

    Invoke-Case 'C' 'Installed for the other scope (/S /AllUsers) -> exit 4' {
        if (-not (Get-Arp 'CurrentUser')) { Assert ((Invoke-Setup '/S /CurrentUser') -eq 0) 'setup for C' }
        Assert ((Invoke-Setup '/S /AllUsers') -eq 4) 'exit code (expected 4)'
        Assert ($null -eq (Get-Arp 'AllUsers')) 'an all-users entry was created'
    }

    Invoke-Case 'D' 'bin\wolm.exe in use -> exit 3' {
        if (-not (Get-Arp 'CurrentUser')) { Assert ((Invoke-Setup '/S /CurrentUser') -eq 0) 'setup for D' }
        $wolm = Join-Path $UserDefaultDir "$CliSubdir\$CliExe"
        $before = (Get-Item -LiteralPath $wolm).LastWriteTimeUtc
        $lock = [IO.File]::Open($wolm, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            Assert ((Invoke-Setup '/S /CurrentUser') -eq 3) 'exit code (expected 3)'
        } finally {
            $lock.Dispose()
        }
        Assert ((Get-Item -LiteralPath $wolm).LastWriteTimeUtc -eq $before) 'wolm.exe was modified'
        Assert-Installed 'CurrentUser' $UserDefaultDir $true
    }

    Invoke-Case 'E' 'Running GUI is asked to quit (mutex + quit event), then upgraded' {
        if (-not (Get-Arp 'CurrentUser')) { Assert ((Invoke-Setup '/S /CurrentUser') -eq 0) 'setup for E' }
        $mutex = New-Object System.Threading.Mutex($false, $MutexName)
        $quit = New-Object System.Threading.EventWaitHandle($false, [Threading.EventResetMode]::AutoReset, $QuitEventName)
        $signaled = $false
        try {
            Write-Host "    setup /S /CurrentUser (fake GUI running)"
            $p = Start-Process -FilePath $Setup -ArgumentList '/S /CurrentUser' -PassThru
            $null = $p.Handle   # PS 5.1: keeps ExitCode available after exit
            $deadline = (Get-Date).AddSeconds(30)
            while (-not $signaled -and -not $p.HasExited -and (Get-Date) -lt $deadline) {
                $signaled = $quit.WaitOne(250)
            }
        } finally {
            # "Quit": close the handles so that the named mutex disappears.
            $quit.Dispose()
            $mutex.Dispose()
        }
        Assert $signaled 'the installer did not set the quit event'
        $code = Wait-ExitCode $p 'setup'
        Write-Host "    -> exit $code"
        Assert ($code -eq 0) "exit code $code"
        Assert-Installed 'CurrentUser' $UserDefaultDir $true
    }

    Invoke-Case 'F' 'Running GUI that does not quit -> exit 3' {
        if (-not (Get-Arp 'CurrentUser')) { Assert ((Invoke-Setup '/S /CurrentUser') -eq 0) 'setup for F' }
        $mutex = New-Object System.Threading.Mutex($false, $MutexName)
        try {
            Assert ((Invoke-Setup '/S /CurrentUser') -eq 3) 'exit code (expected 3 after the 10 s wait)'
        } finally {
            $mutex.Dispose()
        }
    }

    Invoke-Case 'G' 'Uninstall via QuietUninstallString keeps settings and restores PATH' {
        if (-not (Get-Arp 'CurrentUser')) { Assert ((Invoke-Setup '/S /CurrentUser') -eq 0) 'setup for G' }
        New-SettingsSentinels
        Invoke-QuietUninstallString 'CurrentUser'
        Assert-Removed 'CurrentUser' $UserDefaultDir
        Assert (-not (Test-Path -LiteralPath (Get-ShortcutPath 'Programs'))) 'Start menu shortcut still present'
        Assert-PathUnchanged 'CurrentUser' $userPathBefore
        Assert (Test-SettingsSentinels) 'settings were deleted without /PURGE'
    }

    Invoke-Case 'H' 'Uninstall with /PURGE removes settings' {
        Assert ((Invoke-Setup '/S /CurrentUser') -eq 0) 'install exit code'
        New-SettingsSentinels
        Assert ((Invoke-UninstallCopy $UserDefaultDir '/S /CurrentUser /PURGE') -eq 0) 'uninstall exit code'
        Assert-Removed 'CurrentUser' $UserDefaultDir
        Assert (-not (Test-Path -LiteralPath (Join-Path $env:APPDATA $AppDirName))) '%APPDATA% settings folder still present'
        Assert (-not (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA $AppDirName))) '%LOCALAPPDATA% folder still present'
        Assert-PathUnchanged 'CurrentUser' $userPathBefore
    }

    Invoke-Case 'I' '/D=<folder with spaces> /NoPath /DesktopShortcut' {
        $dir = Join-Path $TempRoot 'WoL Test Install'
        Assert ((Invoke-Setup "/S /CurrentUser /NoPath /DesktopShortcut /D=$dir") -eq 0) 'install exit code'
        Assert-Installed 'CurrentUser' $dir $false
        Assert (-not (Test-Path -LiteralPath $UserDefaultDir)) '/D= was ignored (default folder was used)'
        $desktop = Get-ShortcutPath 'DesktopDirectory'
        Assert (Test-Path -LiteralPath $desktop) 'desktop shortcut missing'
        Assert ((Invoke-UninstallCopy $dir '/S /CurrentUser') -eq 0) 'uninstall exit code'
        Assert-Removed 'CurrentUser' $dir
        Assert (-not (Test-Path -LiteralPath $desktop)) 'desktop shortcut still present'
        Assert-PathUnchanged 'CurrentUser' $userPathBefore
    }

    if ($IsElevated) {
        Skip-Case 'J' '/ElevatedChild without elevation -> exit 740' 'this shell is elevated'
    } else {
        Invoke-Case 'J' '/ElevatedChild without elevation -> exit 740' {
            Assert ((Invoke-Setup '/S /AllUsers /ElevatedChild') -eq 740) 'exit code (expected 740)'
            Assert ($null -eq (Get-Arp 'AllUsers')) 'an all-users entry was created'
        }
    }

    if (-not $IsElevated) {
        Skip-Case 'K' 'All users (/S /AllUsers)' 'needs an elevated shell (run again as administrator to cover it)'
    } elseif ($SkipAllUsers) {
        Skip-Case 'K' 'All users (/S /AllUsers)' '-SkipAllUsers'
    } else {
        Invoke-Case 'K' 'All users (/S /AllUsers), other scope -> 4, uninstall' {
            Assert ((Invoke-Setup '/S /AllUsers') -eq 0) 'install exit code'
            Assert-Installed 'AllUsers' $MachineDefaultDir $true
            Assert (Test-Path -LiteralPath (Get-ShortcutPath 'CommonPrograms')) 'common Start menu shortcut missing'
            Assert ((Invoke-Setup '/S /CurrentUser') -eq 4) 'per-user install next to all-users (expected 4)'
            Assert ($null -eq (Get-Arp 'CurrentUser')) 'a per-user entry was created'
            Assert ((Invoke-UninstallCopy $MachineDefaultDir '/S /AllUsers') -eq 0) 'uninstall exit code'
            Assert-Removed 'AllUsers' $MachineDefaultDir
            Assert (-not (Test-Path -LiteralPath (Get-ShortcutPath 'CommonPrograms'))) 'common Start menu shortcut still present'
            Assert-PathUnchanged 'AllUsers' $machinePathBefore
        }
    }

    Invoke-Case 'L' 'Upgrade follows PATH changes made outside the installer' {
        if (Get-Arp 'CurrentUser') { Remove-Leftovers }
        $wolm = Join-Path $UserDefaultDir "$CliSubdir\$CliExe"
        $bin = Join-Path $UserDefaultDir $CliSubdir
        Assert ((Invoke-Setup '/S /CurrentUser /NoPath') -eq 0) 'install exit code'
        Assert-Installed 'CurrentUser' $UserDefaultDir $false
        # Added afterwards (the GUI's PATH switch does the same): an upgrade must keep it.
        Assert ((Invoke-Wolm $wolm @('path', 'add', '--scope', 'user', $bin)) -eq 0) 'wolm path add'
        Assert ((Invoke-Setup '/S') -eq 0) 'upgrade exit code'
        Assert-Installed 'CurrentUser' $UserDefaultDir $true
        # Removed afterwards: an upgrade must not add it again.
        Assert ((Invoke-Wolm $wolm @('path', 'remove', '--scope', 'user', $bin)) -eq 0) 'wolm path remove'
        Assert ((Invoke-Setup '/S') -eq 0) 'second upgrade exit code'
        Assert-Installed 'CurrentUser' $UserDefaultDir $false
        Assert ((Invoke-UninstallCopy $UserDefaultDir '/S /CurrentUser') -eq 0) 'uninstall exit code'
        Assert-Removed 'CurrentUser' $UserDefaultDir
        Assert-PathUnchanged 'CurrentUser' $userPathBefore
    }

    Invoke-Case 'M' 'Upgrade with /D= naming another folder -> exit 2' {
        if (Get-Arp 'CurrentUser') { Remove-Leftovers }
        Assert ((Invoke-Setup '/S /CurrentUser') -eq 0) 'install exit code'
        $other = Join-Path $TempRoot 'WoL Other Folder'
        Assert ((Invoke-Setup "/S /D=$other") -eq 2) 'upgrade with another /D= (expected 2)'
        Assert (-not (Test-Path -LiteralPath $other)) "a second copy was installed in $other"
        Assert-Installed 'CurrentUser' $UserDefaultDir $true
        # The same folder spelled differently is an upgrade in place.
        $same = $UserDefaultDir.ToUpperInvariant() + '\'
        Assert ((Invoke-Setup "/S /CurrentUser /D=$same") -eq 0) 'upgrade with the same folder as /D='
        Assert-Installed 'CurrentUser' $UserDefaultDir $true
        Assert ((Invoke-UninstallCopy $UserDefaultDir '/S /CurrentUser') -eq 0) 'uninstall exit code'
        Assert-Removed 'CurrentUser' $UserDefaultDir
        Assert-PathUnchanged 'CurrentUser' $userPathBefore
    }

    Invoke-Case 'N' 'All users outside Program Files without /AllowOutsideProgramFiles -> exit 2' {
        if (Get-Arp 'CurrentUser') { Remove-Leftovers }
        $dir = Join-Path $TempRoot 'WoL AllUsers Outside'
        # Refused in .onInit, before any elevation: runs elevated or not.
        Assert ((Invoke-Setup "/S /AllUsers /D=$dir") -eq 2) 'exit code (expected 2)'
        Assert (-not (Test-Path -LiteralPath $dir)) "something was installed in $dir"
        Assert ($null -eq (Get-Arp 'AllUsers')) 'an all-users entry was created'
    }
} finally {
    Write-Host ''
    Write-Host 'Final cleanup'
    Remove-Leftovers
    foreach ($d in $settingsBackups.Keys) {
        try {
            $backup = $settingsBackups[$d]
            if (Test-Path -LiteralPath $d) {
                # Only test content can be here: the real folder was moved aside or did not exist.
                Remove-Item -LiteralPath $d -Recurse -Force
            }
            if ($backup) {
                Rename-Item -LiteralPath $backup -NewName (Split-Path -Leaf $d)
                Write-Host "Settings folder restored: $d"
            }
        } catch {
            Write-Warning "Could not restore $d (backup: $($settingsBackups[$d])): $_"
        }
    }
    Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host 'Summary'
$results | ForEach-Object { Write-Host ('  [{0}] {1,-4} {2}{3}' -f $_.Id, $_.Result, $_.Title, $(if ($_.Detail) { " -- $($_.Detail)" } else { '' })) }
$failed = @($results | Where-Object { $_.Result -eq 'FAIL' }).Count
if ($failed -gt 0) {
    Write-Host "$failed case(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host 'All cases passed.' -ForegroundColor Green
exit 0
