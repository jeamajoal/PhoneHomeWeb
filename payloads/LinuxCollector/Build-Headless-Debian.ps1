<#
.SYNOPSIS
    Build a headless Debian unattended-install ISO from a Windows host.

.DESCRIPTION
    Windows-side wrapper around Build-Headless-Debian.sh. Runs the bash
    builder inside WSL2; optionally uses usbipd-win to attach a USB device
    so the resulting ISO can be written directly. The output ISO can also
    be produced as a plain file on the Windows filesystem via -Output.

.PARAMETER SshKey
    Windows path to an SSH public key (.pub). Required unless -AllowPassword.

.PARAMETER Output
    Output ISO path. Accepts a Windows path; will be translated to a WSL path
    so the resulting ISO appears on the Windows filesystem.

.PARAMETER NetinstIso
    Pre-downloaded Debian netinst ISO (Windows path supported).

.PARAMETER NetinstUrl
    URL to download the netinst ISO from.

.PARAMETER Device
    USB device path AS SEEN INSIDE WSL after attach (e.g. /dev/sdb).

.PARAMETER BusId
    usbipd-win bus ID to attach into WSL.

.PARAMETER ListUsb
    List USB devices and exit.

.PARAMETER Hostname
    Hostname for the installed system.

.PARAMETER Username
    Sudo user to create.

.PARAMETER Password
    User password (implies -AllowPassword).

.PARAMETER AllowPassword
    Permit password SSH login.

.PARAMETER RootPassword
    Set a root password (default: locked).

.PARAMETER Timezone
    e.g. America/Denver.

.PARAMETER Locale
    e.g. en_US.UTF-8.

.PARAMETER Mirror
    Debian mirror host (default deb.debian.org).

.PARAMETER ExtraPackages
    Space-separated extra packages.

.PARAMETER NoCollector
    Skip embedding the PhoneHomeWeb collector pull.

.PARAMETER ServerUrl
    PhoneHomeWeb server URL.

.PARAMETER AuthKey
    PhoneHomeWeb auth key.

.PARAMETER WslDistro
    WSL distribution to use (default Debian).

.PARAMETER SkipUsbAttach
    Don't call usbipd attach.

.PARAMETER InstallWslIfMissing
    Install WSL/distro automatically if missing (admin required).

.EXAMPLE
    PS> .\Build-Headless-Debian.ps1 -SshKey C:\Users\me\.ssh\id_ed25519.pub -Output C:\Temp\phw.iso

.EXAMPLE
    PS> .\Build-Headless-Debian.ps1 -SshKey ~\.ssh\id_ed25519.pub -BusId 2-3

.NOTES
    Requires WSL2 + a Debian distro; usbipd-win for USB write.
#>

[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification='Forwarded as-is to bash --password / --root-password flags.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPasswordParams', '', Justification='Not a credential pair; bash flags.')]
param(
    [string]$SshKey,
    [string]$Output,
    [string]$NetinstIso,
    [string]$NetinstUrl,
    [string]$Device,
    [string]$BusId,
    [switch]$ListUsb,
    [string]$DebianHostname = "phw-debian",
    [string]$Username = "phw",
    [string]$Password,
    [switch]$AllowPassword,
    [string]$RootPassword,
    [string]$Timezone = "Etc/UTC",
    [string]$Locale = "en_US.UTF-8",
    [string]$Keymap = "us",
    [string]$Mirror = "deb.debian.org",
    [string]$ExtraPackages,
    [switch]$NoCollector,
    [string]$ServerUrl = "<<SERVERURL>>",
    [string]$AuthKey   = "<<AUTHKEY>>",
    [string]$WslDistro = "Debian",
    [switch]$SkipUsbAttach,
    [switch]$SkipWrite,
    [switch]$InstallWslIfMissing,
    [switch]$KeepWork,
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"

function Write-Info  { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor Cyan }
function Write-Ok    { param([string]$m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn2 { param([string]$m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err2  { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }
function Stop-Hard   { param([string]$m) Write-Err2 $m; exit 1 }

function Test-IsAdmin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
function Test-CommandExists { param([string]$Name) [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue) }

function Test-Wsl2 {
    if (-not (Test-CommandExists 'wsl.exe')) { return $false }
    $null = & wsl.exe --status 2>$null
    return ($LASTEXITCODE -eq 0)
}
function Test-WslDistroPresent {
    param([string]$Name)
    if (-not (Test-CommandExists 'wsl.exe')) { return $false }
    $raw = & wsl.exe -l -q 2>$null
    if (-not $raw) { return $false }
    $names = ($raw | ForEach-Object { ($_ -replace "`0", '').Trim() }) | Where-Object { $_ }
    return ($names -contains $Name)
}
function Initialize-Wsl {
    if (-not (Test-Wsl2)) {
        if ($InstallWslIfMissing -and (Test-IsAdmin)) {
            Write-Info "Installing WSL2..."
            & wsl.exe --install --no-distribution
            Stop-Hard "Reboot Windows and re-run this script."
        }
        Stop-Hard "WSL2 is not available. Install with: wsl --install (admin) and reboot."
    }
    if (-not (Test-WslDistroPresent -Name $WslDistro)) {
        if ($InstallWslIfMissing -and (Test-IsAdmin)) {
            Write-Info "Installing WSL distro '$WslDistro'..."
            & wsl.exe --install -d $WslDistro --no-launch
            Stop-Hard "Distro installed. Launch it once to set up a user, then re-run."
        }
        Stop-Hard "WSL distro '$WslDistro' not found. Install with: wsl --install -d $WslDistro"
    }
}

function ConvertTo-WslPath {
    param([string]$p)
    if (-not $p) { return $null }
    if ($p.StartsWith('/')) { return $p }
    $resolved = Resolve-Path -LiteralPath $p -ErrorAction SilentlyContinue
    $candidate = if ($resolved) { $resolved.Path } else { $p }

    $tmpErr = [System.IO.Path]::GetTempFileName()
    try {
        $out = & wsl.exe -d $WslDistro -e wslpath -a "$candidate" 2>$tmpErr
        $code = $LASTEXITCODE
        $errText = (Get-Content -LiteralPath $tmpErr -Raw -ErrorAction SilentlyContinue)
        if ($code -eq 0 -and $out) {
            $clean = (($out -join '').Trim() -replace "`0", '')
            if ($clean) { return $clean }
        }
        Write-Warn2 "wslpath failed (exit=$code). stderr: $errText"
    } finally {
        Remove-Item -LiteralPath $tmpErr -ErrorAction SilentlyContinue
    }

    if ($candidate -match '^([A-Za-z]):[\\/](.*)$') {
        $drive = $Matches[1].ToLowerInvariant()
        $rest  = $Matches[2] -replace '\\', '/'
        $mapped = "/mnt/$drive/$rest"
        Write-Info "Falling back to manual path translation: $mapped"
        return $mapped
    }

    Stop-Hard "wslpath failed for: $p"
}

function Invoke-WslBash {
    param([string]$BashCommand)
    & wsl.exe -d $WslDistro -u root -- bash -lc $BashCommand
    return $LASTEXITCODE
}

function Test-UsbIpd { Test-CommandExists 'usbipd.exe' }
function Show-UsbHint {
    Write-Warn2 "usbipd-win not installed. Install with: winget install --id dorssel.usbipd-win"
}
function Mount-UsbToWsl {
    param([string]$BusId)
    if (-not (Test-UsbIpd)) { Show-UsbHint; Stop-Hard "usbipd-win required (or pass -SkipUsbAttach)." }
    if (-not (Test-IsAdmin)) { Stop-Hard "usbipd bind/attach requires Administrator." }
    & usbipd.exe bind --busid $BusId 2>$null
    & usbipd.exe attach --wsl --busid $BusId --distribution $WslDistro
    if ($LASTEXITCODE -ne 0) { Stop-Hard "usbipd attach failed (exit $LASTEXITCODE)." }
    Write-Ok "USB $BusId attached to '$WslDistro'."
}
function Dismount-UsbFromWsl { param([string]$BusId) if ($BusId -and (Test-UsbIpd)) { & usbipd.exe detach --busid $BusId 2>$null | Out-Null } }

# ----------------------------------------------------------------------------- 

try {
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  PhoneHomeWeb Headless Debian ISO Builder (Windows wrapper)" -ForegroundColor Yellow
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""

    if ($ListUsb) {
        if (Test-UsbIpd) { & usbipd.exe list } else { Show-UsbHint }
        exit 0
    }

    if (-not $SshKey -and -not $AllowPassword -and -not $Password) {
        Stop-Hard "Provide -SshKey <path> and/or -AllowPassword."
    }

    Initialize-Wsl

    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $bashLocal = Join-Path $scriptDir 'Build-Headless-Debian.sh'
    if (-not (Test-Path $bashLocal)) {
        Stop-Hard "Build-Headless-Debian.sh not found next to this script (expected $bashLocal)."
    }

    # Stage scripts inside WSL
    $stageDirWsl = "/var/tmp/phw-headless-build"
    $stageDirWin = ConvertTo-WslPath $scriptDir
    Write-Info "Staging payloads into WSL: $stageDirWsl"
    $stageCmd = @"
set -e
mkdir -p '$stageDirWsl'
cp -f '$stageDirWin'/Build-Headless-Debian.sh '$stageDirWsl/'
find '$stageDirWsl' -type f -name '*.sh' -exec sed -i 's/\r\$//' {} +
chmod +x '$stageDirWsl'/*.sh
"@
    if ((Invoke-WslBash $stageCmd) -ne 0) { Stop-Hard "Failed to stage payloads." }

    # Optional USB attach (only if a device write is desired)
    $writeRequested = ($BusId -or $Device) -and -not $SkipWrite
    if ($writeRequested -and -not $SkipUsbAttach -and $BusId) {
        Mount-UsbToWsl -BusId $BusId
    }

    # Translate paths
    $sshKeyWsl = $null
    if ($SshKey) { $sshKeyWsl = ConvertTo-WslPath $SshKey }
    $netinstWsl = $null
    if ($NetinstIso) { $netinstWsl = ConvertTo-WslPath $NetinstIso }
    $outputWsl = $null
    if ($Output) {
        # Ensure output directory exists on Windows side first
        if (-not (Test-Path (Split-Path -Parent $Output))) {
            New-Item -ItemType Directory -Path (Split-Path -Parent $Output) -Force | Out-Null
        }
        $outputWsl = ConvertTo-WslPath $Output
    }

    # Build bash arg list
    $bashArgs = @()
    if ($sshKeyWsl)        { $bashArgs += @('--ssh-key', $sshKeyWsl) }
    if ($outputWsl)        { $bashArgs += @('--output', $outputWsl) }
    if ($netinstWsl)       { $bashArgs += @('--netinst-iso', $netinstWsl) }
    if ($NetinstUrl)       { $bashArgs += @('--netinst-url', $NetinstUrl) }
    if ($Device)           { $bashArgs += @('--device', $Device) }
    if ($SkipWrite)        { $bashArgs += '--skip-write' }
    if ($DebianHostname)   { $bashArgs += @('--hostname', $DebianHostname) }
    if ($Username)         { $bashArgs += @('--username', $Username) }
    if ($Password)         { $bashArgs += @('--password', $Password) }
    elseif ($AllowPassword){ $bashArgs += '--allow-password' }
    if ($RootPassword)     { $bashArgs += @('--root-password', $RootPassword) }
    if ($Timezone)         { $bashArgs += @('--timezone', $Timezone) }
    if ($Locale)           { $bashArgs += @('--locale', $Locale) }
    if ($Keymap)           { $bashArgs += @('--keymap', $Keymap) }
    if ($Mirror)           { $bashArgs += @('--mirror', $Mirror) }
    if ($ExtraPackages)    { $bashArgs += @('--extra-packages', $ExtraPackages) }
    if ($NoCollector)      { $bashArgs += '--no-collector' }
    if ($KeepWork)         { $bashArgs += '--keep-work' }
    if ($NonInteractive)   { $bashArgs += '--non-interactive' }
    if ($ServerUrl -and $ServerUrl -notmatch '<<SERVERURL>>') { $bashArgs += @('--server-url', $ServerUrl) }
    if ($AuthKey   -and $AuthKey   -notmatch '<<AUTHKEY>>')   { $bashArgs += @('--auth-key',   $AuthKey)   }

    $quoted = ($bashArgs | ForEach-Object { "'" + ($_ -replace "'", "'\''") + "'" }) -join ' '
    $runCmd = "cd '$stageDirWsl' && bash '$stageDirWsl/Build-Headless-Debian.sh' $quoted"

    Write-Info "Running headless ISO builder inside WSL ($WslDistro) as root..."
    Write-Host  "  $runCmd" -ForegroundColor DarkGray
    $rc = Invoke-WslBash $runCmd
    if ($rc -ne 0) { Stop-Hard "Builder exited with code $rc." }

    Write-Ok "Headless ISO build complete."
}
finally {
    if ($BusId -and -not $SkipUsbAttach) { Dismount-UsbFromWsl -BusId $BusId }
}
