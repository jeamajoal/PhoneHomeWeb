<#
.SYNOPSIS
    Build a PhoneHomeWeb Debian Live diagnostic USB from a Windows host.

.DESCRIPTION
    Windows-side wrapper around the Linux-only Build-Linux-USB.sh.
    The actual build (squashfs/chroot/etc.) requires a Linux kernel,
    so this script:

      1. Verifies WSL2 is available; installs the Debian distro if missing.
      2. Verifies build dependencies inside the WSL distro.
      3. Optionally uses usbipd-win to attach a USB device into WSL so the
         Linux builder can write to it directly.
      4. Copies (or downloads) Build-Linux-USB.sh into WSL and invokes it
         as root with translated arguments.

    No build logic is duplicated; this script is pure orchestration.

.PARAMETER Device
    USB device path AS SEEN INSIDE WSL after attach (e.g. /dev/sdX).
    If omitted and -BusId given, the script will detect the new device.
    If both are omitted and -SkipUsbAttach is set, the bash script will
    prompt interactively.

.PARAMETER BusId
    usbipd-win bus ID (e.g. "2-3") of the USB stick to attach into WSL.
    Use -ListUsb to enumerate.

.PARAMETER ListUsb
    List USB devices visible to usbipd-win and exit.

.PARAMETER DebianIso
    Path to a pre-downloaded Debian Live ISO. Accepts a Windows path
    (e.g. C:\ISOs\debian-live.iso); it will be translated to a WSL path.

.PARAMETER IsoUrl
    Direct URL to a Debian Live ISO (passed through to the bash builder).

.PARAMETER PersistSize
    Persistence partition size in MB (default 10240).

.PARAMETER NoPersistence
    Disable the persistence partition.

.PARAMETER SkipWrite
    Build only; do not write to USB.

.PARAMETER SkipUsbAttach
    Do not call usbipd attach; assume the device is already visible in WSL
    or that the bash script should prompt.

.PARAMETER WorkDir
    Working directory inside WSL (default /var/tmp/linux-usb-build).

.PARAMETER KeepWork
    Pass through --keep-work to the bash builder.

.PARAMETER NonInteractive
    Pass through --non-interactive to the bash builder.

.PARAMETER ServerUrl
    PhoneHomeWeb server URL embedded into scripts on the USB.

.PARAMETER AuthKey
    PhoneHomeWeb auth key embedded into scripts on the USB.

.PARAMETER WslDistro
    WSL distribution name to use (default Debian).

.PARAMETER InstallWslIfMissing
    Run `wsl --install -d <distro>` if WSL or the distro is missing.

.EXAMPLE
    PS> .\Build-Linux-USB.ps1 -ListUsb

.EXAMPLE
    PS> .\Build-Linux-USB.ps1 -BusId 2-3 -ServerUrl https://server:3500 -AuthKey KEY

.EXAMPLE
    PS> .\Build-Linux-USB.ps1 -DebianIso C:\ISOs\debian-live-12.5.0-amd64-standard.iso -BusId 2-3

.NOTES
    Author: jeamajoal
    Requires: Windows 10/11 with WSL2; usbipd-win (https://github.com/dorssel/usbipd-win)
    for USB passthrough. usbipd 'bind' and 'attach --wsl' require admin.
#>

[CmdletBinding()]
param(
    [string]$Device,
    [string]$BusId,
    [switch]$ListUsb,
    [string]$DebianIso,
    [string]$IsoUrl,
    [int]$PersistSize = 10240,
    [switch]$NoPersistence,
    [switch]$SkipWrite,
    [switch]$SkipUsbAttach,
    [string]$WorkDir = "/var/tmp/linux-usb-build",
    [switch]$KeepWork,
    [switch]$NonInteractive,
    [string]$ServerUrl = "<<SERVERURL>>",
    [string]$AuthKey = "<<AUTHKEY>>",
    [string]$WslDistro = "Debian",
    [switch]$InstallWslIfMissing
)

$ErrorActionPreference = "Stop"

# -----------------------------------------------------------------------------
# Console helpers
# -----------------------------------------------------------------------------

function Write-Info    { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor Cyan }
function Write-Ok      { param([string]$m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn2   { param([string]$m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err2    { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }
function Stop-Hard     { param([string]$m) Write-Err2 $m; exit 1 }

# -----------------------------------------------------------------------------
# Admin / WSL / usbipd checks
# -----------------------------------------------------------------------------

function Test-IsAdmin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Test-CommandExists {
    param([string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Test-Wsl2 {
    if (-not (Test-CommandExists 'wsl.exe')) { return $false }
    try {
        $null = & wsl.exe --status 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}

function Test-WslDistroPresent {
    param([string]$Name)
    if (-not (Test-CommandExists 'wsl.exe')) { return $false }
    # `wsl -l -q` outputs distro names (often UTF-16); normalize.
    $raw = & wsl.exe -l -q 2>$null
    if (-not $raw) { return $false }
    $names = ($raw | ForEach-Object { ($_ -replace "`0", '').Trim() }) | Where-Object { $_ }
    return ($names -contains $Name)
}

function Install-WslDistro {
    param([string]$Name)
    if (-not (Test-IsAdmin)) {
        Stop-Hard "Installing WSL or a new WSL distro requires Administrator. Re-run elevated, or pre-install with: wsl --install -d $Name"
    }
    Write-Info "Installing WSL distro '$Name' (this can take several minutes; may require reboot)..."
    & wsl.exe --install -d $Name --no-launch
    if ($LASTEXITCODE -ne 0) {
        Stop-Hard "wsl --install -d $Name failed (exit $LASTEXITCODE). You may need to enable the WSL feature and reboot first."
    }
    Write-Ok "WSL distro '$Name' installed. If this is a fresh WSL setup, REBOOT and re-run this script."
}

function Initialize-Wsl {
    if (-not (Test-Wsl2)) {
        if ($InstallWslIfMissing) {
            if (-not (Test-IsAdmin)) {
                Stop-Hard "WSL is not installed and -InstallWslIfMissing requires Administrator."
            }
            Write-Info "Installing WSL2..."
            & wsl.exe --install --no-distribution
            if ($LASTEXITCODE -ne 0) { Stop-Hard "wsl --install failed (exit $LASTEXITCODE)." }
            Write-Warn2 "WSL was just installed. Reboot Windows and re-run this script."
            exit 0
        }
        Stop-Hard "WSL2 is not available. Install with: wsl --install (admin) and reboot, or pass -InstallWslIfMissing."
    }
    if (-not (Test-WslDistroPresent -Name $WslDistro)) {
        if ($InstallWslIfMissing) {
            Install-WslDistro -Name $WslDistro
            Write-Warn2 "Distro just installed. Launch it once to set up a user, then re-run this script."
            exit 0
        }
        Stop-Hard "WSL distro '$WslDistro' not found. Install with: wsl --install -d $WslDistro (or pass -InstallWslIfMissing -WslDistro $WslDistro)."
    }
    Write-Ok "WSL2 and distro '$WslDistro' available."
}

function Test-UsbIpd {
    return (Test-CommandExists 'usbipd.exe')
}

function Show-UsbIpdInstallHint {
    Write-Warn2 "usbipd-win is not installed. Install with one of:"
    Write-Host  "  winget install --id dorssel.usbipd-win" -ForegroundColor Gray
    Write-Host  "  https://github.com/dorssel/usbipd-win/releases" -ForegroundColor Gray
}

function Invoke-UsbIpdList {
    if (-not (Test-UsbIpd)) { Show-UsbIpdInstallHint; return }
    & usbipd.exe list
}

function Mount-UsbToWsl {
    param([string]$BusId, [string]$Distro)
    if (-not (Test-UsbIpd)) {
        Show-UsbIpdInstallHint
        Stop-Hard "usbipd-win required to attach USB to WSL. Install it or pass -SkipUsbAttach."
    }
    if (-not (Test-IsAdmin)) {
        Stop-Hard "usbipd 'bind' and 'attach' require Administrator. Re-run this script in an elevated PowerShell."
    }
    Write-Info "Binding USB bus $BusId via usbipd..."
    & usbipd.exe bind --busid $BusId 2>$null  # idempotent; ignore "already bound"
    Write-Info "Attaching USB bus $BusId to WSL distro '$Distro'..."
    & usbipd.exe attach --wsl --busid $BusId --distribution $Distro
    if ($LASTEXITCODE -ne 0) {
        Stop-Hard "usbipd attach failed (exit $LASTEXITCODE). Verify the bus ID with: usbipd list"
    }
    Write-Ok "USB $BusId attached to '$Distro'."
}

function Dismount-UsbFromWsl {
    param([string]$BusId)
    if (-not $BusId) { return }
    if (-not (Test-UsbIpd)) { return }
    Write-Info "Detaching USB bus $BusId..."
    & usbipd.exe detach --busid $BusId 2>$null | Out-Null
}

# -----------------------------------------------------------------------------
# Path translation + bash invocation helpers
# -----------------------------------------------------------------------------

function ConvertTo-WslPath {
    param([string]$WindowsPath)
    if (-not $WindowsPath) { return $null }
    # Already a WSL/Linux path?
    if ($WindowsPath.StartsWith('/')) { return $WindowsPath }
    $resolved = (Resolve-Path -LiteralPath $WindowsPath -ErrorAction SilentlyContinue)
    $candidate = if ($resolved) { $resolved.Path } else { $WindowsPath }

    # Try wslpath first; capture stderr so we can diagnose if it fails.
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

    # Fallback: manual translation for drive-letter paths (C:\Foo\Bar -> /mnt/c/Foo/Bar).
    if ($candidate -match '^([A-Za-z]):[\\/](.*)$') {
        $drive = $Matches[1].ToLowerInvariant()
        $rest  = $Matches[2] -replace '\\', '/'
        $mapped = "/mnt/$drive/$rest"
        Write-Info "Falling back to manual path translation: $mapped"
        return $mapped
    }

    Stop-Hard "Failed to translate Windows path to WSL: $WindowsPath"
}

function Invoke-WslBash {
    param([string]$BashCommand, [switch]$AsRoot)
    $wslArgs = @('-d', $WslDistro)
    if ($AsRoot) { $wslArgs += @('-u', 'root') }
    $wslArgs += @('--', 'bash', '-lc', $BashCommand)
    & wsl.exe @wslArgs
    return $LASTEXITCODE
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

try {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "  PhoneHomeWeb Linux USB Builder (Windows wrapper)" -ForegroundColor Yellow
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""

    if ($ListUsb) {
        Invoke-UsbIpdList
        exit 0
    }

    Initialize-Wsl

    # Locate the bash builder (must live next to this script after install).
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $bashLocal = Join-Path $scriptDir 'Build-Linux-USB.sh'
    if (-not (Test-Path $bashLocal)) {
        Stop-Hard "Build-Linux-USB.sh not found next to this script (expected: $bashLocal). Re-run the installer or download it via /payloads/LinuxCollector/download/Build-Linux-USB.sh."
    }

    # Stage the bash script + helper payloads inside WSL so it can be run as root
    # without permission/CRLF issues that show up under /mnt/.
    $stageDirWsl = "/var/tmp/phw-build"
    $stageDirWin = ConvertTo-WslPath $scriptDir
    Write-Info "Staging payloads into WSL: $stageDirWsl"
    $stageCmd = @"
set -e
mkdir -p '$stageDirWsl'
cp -f '$stageDirWin'/*.sh '$stageDirWsl/' 2>/dev/null || true
# Strip CRLF in case files came from a Windows checkout
find '$stageDirWsl' -type f -name '*.sh' -exec sed -i 's/\r\$//' {} +
chmod +x '$stageDirWsl'/*.sh 2>/dev/null || true
"@
    $rc = Invoke-WslBash -BashCommand $stageCmd -AsRoot
    if ($rc -ne 0) { Stop-Hard "Failed to stage payloads in WSL (exit $rc)." }

    # Optional USB attach
    if (-not $SkipWrite -and -not $SkipUsbAttach) {
        if (-not $BusId -and -not $Device) {
            Write-Warn2 "No -BusId or -Device given. Listing USB devices via usbipd..."
            Invoke-UsbIpdList
            Write-Host ""
            Stop-Hard "Re-run with -BusId <id> (e.g. 2-3) to attach a USB into WSL, or pass -SkipUsbAttach to let the Linux builder prompt interactively, or -SkipWrite to build only."
        }
        if ($BusId) { Mount-UsbToWsl -BusId $BusId -Distro $WslDistro }
    }

    # Build bash arg list
    $bashArgs = @()
    if ($Device)         { $bashArgs += @('--device', $Device) }
    if ($DebianIso) {
        $isoWsl = ConvertTo-WslPath $DebianIso
        $bashArgs += @('--debian-iso', $isoWsl)
    }
    if ($IsoUrl)         { $bashArgs += @('--iso-url', $IsoUrl) }
    if ($NoPersistence)  { $bashArgs += '--no-persistence' }
    else                 { $bashArgs += @('--persist-size', "$PersistSize") }
    if ($SkipWrite)      { $bashArgs += '--skip-write' }
    if ($WorkDir)        { $bashArgs += @('--work-dir', $WorkDir) }
    if ($KeepWork)       { $bashArgs += '--keep-work' }
    if ($NonInteractive) { $bashArgs += '--non-interactive' }
    if ($ServerUrl -and $ServerUrl -notmatch '<<SERVERURL>>') { $bashArgs += @('--server-url', $ServerUrl) }
    if ($AuthKey   -and $AuthKey   -notmatch '<<AUTHKEY>>')   { $bashArgs += @('--auth-key',   $AuthKey)   }

    # Quote args safely for bash
    $quoted = ($bashArgs | ForEach-Object { "'" + ($_ -replace "'", "'\''") + "'" }) -join ' '
    $runCmd = "cd '$stageDirWsl' && bash '$stageDirWsl/Build-Linux-USB.sh' $quoted"

    Write-Info "Running Linux builder inside WSL ($WslDistro) as root..."
    Write-Host  "  $runCmd" -ForegroundColor DarkGray
    $rc = Invoke-WslBash -BashCommand $runCmd -AsRoot
    if ($rc -ne 0) { Stop-Hard "Linux builder exited with code $rc." }

    Write-Ok "Build complete."
}
finally {
    if ($BusId -and -not $SkipUsbAttach) {
        Dismount-UsbFromWsl -BusId $BusId
    }
}
