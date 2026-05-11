<#
.SYNOPSIS
    Linux USB Builder Installer (Windows host)

.DESCRIPTION
    Downloads the PhoneHomeWeb Linux USB Builder onto a Windows machine
    so it can be invoked from PowerShell. The actual build runs inside
    WSL2; see Build-Linux-USB.ps1 -? for prerequisites.

.NOTES
    Author: jeamajoal
#>

$ErrorActionPreference = "Stop"
$AuthKey   = "<<AUTHKEY>>"
$ServerUrl = "<<SERVERURL>>"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

function Write-ColorMessage { param([string]$Message, [string]$Color = "White") Write-Host $Message -ForegroundColor $Color }

$Divider = "=" * 80

Clear-Host
Write-Host $Divider -ForegroundColor Cyan
Write-Host " LINUX USB BUILDER INSTALLER (Windows)" -ForegroundColor Yellow
Write-Host $Divider -ForegroundColor Cyan
Write-Host ""

try {
    $installPath = Join-Path $env:USERPROFILE 'LinuxUSBBuilder'
    Write-ColorMessage "Installation directory: $installPath" "Cyan"
    Write-Host ""

    if (Test-Path $installPath) {
        Write-ColorMessage "Refreshing existing installation..." "Gray"
    } else {
        New-Item -ItemType Directory -Path $installPath -Force | Out-Null
    }

    $headers = @{ 'X-Auth-Key' = $AuthKey }
    $iwrCommon = @{ Headers = $headers }
    if ((Get-Command Invoke-WebRequest).Parameters.ContainsKey('UseBasicParsing')) { $iwrCommon.UseBasicParsing = $true }

    # Files to fetch from the server payload directory
    $files = @(
        'Build-Linux-USB.ps1',
        'Build-Linux-USB.sh',
        'Linux-Collector.sh',
        'upload-file.sh',
        'collect-windows-logs.sh'
    )

    foreach ($f in $files) {
        $url  = "$ServerUrl/payloads/LinuxCollector/download/$f"
        $dest = Join-Path $installPath $f
        Write-ColorMessage "  Downloading $f..." "Gray"
        try {
            Invoke-WebRequest @iwrCommon -Uri $url -OutFile $dest
            Write-ColorMessage "    OK" "Green"
        } catch {
            # Linux-Collector.sh and helpers are optional for this installer.
            if ($f -eq 'Build-Linux-USB.ps1' -or $f -eq 'Build-Linux-USB.sh') {
                throw "Required file '$f' could not be downloaded: $($_.Exception.Message)"
            }
            Write-ColorMessage "    SKIP (server returned error: $($_.Exception.Message))" "Yellow"
        }
    }

    # Inject credentials into the downloaded PS1 (server already does this for the
    # installer endpoint, but the raw payload download does not).
    $ps1 = Join-Path $installPath 'Build-Linux-USB.ps1'
    if (Test-Path $ps1) {
        $content = Get-Content -LiteralPath $ps1 -Raw
        $content = $content.Replace('<<SERVERURL>>', $ServerUrl).Replace('<<AUTHKEY>>', $AuthKey)
        Set-Content -LiteralPath $ps1 -Value $content -Encoding UTF8
    }

    # Convenience launcher
    $launcher = @"
@echo off
powershell -NoLogo -ExecutionPolicy Bypass -File "%~dp0Build-Linux-USB.ps1" %*
"@
    Set-Content -LiteralPath (Join-Path $installPath 'Build-USB.bat') -Value $launcher -Encoding ASCII

    Write-Host ""
    Write-Host $Divider -ForegroundColor Green
    Write-ColorMessage " INSTALLATION COMPLETE" "Green"
    Write-Host $Divider -ForegroundColor Green
    Write-Host ""
    Write-ColorMessage "Installed to: $installPath" "Cyan"
    Write-Host ""
    Write-ColorMessage "PREREQUISITES:" "Yellow"
    Write-Host "  - WSL2 + a Debian distro:    wsl --install -d Debian   (admin, may need reboot)" -ForegroundColor Gray
    Write-Host "  - usbipd-win for USB attach: winget install --id dorssel.usbipd-win" -ForegroundColor Gray
    Write-Host ""
    Write-ColorMessage "USAGE:" "Yellow"
    Write-Host "  cd `"$installPath`"" -ForegroundColor Gray
    Write-Host "  .\Build-Linux-USB.ps1 -ListUsb" -ForegroundColor Gray
    Write-Host "  .\Build-Linux-USB.ps1 -BusId 2-3" -ForegroundColor Gray
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
