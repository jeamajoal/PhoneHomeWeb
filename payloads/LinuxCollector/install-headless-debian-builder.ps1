<#
.SYNOPSIS
    Headless Debian Builder Installer (Windows host)

.DESCRIPTION
    Downloads Build-Headless-Debian.ps1 and Build-Headless-Debian.sh
    onto the local machine. The actual build runs inside WSL2.
#>

$ErrorActionPreference = "Stop"
$AuthKey   = "<<AUTHKEY>>"
$ServerUrl = "<<SERVERURL>>"

try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

$Divider = "=" * 80
Clear-Host
Write-Host $Divider -ForegroundColor Cyan
Write-Host " HEADLESS DEBIAN BUILDER INSTALLER (Windows)" -ForegroundColor Yellow
Write-Host $Divider -ForegroundColor Cyan
Write-Host ""

try {
    $installPath = Join-Path $env:USERPROFILE 'HeadlessDebianBuilder'
    Write-Host "Installation directory: $installPath" -ForegroundColor Cyan
    if (-not (Test-Path $installPath)) { New-Item -ItemType Directory -Path $installPath -Force | Out-Null }

    $headers = @{ 'X-Auth-Key' = $AuthKey }
    $iwrCommon = @{ Headers = $headers }
    if ((Get-Command Invoke-WebRequest).Parameters.ContainsKey('UseBasicParsing')) { $iwrCommon.UseBasicParsing = $true }

    $files = @(
        @{ Name = 'Build-Headless-Debian.ps1'; Required = $true  },
        @{ Name = 'Build-Headless-Debian.sh';  Required = $true  }
    )
    foreach ($f in $files) {
        $url  = "$ServerUrl/payloads/LinuxCollector/download/$($f.Name)"
        $dest = Join-Path $installPath $f.Name
        Write-Host ("  {0,-32} ... " -f $f.Name) -NoNewline -ForegroundColor Gray
        try {
            Invoke-WebRequest @iwrCommon -Uri $url -OutFile $dest
            Write-Host "OK" -ForegroundColor Green
        } catch {
            if ($f.Required) { throw "Required file '$($f.Name)' could not be downloaded: $($_.Exception.Message)" }
            Write-Host "skip" -ForegroundColor Yellow
        }
    }

    # Inject creds into PS1 wrapper
    $ps1 = Join-Path $installPath 'Build-Headless-Debian.ps1'
    if (Test-Path $ps1) {
        $c = Get-Content -LiteralPath $ps1 -Raw
        $c = $c.Replace('<<SERVERURL>>', $ServerUrl).Replace('<<AUTHKEY>>', $AuthKey)
        Set-Content -LiteralPath $ps1 -Value $c -Encoding UTF8
    }

    $launcher = @"
@echo off
powershell -NoLogo -ExecutionPolicy Bypass -File "%~dp0Build-Headless-Debian.ps1" %*
"@
    Set-Content -LiteralPath (Join-Path $installPath 'Build-Headless.bat') -Value $launcher -Encoding ASCII

    Write-Host ""
    Write-Host $Divider -ForegroundColor Green
    Write-Host " INSTALLATION COMPLETE" -ForegroundColor Green
    Write-Host $Divider -ForegroundColor Green
    Write-Host ""
    Write-Host "Installed to: $installPath" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "PREREQUISITES:" -ForegroundColor Yellow
    Write-Host "  - WSL2 + a Debian distro:    wsl --install -d Debian   (admin, may need reboot)" -ForegroundColor Gray
    Write-Host "  - usbipd-win (only to write directly to USB):  winget install --id dorssel.usbipd-win" -ForegroundColor Gray
    Write-Host ""
    Write-Host "QUICK START (ISO file only):" -ForegroundColor Yellow
    Write-Host "  cd `"$installPath`"" -ForegroundColor Gray
    Write-Host "  .\Build-Headless-Debian.ps1 -SshKey `$env:USERPROFILE\.ssh\id_ed25519.pub -Output C:\Temp\phw-headless.iso" -ForegroundColor Gray
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
