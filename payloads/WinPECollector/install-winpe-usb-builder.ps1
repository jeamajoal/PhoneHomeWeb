<#
.SYNOPSIS
    WinPE USB Builder Installer

.DESCRIPTION
    Downloads the WinPE USB Builder tool that creates bootable
    diagnostic USB drives.

.NOTES
    Author: jeamajoal
    Date: December 17, 2025
#>

$ErrorActionPreference = "Stop"
$AuthKey = "<<AUTHKEY>>"
$ServerUrl = "<<SERVERURL>>"

# Best-effort TLS hardening for downloads (important on older PS/.NET)
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
catch {
    # Ignore - not available on all builds
}

function Write-ColorMessage {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

$Divider = "================================================================================" 

# Banner
Clear-Host
Write-Host $Divider -ForegroundColor Cyan
Write-Host " WINPE USB BUILDER INSTALLER" -ForegroundColor Yellow
Write-Host $Divider -ForegroundColor Cyan
Write-Host ""

try {
    # Determine install location
    $installPath = "$env:USERPROFILE\Desktop\WinPE-USB-Builder"
    
    Write-ColorMessage "Installation directory: $installPath" "Cyan"
    Write-Host ""
    
    # Create installation directory
    if (Test-Path $installPath) {
        Write-ColorMessage "Removing existing installation..." "Gray"
        Remove-Item -Path $installPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    New-Item -ItemType Directory -Path $installPath -Force | Out-Null
    Write-ColorMessage "Installation directory created" "Green"
    
    Write-Host ""
    Write-ColorMessage "Downloading WinPE USB Builder..." "Cyan"
    
    $headers = @{ 'X-Auth-Key' = $AuthKey }
    
    # Download main builder script
    $builderUrl = "$ServerUrl/payloads/WinPECollector/download/Build-WinPE-USB.ps1"
    $builderPath = Join-Path $installPath "Build-WinPE-USB.ps1"
    
    Write-ColorMessage "  Downloading Build-WinPE-USB.ps1..." "Gray"
    $iwrParams = @{ Uri = $builderUrl; OutFile = $builderPath; Headers = $headers }
    if ((Get-Command Invoke-WebRequest).Parameters.ContainsKey('UseBasicParsing')) { $iwrParams.UseBasicParsing = $true }
    Invoke-WebRequest @iwrParams
    Write-ColorMessage "  Build-WinPE-USB.ps1 downloaded" "Green"
    
    # Create a launcher batch file for easy running
    $launcherContent = @"
@echo off
echo.
echo ================================================================================
echo  WINPE USB BUILDER
echo ================================================================================
echo.
echo This will create a bootable WinPE USB drive for offline diagnostics.
echo.
echo REQUIREMENTS:
echo   - Windows ADK installed (with WinPE add-on)
echo   - USB drive (8GB+ recommended)
echo   - Administrator privileges
echo.

REM Check for admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Please run this as Administrator!
    echo Right-click and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

REM Run the PowerShell script - it will list available USB disks and prompt for selection
powershell -ExecutionPolicy Bypass -File "%~dp0Build-WinPE-USB.ps1"

pause
"@
    
    $launcherPath = Join-Path $installPath "Build-USB.bat"
    $launcherContent | Out-File $launcherPath -Encoding ASCII
    Write-ColorMessage "  Created Build-USB.bat launcher" "Green"
    
    Write-Host ""
    Write-Host $Divider -ForegroundColor Green
    Write-ColorMessage " INSTALLATION COMPLETE!" "Green"
    Write-Host $Divider -ForegroundColor Green
    Write-Host ""
    Write-ColorMessage "Files installed to: $installPath" "Cyan"
    Write-Host ""
    Write-ColorMessage "PREREQUISITES:" "Yellow"
    Write-Host "  1. Install Windows ADK:" -ForegroundColor Gray
    Write-Host "     https://go.microsoft.com/fwlink/?linkid=2243390" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  2. Install Windows PE add-on for ADK:" -ForegroundColor Gray
    Write-Host "     https://go.microsoft.com/fwlink/?linkid=2243391" -ForegroundColor Cyan
    Write-Host ""
    Write-ColorMessage "TO CREATE USB:" "Yellow"
    Write-Host "  1. Right-click 'Build-USB.bat' and select 'Run as administrator'" -ForegroundColor Gray
    Write-Host "  2. Select your USB disk from the list when prompted" -ForegroundColor Gray
    Write-Host "  3. Wait for the build to complete" -ForegroundColor Gray
    Write-Host ""
    Write-ColorMessage "Or run PowerShell as Admin and execute:" "Yellow"
    Write-Host "  cd '$installPath'" -ForegroundColor Gray
    Write-Host "  .\Build-WinPE-USB.ps1                    # Interactive disk selection" -ForegroundColor Gray
    Write-Host "  .\Build-WinPE-USB.ps1 -USBDiskNumber 2   # Use disk 2 directly" -ForegroundColor Gray
    Write-Host ""
    
    # Open the folder
    explorer.exe $installPath
    
} catch {
    Write-Host ""
    Write-Host "INSTALLATION FAILED" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

Read-Host "Press Enter to exit"
