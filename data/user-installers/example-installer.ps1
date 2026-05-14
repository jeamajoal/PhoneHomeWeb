# Example installer for user-installers directory
# This script requires authentication to access via:
# Invoke-WebRequest -Uri "http://your-server:3500/user-installers/example-installer.ps1" -Headers @{"X-Auth-Key"="your-key"} | Invoke-Expression

param(
    [string]$InstallPath = "$env:ProgramFiles\MyApp"
)

Write-Host "Example Protected Installer" -ForegroundColor Green
Write-Host "===========================" -ForegroundColor Green
Write-Host ""

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "This installer requires administrator privileges." -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
    exit 1
}

Write-Host "Install path: $InstallPath" -ForegroundColor Cyan
Write-Host ""

# Example installation steps
Write-Host "Step 1: Creating installation directory..." -ForegroundColor Yellow
if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    Write-Host "  Directory created: $InstallPath" -ForegroundColor Green
} else {
    Write-Host "  Directory already exists: $InstallPath" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Step 2: Creating example files..." -ForegroundColor Yellow
@"
This is an example application installed via PhoneHomeWeb.
Installation date: $(Get-Date)
"@ | Out-File -FilePath "$InstallPath\README.txt" -Encoding UTF8
Write-Host "  Created: $InstallPath\README.txt" -ForegroundColor Green

Write-Host ""
Write-Host "Installation completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  - Configure your application in $InstallPath" -ForegroundColor White
Write-Host "  - Review README.txt for more information" -ForegroundColor White
