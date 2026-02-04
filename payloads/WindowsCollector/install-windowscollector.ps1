<#
.SYNOPSIS
    Windows Collector One-Liner Installer

.DESCRIPTION
    Downloads and executes the Windows-Collector.ps1 script from PhoneHomeWeb server.
    Designed for EPM/RMM deployment or one-liner execution.

.NOTES
    Usage (PowerShell as Admin):
    irm https://server:3500/windowscollector-installer | iex

    Or with parameters:
    $env:SILENT = "1"; irm https://server:3500/windowscollector-installer | iex
#>

$ErrorActionPreference = "Stop"

# Configuration (replaced by server at serve-time)
$ServerUrl = "<<SERVERURL>>"
$AuthKey = "<<AUTHKEY>>"

# Check for admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script requires Administrator privileges." -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
    exit 1
}

# TLS 1.2
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

# Build parameters
$params = @{
    UploadUrl = "$ServerUrl/upload"
    AuthKey = $AuthKey
}

# Check for silent mode from environment
if ($env:SILENT -eq "1" -or $env:WINDOWSCOLLECTOR_SILENT -eq "1") {
    $params.Silent = $true
}

# Check for skip upload from environment
if ($env:SKIP_UPLOAD -eq "1" -or $env:WINDOWSCOLLECTOR_SKIP_UPLOAD -eq "1") {
    $params.SkipUpload = $true
}

# Custom output path from environment
if ($env:OUTPUT_PATH -or $env:WINDOWSCOLLECTOR_OUTPUT_PATH) {
    $params.OutputPath = if ($env:OUTPUT_PATH) { $env:OUTPUT_PATH } else { $env:WINDOWSCOLLECTOR_OUTPUT_PATH }
}

# Include security logs from environment
if ($env:INCLUDE_SECURITY_LOGS -eq "1" -or $env:WINDOWSCOLLECTOR_INCLUDE_SECURITY_LOGS -eq "1") {
    $params.IncludeSecurityLogs = $true
}

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " Windows Collector Installer" -ForegroundColor Yellow
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Server: $ServerUrl" -ForegroundColor Gray
Write-Host "Silent: $($params.ContainsKey('Silent'))" -ForegroundColor Gray
Write-Host ""

# Download script
Write-Host "Downloading Windows-Collector.ps1..." -ForegroundColor Cyan
$scriptUrl = "$ServerUrl/payloads/WindowsCollector/Windows-Collector.ps1"
$tempScript = Join-Path $env:TEMP "Windows-Collector-$(Get-Date -Format 'yyyyMMddHHmmss').ps1"

try {
    # Download with auth header
    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add("X-Auth-Key", $AuthKey)
    $scriptContent = $webClient.DownloadString($scriptUrl)
    
    # Replace placeholders
    $scriptContent = $scriptContent -replace "<<SERVERURL>>", $ServerUrl
    $scriptContent = $scriptContent -replace "<<AUTHKEY>>", $AuthKey
    
    # Save to temp
    $scriptContent | Out-File -FilePath $tempScript -Encoding UTF8 -Force
    
    Write-Host "Downloaded successfully." -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Host "ERROR: Failed to download script: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Execute
Write-Host "Executing Windows-Collector..." -ForegroundColor Cyan
Write-Host ""

try {
    # Build parameter string
    $paramString = ""
    foreach ($key in $params.Keys) {
        $val = $params[$key]
        if ($val -is [bool] -or $val -is [switch]) {
            if ($val) { $paramString += " -$key" }
        }
        else {
            $paramString += " -$key `"$val`""
        }
    }
    
    # Execute script
    $expression = "& `"$tempScript`"$paramString"
    Invoke-Expression $expression
}
finally {
    # Cleanup
    if (Test-Path $tempScript) {
        Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
    }
}
