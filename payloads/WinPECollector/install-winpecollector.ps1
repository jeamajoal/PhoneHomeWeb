<#
.SYNOPSIS
    WinPE Collector Installer - One-liner deployment

.DESCRIPTION
    Downloads and installs the WinPE Collector to X:\WinPECollector
    Designed for quick deployment in WinPE environment via:
    iwr https://<server>/winpecollector-installer -Headers @{'X-Auth-Key'='<key>'} -useb | iex

.NOTES
    Author: jeamajoal
    Date: December 17, 2025
    Environment: Windows PE (WinPE)
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = "<<SERVERURL>>"
)

$ErrorActionPreference = "Stop"
$AuthKey = "<<AUTHKEY>>"

# Best-effort TLS hardening for downloads (important on older PS/.NET)
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
catch {
    # Ignore - not available on all builds
}

function Write-ColorMessage {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

# Banner
Clear-Host
Write-Host "=============================" -ForegroundColor Cyan
Write-Host " WINPE COLLECTOR INSTALLER" -ForegroundColor Yellow
Write-Host "=============================" -ForegroundColor Cyan
Write-Host ""

try {
    # Configuration
    $installPath = "X:\WinPECollector"
    $headers = @{ 'X-Auth-Key' = $AuthKey }
    
    Write-ColorMessage "Checking WinPE environment..." "Cyan"
    
    # Verify we're in WinPE or at least X: drive exists
    if (Test-Path "X:\") {
        Write-ColorMessage "X: drive detected" "Green"
    }
    else {
        Write-ColorMessage "WARNING: X: drive not found - not in typical WinPE environment" "Yellow"
        Write-ColorMessage "Installer will still proceed but installation path may not be available" "Yellow"
        
        # Fallback to C:\Temp if X: not available
        $installPath = "C:\Temp\WinPECollector"
        Write-ColorMessage "Using fallback path: $installPath" "Yellow"
    }
    
    Write-Host ""
    Write-ColorMessage "Installation directory: $installPath" "Cyan"
    
    # Create installation directory
    if (Test-Path $installPath) {
        Write-ColorMessage "  Removing existing installation..." "Gray"
        Remove-Item -Path $installPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    New-Item -ItemType Directory -Path $installPath -Force | Out-Null
    Write-ColorMessage "  Installation directory created" "Green"
    
    Write-Host ""
    Write-ColorMessage "Downloading WinPE Collector..." "Cyan"
    
    # Download main collector script
    $collectorUrl = "$ServerUrl/payloads/WinPECollector/download/WinPE-Collector.ps1"
    $collectorPath = Join-Path $installPath "WinPE-Collector.ps1"
    
    Write-ColorMessage "  Downloading WinPE-Collector.ps1..." "Gray"
    
    # Use Invoke-WebRequest with -OutFile for proper file writing
    try {
        $iwrParams = @{ Uri = $collectorUrl; OutFile = $collectorPath; TimeoutSec = 60; Headers = $headers }
        if ((Get-Command Invoke-WebRequest).Parameters.ContainsKey('UseBasicParsing')) { $iwrParams.UseBasicParsing = $true }
        Invoke-WebRequest @iwrParams
        Write-ColorMessage "  WinPE-Collector.ps1 downloaded" "Green"
    }
    catch {
        Write-ColorMessage "  Error downloading: $($_.Exception.Message)" "Red"
        throw "Failed to download WinPE-Collector.ps1"
    }
    
    Write-Host ""
    Write-ColorMessage "Installation completed successfully!" "Green"
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-ColorMessage " NEXT STEPS" "Yellow"
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
    Write-ColorMessage "1. Navigate to installation directory:" "White"
    Write-ColorMessage "   cd $installPath" "Cyan"
    Write-Host ""
    Write-ColorMessage "2. Run the collector:" "White"
    Write-ColorMessage "   .\WinPE-Collector.ps1" "Cyan"
    Write-Host ""
    Write-ColorMessage "3. Follow the on-screen prompts to:" "White"
    Write-ColorMessage "   - Select the Windows installation to diagnose" "Gray"
    Write-ColorMessage "   - Enter BitLocker recovery key if needed" "Gray"
    Write-ColorMessage "   - Upload diagnostics to server" "Gray"
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host ""
    Write-ColorMessage "Starting WinPE Collector..." "Cyan"
    Write-Host ""
        
    # Change to install directory and run
    Set-Location $installPath
    & "$installPath\WinPE-Collector.ps1"
    
}
catch {
    Write-Host ""
    Write-ColorMessage "INSTALLATION FAILED" "Red"
    Write-ColorMessage "Error: $($_.Exception.Message)" "Red"
    Write-Host ""
    Write-ColorMessage "Please check:" "Yellow"
    Write-ColorMessage "  - Network connectivity to $ServerUrl" "Gray"
    Write-ColorMessage "  - You are in a WinPE environment" "Gray"
    Write-ColorMessage "  - You have write access to X:\" "Gray"
    Write-Host ""
    exit 1
}
