<#
.SYNOPSIS
    Installation helper for FileListCollector

.DESCRIPTION
    This script helps configure FileListCollector.ps1 with your server settings
    by replacing placeholder tokens with actual values.

.PARAMETER ServerUrl
    Your PhoneHomeWeb server URL (e.g., http://server:3500)

.PARAMETER AuthKey
    Your authentication key for the server

.PARAMETER OutputPath
    Where to save the configured script (default: current directory)

.EXAMPLE
    .\install-filelistcollector.ps1 -ServerUrl "http://192.168.1.100:3500" -AuthKey "mykey123"

.NOTES
    This creates a pre-configured copy of FileListCollector.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerUrl,
    
    [Parameter(Mandatory = $true)]
    [string]$AuthKey,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "."
)

$ErrorActionPreference = "Stop"

function Write-ColorMessage {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

try {
    Write-ColorMessage "`n=== FileListCollector Installer ===" "Cyan"
    
    # Get the source script path
    $sourceScript = Join-Path $PSScriptRoot "FileListCollector.ps1"
    
    if (-not (Test-Path $sourceScript)) {
        throw "Source script not found: $sourceScript"
    }
    
    # Read the source script
    $scriptContent = Get-Content -Path $sourceScript -Raw
    
    # Replace placeholders
    Write-ColorMessage "Configuring script with your settings..." "Yellow"
    $scriptContent = $scriptContent -replace '<<SERVERURL>>', $ServerUrl
    $scriptContent = $scriptContent -replace '<<AUTHKEY>>', $AuthKey
    
    # Create output directory if needed
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # Save configured script
    $outputScript = Join-Path $OutputPath "FileListCollector-Configured.ps1"
    $scriptContent | Out-File -FilePath $outputScript -Encoding UTF8 -Force
    
    Write-ColorMessage "`nConfiguration complete!" "Green"
    Write-ColorMessage "Configured script saved to: $outputScript" "Gray"
    Write-ColorMessage "`nYou can now run:" "White"
    Write-ColorMessage "  .\FileListCollector-Configured.ps1 -UploadResults" "Cyan"
    
    exit 0
}
catch {
    Write-ColorMessage "`nInstallation failed: $($_.Exception.Message)" "Red"
    exit 1
}
