# Example PowerShell script for phone home functionality
# This script can be accessed without authentication via:
# Invoke-WebRequest -Uri "http://your-server:3500/user-scripts/example-phone-home.ps1" | Invoke-Expression

# Configuration - these would typically be set by your environment
$ServerUrl = if ($env:PHONEHOME_SERVER) { $env:PHONEHOME_SERVER } else { "http://localhost:3500" }
$AuthKey = if ($env:PHONEHOME_AUTH_KEY) { $env:PHONEHOME_AUTH_KEY } else { "your-auth-key-here" }

Write-Host "PhoneHome Example Script" -ForegroundColor Green
Write-Host "========================" -ForegroundColor Green
Write-Host "Server: $ServerUrl"
Write-Host ""

# Example: Collect basic system info
$Hostname = $env:COMPUTERNAME
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$OutputFile = "$env:TEMP\system-info-$Hostname-$Timestamp.txt"

Write-Host "Collecting system information..." -ForegroundColor Yellow

@"
=== System Information ===
Computer: $env:COMPUTERNAME
User: $env:USERNAME
Date: $(Get-Date)

=== OS Information ===
$(Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture | Format-List | Out-String)

=== Disk Usage ===
$(Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null } | Format-Table Name, @{L='Used(GB)';E={[math]::Round($_.Used/1GB,2)}}, @{L='Free(GB)';E={[math]::Round($_.Free/1GB,2)}} -AutoSize | Out-String)

=== Network Adapters ===
$(Get-NetAdapter | Select-Object Name, Status, LinkSpeed, MacAddress | Format-Table -AutoSize | Out-String)

"@ | Out-File -FilePath $OutputFile -Encoding UTF8

Write-Host "Information collected: $OutputFile" -ForegroundColor Green

# Upload to server
Write-Host "Uploading to server..." -ForegroundColor Yellow

try {
    $headers = @{
        "X-Auth-Key" = $AuthKey
    }
    
    $form = @{
        file = Get-Item -Path $OutputFile
    }
    
    $response = Invoke-RestMethod -Uri "$ServerUrl/upload" -Method Post -Headers $headers -Form $form
    
    if ($response.success) {
        Write-Host "Upload successful!" -ForegroundColor Green
        Remove-Item -Path $OutputFile -Force
    } else {
        Write-Host "Upload failed: $($response.error)" -ForegroundColor Red
        Write-Host "File saved at: $OutputFile" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Upload failed: $_" -ForegroundColor Red
    Write-Host "File saved at: $OutputFile" -ForegroundColor Yellow
}
