<#
.SYNOPSIS
    File System List Collector - Creates file listings with last modified dates

.DESCRIPTION
    This script collects file system information in two formats:
    1. Get-ChildItem (gci) format: Detailed file list with last modified dates
    2. dir /s /b format: Recursive directory listing (bare format)
    
    Results are saved to text files and optionally uploaded to a central server.

.PARAMETER ServerUrl
    The base URL of the PhoneHomeWeb server (e.g., http://localhost:3500)

.PARAMETER AuthKey
    Authentication key for the upload server

.PARAMETER RootPath
    The root path to scan (default: C:\)

.PARAMETER OutputPath
    Directory where output files will be saved (default: current directory)

.PARAMETER UploadResults
    Switch to enable uploading the results to the server

.PARAMETER IncludeSubdirectories
    Switch to recursively scan subdirectories (default: true)

.EXAMPLE
    .\FileListCollector.ps1 -RootPath "C:\" -OutputPath "C:\Temp"
    
.EXAMPLE
    .\FileListCollector.ps1 -RootPath "C:\Users" -ServerUrl "http://server:3500" -AuthKey "mykey" -UploadResults

.NOTES
    Author: PhoneHomeWeb Contributors
    Date: 2026-02-01
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = "<<SERVERURL>>",
    
    [Parameter(Mandatory = $false)]
    [string]$AuthKey = "<<AUTHKEY>>",
    
    [Parameter(Mandatory = $false)]
    [string]$RootPath = "C:\",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".",
    
    [Parameter(Mandatory = $false)]
    [switch]$UploadResults = $false,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSubdirectories = $true
)

$ErrorActionPreference = "Continue"

# Color-coded logging function
function Write-ColorMessage {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

# Main function to collect file listings
function Collect-FileListing {
    param(
        [string]$Path,
        [string]$OutputDir
    )
    
    Write-ColorMessage "`n=== File List Collector ===" "Cyan"
    Write-ColorMessage "Root Path: $Path" "Gray"
    Write-ColorMessage "Output Directory: $OutputDir" "Gray"
    
    # Get computer info for filename
    $computerName = $env:COMPUTERNAME
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    
    # Create output directory if it doesn't exist
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        Write-ColorMessage "Created output directory: $OutputDir" "Green"
    }
    
    # Output file names
    $gciOutputFile = Join-Path $OutputDir "$computerName`_FileList_GCI_$timestamp.txt"
    $dirOutputFile = Join-Path $OutputDir "$computerName`_FileList_DIR_$timestamp.txt"
    
    # Collect Get-ChildItem format (detailed with last modified)
    Write-ColorMessage "`n[1/2] Collecting Get-ChildItem format (with LastWriteTime)..." "Yellow"
    
    try {
        $header = @"
File List Collection Report
Computer: $computerName
Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Root Path: $Path
Method: Get-ChildItem (PowerShell)

Format: Mode | LastWriteTime | Length | Name
=============================================================================

"@
        $header | Out-File -FilePath $gciOutputFile -Encoding UTF8
        
        if ($IncludeSubdirectories) {
            Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | 
                Format-Table -AutoSize Mode, LastWriteTime, Length, FullName | 
                Out-File -FilePath $gciOutputFile -Append -Encoding UTF8 -Width 300
        } else {
            Get-ChildItem -Path $Path -Force -ErrorAction SilentlyContinue | 
                Format-Table -AutoSize Mode, LastWriteTime, Length, FullName | 
                Out-File -FilePath $gciOutputFile -Append -Encoding UTF8 -Width 300
        }
        
        $gciSize = (Get-Item $gciOutputFile).Length
        Write-ColorMessage "  Created: $gciOutputFile ($([math]::Round($gciSize/1KB, 2)) KB)" "Green"
    }
    catch {
        Write-ColorMessage "  Error collecting Get-ChildItem format: $($_.Exception.Message)" "Red"
    }
    
    # Collect dir /s /b format (bare recursive listing)
    Write-ColorMessage "`n[2/2] Collecting dir /s /b format (bare recursive listing)..." "Yellow"
    
    try {
        $header = @"
Directory Listing (Bare Format)
Computer: $computerName
Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Root Path: $Path
Method: cmd.exe dir /s /b

=============================================================================

"@
        $header | Out-File -FilePath $dirOutputFile -Encoding UTF8
        
        # Use cmd.exe to run dir command for compatibility
        if ($IncludeSubdirectories) {
            cmd.exe /c "dir `"$Path`" /s /b 2>nul" | Out-File -FilePath $dirOutputFile -Append -Encoding UTF8
        } else {
            cmd.exe /c "dir `"$Path`" /b 2>nul" | Out-File -FilePath $dirOutputFile -Append -Encoding UTF8
        }
        
        $dirSize = (Get-Item $dirOutputFile).Length
        Write-ColorMessage "  Created: $dirOutputFile ($([math]::Round($dirSize/1KB, 2)) KB)" "Green"
    }
    catch {
        Write-ColorMessage "  Error collecting dir format: $($_.Exception.Message)" "Red"
    }
    
    Write-ColorMessage "`nFile list collection complete!" "Green"
    
    return @{
        GciFile = $gciOutputFile
        DirFile = $dirOutputFile
    }
}

# Function to upload file to server
function Upload-File {
    param(
        [string]$FilePath,
        [string]$UploadUrl,
        [string]$AuthKey
    )
    
    try {
        Add-Type -AssemblyName System.Net.Http
        
        $httpClient = $null
        $content = $null
        $fileStream = $null
        $fileContent = $null
        
        try {
            $httpClient = [System.Net.Http.HttpClient]::new()
            [void]$httpClient.DefaultRequestHeaders.Add("X-Auth-Key", $AuthKey)
            
            $content = [System.Net.Http.MultipartFormDataContent]::new()
            $fileStream = [System.IO.File]::OpenRead($FilePath)
            $fileName = [System.IO.Path]::GetFileName($FilePath)
            $fileContent = [System.Net.Http.StreamContent]::new($fileStream)
            $content.Add($fileContent, "file", $fileName)
            
            Write-ColorMessage "  Uploading: $fileName" "Gray"
            
            $response = $httpClient.PostAsync($UploadUrl, $content).Result
            $responseContent = $response.Content.ReadAsStringAsync().Result
            
            if (-not $response.IsSuccessStatusCode) {
                throw "Upload failed: HTTP $([int]$response.StatusCode) $($response.ReasonPhrase) - $responseContent"
            }
            
            Write-ColorMessage "  Successfully uploaded: $fileName" "Green"
            return $true
        }
        finally {
            if ($fileContent) { $fileContent.Dispose() }
            if ($fileStream) { $fileStream.Dispose() }
            if ($content) { $content.Dispose() }
            if ($httpClient) { $httpClient.Dispose() }
        }
    }
    catch {
        Write-ColorMessage "  Upload failed: $($_.Exception.Message)" "Red"
        return $false
    }
}

# Main execution
try {
    Write-ColorMessage "`nStarting File List Collector..." "Cyan"
    Write-ColorMessage "============================================" "Cyan"
    
    # Validate root path
    if (-not (Test-Path $RootPath)) {
        Write-ColorMessage "Error: Root path does not exist: $RootPath" "Red"
        exit 1
    }
    
    # Collect file listings
    $results = Collect-FileListing -Path $RootPath -OutputDir $OutputPath
    
    # Upload if requested
    if ($UploadResults) {
        Write-ColorMessage "`nUploading results to server..." "Yellow"
        
        $uploadUrl = "$ServerUrl/upload"
        
        if ($results.GciFile -and (Test-Path $results.GciFile)) {
            Upload-File -FilePath $results.GciFile -UploadUrl $uploadUrl -AuthKey $AuthKey
        }
        
        if ($results.DirFile -and (Test-Path $results.DirFile)) {
            Upload-File -FilePath $results.DirFile -UploadUrl $uploadUrl -AuthKey $AuthKey
        }
    }
    
    Write-ColorMessage "`n============================================" "Cyan"
    Write-ColorMessage "File List Collector completed successfully!" "Green"
    Write-ColorMessage "Output files:" "Gray"
    Write-ColorMessage "  - $($results.GciFile)" "Gray"
    Write-ColorMessage "  - $($results.DirFile)" "Gray"
    
    exit 0
}
catch {
    Write-ColorMessage "`nFile List Collector failed: $($_.Exception.Message)" "Red"
    Write-ColorMessage $_.ScriptStackTrace "Red"
    exit 1
}
