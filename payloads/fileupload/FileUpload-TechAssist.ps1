<#
.SYNOPSIS
    Tech-Assisted File Share Helper - Interactive guided file upload

.DESCRIPTION
    A user-friendly, interactive script that guides users through the file upload process.
    Designed for tech support scenarios where a technician walks a user through uploading
    diagnostic files, logs, or other data.

    Features:
    - Interactive file selection with GUI file picker
    - Step-by-step guidance with clear instructions
    - Multiple upload method options (HTTPS, copy to share, manual transfer instructions)
    - Progress feedback and error handling
    - Support for technician-provided one-time codes/keys

.NOTES
    Author: PhoneHomeWeb
    Environment: Windows PowerShell 5.1+ or PowerShell Core
#>

param (
    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = "<<SERVERURL>>",
    [Parameter(Mandatory = $false)]
    [string]$AuthKey = "<<AUTHKEY>>",
    [Parameter(Mandatory = $false)]
    [string]$FilePath = "",
    [Parameter(Mandatory = $false)]
    [switch]$Silent
)

$ErrorActionPreference = "Stop"

function Write-ColorMessage {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    if (-not $Silent) {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Write-Divider {
    if (-not $Silent) {
        Write-Host ("=" * 70) -ForegroundColor DarkGray
    }
}

function Write-Header {
    param([string]$Title)
    if (-not $Silent) {
        Write-Host ""
        Write-Divider
        Write-Host "  $Title" -ForegroundColor Cyan
        Write-Divider
        Write-Host ""
    }
}

function Show-Menu {
    param(
        [string]$Title,
        [string[]]$Options
    )
    
    Write-Header $Title
    
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host "  [$($i + 1)] " -NoNewline -ForegroundColor Yellow
        Write-Host $Options[$i] -ForegroundColor White
    }
    
    Write-Host ""
    do {
        $choice = Read-Host "Enter your choice (1-$($Options.Count))"
        $parsed = 0
        $valid = [int]::TryParse($choice, [ref]$parsed) -and $parsed -ge 1 -and $parsed -le $Options.Count
        if (-not $valid) {
            Write-ColorMessage "Invalid choice. Please enter a number between 1 and $($Options.Count)." "Red"
        }
    } while (-not $valid)
    
    return $parsed
}

function Select-FileWithDialog {
    param([string]$Title = "Select a file to upload")
    
    Add-Type -AssemblyName System.Windows.Forms
    
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = $Title
    $dialog.Filter = "All Files (*.*)|*.*|ZIP Archives (*.zip)|*.zip|Log Files (*.log)|*.log|Text Files (*.txt)|*.txt"
    $dialog.FilterIndex = 1
    $dialog.Multiselect = $false
    
    $result = $dialog.ShowDialog()
    
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return $dialog.FileName
    }
    
    return $null
}

function Get-FileInfo {
    param([string]$Path)
    
    $file = Get-Item $Path
    $sizeKB = [math]::Round($file.Length / 1KB, 2)
    $sizeMB = [math]::Round($file.Length / 1MB, 2)
    $sizeDisplay = if ($sizeMB -ge 1) { "$sizeMB MB" } else { "$sizeKB KB" }
    
    return @{
        Name = $file.Name
        FullPath = $file.FullName
        Size = $file.Length
        SizeDisplay = $sizeDisplay
        Extension = $file.Extension
        LastModified = $file.LastWriteTime
    }
}

function Upload-ViaHTTPS {
    param(
        [string]$ServerUrl,
        [string]$FilePath,
        [string]$AuthKey
    )
    
    Write-ColorMessage "Preparing upload..." "Yellow"
    
    $uploadUrl = "$ServerUrl/upload"
    
    # Get system info for filename prefix
    $computername = $env:COMPUTERNAME
    $serialNumber = try { (Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue).SerialNumber } catch { "" }
    
    $originalFilename = [System.IO.Path]::GetFileName($FilePath)
    if ($serialNumber) {
        $destFilename = "${computername}_${serialNumber}_${originalFilename}"
    } else {
        $destFilename = "${computername}_${originalFilename}"
    }
    
    Write-ColorMessage "Uploading as: $destFilename" "Gray"
    
    Add-Type -AssemblyName System.Net.Http
    
    $httpClient = $null
    $content = $null
    $fileStream = $null
    $fileContent = $null
    
    try {
        $httpClient = [System.Net.Http.HttpClient]::new()
        $httpClient.Timeout = [TimeSpan]::FromMinutes(30)
        [void]$httpClient.DefaultRequestHeaders.Add("X-Auth-Key", $AuthKey)
        
        $content = [System.Net.Http.MultipartFormDataContent]::new()
        $fileStream = [System.IO.File]::OpenRead($FilePath)
        $fileContent = [System.Net.Http.StreamContent]::new($fileStream)
        $content.Add($fileContent, "file", $destFilename)
        
        Write-ColorMessage "Uploading... (this may take a moment for large files)" "Yellow"
        
        $response = $httpClient.PostAsync($uploadUrl, $content).Result
        $responseContent = $response.Content.ReadAsStringAsync().Result
        
        if (-not $response.IsSuccessStatusCode) {
            throw "Upload failed: HTTP $([int]$response.StatusCode) $($response.ReasonPhrase)"
        }
        
        return @{
            Success = $true
            Response = $responseContent
            DestFilename = $destFilename
        }
    }
    finally {
        if ($fileContent) { $fileContent.Dispose() }
        if ($fileStream) { $fileStream.Dispose() }
        if ($content) { $content.Dispose() }
        if ($httpClient) { $httpClient.Dispose() }
    }
}

function Show-ManualTransferInstructions {
    param(
        [string]$FilePath,
        [hashtable]$FileInfo
    )
    
    Write-Header "Manual Transfer Instructions"
    
    Write-ColorMessage "If automatic upload is not available, you can transfer the file manually:" "White"
    Write-Host ""
    
    Write-ColorMessage "FILE INFORMATION:" "Yellow"
    Write-ColorMessage "  Name: $($FileInfo.Name)" "White"
    Write-ColorMessage "  Size: $($FileInfo.SizeDisplay)" "White"
    Write-ColorMessage "  Path: $($FileInfo.FullPath)" "White"
    Write-Host ""
    
    Write-ColorMessage "TRANSFER OPTIONS:" "Yellow"
    Write-Host ""
    
    Write-ColorMessage "  1. EMAIL:" "Cyan"
    Write-ColorMessage "     - Compose a new email to your IT support contact" "Gray"
    Write-ColorMessage "     - Attach the file: $($FileInfo.FullPath)" "Gray"
    Write-ColorMessage "     - Include your computer name: $env:COMPUTERNAME" "Gray"
    Write-Host ""
    
    Write-ColorMessage "  2. CLOUD STORAGE (OneDrive, Google Drive, Dropbox):" "Cyan"
    Write-ColorMessage "     - Upload the file to your cloud storage" "Gray"
    Write-ColorMessage "     - Create a sharing link" "Gray"
    Write-ColorMessage "     - Send the link to your IT support contact" "Gray"
    Write-Host ""
    
    Write-ColorMessage "  3. USB DRIVE:" "Cyan"
    Write-ColorMessage "     - Copy the file to a USB drive" "Gray"
    Write-ColorMessage "     - Deliver to your IT department" "Gray"
    Write-Host ""
    
    Write-ColorMessage "  4. NETWORK SHARE (if available):" "Cyan"
    Write-ColorMessage "     - Copy the file to the designated network share" "Gray"
    Write-ColorMessage "     - Notify your IT support contact" "Gray"
    Write-Host ""
    
    # Offer to open file location
    $openFolder = Read-Host "Would you like to open the folder containing this file? (Y/N)"
    if ($openFolder -eq 'Y' -or $openFolder -eq 'y') {
        Start-Process explorer.exe -ArgumentList "/select,`"$FilePath`""
    }
}

function Copy-ToNetworkShare {
    param([string]$FilePath)
    
    Write-Header "Copy to Network Share"
    
    $sharePath = Read-Host "Enter the network share path (e.g., \\server\share\uploads)"
    
    if ([string]::IsNullOrEmpty($sharePath)) {
        Write-ColorMessage "No path provided. Canceling." "Yellow"
        return $false
    }
    
    if (-not (Test-Path $sharePath)) {
        Write-ColorMessage "Cannot access: $sharePath" "Red"
        Write-ColorMessage "Please verify the path and your network connection." "Yellow"
        return $false
    }
    
    # Get system info for filename prefix
    $computername = $env:COMPUTERNAME
    $serialNumber = try { (Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue).SerialNumber } catch { "" }
    
    $originalFilename = [System.IO.Path]::GetFileName($FilePath)
    if ($serialNumber) {
        $destFilename = "${computername}_${serialNumber}_${originalFilename}"
    } else {
        $destFilename = "${computername}_${originalFilename}"
    }
    
    $destPath = Join-Path $sharePath $destFilename
    
    Write-ColorMessage "Copying to: $destPath" "Yellow"
    
    try {
        Copy-Item -Path $FilePath -Destination $destPath -Force
        Write-ColorMessage "File copied successfully!" "Green"
        return $true
    }
    catch {
        Write-ColorMessage "Copy failed: $($_.Exception.Message)" "Red"
        return $false
    }
}

# ============================================================================
# MAIN SCRIPT
# ============================================================================

try {
    Clear-Host
    
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                                                                   ║" -ForegroundColor Cyan
    Write-Host "  ║          TECH-ASSISTED FILE SHARE HELPER                          ║" -ForegroundColor Cyan
    Write-Host "  ║                                                                   ║" -ForegroundColor Cyan
    Write-Host "  ║   This tool will help you securely upload files to IT support.   ║" -ForegroundColor Cyan
    Write-Host "  ║                                                                   ║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # Step 1: Select file
    Write-Header "STEP 1: Select File to Upload"
    
    $selectedFile = $null
    
    if ($FilePath -and (Test-Path $FilePath)) {
        $selectedFile = $FilePath
        Write-ColorMessage "Using provided file: $FilePath" "Green"
    } else {
        $fileChoice = Show-Menu "How would you like to select the file?" @(
            "Browse for file (opens file picker)",
            "Enter file path manually",
            "Cancel"
        )
        
        switch ($fileChoice) {
            1 {
                Write-ColorMessage "Opening file picker..." "Yellow"
                $selectedFile = Select-FileWithDialog -Title "Select file to upload"
                if (-not $selectedFile) {
                    Write-ColorMessage "No file selected. Exiting." "Yellow"
                    exit 0
                }
            }
            2 {
                $manualPath = Read-Host "Enter the full path to the file"
                if (-not (Test-Path $manualPath)) {
                    Write-ColorMessage "File not found: $manualPath" "Red"
                    exit 1
                }
                $selectedFile = $manualPath
            }
            3 {
                Write-ColorMessage "Cancelled by user." "Yellow"
                exit 0
            }
        }
    }
    
    # Display file info
    $fileInfo = Get-FileInfo -Path $selectedFile
    Write-Host ""
    Write-ColorMessage "Selected file:" "Green"
    Write-ColorMessage "  Name: $($fileInfo.Name)" "White"
    Write-ColorMessage "  Size: $($fileInfo.SizeDisplay)" "White"
    Write-ColorMessage "  Modified: $($fileInfo.LastModified)" "White"
    Write-Host ""
    
    # Step 2: Select upload method
    Write-Header "STEP 2: Select Upload Method"
    
    $methodChoice = Show-Menu "How would you like to transfer this file?" @(
        "Upload directly to server (HTTPS) - Recommended",
        "Copy to network share",
        "Show manual transfer instructions",
        "Cancel"
    )
    
    switch ($methodChoice) {
        1 {
            # HTTPS Upload
            Write-Header "STEP 3: Upload Configuration"
            
            # Check if we have server URL
            $uploadServerUrl = $ServerUrl
            if ($uploadServerUrl -eq "<<SERVERURL>>" -or [string]::IsNullOrEmpty($uploadServerUrl)) {
                $uploadServerUrl = Read-Host "Enter the server URL (provided by your IT support)"
            }
            
            # Check if we have auth key
            $uploadAuthKey = $AuthKey
            if ($uploadAuthKey -eq "<<AUTHKEY>>" -or [string]::IsNullOrEmpty($uploadAuthKey)) {
                $uploadAuthKey = Read-Host "Enter the authentication key (provided by your IT support)"
            }
            
            Write-Header "STEP 4: Uploading File"
            
            try {
                $result = Upload-ViaHTTPS -ServerUrl $uploadServerUrl -FilePath $selectedFile -AuthKey $uploadAuthKey
                
                if ($result.Success) {
                    Write-Host ""
                    Write-ColorMessage "╔═══════════════════════════════════════════════════════════╗" "Green"
                    Write-ColorMessage "║                    UPLOAD SUCCESSFUL!                     ║" "Green"
                    Write-ColorMessage "╚═══════════════════════════════════════════════════════════╝" "Green"
                    Write-Host ""
                    Write-ColorMessage "Your file has been uploaded successfully." "White"
                    Write-ColorMessage "Saved as: $($result.DestFilename)" "Gray"
                    Write-Host ""
                    Write-ColorMessage "You can now close this window." "Yellow"
                }
            }
            catch {
                Write-ColorMessage "Upload failed: $($_.Exception.Message)" "Red"
                Write-Host ""
                Write-ColorMessage "Would you like to see manual transfer options instead?" "Yellow"
                $fallback = Read-Host "(Y/N)"
                if ($fallback -eq 'Y' -or $fallback -eq 'y') {
                    Show-ManualTransferInstructions -FilePath $selectedFile -FileInfo $fileInfo
                }
            }
        }
        2 {
            # Network share
            $result = Copy-ToNetworkShare -FilePath $selectedFile
            if ($result) {
                Write-Host ""
                Write-ColorMessage "File copied successfully to network share!" "Green"
            }
        }
        3 {
            # Manual instructions
            Show-ManualTransferInstructions -FilePath $selectedFile -FileInfo $fileInfo
        }
        4 {
            Write-ColorMessage "Cancelled by user." "Yellow"
            exit 0
        }
    }
    
    Write-Host ""
    Write-Divider
    Read-Host "Press Enter to exit"
}
catch {
    Write-ColorMessage "Error: $($_.Exception.Message)" "Red"
    Read-Host "Press Enter to exit"
    exit 1
}
