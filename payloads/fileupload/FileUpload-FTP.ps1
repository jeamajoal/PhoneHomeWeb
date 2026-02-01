param (
    [Parameter(Mandatory = $false)]
    [string]$FtpServer = "<<FTPSERVER>>",
    [Parameter(Mandatory = $false)]
    [string]$FtpUsername = "<<FTPUSERNAME>>",
    [Parameter(Mandatory = $false)]
    [string]$FtpPassword = "<<FTPPASSWORD>>",
    [Parameter(Mandatory = $false)]
    [string]$FilePath = "<<FILEPATH>>",
    [Parameter(Mandatory = $false)]
    [string]$RemotePath = "/"
)
$ErrorActionPreference = "Stop"

function Write-ColorMessage {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Write-Divider {
    Write-Host ("=" * 60) -ForegroundColor Gray
}

try {
    Write-Divider
    Write-ColorMessage "PhoneHomeWeb FTP File Upload" "Cyan"
    Write-Divider

    # Validate parameters
    if ($FtpServer -eq "<<FTPSERVER>>" -or [string]::IsNullOrEmpty($FtpServer)) {
        throw "FTP server address is required. Use -FtpServer parameter."
    }
    if ($FtpUsername -eq "<<FTPUSERNAME>>" -or [string]::IsNullOrEmpty($FtpUsername)) {
        throw "FTP username is required. Use -FtpUsername parameter."
    }
    if ($FtpPassword -eq "<<FTPPASSWORD>>" -or [string]::IsNullOrEmpty($FtpPassword)) {
        throw "FTP password is required. Use -FtpPassword parameter."
    }
    if ($FilePath -eq "<<FILEPATH>>" -or [string]::IsNullOrEmpty($FilePath)) {
        throw "File path is required. Use -FilePath parameter."
    }

    # Check if file exists
    if (-not (Test-Path $FilePath)) {
        throw "File not found: $FilePath"
    }

    # Get system info for filename prefix
    $computername = $env:COMPUTERNAME
    $serialNumber = try { (Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue).SerialNumber } catch { "" }
    
    # Build destination filename
    $originalFilename = [System.IO.Path]::GetFileName($FilePath)
    if ($serialNumber) {
        $destFilename = "${computername}_${serialNumber}_${originalFilename}"
    } else {
        $destFilename = "${computername}_${originalFilename}"
    }

    # Build FTP URI
    $ftpUri = "ftp://${FtpServer}${RemotePath}${destFilename}"

    Write-ColorMessage "Server:      $FtpServer" "White"
    Write-ColorMessage "Username:    $FtpUsername" "White"
    Write-ColorMessage "Local File:  $FilePath" "White"
    Write-ColorMessage "Remote File: $destFilename" "White"
    Write-Divider

    Write-ColorMessage "Uploading via FTP..." "Yellow"

    # Create FTP request
    $ftpRequest = [System.Net.FtpWebRequest]::Create($ftpUri)
    $ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::UploadFile
    $ftpRequest.Credentials = New-Object System.Net.NetworkCredential($FtpUsername, $FtpPassword)
    $ftpRequest.UseBinary = $true
    $ftpRequest.UsePassive = $true
    $ftpRequest.KeepAlive = $false

    # Read file content
    $fileContent = [System.IO.File]::ReadAllBytes($FilePath)
    $ftpRequest.ContentLength = $fileContent.Length

    # Upload file
    $requestStream = $ftpRequest.GetRequestStream()
    try {
        $requestStream.Write($fileContent, 0, $fileContent.Length)
    }
    finally {
        $requestStream.Close()
    }

    # Get response
    $ftpResponse = $ftpRequest.GetResponse()
    $statusDescription = $ftpResponse.StatusDescription
    $ftpResponse.Close()

    Write-Divider
    Write-ColorMessage "Upload successful!" "Green"
    Write-ColorMessage "Status: $statusDescription" "White"
    Write-Divider

    return @{
        success = $true
        filename = $destFilename
        status = $statusDescription
    }
}
catch {
    Write-Divider
    Write-ColorMessage "FTP upload failed: $($_.Exception.Message)" "Red"
    Write-Divider
    exit 1
}
