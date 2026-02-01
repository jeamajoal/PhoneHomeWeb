param (
    [Parameter(Mandatory = $false)]
    [string]$SftpServer = "<<SFTPSERVER>>",
    [Parameter(Mandatory = $false)]
    [int]$SftpPort = 22,
    [Parameter(Mandatory = $false)]
    [string]$SftpUsername = "<<SFTPUSERNAME>>",
    [Parameter(Mandatory = $false)]
    [string]$SftpPassword = "<<SFTPPASSWORD>>",
    [Parameter(Mandatory = $false)]
    [string]$SftpKeyFile = "",
    [Parameter(Mandatory = $false)]
    [string]$FilePath = "<<FILEPATH>>",
    [Parameter(Mandatory = $false)]
    [string]$RemotePath = "/upload/"
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
    Write-ColorMessage "PhoneHomeWeb SFTP File Upload" "Cyan"
    Write-Divider

    # Validate parameters
    if ($SftpServer -eq "<<SFTPSERVER>>" -or [string]::IsNullOrEmpty($SftpServer)) {
        throw "SFTP server address is required. Use -SftpServer parameter."
    }
    if ($SftpUsername -eq "<<SFTPUSERNAME>>" -or [string]::IsNullOrEmpty($SftpUsername)) {
        throw "SFTP username is required. Use -SftpUsername parameter."
    }
    if ($SftpPassword -eq "<<SFTPPASSWORD>>" -and [string]::IsNullOrEmpty($SftpKeyFile)) {
        throw "Either SFTP password (-SftpPassword) or key file (-SftpKeyFile) is required."
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

    Write-ColorMessage "Server:      ${SftpServer}:${SftpPort}" "White"
    Write-ColorMessage "Username:    $SftpUsername" "White"
    Write-ColorMessage "Local File:  $FilePath" "White"
    Write-ColorMessage "Remote Path: ${RemotePath}${destFilename}" "White"
    Write-Divider

    # Check for OpenSSH sftp command (built into Windows 10+)
    $sftpPath = $null
    
    # Check Windows built-in OpenSSH
    $opensshSftp = "$env:SystemRoot\System32\OpenSSH\sftp.exe"
    if (Test-Path $opensshSftp) {
        $sftpPath = $opensshSftp
    }
    
    # Check PATH
    if (-not $sftpPath) {
        $sftpInPath = Get-Command sftp -ErrorAction SilentlyContinue
        if ($sftpInPath) {
            $sftpPath = $sftpInPath.Source
        }
    }

    if (-not $sftpPath) {
        throw "SFTP client not found. Please ensure OpenSSH is installed (Windows 10+ has it built-in, or install OpenSSH feature)."
    }

    Write-ColorMessage "Using SFTP client: $sftpPath" "Gray"
    Write-ColorMessage "Uploading via SFTP..." "Yellow"

    # Create batch file for SFTP commands
    $batchFile = [System.IO.Path]::GetTempFileName()
    $batchContent = @"
cd $RemotePath
put "$FilePath" "$destFilename"
bye
"@
    Set-Content -Path $batchFile -Value $batchContent -Encoding ASCII

    try {
        # Build SFTP arguments
        $sftpArgs = @()
        $sftpArgs += "-P"
        $sftpArgs += $SftpPort.ToString()
        $sftpArgs += "-oBatchMode=no"
        $sftpArgs += "-oStrictHostKeyChecking=accept-new"
        
        if ($SftpKeyFile -and (Test-Path $SftpKeyFile)) {
            $sftpArgs += "-i"
            $sftpArgs += $SftpKeyFile
        }
        
        $sftpArgs += "-b"
        $sftpArgs += $batchFile
        $sftpArgs += "${SftpUsername}@${SftpServer}"

        # For password auth, we need to use a different approach
        # OpenSSH sftp doesn't support password on command line for security reasons
        # We'll use sshpass if available on Linux, or prompt on Windows
        
        if ($SftpPassword -and $SftpPassword -ne "<<SFTPPASSWORD>>") {
            # Check for sshpass (Linux/WSL)
            $sshpass = Get-Command sshpass -ErrorAction SilentlyContinue
            if ($sshpass) {
                $env:SSHPASS = $SftpPassword
                $process = Start-Process -FilePath "sshpass" -ArgumentList (@("-e", "sftp") + $sftpArgs) -Wait -NoNewWindow -PassThru -RedirectStandardOutput "$env:TEMP\sftp_out.txt" -RedirectStandardError "$env:TEMP\sftp_err.txt"
                $env:SSHPASS = $null
            } else {
                Write-ColorMessage "Note: Password authentication requires manual entry or sshpass utility." "Yellow"
                Write-ColorMessage "For automated uploads, consider using SSH key authentication (-SftpKeyFile)." "Yellow"
                $process = Start-Process -FilePath $sftpPath -ArgumentList $sftpArgs -Wait -NoNewWindow -PassThru
            }
        } else {
            $process = Start-Process -FilePath $sftpPath -ArgumentList $sftpArgs -Wait -NoNewWindow -PassThru
        }

        if ($process.ExitCode -eq 0) {
            Write-Divider
            Write-ColorMessage "SFTP upload successful!" "Green"
            Write-ColorMessage "Remote file: ${RemotePath}${destFilename}" "White"
            Write-Divider
            
            return @{
                success = $true
                filename = $destFilename
                remotePath = "${RemotePath}${destFilename}"
            }
        } else {
            throw "SFTP upload failed with exit code: $($process.ExitCode)"
        }
    }
    finally {
        # Clean up batch file
        if (Test-Path $batchFile) {
            Remove-Item $batchFile -Force -ErrorAction SilentlyContinue
        }
    }
}
catch {
    Write-Divider
    Write-ColorMessage "SFTP upload failed: $($_.Exception.Message)" "Red"
    Write-Divider
    exit 1
}
