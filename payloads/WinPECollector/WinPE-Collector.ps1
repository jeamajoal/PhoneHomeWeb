<#
.SYNOPSIS
    WinPE BitLocker Offline Diagnostic Collector

.DESCRIPTION
    Designed to run in WinPE environment to:
    1. Detect BitLocker-encrypted drives
    2. Prompt for recovery key to unlock drives
    3. Collect diagnostic data from offline Windows installation
    4. Zip and upload to diagnostic server
    
    This script handles systems that cannot boot to Windows normally.

.NOTES
    Author: jeamajoal
    Date: December 16, 2025
    Environment: Windows PE (WinPE)
    Requirements: 
        - WinPE with PowerShell support
        - Network connectivity
        - BitLocker recovery key (if drive is encrypted)
#>

[CmdletBinding()]
param(
    [string]$UploadUrl = "<<SERVERURL>>/upload",
    [string]$AuthKey = "<<AUTHKEY>>"
)

# Best-effort TLS hardening for uploads/downloads (important on older PS/.NET)
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
catch {
    # Ignore - not available on all builds
}

# Divider constant for section headers
$Divider = "================================================================================"

# Session logging
$Global:SessionLogPath = $null
$Global:ScreenVerbose = $false

function Initialize-SessionLogging {
    param(
        [Parameter(Mandatory = $true)][string]$WorkingRoot
    )

    try {
        if (-not (Test-Path $WorkingRoot)) {
            New-Item -ItemType Directory -Path $WorkingRoot -Force | Out-Null
        }

        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $Global:SessionLogPath = Join-Path $WorkingRoot "WinPE-Collector-Session-$timestamp.log"
        "WinPE Collector Session Log" | Out-File -FilePath $Global:SessionLogPath -Force -Encoding UTF8
        "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Add-Content -Path $Global:SessionLogPath -Encoding UTF8
        "WorkingRoot: $WorkingRoot" | Add-Content -Path $Global:SessionLogPath -Encoding UTF8
        "" | Add-Content -Path $Global:SessionLogPath -Encoding UTF8
    }
    catch {
        # If logging can't initialize, keep going (screen-only)
        $Global:SessionLogPath = $null
    }
}

function Write-SessionLog {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Message = ""
    )

    try {
        if ($null -eq $Message) {
            $Message = ""
        }
        if ($Global:SessionLogPath) {
            $Message | Add-Content -Path $Global:SessionLogPath -Encoding UTF8
        }
    }
    catch {
        # ignore
    }
}

# Color-coded logging function
function Write-LogMessage {
    param(
        [string]$Message,
        [string]$Color = "White",
        [switch]$LogOnly
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Always write details to the session log when available
    Write-SessionLog "[$timestamp] [$Color] $Message"

    # Keep on-screen output simple for low-tech users.
    # - Gray messages are treated as "detail" unless verbose screen output is enabled.
    # - Other colors show on screen.
    if (-not $LogOnly) {
        if ($Color -ne 'Gray' -or $Global:ScreenVerbose) {
            Write-Host "[$timestamp] $Message" -ForegroundColor $Color
        }
    }
}

function Write-Section {
    param([Parameter(Mandatory = $true)][string]$Title)

    Write-Host "" 
    Write-Host $Divider -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Yellow
    Write-Host $Divider -ForegroundColor Cyan
    Write-Host ""
    Write-SessionLog ""
    Write-SessionLog ($Divider)
    Write-SessionLog (" " + $Title)
    Write-SessionLog ($Divider)
    Write-SessionLog ""
}

function Save-SessionEnvironmentSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$WorkingRoot
    )

    try {
        $outPath = Join-Path $WorkingRoot "WinPE_SessionEnvironment.txt"
        $lines = @()
        $lines += $Divider
        $lines += "WINPE SESSION ENVIRONMENT"
        $lines += $Divider
        $lines += "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $lines += ""
        $lines += "=== ipconfig /all ==="
        $lines += (ipconfig /all 2>&1)
        $lines += ""
        $lines += "=== route print ==="
        $lines += (route print 2>&1)
        $lines += ""
        $lines += "=== Get-Disk / Get-Partition / Get-Volume ==="
        try {
            $lines += ((Get-Disk | Sort-Object Number | Format-Table -AutoSize | Out-String).TrimEnd())
            $lines += ""
            $lines += ((Get-Partition | Sort-Object DiskNumber, PartitionNumber | Format-Table -AutoSize | Out-String).TrimEnd())
            $lines += ""
            $lines += ((Get-Volume | Sort-Object DriveLetter | Format-Table -AutoSize | Out-String).TrimEnd())
        }
        catch {
            $lines += "Storage snapshot not available: $($_.Exception.Message)"
        }
        $lines += ""
        $lines += "=== DISM (WinPE driver list, best-effort) ==="
        try {
            $lines += (dism /online /get-drivers /format:table 2>&1)
        }
        catch {
            $lines += "DISM driver list not available: $($_.Exception.Message)"
        }

        $lines | Out-File -FilePath $outPath -Force -Encoding UTF8
        Write-LogMessage "Saved WinPE session environment snapshot" "Green"
        Write-LogMessage "  $outPath" "Gray" -LogOnly
    }
    catch {
        Write-LogMessage "Could not write WinPE session environment snapshot: $($_.Exception.Message)" "Yellow"
    }
}

function Get-NetworkStatus {
    # WinPE-safe network detection: parse ipconfig output.
    $status = [PSCustomObject]@{
        HasIPv4       = $false
        IPv4Addresses = @()
        HasGateway    = $false
        Gateway       = $null
        intIndex      = $null
    }

    try {
        if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue) {
            $ip = Get-NetIPAddress -PrefixOrigin DHCP -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -and -not $_.IPAddress.StartsWith('169.254.') } | Select-Object -First 1
            if ($ip -and $ip.IPAddress) {
                $status.HasIPv4 = $true
                $status.IPv4Addresses = @($ip.IPAddress)
                $status.intIndex = $ip.InterfaceIndex

                if ($status.intIndex -and (Get-Command Get-NetRoute -ErrorAction SilentlyContinue)) {
                    $route = Get-NetRoute -AddressFamily IPv4 -InterfaceIndex $status.intIndex -ErrorAction Stop |
                        Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' -and $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
                        Sort-Object -Property RouteMetric |
                        Select-Object -First 1
                    if ($route -and $route.NextHop) {
                        $status.HasGateway = $true
                        $status.Gateway = $route.NextHop
                    }
                }

                return $status
            }
        }

        $raw = (ipconfig /all 2>&1) | Out-String

        $ipv4 = @()
        foreach ($m in [regex]::Matches($raw, '(?im)^\s*IPv4 Address\s*\.\s*\.\s*\.\s*\.\s*\.\s*\.\s*:\s*(?<ip>\d{1,3}(?:\.\d{1,3}){3})')) {
            $ipText = $m.Groups['ip'].Value
            if ($ipText -and -not $ipText.StartsWith('169.254.')) {
                $ipv4 += $ipText
            }
        }

        $gwMatch = [regex]::Match($raw, '(?im)^\s*Default Gateway\s*\.\s*\.\s*\.\s*\.\s*\.\s*\.\s*:\s*(?<gw>\d{1,3}(?:\.\d{1,3}){3})')
        if ($gwMatch.Success -and $gwMatch.Groups['gw'].Value) {
            $status.HasGateway = $true
            $status.Gateway = $gwMatch.Groups['gw'].Value
        }

        if ($ipv4.Count -gt 0) {
            $status.HasIPv4 = $true
            $status.IPv4Addresses = $ipv4
        }
    }
    catch {
        # ignore
    }

    return $status
}

function Wait-ForNetwork {
    param(
        [int]$TimeoutSeconds = 20,
        [int]$PollSeconds = 2
    )

    $stopAt = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $stopAt) {
        $st = Get-NetworkStatus
        if ($st.HasIPv4) {
            return $true
        }
        Start-Sleep -Seconds $PollSeconds
    }
    return $false
}

function Test-ServerPort {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [int]$TimeoutMs = 2500
    )

    try {
        $uri = [Uri]$Url
        $hostName = $uri.Host
        $port = if ($uri.IsDefaultPort) {
            if ($uri.Scheme -eq 'https') { 443 } elseif ($uri.Scheme -eq 'http') { 80 } else { $uri.Port }
        } else {
            $uri.Port
        }

        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $client.BeginConnect($hostName, $port, $null, $null)
            if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
                return $false
            }
            $client.EndConnect($iar)
            return $true
        }
        finally {
            $client.Close()
        }
    }
    catch {
        return $false
    }
}

function Invoke-WiFiSetupInteractive {
    # Best-effort WiFi helper for WinPE when WinPE-WiFi-Package is present.
    if (-not (Get-Command netsh -ErrorAction SilentlyContinue)) {
        Write-LogMessage "WiFi configuration is not available (netsh not found)." "Yellow"
        return $false
    }

    Write-Host "" 
    Write-LogMessage "WiFi setup (best-effort)" "Cyan"

    try {
        # Show visible networks (may fail if WiFi components aren't present)
        Write-Host "Available WiFi networks:" -ForegroundColor Cyan
        & netsh wlan show networks mode=bssid 2>&1 | ForEach-Object { Write-Host $_ }
    }
    catch {
        Write-LogMessage "Could not enumerate WiFi networks." "Yellow"
    }

    $ssid = Read-Host "Enter WiFi SSID (or blank to cancel)"
    if ([string]::IsNullOrWhiteSpace($ssid)) {
        return $false
    }

    $secure = Read-Host "Enter WiFi password (leave blank for open network)" -AsSecureString
    $pwd = $null
    if ($secure -and $secure.Length -gt 0) {
        try {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            $pwd = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            if ($bstr -and $bstr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
    }

    $tmp = $null
    try {
        $tmp = Join-Path $env:TEMP ("wifi-" + [Guid]::NewGuid().ToString() + ".xml")

        $auth = if ($pwd) { 'WPA2PSK' } else { 'open' }
        $encryption = if ($pwd) { 'AES' } else { 'none' }

        if ($pwd) {
            $profile = @"
<?xml version=\"1.0\"?>
<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">
  <name>$ssid</name>
  <SSIDConfig>
    <SSID>
      <name>$ssid</name>
    </SSID>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>$auth</authentication>
        <encryption>$encryption</encryption>
        <useOneX>false</useOneX>
      </authEncryption>
      <sharedKey>
        <keyType>passPhrase</keyType>
        <protected>false</protected>
        <keyMaterial>$pwd</keyMaterial>
      </sharedKey>
    </security>
  </MSM>
</WLANProfile>
"@
        }
        else {
            $profile = @"
<?xml version=\"1.0\"?>
<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">
  <name>$ssid</name>
  <SSIDConfig>
    <SSID>
      <name>$ssid</name>
    </SSID>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>manual</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>$auth</authentication>
        <encryption>$encryption</encryption>
        <useOneX>false</useOneX>
      </authEncryption>
    </security>
  </MSM>
</WLANProfile>
"@
        }

        $profile | Out-File -FilePath $tmp -Force -Encoding ASCII

        # Add profile and connect
        & netsh wlan add profile filename="$tmp" user=all 2>&1 | ForEach-Object { Write-Host $_ }
        & netsh wlan connect name="$ssid" 2>&1 | ForEach-Object { Write-Host $_ }

        Write-LogMessage "Waiting for network (DHCP)..." "Gray"
        if (Wait-ForNetwork -TimeoutSeconds 30 -PollSeconds 2) {
            $st = Get-NetworkStatus
            Write-LogMessage "Network detected: $($st.IPv4Addresses -join ', ')" "Green"
            return $true
        }

        Write-LogMessage "Still no IP address after WiFi setup." "Yellow"
        return $false
    }
    catch {
        Write-LogMessage "WiFi setup failed: $($_.Exception.Message)" "Yellow"
        return $false
    }
    finally {
        if ($tmp -and (Test-Path $tmp)) {
            Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
        }
    }
}

function Ensure-NetworkOrContinue {
    param(
        [Parameter(Mandatory = $true)][string]$UploadUrl
    )

    Write-Section "Network"
    Write-LogMessage "Waiting briefly for network..." "Cyan"
    $hasNet = Wait-ForNetwork -TimeoutSeconds 20 -PollSeconds 2
    if ($hasNet) {
        $st = Get-NetworkStatus
        Write-LogMessage "Network detected: $($st.IPv4Addresses -join ', ')" "Green"

        # Best-effort server reachability check (does not require ICMP)
        if (-not (Test-ServerPort -Url $UploadUrl -TimeoutMs 2500)) {
            Write-LogMessage "Network is up, but server is not reachable yet." "Yellow"
        }
        return
    }

    Write-LogMessage "No IP address detected. Upload may not be possible yet." "Yellow"
    Write-Host "" 
    Write-Host "Options:" -ForegroundColor Cyan
    Write-Host "  [1] Continue (collect now, save ZIP for later)" -ForegroundColor Gray
    Write-Host "  [2] Configure WiFi" -ForegroundColor Gray
    Write-Host "  [3] Retry network check" -ForegroundColor Gray

    while ($true) {
        $choice = Read-Host "Select 1-3"
        switch ($choice) {
            '1' { return }
            '2' {
                [void](Invoke-WiFiSetupInteractive)
                return
            }
            '3' {
                Write-LogMessage "Retrying network check..." "Cyan"
                if (Wait-ForNetwork -TimeoutSeconds 20 -PollSeconds 2) {
                    $st = Get-NetworkStatus
                    Write-LogMessage "Network detected: $($st.IPv4Addresses -join ', ')" "Green"
                }
                else {
                    Write-LogMessage "Still no IP address detected." "Yellow"
                }
                return
            }
            default {
                Write-Host "Invalid selection." -ForegroundColor Yellow
            }
        }
    }
}

# Banner
function Show-Banner {
    Clear-Host
    Write-Host $Divider -ForegroundColor Cyan
    Write-Host " WINPE OFFLINE DIAGNOSTIC COLLECTOR" -ForegroundColor Yellow
    Write-Host $Divider -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This tool collects diagnostic data from offline Windows installations." -ForegroundColor Gray
    Write-Host "Use this when a system cannot boot to Windows normally." -ForegroundColor Gray
    Write-Host ""
}

function Ensure-DriveLetters {
    param(
        [switch]$VerboseOutput
    )

    try {
        Write-LogMessage "Ensuring drive letters are assigned (WinPE session only)..." "Cyan"

        $usedLetters = @(Get-Volume -ErrorAction SilentlyContinue |
                Where-Object { $_.DriveLetter } |
                ForEach-Object { $_.DriveLetter.ToString().ToUpperInvariant() })

        $candidateLetters = @('S','T','U','V','W','Y','Z')
        $availableLetters = New-Object System.Collections.Generic.Queue[string]
        foreach ($letter in $candidateLetters) {
            if ($usedLetters -notcontains $letter) {
                $availableLetters.Enqueue($letter)
            }
        }

        if ($availableLetters.Count -eq 0) {
            Write-LogMessage "No spare drive letters available to assign." "Yellow"
            return
        }

        $gptDisallowed = @(
            '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}', # EFI System Partition
            '{E3C9E316-0B5C-4DB8-817D-F92DF00215AE}', # Microsoft Reserved (MSR)
            '{DE94BBA4-06D1-4D40-A16A-BFD50179D6AC}'  # Windows Recovery
        )

        $partitions = @(Get-Partition -ErrorAction SilentlyContinue |
                Where-Object {
                    -not $_.DriveLetter -and
                    $_.Size -gt 200MB -and
                    (-not $_.IsHidden) -and
                    (-not $_.IsSystem) -and
                    (-not $_.IsBoot) -and
                    ($null -eq $_.Type -or $_.Type -ne 'Reserved') -and
                    ($null -eq $_.GptType -or ($gptDisallowed -notcontains $_.GptType.ToString().ToUpperInvariant()))
                })

        if ($partitions.Count -eq 0) {
            if ($VerboseOutput) {
                Write-LogMessage "No partitions without drive letters found." "Gray"
            }
            return
        }

        $assigned = 0
        foreach ($partition in $partitions) {
            if ($availableLetters.Count -eq 0) {
                break
            }

            $newLetter = $availableLetters.Dequeue()
            try {
                Set-Partition -DiskNumber $partition.DiskNumber -PartitionNumber $partition.PartitionNumber -NewDriveLetter $newLetter -ErrorAction Stop | Out-Null
                $assigned++
                if ($VerboseOutput) {
                    Write-LogMessage "Assigned $newLetter`: to Disk $($partition.DiskNumber) Partition $($partition.PartitionNumber)" "Gray"
                }
            }
            catch {
                if ($VerboseOutput) {
                    Write-LogMessage "Could not assign $newLetter`: to Disk $($partition.DiskNumber) Partition $($partition.PartitionNumber): $($_.Exception.Message)" "Yellow"
                }
            }
        }

        if ($assigned -gt 0) {
            Write-LogMessage "Assigned $assigned temporary drive letter(s)." "Green"
        }
        else {
            Write-LogMessage "No drive letters were assigned." "Gray"
        }
    }
    catch {
        Write-LogMessage "Drive-letter assignment failed: $($_.Exception.Message)" "Yellow"
    }
}

# Detect all drives and their BitLocker status
function Get-DriveInfo {
    Write-LogMessage "Scanning for drives and BitLocker status..." "Cyan"
    
    $driveInfo = @()


    $hasGetBitLockerVolume = $null -ne (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)
    $hasManageBde = $null -ne (Get-Command manage-bde -ErrorAction SilentlyContinue)

    # Get all fixed drives (drive letters are required for manage-bde and easy path checks)
    $volumes = Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter }
    
    foreach ($volume in $volumes) {
        $driveLetter = $volume.DriveLetter
        $info = [PSCustomObject]@{
            DriveLetter       = $driveLetter
            FileSystem        = $volume.FileSystem
            Size              = $volume.Size
            SizeGB            = [Math]::Round($volume.Size / 1GB, 2)
            FreeSpace         = $volume.SizeRemaining
            FreeSpaceGB       = [Math]::Round($volume.SizeRemaining / 1GB, 2)
            Label             = $volume.FileSystemLabel
            IsLocked          = $false
            IsEncrypted       = $false
            IsWindowsOS       = $false
            WindowsVersion    = $null
            KeyProtectorId    = $null
        }
        
        # Check if drive is BitLocker encrypted/locked
        if ($hasGetBitLockerVolume) {
            try {
                $blVolume = Get-BitLockerVolume -MountPoint "$($driveLetter):" -ErrorAction Stop
                if ($blVolume) {
                    $info.IsLocked = ($blVolume.LockStatus -eq 'Locked')
                    $info.IsEncrypted = ($blVolume.VolumeStatus -ne 'FullyDecrypted')
                    $kp = @($blVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | Select-Object -First 1)
                    if ($kp.Count -gt 0) {
                        $info.KeyProtectorId = $kp[0].KeyProtectorId
                    }
                }
            }
            catch {
                # Fall back to manage-bde parsing below
            }
        }

        if (-not $info.IsEncrypted -and -not $info.IsLocked -and $hasManageBde) {
            try {
                $manageBde = (manage-bde -status "$($driveLetter):" 2>&1 | Out-String)
                if ($manageBde -match 'Conversion Status:\s+(.+)$') {
                    $info.IsEncrypted = $true
                }
                if ($manageBde -match 'Lock Status:\s+Locked') {
                    $info.IsEncrypted = $true
                    $info.IsLocked = $true
                }
                elseif ($manageBde -match 'Lock Status:\s+Unlocked') {
                    $info.IsEncrypted = $true
                    $info.IsLocked = $false
                }

                if ($info.IsEncrypted -and -not $info.KeyProtectorId) {
                    $protectors = (manage-bde -protectors -get "$($driveLetter):" 2>&1 | Out-String)
                    if ($protectors -match 'Numerical Password:\s*(?:\r?\n)+\s*ID:\s*\{([0-9A-Fa-f-]{36})\}') {
                        $info.KeyProtectorId = $Matches[1]
                    }
                }
            }
            catch {
                # Unable to determine BitLocker status
            }
        }
        
        # Check if this appears to be a Windows OS drive
        $windowsPath = "$($driveLetter):\Windows"
        if (Test-Path $windowsPath) {
            $info.IsWindowsOS = $true
            
            # Try to read Windows version from registry
            $versionPath = "$($driveLetter):\Windows\System32\config\SOFTWARE"
            if (Test-Path $versionPath) {
                try {
                    # Load offline registry hive
                    $tempHive = "HKLM\WinPE_Temp_$(Get-Random)"
                    reg load $tempHive $versionPath 2>&1 | Out-Null
                    
                    $productName = (Get-ItemProperty -Path "$tempHive\Microsoft\Windows NT\CurrentVersion" -Name ProductName -ErrorAction SilentlyContinue).ProductName
                    $currentBuild = (Get-ItemProperty -Path "$tempHive\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuild -ErrorAction SilentlyContinue).CurrentBuild
                    
                    if ($productName -and $currentBuild) {
                        $info.WindowsVersion = "$productName (Build $currentBuild)"
                    }
                    
                    # Unload registry hive
                    [gc]::Collect()
                    Start-Sleep -Milliseconds 500
                    reg unload $tempHive 2>&1 | Out-Null
                }
                catch {
                    # Could not read version info
                }
            }
        }
        
        $driveInfo += $info
    }
    
    return $driveInfo
}

# Display drive information
function Show-DriveInfo {
    param($DriveInfo)
    
    Write-Host ""
    Write-Host $Divider -ForegroundColor Cyan
    Write-Host " DETECTED DRIVES" -ForegroundColor Yellow
    Write-Host $Divider -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($drive in $DriveInfo) {
        $statusColor = "White"
        $status = "Available"
        
        if ($drive.IsLocked) {
            $statusColor = "Red"
            $status = "LOCKED (BitLocker)"
        }
        elseif ($drive.IsEncrypted) {
            $statusColor = "Yellow"
            $status = "Encrypted (Unlocked)"
        }
        
        Write-Host "Drive $($drive.DriveLetter):\" -ForegroundColor Cyan -NoNewline
        Write-Host " - $status" -ForegroundColor $statusColor
        Write-Host "  Size: $($drive.SizeGB) GB (Free: $($drive.FreeSpaceGB) GB)" -ForegroundColor Gray
        Write-Host "  Label: $($drive.Label)" -ForegroundColor Gray
        
        if ($drive.IsWindowsOS) {
            Write-Host "  Windows OS: YES" -ForegroundColor Green
            if ($drive.WindowsVersion) {
                Write-Host "  Version: $($drive.WindowsVersion)" -ForegroundColor Gray
            }
        }
        
        Write-Host ""
    }
}

# Unlock BitLocker encrypted drive
function Unlock-BitLockerDrive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DriveLetter,

        [string]$KeyProtectorId
    )
    
    Write-Host ""
    Write-Host $Divider -ForegroundColor Yellow
    Write-Host " BITLOCKER UNLOCK REQUIRED FOR DRIVE $($DriveLetter):" -ForegroundColor Yellow
    Write-Host $Divider -ForegroundColor Yellow
    Write-Host ""
    Write-Host "The drive is BitLocker encrypted and currently locked." -ForegroundColor Gray
    Write-Host "You will need the BitLocker recovery key to unlock it." -ForegroundColor Gray
    if ($KeyProtectorId) {
        Write-Host "" 
        Write-Host "Recovery Key ID: $KeyProtectorId" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "Recovery Key Format: XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX" -ForegroundColor Cyan
    Write-Host ""

    if (-not (Get-Command manage-bde -ErrorAction SilentlyContinue)) {
        Write-LogMessage "manage-bde is not available in this WinPE image; cannot unlock BitLocker." "Red"
        return $false
    }
    
    $maxAttempts = 3
    $attempt = 0
    
    while ($attempt -lt $maxAttempts) {
        $attempt++
        Write-Host "Attempt $attempt of $maxAttempts" -ForegroundColor Gray
        
        $recoveryKey = Read-Host "Enter BitLocker Recovery Key (or 'skip' to skip this drive)"
        
        if ([string]::IsNullOrWhiteSpace($recoveryKey) -or $recoveryKey -eq 'skip') {
            Write-LogMessage "Skipping drive $($DriveLetter):" "Yellow"
            return $false
        }
        
        # Clean up the recovery key (remove spaces, dashes)
        $recoveryKey = $recoveryKey -replace '\s', '' -replace '-', ''
        
        # Reformat with dashes in correct positions
        if ($recoveryKey.Length -eq 48) {
            $formattedKey = $recoveryKey -replace '(.{6})', '$1-'
            $formattedKey = $formattedKey.TrimEnd('-')
            
            Write-LogMessage "Attempting to unlock drive $($DriveLetter): with recovery key..." "Cyan"
            
            try {
                # Try using manage-bde (more reliable in WinPE)
                $result = manage-bde -unlock "$($DriveLetter):" -RecoveryPassword $formattedKey 2>&1
                
                if ($result -match "successfully|unlocked") {
                    Write-LogMessage "Drive $($DriveLetter): successfully unlocked!" "Green"
                    return $true
                }
                else {
                    Write-LogMessage "Failed to unlock drive. Invalid recovery key." "Red"
                    Write-Host "Error: $result" -ForegroundColor Red
                }
            }
            catch {
                Write-LogMessage "Error unlocking drive: $($_.Exception.Message)" "Red"
            }
        }
        else {
            Write-LogMessage "Invalid recovery key format. Key must be 48 digits." "Red"
        }
        
        Write-Host ""
    }
    
    Write-LogMessage "Maximum unlock attempts reached for drive $($DriveLetter):" "Red"
    return $false
}

function Get-CollectorCustomConfig {
    param(
        [Parameter(Mandatory = $true)][string[]]$SearchRoots
    )

    $fileName = "WinPE-Collector.custom.json"

    foreach ($root in $SearchRoots) {
        if ([string]::IsNullOrWhiteSpace($root)) {
            continue
        }

        try {
            $candidate = Join-Path $root $fileName
            if (-not (Test-Path $candidate)) {
                continue
            }

            $raw = Get-Content -Path $candidate -Raw -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($raw)) {
                continue
            }

            $cfg = $raw | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $cfg) {
                continue
            }

            Write-LogMessage "  Loaded custom config: $candidate" "Gray" -LogOnly
            return $cfg
        }
        catch {
            Write-LogMessage "  Custom config found but could not be read/parsed ($root\\$fileName): $($_.Exception.Message)" "Yellow"
        }
    }

    return $null
}

function ConvertTo-SafeFolderName {
    param([Parameter(Mandatory = $true)][string]$Name)

    $safe = ($Name -replace '[^A-Za-z0-9._-]', '_')
    if ([string]::IsNullOrWhiteSpace($safe)) {
        return "Extra"
    }
    return $safe
}

function Try-ResolveOfflineRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$BasePath,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][ref]$ResolvedPath,
        [Parameter(Mandatory = $true)][ref]$FailureReason
    )

    $ResolvedPath.Value = $null
    $FailureReason.Value = $null

    if ([string]::IsNullOrWhiteSpace($RelativePath)) {
        $FailureReason.Value = "Empty path"
        return $false
    }

    $p = $RelativePath.Trim()

    # Must be relative to the offline OS root. Disallow absolute paths, drive prefixes, and traversal.
    if ($p.StartsWith('\\') -or $p.StartsWith('/') -or $p.StartsWith('\') ) {
        $FailureReason.Value = "Absolute/UNC path not allowed"
        return $false
    }
    if ($p -match ':') {
        $FailureReason.Value = "Drive-qualified path not allowed"
        return $false
    }
    if ($p -match '(^|[\\/])\.\.([\\/]|$)') {
        $FailureReason.Value = "Path traversal (..) not allowed"
        return $false
    }

    # Normalize separators to backslash for logging and consistency
    $p = ($p -replace '/', '\\')

    try {
        $baseFull = [System.IO.Path]::GetFullPath($BasePath)
        if (-not $baseFull.EndsWith("\\")) {
            $baseFull = $baseFull + "\\"
        }

        $combined = Join-Path $BasePath $p
        $full = [System.IO.Path]::GetFullPath($combined)

        if (-not $full.ToLowerInvariant().StartsWith($baseFull.ToLowerInvariant())) {
            $FailureReason.Value = "Resolved path escaped base path"
            return $false
        }

        $ResolvedPath.Value = $full
        return $true
    }
    catch {
        $FailureReason.Value = $_.Exception.Message
        return $false
    }
}

# Collect diagnostics from offline Windows drive
function Invoke-OfflineDiagnosticsCollection {
    param(
        [string]$DriveLetter,
        [string]$OutputPath
    )
    
    Write-LogMessage "Collecting diagnostics from offline Windows on $($DriveLetter):..." "Cyan"
    
    $basePath = "$($DriveLetter):\"
    $systemInfoDir = Join-Path $OutputPath "SystemInfo"
    $logsDir = Join-Path $OutputPath "Logs"
    $evtxDir = Join-Path $OutputPath "EvtxLogs"
    
    New-Item -ItemType Directory -Path $systemInfoDir -Force | Out-Null
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
    New-Item -ItemType Directory -Path $evtxDir -Force | Out-Null
    
    $collectionInfo = @()
    $collectionInfo += $Divider
    $collectionInfo += "OFFLINE WINDOWS DIAGNOSTIC COLLECTION"
    $collectionInfo += $Divider
    $collectionInfo += "Collection Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $collectionInfo += "Collection Environment: WinPE"
    $collectionInfo += "Source Drive: $($DriveLetter):"
    $collectionInfo += ""

    # 0. Collect WinPE environment snapshot (useful for upload and storage troubleshooting)
    Write-LogMessage "  Collecting WinPE environment information..." "Gray"
    try {
        $winpeInfo = @()
        $winpeInfo += $Divider
        $winpeInfo += "WINPE ENVIRONMENT INFORMATION"
        $winpeInfo += $Divider
        $winpeInfo += "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $winpeInfo += ""
        $winpeInfo += "=== Network (ipconfig /all) ==="
        $winpeInfo += (ipconfig /all 2>&1)
        $winpeInfo += ""
        $winpeInfo += "=== Routing Table (route print) ==="
        $winpeInfo += (route print 2>&1)
        $winpeInfo += ""
        $winpeInfo += "=== ARP Cache (arp -a) ==="
        $winpeInfo += (arp -a 2>&1)
        $winpeInfo += ""
        $winpeInfo += "=== Storage (Get-Disk / Get-Partition / Get-Volume) ==="
        try {
            $winpeInfo += ((Get-Disk | Sort-Object Number | Format-Table -AutoSize | Out-String).TrimEnd())
            $winpeInfo += ""
            $winpeInfo += ((Get-Partition | Sort-Object DiskNumber, PartitionNumber | Format-Table -AutoSize | Out-String).TrimEnd())
            $winpeInfo += ""
            $winpeInfo += ((Get-Volume | Sort-Object DriveLetter | Format-Table -AutoSize | Out-String).TrimEnd())
        }
        catch {
            $winpeInfo += "Storage snapshot not available: $($_.Exception.Message)"
        }

        $winpeInfo | Out-File (Join-Path $systemInfoDir "WinPE_Environment.txt")
        $collectionInfo += "WinPE Environment: Collected (network/storage snapshot)"
        Write-LogMessage "  WinPE environment information collected" "Green"
    }
    catch {
        $collectionInfo += "WinPE Environment: ERROR - $($_.Exception.Message)"
        Write-LogMessage "  Error collecting WinPE environment information: $($_.Exception.Message)" "Yellow"
    }
    
    # 1. Collect Event Logs (.evtx files)
    Write-LogMessage "  Collecting event logs..." "Gray"
    $eventLogPath = "$basePath\Windows\System32\winevt\Logs"
    if (Test-Path $eventLogPath) {
        try {
            Copy-Item -Path $eventLogPath -Destination $evtxDir -Recurse -Force -ErrorAction SilentlyContinue
            $evtxCount = (Get-ChildItem -Path $evtxDir -Filter *.evtx -Recurse).Count
            $collectionInfo += "Event Logs: Collected $evtxCount .evtx files"
            Write-LogMessage "  Collected $evtxCount event log files" "Green"
        }
        catch {
            $collectionInfo += "Event Logs: ERROR - $($_.Exception.Message)"
            Write-LogMessage "  Error collecting event logs: $($_.Exception.Message)" "Yellow"
        }
    }
    else {
        $collectionInfo += "Event Logs: NOT FOUND"
    }
    
    # 2. Collect Registry Hives
    Write-LogMessage "  Collecting registry hives..." "Gray"
    $registryPath = "$basePath\Windows\System32\config"
    if (Test-Path $registryPath) {
        $registryDest = Join-Path $OutputPath "RegistryHives"
        New-Item -ItemType Directory -Path $registryDest -Force | Out-Null

        # Privacy-by-default: collect only non-sensitive hives.
        # (SAM/SECURITY can contain credential-related material and are intentionally excluded.)
        $hives = @("SYSTEM", "SOFTWARE", "DEFAULT")
        Write-LogMessage "    Registry hives selected: $($hives -join ', ') (SAM/SECURITY excluded)" "Gray" -LogOnly
        $collectedHives = 0
        
        foreach ($hive in $hives) {
            $hivePath = Join-Path $registryPath $hive
            if (Test-Path $hivePath) {
                try {
                    Copy-Item -Path $hivePath -Destination $registryDest -Force -ErrorAction Stop
                    $collectedHives++
                }
                catch {
                    Write-LogMessage "    Could not copy $hive hive" "Yellow"
                }
            }
        }
        
        $collectionInfo += "Registry Hives: Collected $collectedHives of $($hives.Count) hives (SAM/SECURITY excluded)"
        Write-LogMessage "  Collected $collectedHives registry hives" "Green"
    }
    else {
        $collectionInfo += "Registry Hives: NOT FOUND"
    }
    
    # 3. Collect Windows Update Logs
    Write-LogMessage "  Collecting Windows Update logs..." "Gray"
    $wuLogPath = "$basePath\Windows\Logs\WindowsUpdate"
    if (Test-Path $wuLogPath) {
        try {
            Copy-Item -Path $wuLogPath -Destination (Join-Path $logsDir "WindowsUpdate") -Recurse -Force -ErrorAction SilentlyContinue
            $collectionInfo += "Windows Update Logs: Collected"
            Write-LogMessage "  Windows Update logs collected" "Green"
        }
        catch {
            $collectionInfo += "Windows Update Logs: ERROR - $($_.Exception.Message)"
        }
    }
    else {
        $collectionInfo += "Windows Update Logs: NOT FOUND"
    }
    
    # 4. Collect CBS (Component-Based Servicing) Logs
    Write-LogMessage "  Collecting CBS logs..." "Gray"
    $cbsLogPath = "$basePath\Windows\Logs\CBS"
    if (Test-Path $cbsLogPath) {
        try {
            Copy-Item -Path $cbsLogPath -Destination (Join-Path $logsDir "CBS") -Recurse -Force -ErrorAction SilentlyContinue
            $collectionInfo += "CBS Logs: Collected"
            Write-LogMessage "  CBS logs collected" "Green"
        }
        catch {
            $collectionInfo += "CBS Logs: ERROR - $($_.Exception.Message)"
        }
    }
    else {
        $collectionInfo += "CBS Logs: NOT FOUND"
    }
    
    # 5. Collect DISM Logs
    Write-LogMessage "  Collecting DISM logs..." "Gray"
    $dismLogPath = "$basePath\Windows\Logs\DISM"
    if (Test-Path $dismLogPath) {
        try {
            Copy-Item -Path $dismLogPath -Destination (Join-Path $logsDir "DISM") -Recurse -Force -ErrorAction SilentlyContinue
            $collectionInfo += "DISM Logs: Collected"
            Write-LogMessage "  DISM logs collected" "Green"
        }
        catch {
            $collectionInfo += "DISM Logs: ERROR - $($_.Exception.Message)"
        }
    }
    else {
        $collectionInfo += "DISM Logs: NOT FOUND"
    }
    
    # 6. Collect Panther logs (Setup/Upgrade)
    Write-LogMessage "  Collecting Windows Setup logs..." "Gray"
    $pantherPath = "$basePath\Windows\Panther"
    if (Test-Path $pantherPath) {
        try {
            Copy-Item -Path $pantherPath -Destination (Join-Path $logsDir "Panther") -Recurse -Force -ErrorAction SilentlyContinue
            $collectionInfo += "Setup Logs (Panther): Collected"
            Write-LogMessage "  Windows Setup logs collected" "Green"
        }
        catch {
            $collectionInfo += "Setup Logs (Panther): ERROR - $($_.Exception.Message)"
        }
    }
    else {
        $collectionInfo += "Setup Logs (Panther): NOT FOUND"
    }

    # 6b. Collect MoSetup logs (Upgrade/Setup)
    Write-LogMessage "  Collecting MoSetup logs..." "Gray"
    $moSetupPath = "$basePath\Windows\Logs\MoSetup"
    if (Test-Path $moSetupPath) {
        try {
            Copy-Item -Path $moSetupPath -Destination (Join-Path $logsDir "MoSetup") -Recurse -Force -ErrorAction SilentlyContinue
            $collectionInfo += "MoSetup Logs: Collected"
            Write-LogMessage "  MoSetup logs collected" "Green"
        }
        catch {
            $collectionInfo += "MoSetup Logs: ERROR - $($_.Exception.Message)"
        }
    }
    else {
        $collectionInfo += "MoSetup Logs: NOT FOUND"
    }

    # 6c. Collect SetupAPI device installation logs (drivers)
    Write-LogMessage "  Collecting SetupAPI logs..." "Gray"
    $setupApiDir = "$basePath\Windows\INF"
    if (Test-Path $setupApiDir) {
        try {
            $setupApiDest = Join-Path $logsDir "SetupAPI"
            New-Item -ItemType Directory -Path $setupApiDest -Force | Out-Null
            $setupApiLogs = Get-ChildItem -Path $setupApiDir -Filter "setupapi*.log" -ErrorAction SilentlyContinue
            foreach ($log in $setupApiLogs) {
                Copy-Item -Path $log.FullName -Destination $setupApiDest -Force -ErrorAction SilentlyContinue
            }
            if ($setupApiLogs) {
                $collectionInfo += "SetupAPI Logs: Collected $($setupApiLogs.Count) file(s)"
                Write-LogMessage "  SetupAPI logs collected ($($setupApiLogs.Count))" "Green"
            }
            else {
                $collectionInfo += "SetupAPI Logs: None found"
            }
        }
        catch {
            $collectionInfo += "SetupAPI Logs: ERROR - $($_.Exception.Message)"
        }
    }
    else {
        $collectionInfo += "SetupAPI Logs: NOT FOUND"
    }

    # 6d. Collect Startup Repair logs (SrtTrail)
    Write-LogMessage "  Collecting Startup Repair logs..." "Gray"
    $srtPath = "$basePath\Windows\System32\LogFiles\Srt"
    if (Test-Path $srtPath) {
        try {
            Copy-Item -Path $srtPath -Destination (Join-Path $logsDir "Srt") -Recurse -Force -ErrorAction SilentlyContinue
            $collectionInfo += "Startup Repair Logs (Srt): Collected"
            Write-LogMessage "  Startup Repair logs collected" "Green"
        }
        catch {
            $collectionInfo += "Startup Repair Logs (Srt): ERROR - $($_.Exception.Message)"
        }
    }
    else {
        $collectionInfo += "Startup Repair Logs (Srt): NOT FOUND"
    }

    # 6e. Collect NetSetup logs (domain join / networking history)
    Write-LogMessage "  Collecting NetSetup logs..." "Gray"
    $netSetupPaths = @(
        "$basePath\Windows\debug\NetSetup",
        "$basePath\Windows\debug\NetSetup.log",
        "$basePath\Windows\System32\LogFiles\NetSetup"
    )
    $netSetupDest = Join-Path $logsDir "NetSetup"
    $netSetupCollected = $false
    foreach ($p in $netSetupPaths) {
        if (Test-Path $p) {
            try {
                New-Item -ItemType Directory -Path $netSetupDest -Force | Out-Null
                Copy-Item -Path $p -Destination $netSetupDest -Recurse -Force -ErrorAction SilentlyContinue
                $netSetupCollected = $true
            }
            catch {
                # ignore per-path failures
            }
        }
    }
    if ($netSetupCollected) {
        $collectionInfo += "NetSetup Logs: Collected"
        Write-LogMessage "  NetSetup logs collected" "Green"
    }
    else {
        $collectionInfo += "NetSetup Logs: NOT FOUND"
    }
    
    # 7. Collect BitLocker information
    Write-LogMessage "  Collecting BitLocker information..." "Gray"
    try {
        $blInfo = @()
        $blInfo += $Divider
        $blInfo += "BITLOCKER STATUS (OFFLINE COLLECTION)"
        $blInfo += $Divider
        $blInfo += ""
        
        # Use manage-bde to get status
        $manageBdeResult = manage-bde -status "$($DriveLetter):" 2>&1
        $blInfo += "manage-bde -status output:"
        $blInfo += $manageBdeResult
        $blInfo += ""
        
        $blInfo | Out-File (Join-Path $systemInfoDir "BitLocker_Status_Offline.txt")
        $collectionInfo += "BitLocker Status: Collected"
    }
    catch {
        $collectionInfo += "BitLocker Status: ERROR - $($_.Exception.Message)"
    }
    
    # 8. Collect Windows version information
    Write-LogMessage "  Collecting Windows version information..." "Gray"
    try {
        $versionInfo = @()
        $versionInfo += $Divider
        $versionInfo += "WINDOWS VERSION INFORMATION (OFFLINE)"
        $versionInfo += $Divider
        $versionInfo += ""
        
        # Read version info from registry
        $softwarePath = "$basePath\Windows\System32\config\SOFTWARE"
        if (Test-Path $softwarePath) {
            $tempHive = "HKLM\WinPE_Version_$(Get-Random)"
            reg load $tempHive $softwarePath 2>&1 | Out-Null
            
            try {
                $regPath = "$tempHive\Microsoft\Windows NT\CurrentVersion"
                $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                
                if ($props) {
                    $versionInfo += "Product Name: $($props.ProductName)"
                    $versionInfo += "Edition ID: $($props.EditionID)"
                    $versionInfo += "Current Build: $($props.CurrentBuild)"
                    $versionInfo += "UBR: $($props.UBR)"
                    $versionInfo += "Display Version: $($props.DisplayVersion)"
                    $versionInfo += "Release ID: $($props.ReleaseId)"
                    $versionInfo += "Build Lab: $($props.BuildLabEx)"
                    $versionInfo += "Installation Date: $([DateTime]::FromFileTime($props.InstallDate))"
                    $versionInfo += "Registered Owner: $($props.RegisteredOwner)"
                    $versionInfo += "Registered Organization: $($props.RegisteredOrganization)"
                    $versionInfo += "Product ID: $($props.ProductId)"
                }
                
                [gc]::Collect()
                Start-Sleep -Milliseconds 500
            }
            finally {
                reg unload $tempHive 2>&1 | Out-Null
            }
        }
        
        $versionInfo | Out-File (Join-Path $systemInfoDir "WindowsVersion_Offline.txt")
        $collectionInfo += "Windows Version: Collected"
    }
    catch {
        $collectionInfo += "Windows Version: ERROR - $($_.Exception.Message)"
    }
    
    # 9. Collect servicing package inventory (often used as a proxy for installed updates)
    Write-LogMessage "  Collecting servicing package inventory..." "Gray"
    $updatesPath = "$basePath\Windows\servicing\Packages"
    if (Test-Path $updatesPath) {
        try {
            $packages = Get-ChildItem -Path $updatesPath -Filter "*.mum" -ErrorAction SilentlyContinue
            $updateInfo = @()
            $updateInfo += $Divider
            $updateInfo += "SERVICING PACKAGE INVENTORY (OFFLINE)"
            $updateInfo += $Divider
            $updateInfo += "Total Packages: $($packages.Count)"
            $updateInfo += ""
            
            # Get up to 100 KB-named packages
            $kbPackages = $packages | Where-Object { $_.Name -match "KB\d+" } | Sort-Object LastWriteTime -Descending | Select-Object -First 100
            
            foreach ($pkg in $kbPackages) {
                if ($pkg.Name -match "(KB\d+)") {
                    $kb = $matches[1]
                    $updateInfo += "$kb - Installed: $($pkg.LastWriteTime)"
                }
            }
            
            $updateInfo | Out-File (Join-Path $systemInfoDir "InstalledUpdates_Offline.txt")
            $collectionInfo += "Servicing Package Inventory: Collected (Up to 100 KB-named packages)"
        }
        catch {
            $collectionInfo += "Servicing Package Inventory: ERROR - $($_.Exception.Message)"
        }
    }
    else {
        $collectionInfo += "Servicing Package Inventory: NOT FOUND"
    }
    
    # 10. Collect crash dumps
    Write-LogMessage "  Collecting crash dumps..." "Gray"
    $minidumpPath = "$basePath\Windows\Minidump"
    $memorydmpPath = "$basePath\Windows\MEMORY.DMP"
    $liveKernelReportsPath = "$basePath\Windows\LiveKernelReports"
    
    $dumpDest = Join-Path $OutputPath "CrashDumps"
    New-Item -ItemType Directory -Path $dumpDest -Force | Out-Null
    
    $dumpCount = 0
    
    if (Test-Path $minidumpPath) {
        try {
            $dumps = Get-ChildItem -Path $minidumpPath -Filter *.dmp -ErrorAction SilentlyContinue
            if ($dumps) {
                Copy-Item -Path $minidumpPath -Destination (Join-Path $dumpDest "Minidump") -Recurse -Force -ErrorAction SilentlyContinue
                $dumpCount += $dumps.Count
            }
        }
        catch {}
    }
    
    if (Test-Path $memorydmpPath) {
        try {
            $memDump = Get-Item $memorydmpPath
            # Only copy if less than 500MB
            if ($memDump.Length -lt 500MB) {
                Copy-Item -Path $memorydmpPath -Destination $dumpDest -Force -ErrorAction SilentlyContinue
                $dumpCount++
            }
            else {
                $collectionInfo += "Crash Dumps: MEMORY.DMP too large ($([Math]::Round($memDump.Length / 1MB, 2)) MB) - skipped"
            }
        }
        catch {}
    }

    # LiveKernelReports (kernel-mode dumps useful for hardware/driver issues)
    if (Test-Path $liveKernelReportsPath) {
        try {
            $lkDest = Join-Path $dumpDest "LiveKernelReports"
            New-Item -ItemType Directory -Path $lkDest -Force | Out-Null

            $lkDumps = Get-ChildItem -Path $liveKernelReportsPath -Filter *.dmp -Recurse -ErrorAction SilentlyContinue
            foreach ($dmp in $lkDumps) {
                try {
                    if ($dmp.Length -lt 500MB) {
                        $target = Join-Path $lkDest $dmp.Name
                        Copy-Item -Path $dmp.FullName -Destination $target -Force -ErrorAction SilentlyContinue
                        $dumpCount++
                    }
                }
                catch {
                    # ignore per-file copy failures
                }
            }
        }
        catch {
            $collectionInfo += "Crash Dumps: ERROR collecting LiveKernelReports - $($_.Exception.Message)"
        }
    }
    
    if ($dumpCount -gt 0) {
        $collectionInfo += "Crash Dumps: Collected $dumpCount dump file(s)"
        Write-LogMessage "  Collected $dumpCount crash dump(s)" "Green"
    }
    else {
        $collectionInfo += "Crash Dumps: None found"
    }
    
    # 11. Collect optional extra folders (implementation-specific)
    # Easiest path for implementers: drop a WinPE-Collector.custom.json next to the script (or in the working folder)
    # or set EXTRA_OFFLINE_FOLDERS (semicolon-separated list of relative paths, optionally "Label=RelativePath").
    # Back-compat: ORG_PROGRAMDATA_FOLDER is treated as "ProgramData\<ORG_PROGRAMDATA_FOLDER>".
    Write-LogMessage "  Collecting optional extra folders..." "Gray"

    $customConfig = Get-CollectorCustomConfig -SearchRoots @(
        $PSScriptRoot,
        (Split-Path -Parent $OutputPath),
        $OutputPath
    )

    $extraSpecs = New-Object System.Collections.Generic.List[object]

    $orgProgramDataFolder = $env:ORG_PROGRAMDATA_FOLDER
    if ([string]::IsNullOrWhiteSpace($orgProgramDataFolder) -and $customConfig -and $customConfig.orgProgramDataFolder) {
        $orgProgramDataFolder = [string]$customConfig.orgProgramDataFolder
    }
    if (-not [string]::IsNullOrWhiteSpace($orgProgramDataFolder)) {
        $extraSpecs.Add([PSCustomObject]@{
                Name = "ProgramData_$orgProgramDataFolder"
                RelativePath = "ProgramData\\$orgProgramDataFolder"
                Source = "ORG_PROGRAMDATA_FOLDER"
            })
    }

    # Parse env-based extras
    $extraRaw = $env:EXTRA_OFFLINE_FOLDERS
    if (-not [string]::IsNullOrWhiteSpace($extraRaw)) {
        $tokens = $extraRaw -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        foreach ($t in $tokens) {
            $name = $null
            $rel = $null

            if ($t -match '^(.*?)=(.+)$') {
                $name = $Matches[1].Trim()
                $rel = $Matches[2].Trim()
            }
            else {
                $rel = $t
                $name = Split-Path $rel -Leaf
            }

            if (-not [string]::IsNullOrWhiteSpace($rel)) {
                $extraSpecs.Add([PSCustomObject]@{ Name = $name; RelativePath = $rel; Source = "EXTRA_OFFLINE_FOLDERS" })
            }
        }
    }

    # Parse JSON config extras
    if ($customConfig) {
        if ($customConfig.extraFolders) {
            foreach ($item in @($customConfig.extraFolders)) {
                try {
                    $rel = if ($item.path) { [string]$item.path } else { $null }
                    $name = if ($item.name) { [string]$item.name } else { (Split-Path $rel -Leaf) }
                    if (-not [string]::IsNullOrWhiteSpace($rel)) {
                        $extraSpecs.Add([PSCustomObject]@{ Name = $name; RelativePath = $rel; Source = "WinPE-Collector.custom.json" })
                    }
                }
                catch {
                    # ignore malformed items
                }
            }
        }

        if ($customConfig.extraFolderPaths) {
            foreach ($rel in @($customConfig.extraFolderPaths)) {
                try {
                    $r = [string]$rel
                    if (-not [string]::IsNullOrWhiteSpace($r)) {
                        $extraSpecs.Add([PSCustomObject]@{ Name = (Split-Path $r -Leaf); RelativePath = $r; Source = "WinPE-Collector.custom.json" })
                    }
                }
                catch {
                    # ignore
                }
            }
        }
    }

    if ($extraSpecs.Count -eq 0) {
        $collectionInfo += "Extra folders: SKIPPED (none configured)"
    }
    else {
        $extrasRoot = Join-Path $OutputPath "ExtraFolders"
        New-Item -ItemType Directory -Path $extrasRoot -Force | Out-Null

        $collected = 0
        $skipped = 0

        foreach ($spec in $extraSpecs) {
            $resolved = $null
            $reason = $null
            $ok = Try-ResolveOfflineRelativePath -BasePath $basePath -RelativePath $spec.RelativePath -ResolvedPath ([ref]$resolved) -FailureReason ([ref]$reason)
            if (-not $ok) {
                $skipped++
                $collectionInfo += "Extra folder ($($spec.Source)): SKIPPED - $($spec.RelativePath) ($reason)"
                continue
            }

            if (-not (Test-Path $resolved)) {
                $skipped++
                $collectionInfo += "Extra folder ($($spec.Source)): NOT FOUND - $($spec.RelativePath)"
                continue
            }

            $safeName = ConvertTo-SafeFolderName -Name ($spec.Name)
            $dest = Join-Path $extrasRoot $safeName

            try {
                Copy-Item -Path $resolved -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
                $collected++
                $collectionInfo += "Extra folder ($($spec.Source)): Collected - $($spec.RelativePath)"
                Write-LogMessage "  Extra folder collected: $($spec.RelativePath)" "Green"
            }
            catch {
                $skipped++
                $collectionInfo += "Extra folder ($($spec.Source)): ERROR - $($spec.RelativePath) ($($_.Exception.Message))"
            }
        }

        $collectionInfo += "Extra folders: Collected $collected, skipped $skipped"
    }
    
    # 12. Save collection summary
    $collectionInfo += ""
    $collectionInfo += $Divider
    $collectionInfo += "COLLECTION COMPLETED: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $collectionInfo += $Divider
    
    $collectionInfo | Out-File (Join-Path $OutputPath "Collection_Summary.txt")
    
    Write-LogMessage "Offline diagnostic collection completed" "Green"
}

function Invoke-MultipartFileUpload {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string]$UploadUrl,
        [Parameter(Mandatory = $true)][string]$AuthKey,
        [int]$TimeoutMinutes = 30
    )

    Add-Type -AssemblyName System.Net.Http

    $httpClient = $null
    $content = $null
    $fileStream = $null
    $response = $null

    try {
        $httpClient = New-Object System.Net.Http.HttpClient
        $httpClient.Timeout = New-Object System.TimeSpan(0, $TimeoutMinutes, 0)
        $httpClient.DefaultRequestHeaders.Remove("X-Auth-Key") | Out-Null
        $httpClient.DefaultRequestHeaders.Add("X-Auth-Key", $AuthKey)

        $content = New-Object System.Net.Http.MultipartFormDataContent
        $fileStream = [System.IO.File]::OpenRead($FilePath)
        $fileContent = New-Object System.Net.Http.StreamContent($fileStream)
        $content.Add($fileContent, "file", $FileName)

        $response = $httpClient.PostAsync($UploadUrl, $content).Result
        return $response.IsSuccessStatusCode
    }
    finally {
        if ($response) { $response.Dispose() }
        if ($fileStream) { $fileStream.Dispose() }
        if ($content) { $content.Dispose() }
        if ($httpClient) { $httpClient.Dispose() }
    }
}

# Upload diagnostics to server
function Send-DiagnosticsPackage {
    param(
        [string]$ZipPath,
        [string]$UploadUrl,
        [string]$AuthKey
    )
    
    Write-LogMessage "Uploading diagnostics to server..." "Cyan"
    
    try {
        $fileName = Split-Path $ZipPath -Leaf
        Write-LogMessage "  Uploading $fileName ($([Math]::Round((Get-Item $ZipPath).Length / 1MB, 2)) MB)..." "Gray"

        $ok = Invoke-MultipartFileUpload -FilePath $ZipPath -FileName $fileName -UploadUrl $UploadUrl -AuthKey $AuthKey -TimeoutMinutes 30
        if ($ok) {
            Write-LogMessage "Upload successful!" "Green"
            return $true
        }

        Write-LogMessage "Upload failed (non-success HTTP status)." "Red"
        return $false
    }
    catch {
        Write-LogMessage "Upload error: $($_.Exception.Message)" "Red"
        Write-LogMessage "The diagnostic package has been saved locally to:" "Yellow"
        Write-LogMessage "  $ZipPath" "Yellow"
        return $false
    }
}

# Upload error log on failure
function Send-ErrorLogPackage {
    param(
        [string]$ErrorLogPath,
        [string]$UploadUrl,
        [string]$AuthKey,
        [string]$ComputerName = "UNKNOWN",
        [string]$Serial = "UNKNOWN"
    )
    
    $errorZipPath = $null
    try {
        # Create a small zip with just the error log
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $errorZipName = "WinPE-ERROR-$ComputerName-$Serial-$timestamp.zip"
        $errorZipPath = Join-Path (Split-Path $ErrorLogPath -Parent) $errorZipName
        
        Compress-Archive -Path $ErrorLogPath -DestinationPath $errorZipPath -CompressionLevel Fastest -Force
        
        $ok = Invoke-MultipartFileUpload -FilePath $errorZipPath -FileName $errorZipName -UploadUrl $UploadUrl -AuthKey $AuthKey -TimeoutMinutes 5
        if ($ok) {
            Write-LogMessage "Error log uploaded successfully" "Green"
            return $true
        }
        else {
            Write-LogMessage "Could not upload error log (non-success HTTP status)." "Yellow"
            return $false
        }
    }
    catch {
        Write-LogMessage "Could not upload error log: $($_.Exception.Message)" "Yellow"
        return $false
    }
    finally {
        if ($errorZipPath -and (Test-Path $errorZipPath)) {
            Remove-Item -Path $errorZipPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# Main execution
function Main {
    Show-Banner
    
    # Determine working directory (X:\ for WinPE, C:\Temp for online Windows)
    $isWinPE = Test-Path "X:\Windows"
    $workingRoot = if ($isWinPE) {
        # Prefer writing to removable media (USB) instead of X: (RAM disk)
        # 1) Prefer a known label (WINPE_DIAG)
        $preferred = (Get-Volume -ErrorAction SilentlyContinue |
                Where-Object { $_.DriveLetter -and $_.FileSystemLabel -eq "WINPE_DIAG" } |
                Select-Object -First 1)

        if ($preferred -and $preferred.DriveLetter) {
            "$($preferred.DriveLetter):\WinPECollector"
        }
        else {
            # 2) Fallback: choose the best writable removable/USB volume by free space
            $candidates = @(Get-Volume -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.DriveLetter -and
                        $_.DriveLetter -ne 'X' -and
                        $_.FileSystem -and
                        ($_.DriveType -in @('Removable','Fixed'))
                    } |
                    Sort-Object SizeRemaining -Descending)

            $selectedRoot = $null
            foreach ($vol in $candidates) {
                $root = "$($vol.DriveLetter):\WinPECollector"
                try {
                    if (-not (Test-Path $root)) {
                        New-Item -ItemType Directory -Path $root -Force | Out-Null
                    }

                    # quick write check
                    $probe = Join-Path $root (".write-test-" + [Guid]::NewGuid().ToString() + ".tmp")
                    'ok' | Out-File -FilePath $probe -Force
                    Remove-Item -Path $probe -Force -ErrorAction SilentlyContinue

                    $selectedRoot = $root
                    break
                }
                catch {
                    # Not writable; try next candidate
                }
            }

            if ($selectedRoot) {
                $selectedRoot
            }
            else {
                "X:\WinPECollector"
            }
        }
    }
    else {
        "C:\Temp\WinPECollector"
    }
    
    # Ensure working directory exists and initialize a session log
    Initialize-SessionLogging -WorkingRoot $workingRoot
    if (-not (Test-Path $workingRoot)) {
        New-Item -ItemType Directory -Path $workingRoot -Force | Out-Null
    }

    Write-Section "Session"
    Write-LogMessage "Working directory: $workingRoot" "Cyan"
    if ($Global:SessionLogPath) {
        Write-LogMessage "Session log: $Global:SessionLogPath" "Gray"
    }

    # Capture early environment snapshot for troubleshooting (network + storage + drivers)
    Save-SessionEnvironmentSnapshot -WorkingRoot $workingRoot

    # Pre-flight: if network isn't ready, give the user a chance to set up WiFi (WinPE only)
    if ($isWinPE) {
        Ensure-NetworkOrContinue -UploadUrl $UploadUrl
    }
    
    # Initialize error log for failure reporting
    $errorLogPath = Join-Path $workingRoot "WinPE-Collector-Error.log"
    $errorLog = @()
    $errorLog += "=" * 60
    $errorLog += "WinPE Collector Error Log"
    $errorLog += "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $errorLog += "Environment: $(if ($isWinPE) { 'WinPE' } else { 'Online Windows' })"
    $errorLog += "=" * 60
    $errorLog += ""
    
    if ($isWinPE) {
        Write-LogMessage "Running in WinPE environment" "Green"
    }
    else {
        Write-LogMessage "Running in online Windows environment (fallback mode)" "Yellow"
        $errorLog += "Note: Running in online Windows, not WinPE"
    }
    
    Write-Host ""

    if ($isWinPE) {
        Ensure-DriveLetters
        Start-Sleep -Seconds 1
    }
    
    Write-Section "Detecting Offline Windows"
    # Detect drives
    $drives = Get-DriveInfo
    Show-DriveInfo -DriveInfo $drives
    
    # Find Windows OS drives - force to array
    $windowsDrives = @($drives | Where-Object { $_.IsWindowsOS -eq $true })
    
    # If no Windows OS found, assume BitLocker encrypted drives and prompt for recovery key
    if ($windowsDrives.Count -eq 0) {
        Write-LogMessage "No accessible Windows OS installations detected!" "Yellow"
        Write-Host ""
        $unlockedAny = $false
        $lockedDrives = @($drives | Where-Object { $_.IsLocked -eq $true })
        if ($lockedDrives.Count -gt 0) {
            Write-Host "Locked Drives Detected:" -ForegroundColor Yellow
            foreach ($drive in $lockedDrives) {
                $unlocked = Unlock-BitLockerDrive -DriveLetter $drive.DriveLetter -KeyProtectorId $drive.KeyProtectorId
                if ($unlocked) {
                    $unlockedAny = $true
                }
            }

            Start-Sleep -Seconds 2
            $drives = Get-DriveInfo
            Show-DriveInfo -DriveInfo $drives
            $windowsDrives = @($drives | Where-Object { $_.IsWindowsOS -eq $true })
        }
        
        if ($lockedDrives.Count -eq 0) {
            Write-Host "No locked drives detected." -ForegroundColor Gray
        }

        # Re-check if we found any Windows drives after unlocking
        if ($windowsDrives.Count -eq 0) {
            if ($unlockedAny) {
                Write-LogMessage "Unlocked drives but no Windows OS installations found." "Red"
            }
            else {
                Write-LogMessage "Could not unlock any drives with the provided key." "Red"
            }
            Write-Host ""
            Read-Host "Press Enter to exit"
            return
        }
        
        Write-Host ""
        Write-LogMessage "Found Windows OS after unlocking!" "Green"
    }
    
    # If multiple Windows drives, let user choose
    $targetDrive = $null
    
    if ($windowsDrives.Count -eq 1) {
        $targetDrive = $windowsDrives[0]
        Write-LogMessage "Found Windows installation on drive $($targetDrive.DriveLetter):" "Green"
    }
    else {
        Write-Host ""
        Write-Host "Multiple Windows installations detected:" -ForegroundColor Yellow
        Write-Host ""
        for ($i = 0; $i -lt $windowsDrives.Count; $i++) {
            $version = if ($windowsDrives[$i].WindowsVersion) { $windowsDrives[$i].WindowsVersion } else { "Unknown Version" }
            Write-Host "  [$($i + 1)] Drive $($windowsDrives[$i].DriveLetter): - $version" -ForegroundColor Cyan
        }
        Write-Host ""
        
        $selection = Read-Host "Select drive number (1-$($windowsDrives.Count))"
        $index = [int]$selection - 1
        
        if ($index -ge 0 -and $index -lt $windowsDrives.Count) {
            $targetDrive = $windowsDrives[$index]
        }
        else {
            Write-LogMessage "Invalid selection" "Red"
            return
        }
    }
    
    Write-Host ""
    
    Write-Section "Selected Target"
    # Check if drive is locked
    if ($targetDrive.IsLocked) {
        $unlocked = Unlock-BitLockerDrive -DriveLetter $targetDrive.DriveLetter
        
        if (-not $unlocked) {
            Write-LogMessage "Cannot proceed without unlocking drive $($targetDrive.DriveLetter):" "Red"
            Write-Host ""
            Read-Host "Press Enter to exit"
            return
        }
        
        # Refresh drive info after unlock
        Start-Sleep -Seconds 2
    }
    
    Write-Section "Collecting Diagnostics"
    # Create output directory
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $computerName = "OFFLINE"
    $serial = "UNKNOWN"
    
    # Try to get computer name from registry
    try {
        $systemPath = "$($targetDrive.DriveLetter):\Windows\System32\config\SYSTEM"
        if (Test-Path $systemPath) {
            $tempHive = "HKLM\WinPE_System_$(Get-Random)"
            reg load $tempHive $systemPath 2>&1 | Out-Null
            
            $computerName = (Get-ItemProperty -Path "$tempHive\ControlSet001\Control\ComputerName\ComputerName" -Name ComputerName -ErrorAction SilentlyContinue).ComputerName
            
            [gc]::Collect()
            Start-Sleep -Milliseconds 500
            reg unload $tempHive 2>&1 | Out-Null
        }
    }
    catch {}
    
    # Try to get serial number
    try {
        $biosSerial = (Get-WmiObject -Class Win32_BIOS -ErrorAction SilentlyContinue).SerialNumber
        if ($biosSerial) {
            $serial = $biosSerial
        }
    }
    catch {}
    
    $diagName = "WinPE-Diag-$computerName-$serial-$timestamp"
    $outputDir = Join-Path $workingRoot $diagName
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    
    Write-Host ""
    Write-LogMessage "Output directory: $outputDir" "Cyan"
    Write-Host ""
    
    # Collect diagnostics
    $collectionSucceeded = $true
    try {
        Invoke-OfflineDiagnosticsCollection -DriveLetter $targetDrive.DriveLetter -OutputPath $outputDir
    }
    catch {
        $errorMsg = "Failed to collect diagnostics: $($_.Exception.Message)"
        Write-LogMessage $errorMsg "Red"
        $errorLog += $errorMsg
        $errorLog += $_.ScriptStackTrace
        $collectionSucceeded = $false
    }

    # Save error log into working root and also into the output folder (so it rides along in the ZIP)
    try {
        $errorLog | Out-File $errorLogPath -Force
        Copy-Item -Path $errorLogPath -Destination (Join-Path $outputDir "WinPE-Collector-Error.log") -Force -ErrorAction SilentlyContinue
    }
    catch {
        # ignore
    }

    # Include session log in the output folder (best-effort)
    try {
        if ($Global:SessionLogPath -and (Test-Path $Global:SessionLogPath)) {
            Copy-Item -Path $Global:SessionLogPath -Destination (Join-Path $outputDir (Split-Path $Global:SessionLogPath -Leaf)) -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        # ignore
    }
    
    # Create ZIP file (even if collection failed partway, zip what we have)
    Write-Host ""
    Write-LogMessage "Creating ZIP archive..." "Cyan"
    
    $zipPath = Join-Path $workingRoot "$diagName.zip"
    
    try {
        Compress-Archive -Path "$outputDir\*" -DestinationPath $zipPath -CompressionLevel Optimal -Force
        $zipSize = [Math]::Round((Get-Item $zipPath).Length / 1MB, 2)
        Write-LogMessage "ZIP archive created: $zipSize MB" "Green"
    }
    catch {
        $errorMsg = "Error creating ZIP: $($_.Exception.Message)"
        Write-LogMessage $errorMsg "Red"
        $errorLog += $errorMsg
        $errorLog += $_.ScriptStackTrace

        # Try to upload the error log (best-effort) for troubleshooting
        try {
            $errorLog | Out-File $errorLogPath -Force
            Write-LogMessage "Uploading error log (best-effort)..." "Yellow"
            Send-ErrorLogPackage -ErrorLogPath $errorLogPath -UploadUrl $UploadUrl -AuthKey $AuthKey -ComputerName $computerName -Serial $serial
        }
        catch {
            # ignore
        }

        Write-Host ""
        Write-LogMessage "Unable to create ZIP. Logs saved to:" "Yellow"
        Write-LogMessage "  $outputDir" "Yellow"
        if ($Global:SessionLogPath) {
            Write-LogMessage "Session log: $Global:SessionLogPath" "Yellow"
        }
        Write-Host ""
        Read-Host "Press Enter to exit"
        return
    }
    
    # Upload (best-effort). If collection failed, still attempt upload so we can troubleshoot.
    Write-Host ""
    Write-LogMessage "Uploading diagnostic package..." "Cyan"   
        $uploaded = Send-DiagnosticsPackage -ZipPath $zipPath -UploadUrl $UploadUrl -AuthKey $AuthKey
        
    if ($uploaded) {
        Write-Host ""
        if ($collectionSucceeded) {
            Write-LogMessage "Diagnostic collection and upload completed successfully!" "Green"
        }
        else {
            Write-LogMessage "Upload completed, but collection had errors (see logs in the ZIP)." "Yellow"
        }
        if ($isWinPE) {
            Write-LogMessage "You can now safely remove the WinPE media and restart the system." "Yellow"
        }
    }
    else {
        Write-Host ""
        Write-LogMessage "Upload not available or failed. The package has been saved locally to:" "Yellow"
        Write-LogMessage "  $zipPath" "Yellow"

        # Give a last-chance WiFi setup + retry in WinPE
        if ($isWinPE) {
            Write-Host "" 
            $doWifi = Read-Host "Configure WiFi and retry upload now? (y/n)"
            if ($doWifi -eq 'y') {
                if (Invoke-WiFiSetupInteractive) {
                    Write-LogMessage "Retrying upload..." "Cyan"
                    $retryUploaded = Send-DiagnosticsPackage -ZipPath $zipPath -UploadUrl $UploadUrl -AuthKey $AuthKey
                    if ($retryUploaded) {
                        Write-LogMessage "Upload successful after WiFi setup!" "Green"
                        if ($isWinPE) {
                            Write-LogMessage "You can now safely remove the WinPE media and restart the system." "Yellow"
                        }
                        Write-Host ""
                        Write-Host $Divider -ForegroundColor Cyan
                        Read-Host "Press Enter to exit"
                        return
                    }
                }
            }
        }

        if (-not $collectionSucceeded) {
            Write-LogMessage "Collection had errors; include the ZIP + session log for troubleshooting." "Yellow"
        }
        if ($Global:SessionLogPath) {
            Write-LogMessage "Session log: $Global:SessionLogPath" "Yellow"
        }
    }
    
    Write-Host ""
    Write-Host $Divider -ForegroundColor Cyan
    Read-Host "Press Enter to exit"
}

# Run main function
Main
