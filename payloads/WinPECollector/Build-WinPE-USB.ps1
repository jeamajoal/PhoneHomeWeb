<#
.SYNOPSIS
    WinPE USB Builder for Offline Diagnostic Collection

.DESCRIPTION
    Creates a bootable WinPE USB drive with:
    - PowerShell support
    - Network drivers
    - Pre-loaded WinPE Collector script
    - Auto-launch of collector on boot
    
    Requires Windows ADK with WinPE add-on installed.

.PARAMETER USBDiskNumber
    The disk number of the USB drive to make bootable.
    If not specified, available USB disks will be listed for selection.

.PARAMETER IncludeWiFi
    Include WiFi drivers and support (larger image). Enabled by default.
    To disable WiFi support: -IncludeWiFi:$false

.PARAMETER ADKPath
    Path to Windows ADK installation (auto-detected if not specified)

.PARAMETER CollectorScriptPath
    Optional path to a local WinPE-Collector.ps1 to embed into the WinPE image.
    Use this to build the USB without needing a server available at build time.

.EXAMPLE
    .\Build-WinPE-USB.ps1
    Lists available USB disks and prompts for selection.
    
.EXAMPLE
    .\Build-WinPE-USB.ps1 -USBDiskNumber 2
    Uses disk 2 directly.

.EXAMPLE
    .\Build-WinPE-USB.ps1 -USBDiskNumber 2 -IncludeWiFi

.NOTES
    Author: jeamajoal
    Date: December 17, 2025
    Requirements:
        - Windows 10/11 with Admin rights
        - Windows ADK installed
        - Windows PE add-on for ADK installed
        - USB drive (8GB+ recommended)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$USBDiskNumber = -1,
    
    [switch]$IncludeWiFi = $true,
    
    [string]$ADKPath = "",
    
    [string]$ServerUrl = "<<SERVERURL>>",
    [string]$AuthKey = "<<AUTHKEY>>",

    [string]$CollectorScriptPath = ""
)

$ErrorActionPreference = "Stop"

# Best-effort TLS hardening for downloads (important on older PS/.NET)
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
catch {
    # Ignore - not available on all builds
}

# Divider for output
$Divider = "================================================================================" 

function Invoke-WebRequestCompat {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [hashtable]$Headers,
        [int]$TimeoutSec = 0
    )

    $params = @{ Uri = $Uri; OutFile = $OutFile }
    if ($Headers) { $params.Headers = $Headers }
    if ($TimeoutSec -gt 0 -and (Get-Command Invoke-WebRequest).Parameters.ContainsKey('TimeoutSec')) {
        $params.TimeoutSec = $TimeoutSec
    }
    if ((Get-Command Invoke-WebRequest).Parameters.ContainsKey('UseBasicParsing')) {
        $params.UseBasicParsing = $true
    }

    Invoke-WebRequest @params
}

function Assert-Prerequisites {
    # Check admin rights
    if (-not (Test-AdminRights)) {
        Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
        Write-Host ""
        Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
        exit 1
    }

    Write-Status "Running with Administrator privileges" "Green"

    # Find ADK
    if ([string]::IsNullOrEmpty($script:ADKPath)) {
        Write-Status "Searching for Windows ADK installation..." "Cyan"
        $script:ADKPath = Find-ADKPath
    }

    if ([string]::IsNullOrEmpty($script:ADKPath)) {
        Write-Host ""
        Write-Host "ERROR: Windows ADK not found!" -ForegroundColor Red
        Write-Host ""
        Write-Host "Please install:" -ForegroundColor Yellow
        Write-Host "  1. Windows ADK: https://go.microsoft.com/fwlink/?linkid=2243390" -ForegroundColor Gray
        Write-Host "  2. Windows PE add-on: https://go.microsoft.com/fwlink/?linkid=2243391" -ForegroundColor Gray
        Write-Host ""
        Write-Host "During ADK installation, you only need 'Deployment Tools'" -ForegroundColor Gray
        exit 1
    }

    Write-Status "Found ADK at: $script:ADKPath" "Green"

    # Check WinPE add-on
    if (-not (Test-WinPEAddon -ADKPath $script:ADKPath)) {
        Write-Host ""
        Write-Host "ERROR: Windows PE add-on not installed!" -ForegroundColor Red
        Write-Host ""
        Write-Host "Please install the Windows PE add-on for ADK:" -ForegroundColor Yellow
        Write-Host "  https://go.microsoft.com/fwlink/?linkid=2243391" -ForegroundColor Gray
        exit 1
    }

    Write-Status "Windows PE add-on found" "Green"
}

function Mitigate-WriteBlock {
    
    # Disable USB write protection policies (required in environments that block unencrypted USB writes)
    Write-Status "Checking USB write protection policies..." "Cyan"

    $policyChanged = $false

    # Policy 1: BitLocker FVE policy - blocks writes to non-BitLocker removable drives
    $fvePath = "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE"
    try {
        if (-not (Test-Path $fvePath)) {
            New-Item -Path $fvePath -Force | Out-Null
            Write-Status "Created FVE policy registry key" "Gray"
        }
    
        $fveValue = Get-ItemProperty -Path $fvePath -Name "RDVDenyWriteAccess" -ErrorAction SilentlyContinue
    
        if ($fveValue.RDVDenyWriteAccess -eq 1) {
            Write-Status "BitLocker removable drive write protection is ENABLED - disabling..." "Yellow"
            Set-ItemProperty -Path $fvePath -Name "RDVDenyWriteAccess" -Value 0 -Type DWord
            $policyChanged = $true
            Write-Status "BitLocker RDVDenyWriteAccess disabled" "Green"
        }
        else {
            Set-ItemProperty -Path $fvePath -Name "RDVDenyWriteAccess" -Value 0 -Type DWord
            Write-Status "BitLocker removable drive write protection: disabled" "Green"
        }
    }
    catch {
        Write-Status "Warning: Could not modify FVE policy: $($_.Exception.Message)" "Yellow"
    }

    # If policies changed, ask to remove and remount USB disks
    if ($policyChanged) {
        Write-Host ""
        Write-Host $Divider -ForegroundColor Yellow
        Write-Host " USB REMOUNT REQUIRED" -ForegroundColor Yellow
        Write-Host $Divider -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Policy changes have been applied to allow USB writes." -ForegroundColor White
        Write-Host ""
        Write-Host "ACTION REQUIRED:" -ForegroundColor Cyan
        Write-Host "  1. Remove all USB drives from this computer" -ForegroundColor Gray
        Write-Host "  2. Wait 3 seconds" -ForegroundColor Gray
        Write-Host "  3. Re-insert the USB drives" -ForegroundColor Gray
        Write-Host "  4. Press any key to continue" -ForegroundColor Gray
        Write-Host ""
        Write-Host "This allows Windows to re-mount the drives with the new policy." -ForegroundColor White
        Write-Host ""
        Pause
        Write-Host ""
    }
}

function Select-UsbDisk ($USBDiskNumber) {
    # Select USB disk - either from parameter or interactive selection
    if ($USBDiskNumber -ge 0) {
        # Validate the provided disk number
        $usbDisk = Get-Disk -Number $USBDiskNumber -ErrorAction SilentlyContinue
    
        if (-not $usbDisk) {
            Write-Host ""
            Write-Host "ERROR: Disk $USBDiskNumber not found!" -ForegroundColor Red
            exit 1
        }
    
        if ($usbDisk.BusType -ne 'USB') {
            Write-Host ""
            Write-Host "WARNING: Disk $USBDiskNumber does not appear to be a USB drive!" -ForegroundColor Yellow
            Write-Host "Bus Type: $($usbDisk.BusType)" -ForegroundColor Gray
            Write-Host "Name: $($usbDisk.FriendlyName)" -ForegroundColor Gray
            $continue = Read-Host "Continue anyway? (y/n)"
            if ($continue -ne 'y') {
                exit 1
            }
        }
    
        $diskNumber = $USBDiskNumber
    }
    else {
        # Interactive disk selection
        $diskNumber = Show-USBDiskSelection
    
        if ($null -eq $diskNumber) {
            Write-Host "Operation cancelled." -ForegroundColor Yellow
            exit 0
        }
    
        $usbDisk = Get-Disk -Number $diskNumber
    }
    return $usbDisk
}

function Confirm-DiskSelection {
    param([Parameter(Mandatory = $true)][object]$usbDisk)
    # Get disk details for confirmation
    $usbSizeGB = [Math]::Round($usbDisk.Size / 1GB, 2)
    $partitions = Get-Partition -DiskNumber $usbDisk.Number -ErrorAction SilentlyContinue
    $driveLetters = ($partitions | Where-Object { $_.DriveLetter } | ForEach-Object { "$($_.DriveLetter):" }) -join ", "
    if (-not $driveLetters) { $driveLetters = "(No drive letter assigned)" }

    Write-Host ""
    Write-Status "Selected Disk $($usbDisk.Number)`: $($usbDisk.FriendlyName)" "Cyan"
    Write-Status "Size: $usbSizeGB GB | Current Drive Letters: $driveLetters" "Cyan"

    # Confirm destructive operation
    Write-Host ""
    Write-Host $Divider -ForegroundColor Red
    Write-Host " WARNING: ALL DATA ON DISK $($usbDisk.Number) WILL BE ERASED!" -ForegroundColor Red
    Write-Host $Divider -ForegroundColor Red
    Write-Host ""
    Write-Host "Disk Number:   $($usbDisk.Number)" -ForegroundColor Yellow
    Write-Host "Name:          $($usbDisk.FriendlyName)" -ForegroundColor Yellow
    Write-Host "Size:          $usbSizeGB GB" -ForegroundColor Yellow
    Write-Host "Drive Letters: $driveLetters" -ForegroundColor Yellow
    Write-Host ""

    $confirm = Read-Host "Type 'YES' to continue"
    if ($confirm -ne 'YES') {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        exit 0
    }
}

function Format-SelectedDrive {
    param([Parameter(Mandatory = $true)][object]$usbDisk)
    $diskNumber = $usbDisk.Number
    # Format and prepare USB for both UEFI and Legacy boot
    Write-Status "Preparing USB drive for UEFI and Legacy boot..." "Cyan"

    # Ensure disk is online and writable
    Write-Status "Ensuring disk is online and writable..." "Gray"
    Set-Disk -Number $diskNumber -IsOffline $false -ErrorAction SilentlyContinue
    Set-Disk -Number $diskNumber -IsReadOnly $false -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    Write-Status "Cleaning disk $diskNumber..." "Gray"

    # Use PowerShell cmdlets for more reliable formatting
    # First, remove all partitions (more reliable than Clear-Disk alone)
    Get-Partition -DiskNumber $diskNumber -ErrorAction SilentlyContinue | Remove-Partition -Confirm:$false -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    # Clear the disk completely - this should leave it as RAW
    try {
        Clear-Disk -Number $diskNumber -RemoveData -RemoveOEM -Confirm:$false -ErrorAction Stop
        Write-Status "Disk cleared successfully" "Green"
    }
    catch {
        Write-Status "Warning: Clear-Disk reported: $($_.Exception.Message)" "Yellow"
        # If Clear-Disk fails because disk is already raw, that's OK - continue
    }
    Start-Sleep -Seconds 2

    # Check if disk needs initialization
    Write-Status "Checking disk initialization status..." "Gray"

    $diskInfo = Get-Disk -Number $diskNumber
    Write-Status "Current partition style: $($diskInfo.PartitionStyle)" "Gray"

    # Only initialize if disk is RAW (uninitialized)
    if ($diskInfo.PartitionStyle -eq 'RAW') {
        Write-Status "Disk is uninitialized (RAW), initializing as GPT for UEFI..." "Gray"
        Initialize-Disk -Number $diskNumber -PartitionStyle GPT -ErrorAction Stop
        Write-Status "Disk initialized as GPT" "Green"
    }
    elseif ($diskInfo.PartitionStyle -eq 'GPT') {
        Write-Status "Disk already initialized as GPT (ready for UEFI)" "Green"
    }
    elseif ($diskInfo.PartitionStyle -eq 'MBR') {
        Write-Status "Disk initialized as MBR (will work with legacy boot)" "Green"
        # MBR is fine for legacy boot, no need to convert
    }

    # Create a single NTFS partition (works for both UEFI and can have legacy boot added)
    Write-Status "Creating NTFS partition..." "Gray"
    $partition = New-Partition -DiskNumber $diskNumber -UseMaximumSize -AssignDriveLetter

    # Get the assigned drive letter
    $newDriveLetter = $partition.DriveLetter
    Write-Status "Partition created with drive letter: $newDriveLetter" "Gray"

    # Refresh storage cache; sometimes the volume/drive letter isn't immediately materialized.
    try { Update-HostStorageCache | Out-Null } catch { }

    # If DriveLetter didn't populate yet, try to locate the partition and assign one.
    if (-not $newDriveLetter) {
        try {
            $partition = Get-Partition -DiskNumber $diskNumber | Sort-Object -Property Size -Descending | Select-Object -First 1
            $newDriveLetter = $partition.DriveLetter
        } catch { }
    }

    if (-not $newDriveLetter) {
        # Choose an available letter (avoid common removable letters if possible)
        $used = (Get-Volume -ErrorAction SilentlyContinue | Where-Object DriveLetter | ForEach-Object { $_.DriveLetter.ToString().ToUpperInvariant() })
        $candidates = @('U','V','W','X','Y','Z','T','S','R','Q','P','O','N','M','L','K','J','I','H','G','F','E','D')
        $pick = $candidates | Where-Object { $used -notcontains $_ } | Select-Object -First 1
        if (-not $pick) { throw "No free drive letters available to assign to the USB partition." }

        Write-Status "Assigning drive letter: $pick" "Gray"
        Set-Partition -DiskNumber $diskNumber -PartitionNumber $partition.PartitionNumber -NewDriveLetter $pick -ErrorAction Stop | Out-Null
        $newDriveLetter = $pick
    }

    # Format as NTFS (retry briefly in case the volume object is still appearing)
    Write-Status "Formatting as NTFS..." "Gray"
    $formatRetries = 0
    $formatMax = 10
    while ($true) {
        try {
            try { Update-HostStorageCache | Out-Null } catch { }
            # Prefer DriveLetter, but fall back to formatting by Partition object if needed.
            if (Get-Volume -DriveLetter $newDriveLetter -ErrorAction SilentlyContinue) {
                Format-Volume -DriveLetter $newDriveLetter -FileSystem NTFS -NewFileSystemLabel "WINPE_DIAG" -Confirm:$false -ErrorAction Stop | Out-Null
            } else {
                $p = Get-Partition -DiskNumber $diskNumber -PartitionNumber $partition.PartitionNumber -ErrorAction Stop
                Format-Volume -Partition $p -FileSystem NTFS -NewFileSystemLabel "WINPE_DIAG" -Confirm:$false -ErrorAction Stop | Out-Null
            }
            break
        } catch {
            $formatRetries++
            if ($formatRetries -ge $formatMax) { throw }
            Start-Sleep -Milliseconds 750
        }
    }

    # Store the final drive letter for use in file copy operations
    $USBDriveLetter = $newDriveLetter
    

    # Verify the volume is ready
    Write-Status "Verifying volume is ready..." "Gray"
    $retries = 0
    $maxRetries = 30
    while ($retries -lt $maxRetries) {
        $vol = Get-Volume -DriveLetter $USBDriveLetter -ErrorAction SilentlyContinue
        if ($vol -and $vol.FileSystem -eq 'NTFS') {
            Write-Status "Volume ready: NTFS, $([Math]::Round($vol.Size / 1GB, 2)) GB" "Green"
            break
        }
        Start-Sleep -Seconds 1
        $retries++
    }

    if ($retries -eq $maxRetries) {
        throw "Timeout waiting for USB volume to be ready. The disk may still be RAW."
    }

    Write-Status "USB drive formatted successfully" "Green"

    return $USBDriveLetter
}

function Write-Status {
    param([string]$Message, [string]$Color = "White")
    Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] $Message" -ForegroundColor $Color
}

function Test-AdminRights {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-ADKPath {
    $possiblePaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit",
        "$env:ProgramFiles\Windows Kits\10\Assessment and Deployment Kit",
        "${env:ProgramFiles(x86)}\Windows Kits\11\Assessment and Deployment Kit",
        "$env:ProgramFiles\Windows Kits\11\Assessment and Deployment Kit"
    )
    
    foreach ($path in $possiblePaths) {
        if (Test-Path "$path\Windows Preinstallation Environment") {
            return $path
        }
    }
    
    return $null
}

function Test-WinPEAddon {
    param([string]$ADKPath)
    return Test-Path "$ADKPath\Windows Preinstallation Environment\amd64\en-us\winpe.wim"
}

function Get-USBDisks {
    # Get all USB disks with detailed information
    $usbDisks = Get-Disk | Where-Object { $_.BusType -eq 'USB' }
    
    $diskList = @()
    foreach ($disk in $usbDisks) {
        $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue
        $driveLetters = ($partitions | Where-Object { $_.DriveLetter } | ForEach-Object { "$($_.DriveLetter):" }) -join ", "
        if (-not $driveLetters) { $driveLetters = "(No letter)" }
        
        $sizeGB = [Math]::Round($disk.Size / 1GB, 2)
        
        $diskList += [PSCustomObject]@{
            DiskNumber        = $disk.Number
            FriendlyName      = $disk.FriendlyName
            SizeGB            = $sizeGB
            DriveLetters      = $driveLetters
            PartitionStyle    = $disk.PartitionStyle
            OperationalStatus = $disk.OperationalStatus
        }
    }
    
    return $diskList
}

function Show-USBDiskSelection {
    $usbDisks = Get-USBDisks
    
    if ($usbDisks.Count -eq 0) {
        Write-Host ""
        Write-Host "ERROR: No USB disks found!" -ForegroundColor Red
        Write-Host ""
        Write-Host "Please insert a USB drive and try again." -ForegroundColor Yellow
        return $null
    }
    
    Write-Host ""
    Write-Host $Divider -ForegroundColor Cyan
    Write-Host " AVAILABLE USB DISKS" -ForegroundColor Yellow
    Write-Host $Divider -ForegroundColor Cyan
    Write-Host ""
    
    # Header
    Write-Host ("{0,-6} {1,-30} {2,-10} {3,-15} {4,-12}" -f "Disk#", "Name", "Size", "Drive Letter", "Status") -ForegroundColor Cyan
    Write-Host ("{0,-6} {1,-30} {2,-10} {3,-15} {4,-12}" -f "-----", "----", "----", "------------", "------") -ForegroundColor Gray
    
    foreach ($disk in $usbDisks) {
        $statusColor = if ($disk.OperationalStatus -eq 'Online') { 'Green' } else { 'Yellow' }
        
        Write-Host ("{0,-6}" -f $disk.DiskNumber) -ForegroundColor White -NoNewline
        Write-Host ("{0,-30}" -f ($disk.FriendlyName.Substring(0, [Math]::Min(29, $disk.FriendlyName.Length)))) -ForegroundColor Gray -NoNewline
        Write-Host ("{0,-10}" -f "$($disk.SizeGB) GB") -ForegroundColor Gray -NoNewline
        Write-Host ("{0,-15}" -f $disk.DriveLetters) -ForegroundColor Gray -NoNewline
        Write-Host ("{0,-12}" -f $disk.OperationalStatus) -ForegroundColor $statusColor
    }
    
    Write-Host ""
    
    while ($true) {
        $selection = Read-Host "Enter disk number to use (or 'q' to quit)"
        
        if ($selection -eq 'q') {
            return $null
        }
        
        $diskNum = $null
        if ([int]::TryParse($selection, [ref]$diskNum)) {
            $selectedDisk = $usbDisks | Where-Object { $_.DiskNumber -eq $diskNum }
            if ($selectedDisk) {
                return $diskNum
            }
        }
        
        Write-Host "Invalid selection. Please enter a disk number from the list above." -ForegroundColor Yellow
    }
}

# Banner
Clear-Host
Write-Host $Divider -ForegroundColor Cyan
Write-Host " WINPE USB BUILDER" -ForegroundColor Yellow
Write-Host $Divider -ForegroundColor Cyan
Write-Host ""
Write-Host "This tool creates a bootable WinPE USB drive for offline diagnostics." -ForegroundColor Gray
Write-Host ""

# Check prerequisites - will inform and exit if not met
Assert-Prerequisites

# Mitigate write block will inform if action taken
Mitigate-WriteBlock

# User selects USB disk if not provided
$usbDisk = Select-UsbDisk -USBDiskNumber $USBDiskNumber
$diskNumber = $usbDisk.Number

# User confirmation
Confirm-DiskSelection -usbDisk $usbDisk

# Format the selected USB drive
$USBDriveLetter = Format-SelectedDrive -usbDisk $usbDisk
$usbPath = "$USBDriveLetter`:\"





# Create working directory in Windows\Temp (more reliable than user profile temp)
$workDir = "C:\Windows\Temp\WinPE_Build_$(Get-Random)"
$mountDir = "$workDir\mount"
$mediaDir = "$workDir\media"

New-Item -ItemType Directory -Path $workDir -Force | Out-Null
New-Item -ItemType Directory -Path $mountDir -Force | Out-Null

Write-Status "Working directory: $workDir" "Gray"

try {
    # Copy WinPE files
    Write-Status "Copying WinPE base files..." "Cyan"
    
    $winpeWim = "$ADKPath\Windows Preinstallation Environment\amd64\en-us\winpe.wim"
    $winpeMedia = "$ADKPath\Windows Preinstallation Environment\amd64\Media"
    
    # Create media directory and copy contents (not the folder itself)
    New-Item -ItemType Directory -Path $mediaDir -Force | Out-Null
    Copy-Item -Path "$winpeMedia\*" -Destination $mediaDir -Recurse -Force
    
    # Ensure sources directory exists
    $sourcesDir = Join-Path $mediaDir "sources"
    if (-not (Test-Path $sourcesDir)) {
        New-Item -ItemType Directory -Path $sourcesDir -Force | Out-Null
    }
    
    Copy-Item -Path $winpeWim -Destination "$sourcesDir\boot.wim" -Force
    
    Write-Status "WinPE base files copied" "Green"
    
    # Mount the WIM
    Write-Status "Mounting WinPE image for customization..." "Cyan"
    
    # Make boot.wim writable
    Set-ItemProperty -Path "$sourcesDir\boot.wim" -Name IsReadOnly -Value $false
    
    Mount-WindowsImage -ImagePath "$sourcesDir\boot.wim" -Index 1 -Path $mountDir | Out-Null
    
    Write-Status "WinPE image mounted" "Green"
    
    # Add PowerShell support
    Write-Status "Adding PowerShell support..." "Cyan"
    
    $packagesPath = "$ADKPath\Windows Preinstallation Environment\amd64\WinPE_OCs"
    
    $packages = @(
        "WinPE-WMI.cab",
        "en-us\WinPE-WMI_en-us.cab",
        "WinPE-NetFx.cab",
        "en-us\WinPE-NetFx_en-us.cab",
        "WinPE-Scripting.cab",
        "en-us\WinPE-Scripting_en-us.cab",
        "WinPE-PowerShell.cab",
        "en-us\WinPE-PowerShell_en-us.cab",
        "WinPE-StorageWMI.cab",
        "en-us\WinPE-StorageWMI_en-us.cab",
        "WinPE-DismCmdlets.cab",
        "en-us\WinPE-DismCmdlets_en-us.cab",
        "WinPE-SecureBootCmdlets.cab",
        "WinPE-EnhancedStorage.cab",
        "en-us\WinPE-EnhancedStorage_en-us.cab"
    )
    
    foreach ($pkg in $packages) {
        $pkgPath = Join-Path $packagesPath $pkg
        if (Test-Path $pkgPath) {
            Write-Host "  Adding: $pkg" -ForegroundColor Gray
            Add-WindowsPackage -Path $mountDir -PackagePath $pkgPath -IgnoreCheck | Out-Null
        }
    }
    
    Write-Status "PowerShell support added" "Green"
    
    # Add additional diagnostic and troubleshooting tools
    Write-Status "Adding diagnostic and troubleshooting tools..." "Cyan"
    
    $diagnosticPackages = @(
        # BitLocker support (manage-bde)
        "WinPE-FMAPI.cab",
        
        # HTML rendering (for better PowerShell reports)
        "WinPE-HTA.cab",
        "en-us\WinPE-HTA_en-us.cab",
        
        # DISM commands for image servicing
        "WinPE-DISM.cab",
        "en-us\WinPE-DISM_en-us.cab",
        
        # Windows Recovery Environment tools
        "WinPE-WinReCfg.cab",
        "en-us\WinPE-WinReCfg_en-us.cab",
        
        # Windows Data Storage Management (for better disk tools)
        "WinPE-WDS-Tools.cab",
        "en-us\WinPE-WDS-Tools_en-us.cab",
        
        # Secure startup (TPM tools)
        "WinPE-SecureStartup.cab",
        "en-us\WinPE-SecureStartup_en-us.cab",
        
        # Windows PE PPPoE support (for certain network scenarios)
        "WinPE-PPPoE.cab",
        "en-us\WinPE-PPPoE_en-us.cab",
        
        # Network diagnostic tools
        "WinPE-Dot3Svc.cab",
        "en-us\WinPE-Dot3Svc_en-us.cab",
        
        # Font support for better console display
        "WinPE-FontSupport-JA-JP.cab",
        "WinPE-FontSupport-KO-KR.cab",
        "WinPE-FontSupport-ZH-CN.cab",
        "WinPE-FontSupport-ZH-HK.cab",
        "WinPE-FontSupport-ZH-TW.cab"
    )
    
    $toolCount = 0
    foreach ($pkg in $diagnosticPackages) {
        $pkgPath = Join-Path $packagesPath $pkg
        if (Test-Path $pkgPath) {
            Write-Host "  Adding: $pkg" -ForegroundColor Gray
            Add-WindowsPackage -Path $mountDir -PackagePath $pkgPath -IgnoreCheck -ErrorAction SilentlyContinue | Out-Null
            $toolCount++
        }
    }
    
    Write-Status "Added $toolCount diagnostic tools (includes BitLocker/manage-bde, DISM, Recovery tools)" "Green"
    
    # Optional WiFi support
    if (-not $IncludeWiFi) {
        Write-Status "Skipping WiFi support (use -IncludeWiFi to add it)" "Gray"
    }
    else {
        Write-Status "Adding WiFi and network tools..." "Cyan"
    
        $wifiPackages = @(
            "WinPE-WiFi-Package.cab"
        )

        $wifiCount = 0
        foreach ($pkg in $wifiPackages) {
            $pkgPath = Join-Path $packagesPath $pkg
            if (Test-Path $pkgPath) {
                Write-Host "  Adding: $pkg" -ForegroundColor Gray
                Add-WindowsPackage -Path $mountDir -PackagePath $pkgPath -IgnoreCheck -ErrorAction SilentlyContinue | Out-Null
                $wifiCount++
            }
        }

        if ($wifiCount -gt 0) {
            Write-Status "WiFi and network support added" "Green"
        }
        else {
            Write-Status "WiFi packages not found (wired only)" "Yellow"
        }
    }
    
    # Stage collector script
    $collectorDir = "$mountDir\WinPECollector"
    New-Item -ItemType Directory -Path $collectorDir -Force | Out-Null

    # Shared request headers for any server downloads
    $headers = @{ 'X-Auth-Key' = $AuthKey }

    if (-not [string]::IsNullOrWhiteSpace($CollectorScriptPath)) {
        Write-Status "Embedding local WinPE Collector from: $CollectorScriptPath" "Cyan"
        if (-not (Test-Path $CollectorScriptPath)) {
            throw "CollectorScriptPath not found: $CollectorScriptPath"
        }

        Copy-Item -Path $CollectorScriptPath -Destination "$collectorDir\WinPE-Collector.ps1" -Force
        $localCustomConfig = Join-Path (Split-Path -Parent $CollectorScriptPath) "WinPE-Collector.custom.json"
        if (Test-Path $localCustomConfig) {
            Copy-Item -Path $localCustomConfig -Destination "$collectorDir\WinPE-Collector.custom.json" -Force
            Write-Status "Custom collector config embedded (WinPE-Collector.custom.json)" "Green"
        }
        Write-Status "Collector script embedded" "Green"
    }
    else {
        Write-Status "Downloading WinPE Collector..." "Cyan"
        
        try {
            Invoke-WebRequestCompat -Uri "$ServerUrl/payloads/WinPECollector/download/WinPE-Collector.ps1" -OutFile "$collectorDir\WinPE-Collector.ps1" -Headers $headers
            Write-Status "Collector script downloaded" "Green"

            # Optional: download drop-in config for additional folders (404-safe)
            try {
                Invoke-WebRequestCompat -Uri "$ServerUrl/payloads/WinPECollector/download/WinPE-Collector.custom.json" -OutFile "$collectorDir\WinPE-Collector.custom.json" -Headers $headers
                Write-Status "Custom collector config downloaded (WinPE-Collector.custom.json)" "Green"
            }
            catch {
                Write-Status "No custom collector config found on server (optional)" "Gray"
            }
        }
        catch {
            Write-Status "Could not download collector, will download at runtime" "Yellow"
            
            # Create a bootstrap script that downloads at runtime
            @"
# WinPE Collector Bootstrap
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {}

`$headers = @{ 'X-Auth-Key' = '$AuthKey' }
try {
    `$params = @{ Uri = '$ServerUrl/payloads/WinPECollector/download/WinPE-Collector.ps1'; OutFile = 'X:\WinPECollector\WinPE-Collector.ps1'; Headers = `$headers }
    if ((Get-Command Invoke-WebRequest).Parameters.ContainsKey('UseBasicParsing')) { `$params.UseBasicParsing = `$true }
    Invoke-WebRequest @params

    # Optional: download drop-in config for additional folders
    try {
        `$cfgParams = @{ Uri = '$ServerUrl/payloads/WinPECollector/download/WinPE-Collector.custom.json'; OutFile = 'X:\WinPECollector\WinPE-Collector.custom.json'; Headers = `$headers }
        if ((Get-Command Invoke-WebRequest).Parameters.ContainsKey('UseBasicParsing')) { `$cfgParams.UseBasicParsing = `$true }
        Invoke-WebRequest @cfgParams
    } catch {
        # optional
    }

    & 'X:\WinPECollector\WinPE-Collector.ps1'
} catch {
    Write-Host "Failed to download collector: `$(`$_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check network connectivity and try again." -ForegroundColor Yellow
    pause
}
"@ | Out-File "$collectorDir\Bootstrap.ps1" -Encoding UTF8
    }
    }
    
    # Create startup script
    Write-Status "Creating auto-start configuration..." "Cyan"
    
    # Create PowerShell startup script with network checking
    $psStartupScript = @"
# WinPE Startup Script
`$ErrorActionPreference = 'Continue'

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " WINPE DIAGNOSTIC COLLECTOR" -ForegroundColor Yellow
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Launch collector or drop to PowerShell
if (Test-Path "X:\WinPECollector\WinPE-Collector.ps1") {
    Write-Host "Starting diagnostic collector..." -ForegroundColor Cyan
    Write-Host ""
    & "X:\WinPECollector\WinPE-Collector.ps1"
} elseif (Test-Path "X:\WinPECollector\Bootstrap.ps1") {
    Write-Host "Starting diagnostic collector (bootstrap mode)..." -ForegroundColor Cyan
    Write-Host ""
    & "X:\WinPECollector\Bootstrap.ps1"
} else {
    Write-Host "ERROR: Collector script not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "You can manually download and run:" -ForegroundColor Yellow
    Write-Host "  `$headers = @{'X-Auth-Key'='$AuthKey'}" -ForegroundColor Gray
    Write-Host "  iwr <<SERVERURL>>/winpecollector-installer -Headers `$headers -useb | iex" -ForegroundColor Gray
    Write-Host ""
}

# Stay in PowerShell after collector finishes
Write-Host ""
Write-Host "PowerShell environment ready. Type 'exit' to return to command prompt." -ForegroundColor Gray
Write-Host ""
"@
    
    $psStartupScript | Out-File "$collectorDir\Start-Collector.ps1" -Encoding UTF8
    
    # Create a standalone upload utility script
    $uploadScript = @"
# Quick File Upload Utility
# Usage: .\Upload-File.ps1 -FilePath "C:\path\to\file.zip"

param(
    [Parameter(Mandatory=`$true)]
    [string]`$FilePath,
    
    [string]`$UploadUrl = "<<SERVERURL>>/upload",
    [string]`$AuthKey = "$AuthKey"
)

if (-not (Test-Path `$FilePath)) {
    Write-Host "ERROR: File not found: `$FilePath" -ForegroundColor Red
    exit 1
}

Write-Host "Uploading file: `$FilePath" -ForegroundColor Cyan
Write-Host "Size: `$([Math]::Round((Get-Item `$FilePath).Length / 1MB, 2)) MB" -ForegroundColor Gray
Write-Host ""

try {
    Add-Type -AssemblyName System.Net.Http
    `$file = Get-Item `$FilePath
    `$fileName = `$file.Name

    `$httpClient = New-Object System.Net.Http.HttpClient
    `$httpClient.Timeout = New-Object System.TimeSpan(0, 5, 0)
    `$httpClient.DefaultRequestHeaders.Add('X-Auth-Key', `$AuthKey)

    `$content = New-Object System.Net.Http.MultipartFormDataContent
    `$fileStream = [System.IO.File]::OpenRead(`$file.FullName)
    try {
        `$fileContent = New-Object System.Net.Http.StreamContent(`$fileStream)
        `$content.Add(`$fileContent, 'file', `$fileName)
        `$response = `$httpClient.PostAsync(`$UploadUrl, `$content).Result
    }
    finally {
        `$fileStream.Close()
        `$fileStream.Dispose()
    }

    if (-not `$response.IsSuccessStatusCode) {
        throw "Upload failed: `$(`$response.StatusCode) - `$(`$response.ReasonPhrase)"
    }

    Write-Host "Upload successful!" -ForegroundColor Green
    Write-Host "Status: `$(`$response.StatusCode)" -ForegroundColor Gray
    
} catch {
    Write-Host "Upload failed: `$(`$_.Exception.Message)" -ForegroundColor Red
    exit 1
}
"@
    
    $uploadScript | Out-File "$collectorDir\Upload-File.ps1" -Encoding UTF8
    Write-Status "Created Upload-File.ps1 utility" "Gray"
    
    # Create startnet.cmd that launches PowerShell
    $startupScript = @"
@echo off
echo.
echo Initializing WinPE environment...
wpeinit

REM Launch PowerShell with startup script
powershell -NoExit -ExecutionPolicy Bypass -File "X:\WinPECollector\Start-Collector.ps1"
"@
    
    $startupScript | Out-File "$mountDir\Windows\System32\startnet.cmd" -Encoding ASCII
    
    Write-Status "Auto-start configured (launches PowerShell with network check)" "Green"
    
    # Configure ramdisk size (scratch space) to 1GB
    Write-Status "Configuring ramdisk size to 1GB..." "Cyan"
    
    # Method 1: Set via registry in the mounted image
    $regPath = "$mountDir\Windows\System32\config\SYSTEM"
    if (Test-Path $regPath) {
        # Load the SYSTEM hive
        reg load HKLM\WinPE_SYSTEM "$regPath" 2>&1 | Out-Null
        
        # Set scratch space to 1024 MB (1GB)
        reg add "HKLM\WinPE_SYSTEM\ControlSet001\Services\FBWF" /v "ScratchSpaceSize" /t REG_DWORD /d 1024 /f 2>&1 | Out-Null
        
        # Unload the hive
        reg unload HKLM\WinPE_SYSTEM 2>&1 | Out-Null
        
        Write-Status "Ramdisk configured to 1GB via registry" "Green"
    }
    
    # Method 2: Use DISM to set scratch space
    try {
        # Set scratch space using DISM
        Dism /Image:"$mountDir" /Set-ScratchSpace:1024 2>&1 | Out-Null
        Write-Status "Ramdisk configured to 1GB via DISM" "Green"
    }
    catch {
        Write-Status "Note: DISM scratch space configuration not available on this ADK version" "Gray"
    }
    
    # Add drivers from server payload (optional)
    Write-Status "Adding additional drivers (hp-network.zip, if present)..." "Cyan"
    try {
        $driverZipPath = "$workDir\hp-network.zip"
        Invoke-WebRequestCompat -Uri "$ServerUrl/payloads/WinPECollector/download/hp-network.zip" -OutFile $driverZipPath -Headers $headers
        if (Test-Path $driverZipPath) {
            # Extract drivers
            Write-Status "Extracting driver package..." "Gray"
            $driverExtractPath = "$workDir\drivers"
            New-Item -ItemType Directory -Path $driverExtractPath -Force | Out-Null
            try {
                Expand-Archive -Path $driverZipPath -DestinationPath $driverExtractPath -Force -ErrorAction Stop
            }
            catch {
                throw "Driver package extraction failed: $($_.Exception.Message)"
            }
            
            # Add drivers to WinPE image
            Write-Status "Adding drivers to WinPE image..." "Gray"
            $driverFiles = Get-ChildItem -Path $driverExtractPath -Recurse -Include *.inf -ErrorAction SilentlyContinue
            $driverCount = @($driverFiles).Count
            if ($driverCount -le 0) {
                Write-Status "No driver files found in the downloaded package" "Gray"
            }
            else {
                Write-Status "Found $driverCount driver INF files" "Gray"

                # Preferred: let DISM scan the extracted folder once (faster + more reliable than per-INF)
                try {
                    Add-WindowsDriver -Path $mountDir -Driver $driverExtractPath -Recurse -ErrorAction Stop | Out-Null
                    Write-Status "Additional drivers added to WinPE image" "Green"
                }
                catch {
                    Write-Status "Driver injection failed (signed-only attempt): $($_.Exception.Message)" "Yellow"
                    Write-Status "Retrying driver injection with -ForceUnsigned..." "Yellow"
                    Add-WindowsDriver -Path $mountDir -Driver $driverExtractPath -Recurse -ForceUnsigned -ErrorAction Stop | Out-Null
                    Write-Status "Additional drivers added to WinPE image (ForceUnsigned)" "Green"
                }
            }
        }
        else {
            Write-Status "No additional drivers to add" "Gray"
        }
    }
    catch {
        Write-Status "Could not retrieve or add drivers: $($_.Exception.Message)" "Yellow"
    }

    # Unmount and save
    Write-Status "Saving WinPE image (this may take a few minutes)..." "Cyan"
    
    Dismount-WindowsImage -Path $mountDir -Save | Out-Null
    
    Write-Status "WinPE image saved" "Green"
    
   
    # Copy WinPE files to USB
    Write-Status "Copying WinPE files to USB (this may take several minutes)..." "Cyan"
    
    # Use robocopy for reliable copying
    & robocopy "$mediaDir" $usbPath /E /R:3 /W:1 /NFL /NDL /NJH /NJS /nc /ns /np 2>&1 | Out-Null
    
    # Robocopy returns various exit codes, 0-7 are generally success
    if ($LASTEXITCODE -gt 7) {
        Write-Status "Warning: Some files may not have copied correctly (robocopy exit: $LASTEXITCODE)" "Yellow"
    }
    
    # Verify boot files exist
    if (-not (Test-Path "$usbPath\sources\boot.wim")) {
        throw "Boot files not copied correctly. boot.wim not found on USB."
    }
    
    Write-Status "WinPE files copied to USB" "Green"
    
    # Setup UEFI boot - the EFI files should already be copied from mediaDir
    Write-Status "Configuring UEFI boot..." "Cyan"
    
    $efiBootDir = "$usbPath\EFI\Boot"
    if (-not (Test-Path $efiBootDir)) {
        New-Item -ItemType Directory -Path $efiBootDir -Force | Out-Null
    }
    
    # Check if bootx64.efi was copied, if not get from ADK
    if (-not (Test-Path "$efiBootDir\bootx64.efi")) {
        $bootmgrEfi = "$ADKPath\Windows Preinstallation Environment\amd64\Media\EFI\Boot\bootx64.efi"
        if (Test-Path $bootmgrEfi) {
            Copy-Item -Path $bootmgrEfi -Destination "$efiBootDir\bootx64.efi" -Force
            Write-Status "UEFI boot configured (bootx64.efi from ADK)" "Green"
        }
        else {
            Write-Status "Warning: Could not find bootx64.efi - UEFI boot may not work" "Yellow"
        }
    }
    else {
        Write-Status "UEFI boot configured (bootx64.efi)" "Green"
    }
    
    # Setup Legacy BIOS boot
    Write-Status "Configuring Legacy BIOS boot..." "Cyan"
    
    $bootsectPath = "$ADKPath\Deployment Tools\amd64\BCDBoot\bootsect.exe"
    if (Test-Path $bootsectPath) {
        & $bootsectPath /nt60 "$USBDriveLetter`:" /force /mbr 2>&1 | Out-Null
        Write-Status "Legacy BIOS boot configured" "Green"
    }
    else {
        Write-Status "Warning: bootsect.exe not found - Legacy boot may not work" "Yellow"
    }
    
    Write-Host ""
    Write-Host $Divider -ForegroundColor Green
    Write-Host " WINPE USB CREATED SUCCESSFULLY!" -ForegroundColor Green
    Write-Host $Divider -ForegroundColor Green
    Write-Host ""
    Write-Host "USB Drive: $USBDriveLetter`:" -ForegroundColor Cyan
    Write-Host "Boot Mode: UEFI and Legacy BIOS supported" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "To use:" -ForegroundColor Yellow
    Write-Host "  1. Insert USB into target computer" -ForegroundColor Gray
    Write-Host "  2. Boot from USB (press F9 at startup)" -ForegroundColor Gray
    Write-Host "  3. Select USB drive from boot menu" -ForegroundColor Gray
    Write-Host "  4. WinPE will start and auto-launch the collector" -ForegroundColor Gray
    Write-Host "  5. Follow the prompts to unlock BitLocker and collect diagnostics" -ForegroundColor Gray
    Write-Host ""
    Write-Host "The collector will automatically:" -ForegroundColor Yellow
    Write-Host "  - Detect Windows installations" -ForegroundColor Gray
    Write-Host "  - Prompt for BitLocker recovery key if needed" -ForegroundColor Gray
    Write-Host "  - Collect event logs, registry hives, and crash dumps" -ForegroundColor Gray
    Write-Host "  - Upload to diagnostic server" -ForegroundColor Gray
    Write-Host ""
    
}
catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    
    # Try to unmount if mounted
    try {
        Dismount-WindowsImage -Path $mountDir -Discard -ErrorAction SilentlyContinue | Out-Null
    }
    catch {}
    
}
finally {
    # Cleanup
    Write-Status "Cleaning up temporary files..." "Gray"
    
    try {
        # Make sure nothing is mounted
        Dismount-WindowsImage -Path $mountDir -Discard -ErrorAction SilentlyContinue | Out-Null
    }
    catch {}
    
    if (Test-Path $workDir) {
        Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Read-Host "Press Enter to exit"
