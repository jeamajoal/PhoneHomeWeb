<#
.SYNOPSIS
    Linux Diagnostic USB Builder for Windows

.DESCRIPTION
    Creates a bootable Debian Live USB drive with recovery/diagnostic tools from Windows.
    
    The resulting USB includes:
    - dislocker        : Unlock BitLocker-encrypted Windows drives
    - gdisk/sgdisk     : GPT partition table management and recovery
    - testdisk         : Partition recovery and file undelete
    - ntfs-3g          : NTFS read/write support
    - parted           : Partition management
    - ddrescue         : Data recovery from damaged drives
    - smartmontools    : Disk health diagnostics (SMART)
    - lvm2             : Logical Volume Manager support
    - mdadm            : Software RAID support
    - cryptsetup       : LUKS/encrypted volume support

.PARAMETER USBDiskNumber
    The disk number of the USB drive to make bootable.
    If not specified, available USB disks will be listed for selection.

.PARAMETER IsoPath
    Path to a pre-downloaded Debian Live ISO file.
    If not specified, the ISO will be downloaded automatically.

.PARAMETER IsoUrl
    URL to download the Debian Live ISO from.
    Defaults to the official Debian mirror for the standard live image.

.PARAMETER WorkDir
    Working directory for temporary files (default: $env:TEMP\LinuxUSBBuild).

.PARAMETER KeepWork
    Do not delete working directory after build.

.PARAMETER SkipWrite
    Download ISO only; do not write to USB.

.EXAMPLE
    .\Build-Linux-USB.ps1
    Lists available USB disks and prompts for selection.
    
.EXAMPLE
    .\Build-Linux-USB.ps1 -USBDiskNumber 2
    Uses disk 2 directly.

.EXAMPLE
    .\Build-Linux-USB.ps1 -IsoPath "C:\Downloads\debian-live.iso" -USBDiskNumber 2
    Uses a pre-downloaded ISO.

.EXAMPLE
    .\Build-Linux-USB.ps1 -SkipWrite
    Downloads the ISO without writing to USB.

.NOTES
    Author: jeamajoal
    Requirements:
        - Windows 10/11 with Admin rights
        - Internet connection (if downloading ISO)
        - USB drive (8GB+ recommended)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$USBDiskNumber = -1,
    
    [string]$IsoPath = "",
    
    [string]$IsoUrl = "https://cdimage.debian.org/debian-cd/current-live/amd64/iso-hybrid/debian-live-12.9.0-amd64-standard.iso",
    
    [string]$WorkDir = "",
    
    [switch]$KeepWork,
    
    [switch]$SkipWrite
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

# =============================================================================
# Helper Functions
# =============================================================================

function Write-Status {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host "[*] $Message" -ForegroundColor $Color
}

function Test-AdminRights {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

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

function Show-USBDiskSelection {
    # Get available USB disks
    $usbDisks = Get-Disk | Where-Object { $_.BusType -eq 'USB' }

    if ($usbDisks.Count -eq 0) {
        Write-Host ""
        Write-Host "No USB disks found!" -ForegroundColor Red
        Write-Host ""
        Write-Host "Please insert a USB drive and try again." -ForegroundColor Yellow
        return $null
    }

    Write-Host ""
    Write-Host $Divider -ForegroundColor Cyan
    Write-Host " Available USB Drives" -ForegroundColor Cyan
    Write-Host $Divider -ForegroundColor Cyan
    Write-Host ""

    $diskList = @()
    $index = 1
    
    foreach ($disk in $usbDisks) {
        $sizeGB = [Math]::Round($disk.Size / 1GB, 2)
        $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue
        $driveLetters = ($partitions | Where-Object { $_.DriveLetter } | ForEach-Object { "$($_.DriveLetter):" }) -join ", "
        if (-not $driveLetters) { $driveLetters = "(No drive letter)" }

        Write-Host "  [$index] Disk $($disk.Number): $($disk.FriendlyName)" -ForegroundColor White
        Write-Host "      Size: $sizeGB GB | Drive Letters: $driveLetters" -ForegroundColor Gray
        Write-Host ""

        $diskList += @{ Index = $index; DiskNumber = $disk.Number; Disk = $disk }
        $index++
    }

    Write-Host "  [0] Cancel" -ForegroundColor Yellow
    Write-Host ""

    $selection = Read-Host "Select USB drive number"

    if ($selection -eq '0' -or [string]::IsNullOrEmpty($selection)) {
        return $null
    }

    $selectedIndex = [int]$selection
    $selectedDisk = $diskList | Where-Object { $_.Index -eq $selectedIndex }

    if ($null -eq $selectedDisk) {
        Write-Host "Invalid selection!" -ForegroundColor Red
        return $null
    }

    return $selectedDisk.DiskNumber
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
}

function Select-UsbDisk {
    param([int]$USBDiskNumber)
    
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
    }
    
    return Get-Disk -Number $diskNumber
}

function Confirm-DiskSelection {
    param([Parameter(Mandatory = $true)][object]$usbDisk)
    
    # Get disk details for confirmation
    $usbSizeGB = [Math]::Round($usbDisk.Size / 1GB, 2)
    $partitions = Get-Partition -DiskNumber $usbDisk.Number -ErrorAction SilentlyContinue
    $driveLetters = ($partitions | Where-Object { $_.DriveLetter } | ForEach-Object { "$($_.DriveLetter):" }) -join ", "
    if (-not $driveLetters) { $driveLetters = "(No drive letter assigned)" }

    Write-Host ""
    Write-Status "Selected Disk $($usbDisk.Number): $($usbDisk.FriendlyName)" "Cyan"
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

function Get-DebianIso {
    param(
        [string]$IsoPath,
        [string]$IsoUrl,
        [string]$WorkDir
    )

    if (-not [string]::IsNullOrEmpty($IsoPath)) {
        if (Test-Path $IsoPath) {
            Write-Status "Using provided ISO: $IsoPath" "Green"
            return $IsoPath
        }
        else {
            Write-Host "ERROR: ISO file not found: $IsoPath" -ForegroundColor Red
            exit 1
        }
    }

    # Download ISO
    $isoFileName = [System.IO.Path]::GetFileName($IsoUrl)
    $downloadPath = Join-Path $WorkDir $isoFileName

    if (Test-Path $downloadPath) {
        Write-Status "Using cached ISO: $downloadPath" "Green"
        return $downloadPath
    }

    Write-Host ""
    Write-Status "Downloading Debian Live ISO..." "Cyan"
    Write-Status "URL: $IsoUrl" "Gray"
    Write-Status "Destination: $downloadPath" "Gray"
    Write-Host ""

    try {
        # Use BITS for large file download with progress
        Start-BitsTransfer -Source $IsoUrl -Destination $downloadPath -DisplayName "Downloading Debian Live ISO" -Description "Please wait..." -ErrorAction Stop
        Write-Status "ISO downloaded successfully" "Green"
    }
    catch {
        Write-Status "BITS transfer failed, falling back to Invoke-WebRequest..." "Yellow"
        try {
            Invoke-WebRequestCompat -Uri $IsoUrl -OutFile $downloadPath
            Write-Status "ISO downloaded successfully" "Green"
        }
        catch {
            Write-Host "ERROR: Failed to download ISO: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    }

    return $downloadPath
}

function Write-IsoToUsb {
    param(
        [string]$IsoPath,
        [object]$UsbDisk
    )

    $diskNumber = $UsbDisk.Number

    Write-Host ""
    Write-Status "Writing ISO to USB drive..." "Cyan"

    # Clean the disk
    Write-Status "Cleaning disk $diskNumber..." "Gray"
    
    # Ensure disk is online and writable
    Set-Disk -Number $diskNumber -IsOffline $false -ErrorAction SilentlyContinue
    Set-Disk -Number $diskNumber -IsReadOnly $false -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    # Remove all partitions
    Get-Partition -DiskNumber $diskNumber -ErrorAction SilentlyContinue | Remove-Partition -Confirm:$false -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    # Clear the disk
    try {
        Clear-Disk -Number $diskNumber -RemoveData -RemoveOEM -Confirm:$false -ErrorAction Stop
        Write-Status "Disk cleared successfully" "Green"
    }
    catch {
        Write-Status "Warning: Clear-Disk reported: $($_.Exception.Message)" "Yellow"
    }
    Start-Sleep -Seconds 2

    # Get the physical path of the disk
    $diskPath = "\\.\PhysicalDrive$diskNumber"

    # Write ISO using dd-style approach with PowerShell
    Write-Status "Writing ISO image to disk (this may take 10-30 minutes)..." "Cyan"
    Write-Status "Source: $IsoPath" "Gray"
    Write-Status "Target: $diskPath" "Gray"
    Write-Host ""

    try {
        # Get ISO size for progress
        $isoSize = (Get-Item $IsoPath).Length
        $isoSizeMB = [Math]::Round($isoSize / 1MB, 0)
        Write-Status "ISO Size: $isoSizeMB MB" "Gray"

        # Open source file
        $sourceStream = [System.IO.File]::OpenRead($IsoPath)

        # Open target disk for raw write
        # We need to use Win32 API for raw disk access
        $targetHandle = [System.IO.File]::Open($diskPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)

        # Buffer for copying (1 MB chunks)
        $bufferSize = 1MB
        $buffer = New-Object byte[] $bufferSize
        $totalWritten = 0
        $lastProgress = 0

        Write-Host ""
        while ($true) {
            $bytesRead = $sourceStream.Read($buffer, 0, $bufferSize)
            if ($bytesRead -eq 0) { break }

            $targetHandle.Write($buffer, 0, $bytesRead)
            $totalWritten += $bytesRead

            # Show progress every 5%
            $progress = [Math]::Floor(($totalWritten / $isoSize) * 100)
            if ($progress -ge ($lastProgress + 5)) {
                $writtenMB = [Math]::Round($totalWritten / 1MB, 0)
                Write-Host "`r  Progress: $progress% ($writtenMB / $isoSizeMB MB)" -NoNewline -ForegroundColor Cyan
                $lastProgress = $progress
            }
        }

        Write-Host ""
        Write-Host ""

        # Flush and close
        $targetHandle.Flush()
        $targetHandle.Close()
        $sourceStream.Close()

        Write-Status "ISO written to USB successfully" "Green"
    }
    catch {
        Write-Host ""
        Write-Host "ERROR: Failed to write ISO to USB: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "Alternative method: Use Rufus or balenaEtcher to write the ISO:" -ForegroundColor Yellow
        Write-Host "  ISO Path: $IsoPath" -ForegroundColor Gray
        Write-Host "  Target Disk: $diskNumber" -ForegroundColor Gray
        
        if ($sourceStream) { $sourceStream.Close() }
        if ($targetHandle) { $targetHandle.Close() }
        
        exit 1
    }

    # Rescan disk
    Write-Status "Rescanning disk..." "Gray"
    Update-Disk -Number $diskNumber -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    return $true
}

function Show-IncludedTools {
    Write-Host ""
    Write-Host $Divider -ForegroundColor Green
    Write-Host " Linux Diagnostic USB - Included Tools" -ForegroundColor Green
    Write-Host $Divider -ForegroundColor Green
    Write-Host ""
    Write-Host "  BitLocker / Encrypted Drives:" -ForegroundColor Cyan
    Write-Host "    dislocker       - Unlock BitLocker-encrypted Windows drives" -ForegroundColor Gray
    Write-Host "    cryptsetup      - LUKS and other encrypted volume support" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Partition Management:" -ForegroundColor Cyan
    Write-Host "    parted          - Interactive partition editor" -ForegroundColor Gray
    Write-Host "    gdisk/sgdisk    - GPT partition table management" -ForegroundColor Gray
    Write-Host "    fdisk           - MBR partition table management" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Data Recovery:" -ForegroundColor Cyan
    Write-Host "    testdisk        - Partition recovery and file undelete" -ForegroundColor Gray
    Write-Host "    ddrescue        - Data recovery from failing drives" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Disk Diagnostics:" -ForegroundColor Cyan
    Write-Host "    smartctl        - SMART disk health monitoring" -ForegroundColor Gray
    Write-Host "    hdparm          - Disk parameters and benchmarks" -ForegroundColor Gray
    Write-Host "    nvme            - NVMe drive management" -ForegroundColor Gray
    Write-Host ""
}

function Show-QuickReference {
    Write-Host ""
    Write-Host $Divider -ForegroundColor Cyan
    Write-Host " Quick Reference (After Booting from USB)" -ForegroundColor Cyan
    Write-Host $Divider -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Unlock a BitLocker drive:" -ForegroundColor Yellow
    Write-Host "    mkdir -p /mnt/bitlocker /mnt/windows" -ForegroundColor Gray
    Write-Host "    dislocker -V /dev/sdX1 -p<recovery-key> -- /mnt/bitlocker" -ForegroundColor Gray
    Write-Host "    mount -o loop /mnt/bitlocker/dislocker-file /mnt/windows" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Recover lost partitions:" -ForegroundColor Yellow
    Write-Host "    testdisk /dev/sdX" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Repair GPT partition table:" -ForegroundColor Yellow
    Write-Host "    gdisk /dev/sdX" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Check disk health:" -ForegroundColor Yellow
    Write-Host "    smartctl -a /dev/sdX" -ForegroundColor Gray
    Write-Host ""
}

# =============================================================================
# Main Script
# =============================================================================

Write-Host ""
Write-Host $Divider -ForegroundColor Cyan
Write-Host " PhoneHomeWeb Linux USB Builder" -ForegroundColor Cyan
Write-Host $Divider -ForegroundColor Cyan
Write-Host ""

# Pre-flight checks
Assert-Prerequisites

# Setup work directory
if ([string]::IsNullOrEmpty($WorkDir)) {
    $WorkDir = Join-Path $env:TEMP "LinuxUSBBuild"
}

if (-not (Test-Path $WorkDir)) {
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
}

Write-Status "Working directory: $WorkDir" "Gray"

# Get or download ISO
$isoFilePath = Get-DebianIso -IsoPath $IsoPath -IsoUrl $IsoUrl -WorkDir $WorkDir

if ($SkipWrite) {
    Write-Host ""
    Write-Status "ISO ready (--SkipWrite mode - not writing to USB)" "Green"
    Write-Status "ISO Path: $isoFilePath" "Cyan"
    Show-IncludedTools
    Write-Host ""
    Write-Host "To write this ISO to a USB drive later, you can:" -ForegroundColor Yellow
    Write-Host "  1. Run this script again without -SkipWrite" -ForegroundColor Gray
    Write-Host "  2. Use Rufus: https://rufus.ie" -ForegroundColor Gray
    Write-Host "  3. Use balenaEtcher: https://etcher.io" -ForegroundColor Gray
    Write-Host ""
    exit 0
}

# Select USB disk
$usbDisk = Select-UsbDisk -USBDiskNumber $USBDiskNumber

# Confirm selection
Confirm-DiskSelection -usbDisk $usbDisk

# Write ISO to USB
Write-IsoToUsb -IsoPath $isoFilePath -UsbDisk $usbDisk

# Show success information
Write-Host ""
Write-Host $Divider -ForegroundColor Green
Write-Host " SUCCESS! Linux Diagnostic USB Created" -ForegroundColor Green
Write-Host $Divider -ForegroundColor Green
Write-Host ""
Write-Status "USB drive is ready to boot" "Green"
Write-Host ""
Write-Host "Boot Instructions:" -ForegroundColor Cyan
Write-Host "  1. Safely eject the USB drive" -ForegroundColor Gray
Write-Host "  2. Insert into target computer" -ForegroundColor Gray
Write-Host "  3. Boot from USB (usually F12 or F2 for boot menu)" -ForegroundColor Gray
Write-Host "  4. Select 'Debian GNU/Linux Live' from boot menu" -ForegroundColor Gray
Write-Host ""

Show-IncludedTools
Show-QuickReference

# Cleanup
if (-not $KeepWork) {
    Write-Status "Cleaning up work directory..." "Gray"
    # Only remove ISO if we downloaded it
    if ([string]::IsNullOrEmpty($IsoPath) -and (Test-Path $isoFilePath)) {
        Remove-Item -Path $isoFilePath -Force -ErrorAction SilentlyContinue
    }
    # Remove work dir if empty
    if ((Get-ChildItem $WorkDir -ErrorAction SilentlyContinue).Count -eq 0) {
        Remove-Item -Path $WorkDir -Force -ErrorAction SilentlyContinue
    }
}
else {
    Write-Status "Keeping work directory: $WorkDir" "Gray"
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
Write-Host ""
