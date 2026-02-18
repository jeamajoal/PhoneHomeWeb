<#
.SYNOPSIS
    Windows Online Diagnostic Log Collector

.DESCRIPTION
    Comprehensive diagnostic data collector for running Windows systems.
    Designed to run as SYSTEM via EPM/RMM tools or interactively with admin rights.
    
    Collects:
    - Event logs (evtx files)
    - Registry hives (SYSTEM, SOFTWARE, DEFAULT)
    - Windows Update/CBS/DISM logs
    - Setup logs (Panther, MoSetup, SetupAPI)
    - Crash dumps (Minidump, LiveKernelReports)
    - Network configuration
    - Installed software and features
    - Running processes and services
    - Scheduled tasks
    - Disk/storage health
    - Group Policy results
    - Windows Defender status
    - Driver information
    - System information
    - WER reports

.PARAMETER UploadUrl
    Full URL for file upload (e.g., https://server:3500/upload)

.PARAMETER AuthKey
    Authentication key for secure upload

.PARAMETER Silent
    Run without interactive prompts (for EPM/RMM deployment)

.PARAMETER Interactive
    Enable interactive console output and exit prompts

.PARAMETER SkipUpload
    Collect logs only, do not upload to server

.PARAMETER OutputPath
    Custom output directory (default: %TEMP%\WindowsCollector)

.PARAMETER IncludeSecurityLogs
    Include Security event log (large, may contain sensitive data)

.NOTES
    Author: jeamajoal
    Version: 1.0.0
    Requires: PowerShell 5.1+, Administrator/SYSTEM privileges
#>

[CmdletBinding()]
param(
    [string]$UploadUrl = "<<SERVERURL>>/upload",
    [string]$AuthKey = "<<AUTHKEY>>",
    [switch]$Interactive,
    [switch]$Silent,
    [switch]$SkipUpload,
    [string]$OutputPath = "",
    [switch]$IncludeSecurityLogs
)

#Requires -RunAsAdministrator

# ============================================================================
# Configuration
# ============================================================================

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# Default to non-interactive mode unless explicitly requested
if (-not $Interactive) {
    $Silent = $true
}

# TLS 1.2 for uploads
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$Script:Divider = "================================================================================"
$Script:CollectionStart = Get-Date
$Script:LogMessages = @()
$Script:LogFilePath = $null

# ============================================================================
# Logging Functions
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Color = "White"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $Script:LogMessages += $logEntry
    
    if (-not $Silent) {
        $displayColor = switch ($Level) {
            "ERROR" { "Red" }
            "WARN"  { "Yellow" }
            "SUCCESS" { "Green" }
            "INFO" { $Color }
            default { "White" }
        }
        Write-Host $logEntry -ForegroundColor $displayColor
    }
}

function Sync-Log {
    if ($Script:LogFilePath) {
        try {
            $Script:LogMessages | Out-File -FilePath $Script:LogFilePath -Encoding UTF8 -Force
        } catch { }
    }
}

function Write-Section {
    param([string]$Title)
    
    if (-not $Silent) {
        Write-Host ""
        Write-Host $Script:Divider -ForegroundColor Cyan
        Write-Host " $Title" -ForegroundColor Yellow
        Write-Host $Script:Divider -ForegroundColor Cyan
        Write-Host ""
    }
    $Script:LogMessages += ""
    $Script:LogMessages += $Script:Divider
    $Script:LogMessages += " $Title"
    $Script:LogMessages += $Script:Divider
    Sync-Log
}

function Write-Banner {
    if (-not $Silent) {
        Clear-Host
        Write-Host $Script:Divider -ForegroundColor Cyan
        Write-Host " WINDOWS ONLINE DIAGNOSTIC COLLECTOR" -ForegroundColor Yellow
        Write-Host $Script:Divider -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Collecting comprehensive diagnostic data from this system." -ForegroundColor Gray
        Write-Host "Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -ForegroundColor Gray
        Write-Host ""
    }
}

# ============================================================================
# Helper Functions
# ============================================================================

function Get-SafeFileName {
    param([string]$Name)
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $safe = $Name
    foreach ($char in $invalid) {
        $safe = $safe.Replace($char, '_')
    }
    return $safe
}

function Invoke-SafeCommand {
    param(
        [string]$Description,
        [scriptblock]$Command,
        [string]$OutputFile = $null
    )
    
    try {
        $result = & $Command 2>&1
        if ($OutputFile -and $result) {
            $result | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
        }
        return $result
    }
    catch {
        Write-Log "Failed: $Description - $($_.Exception.Message)" "WARN"
        if ($OutputFile) {
            "ERROR: $($_.Exception.Message)" | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
        }
        return $null
    }
}

function Get-FreeDriveLetter {
    $preferredLetters = @('S','T','U','V','W','X','Y','Z')
    try {
        $usedLetters = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Name
        foreach ($letter in $preferredLetters) {
            if ($usedLetters -notcontains $letter) {
                return $letter
            }
        }
    } catch { }
    return $null
}

function Get-SystemIdentity {
    $identity = @{
        ComputerName = $env:COMPUTERNAME
        Domain = $env:USERDOMAIN
        Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        SerialNumber = $null
        Manufacturer = $null
        Model = $null
    }
    
    try {
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        
        if ($bios) { $identity.SerialNumber = $bios.SerialNumber }
        if ($cs) {
            $identity.Manufacturer = $cs.Manufacturer
            $identity.Model = $cs.Model
        }
    } catch { }
    
    return $identity
}

function Get-ZipFileName {
    param([hashtable]$Identity)
    
    $parts = @()
    $parts += $Identity.ComputerName
    
    if ($Identity.SerialNumber -and $Identity.SerialNumber -ne "System Serial Number") {
        $serial = Get-SafeFileName $Identity.SerialNumber
        if ($serial.Length -gt 20) { $serial = $serial.Substring(0, 20) }
        $parts += $serial
    }
    
    $parts += $Identity.Timestamp
    $parts += "WindowsLogs"
    
    return ($parts -join "_") + ".zip"
}

function Get-WindowsCollectorCustomConfig {
    param(
        [string]$UploadUrl,
        [string]$AuthKey,
        [string]$WorkDir
    )

    if ([string]::IsNullOrWhiteSpace($UploadUrl) -or $UploadUrl -match "<SERVERURL>") {
        Write-Log "Custom config download skipped: UploadUrl is not configured" "WARN"
        return $null
    }

    if ([string]::IsNullOrWhiteSpace($AuthKey) -or $AuthKey -match "<AUTHKEY>") {
        Write-Log "Custom config download skipped: AuthKey is not configured" "WARN"
        return $null
    }

    $uploadUri = $null
    if (-not [Uri]::TryCreate($UploadUrl, [UriKind]::Absolute, [ref]$uploadUri)) {
        Write-Log "Custom config download skipped: UploadUrl is invalid" "WARN"
        return $null
    }

    $downloadUrl = "{0}://{1}/payloads/WindowsCollector/download/Windows-Collector.custom.json" -f $uploadUri.Scheme, $uploadUri.Authority
    $localConfigPath = Join-Path $WorkDir "Windows-Collector.custom.json"

    try {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        } catch {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }

        $request = [System.Net.HttpWebRequest]::Create($downloadUrl)
        $request.Method = "GET"
        $request.Headers.Add("X-Auth-Key", $AuthKey)
        $request.Timeout = 60000
        $request.ReadWriteTimeout = 60000

        $response = $request.GetResponse()
        try {
            $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
            try {
                $jsonText = $reader.ReadToEnd()
            } finally {
                $reader.Close()
            }
        } finally {
            $response.Close()
        }

        if ([string]::IsNullOrWhiteSpace($jsonText)) {
            Write-Log "Custom config download returned empty content" "WARN"
            return $null
        }

        try {
            $jsonText | Out-File -FilePath $localConfigPath -Encoding UTF8 -Force
        } catch {
            Write-Log "Could not save custom config locally: $($_.Exception.Message)" "WARN"
        }

        try {
            $customConfig = $jsonText | ConvertFrom-Json -ErrorAction Stop
            Write-Log "Loaded custom config from server" "SUCCESS"
            return $customConfig
        }
        catch {
            Write-Log "Custom config parse failed (strict JSON required, no comments): $($_.Exception.Message)" "WARN"
            return $null
        }
    }
    catch [System.Net.WebException] {
        $ex = $_.Exception
        if ($ex.Response) {
            try {
                $statusCode = [int]$ex.Response.StatusCode
                if ($statusCode -eq 404) {
                    Write-Log "No custom config found on server (404); skipping custom collections" "INFO"
                } else {
                    Write-Log "Custom config download failed: HTTP $statusCode $($ex.Response.StatusDescription)" "WARN"
                }
            } catch {
                Write-Log "Custom config download failed: $($ex.Message)" "WARN"
            }
        } else {
            Write-Log "Custom config download failed: $($ex.Message)" "WARN"
        }
        return $null
    }
    catch {
        Write-Log "Custom config download failed: $($_.Exception.Message)" "WARN"
        return $null
    }
}

function Collect-CustomConfiguredFolders {
    param(
        [string]$OutputDir,
        $CustomConfig
    )

    if (-not $CustomConfig) {
        return
    }

    Write-Section "Custom Collections"
    $customRoot = Join-Path $OutputDir "CustomCollections"
    New-Item -ItemType Directory -Path $customRoot -Force | Out-Null

    $targets = @()

    try {
        if ($CustomConfig.PSObject.Properties.Name -contains "orgProgramDataFolder") {
            $orgFolder = [string]$CustomConfig.orgProgramDataFolder
            if (-not [string]::IsNullOrWhiteSpace($orgFolder)) {
                $targets += [PSCustomObject]@{
                    Name = "ProgramData_$orgFolder"
                    Path = (Join-Path $env:ProgramData $orgFolder)
                    Source = "orgProgramDataFolder"
                }
            }
        }
    } catch { }

    try {
        if ($CustomConfig.PSObject.Properties.Name -contains "extraFolders" -and $CustomConfig.extraFolders) {
            foreach ($item in @($CustomConfig.extraFolders)) {
                if (-not $item) { continue }
                $pathValue = [string]$item.path
                if ([string]::IsNullOrWhiteSpace($pathValue)) { continue }
                $nameValue = [string]$item.name
                if ([string]::IsNullOrWhiteSpace($nameValue)) {
                    $nameValue = Split-Path -Path $pathValue -Leaf
                }
                if ([string]::IsNullOrWhiteSpace($nameValue)) {
                    $nameValue = "ExtraFolder"
                }

                if (-not [System.IO.Path]::IsPathRooted($pathValue)) {
                    $pathValue = Join-Path $env:SystemDrive ($pathValue.TrimStart('\\','/'))
                }

                $targets += [PSCustomObject]@{
                    Name = $nameValue
                    Path = $pathValue
                    Source = "extraFolders"
                }
            }
        }
    } catch { }

    try {
        if ($CustomConfig.PSObject.Properties.Name -contains "extraFolderPaths" -and $CustomConfig.extraFolderPaths) {
            $pathIndex = 0
            foreach ($pathRaw in @($CustomConfig.extraFolderPaths)) {
                $pathIndex++
                $pathValue = [string]$pathRaw
                if ([string]::IsNullOrWhiteSpace($pathValue)) { continue }
                $nameValue = Split-Path -Path $pathValue -Leaf
                if ([string]::IsNullOrWhiteSpace($nameValue)) {
                    $nameValue = "ExtraPath$pathIndex"
                }

                if (-not [System.IO.Path]::IsPathRooted($pathValue)) {
                    $pathValue = Join-Path $env:SystemDrive ($pathValue.TrimStart('\\','/'))
                }

                $targets += [PSCustomObject]@{
                    Name = $nameValue
                    Path = $pathValue
                    Source = "extraFolderPaths"
                }
            }
        }
    } catch { }

    if (-not $targets -or $targets.Count -eq 0) {
        Write-Log "Custom config has no recognized collection targets" "WARN"
        return
    }

    $attempted = 0
    $collected = 0
    $missing = 0
    $failed = 0

    foreach ($target in $targets) {
        $attempted++
        $sourcePath = [string]$target.Path
        $safeName = Get-SafeFileName ([string]$target.Name)
        if ([string]::IsNullOrWhiteSpace($safeName)) {
            $safeName = "Custom_$attempted"
        }

        $destPath = Join-Path $customRoot $safeName

        if (-not (Test-Path -LiteralPath $sourcePath)) {
            $missing++
            Write-Log "Custom path not found ($($target.Source)): $sourcePath" "WARN"
            continue
        }

        try {
            $item = Get-Item -LiteralPath $sourcePath -ErrorAction Stop
            if ($item.PSIsContainer) {
                Copy-Item -Path $sourcePath -Destination $destPath -Recurse -Force -ErrorAction Stop
            } else {
                New-Item -ItemType Directory -Path $destPath -Force | Out-Null
                Copy-Item -LiteralPath $sourcePath -Destination $destPath -Force -ErrorAction Stop
            }
            $collected++
            Write-Log "Collected custom path: $sourcePath -> $destPath" "SUCCESS"
        }
        catch {
            $failed++
            Write-Log "Failed custom collection '$sourcePath': $($_.Exception.Message)" "WARN"
        }
    }

    Write-Log "Custom collections summary: attempted=$attempted collected=$collected missing=$missing failed=$failed"
}

# ============================================================================
# Collection Functions
# ============================================================================

function Collect-SystemInformation {
    param([string]$OutputDir)
    
    Write-Section "System Information"
    $sysInfoDir = Join-Path $OutputDir "SystemInfo"
    New-Item -ItemType Directory -Path $sysInfoDir -Force | Out-Null
    
    # Basic system info
    Write-Log "Collecting basic system information..."
    Invoke-SafeCommand -Description "systeminfo" -Command {
        systeminfo /FO LIST 2>&1
    } -OutputFile (Join-Path $sysInfoDir "SystemInfo.txt")
    
    # Computer system details
    Write-Log "Collecting hardware information..."
    Invoke-SafeCommand -Description "ComputerSystem" -Command {
        $cs = Get-CimInstance Win32_ComputerSystem
        $bios = Get-CimInstance Win32_BIOS
        $baseboard = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
        $os = Get-CimInstance Win32_OperatingSystem
        $cpu = Get-CimInstance Win32_Processor
        
        @"
$Script:Divider
COMPUTER SYSTEM INFORMATION
$Script:Divider
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

=== Computer System ===
Name: $($cs.Name)
Domain: $($cs.Domain)
Manufacturer: $($cs.Manufacturer)
Model: $($cs.Model)
System Type: $($cs.SystemType)
Total Physical Memory: $([math]::Round($cs.TotalPhysicalMemory / 1GB, 2)) GB
Domain Role: $($cs.DomainRole)

=== BIOS ===
Manufacturer: $($bios.Manufacturer)
Version: $($bios.SMBIOSBIOSVersion)
Serial Number: $($bios.SerialNumber)
Release Date: $($bios.ReleaseDate)

=== Operating System ===
Name: $($os.Caption)
Version: $($os.Version)
Build: $($os.BuildNumber)
Architecture: $($os.OSArchitecture)
Install Date: $($os.InstallDate)
Last Boot: $($os.LastBootUpTime)

=== Processor ===
Name: $($cpu.Name)
Cores: $($cpu.NumberOfCores)
Logical Processors: $($cpu.NumberOfLogicalProcessors)
Max Clock Speed: $($cpu.MaxClockSpeed) MHz

=== BaseBoard ===
Manufacturer: $($baseboard.Manufacturer)
Product: $($baseboard.Product)
Serial Number: $($baseboard.SerialNumber)
Version: $($baseboard.Version)
"@
    } -OutputFile (Join-Path $sysInfoDir "HardwareInfo.txt")
    
    # Windows version details
    Write-Log "Collecting Windows version details..."
    Invoke-SafeCommand -Description "WindowsVersion" -Command {
        $props = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
        @"
$Script:Divider
WINDOWS VERSION DETAILS
$Script:Divider
Product Name: $($props.ProductName)
Display Version: $($props.DisplayVersion)
Edition ID: $($props.EditionID)
Current Build: $($props.CurrentBuild)
UBR: $($props.UBR)
Full Build: $($props.CurrentBuild).$($props.UBR)
Release ID: $($props.ReleaseId)
Build Lab: $($props.BuildLabEx)
Install Date: $([DateTime]::FromFileTime($props.InstallDate))
Registered Owner: $($props.RegisteredOwner)
Registered Organization: $($props.RegisteredOrganization)
Product ID: $($props.ProductId)
"@
    } -OutputFile (Join-Path $sysInfoDir "WindowsVersion.txt")
    
    # Environment variables
    Write-Log "Collecting environment variables..."
    Invoke-SafeCommand -Description "Environment" -Command {
        Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize -Wrap | Out-String
    } -OutputFile (Join-Path $sysInfoDir "EnvironmentVariables.txt")
    
    # Installed hotfixes
    Write-Log "Collecting installed hotfixes..."
    Invoke-SafeCommand -Description "Hotfixes" -Command {
        Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table -AutoSize | Out-String
    } -OutputFile (Join-Path $sysInfoDir "InstalledHotfixes.txt")
    try {
        Get-HotFix -ErrorAction SilentlyContinue |
            Select-Object HotFixID, Description, InstalledOn, InstalledBy |
            Sort-Object InstalledOn -Descending |
            Export-Csv -Path (Join-Path $sysInfoDir "InstalledHotfixes.csv") -NoTypeInformation -Encoding UTF8 -Force
    } catch {
        Write-Log "Failed: InstalledHotfixes CSV - $($_.Exception.Message)" "WARN"
    }
    
    # Installed software
    Write-Log "Collecting installed software..."
    Invoke-SafeCommand -Description "InstalledSoftware" -Command {
        $software = @()
        $paths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        foreach ($path in $paths) {
            $software += Get-ItemProperty $path -ErrorAction SilentlyContinue | 
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
        }
        $software | Sort-Object DisplayName -Unique | Format-Table -AutoSize -Wrap | Out-String
    } -OutputFile (Join-Path $sysInfoDir "InstalledSoftware.txt")
    try {
        $softwareCsv = @()
        $softwarePaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        foreach ($path in $softwarePaths) {
            $softwareCsv += Get-ItemProperty $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
        }
        $softwareCsv | Sort-Object DisplayName -Unique |
            Export-Csv -Path (Join-Path $sysInfoDir "InstalledSoftware.csv") -NoTypeInformation -Encoding UTF8 -Force
    } catch {
        Write-Log "Failed: InstalledSoftware CSV - $($_.Exception.Message)" "WARN"
    }
    
    # Windows Features
    Write-Log "Collecting Windows features..."
    Invoke-SafeCommand -Description "WindowsFeatures" -Command {
        if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
            Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq "Enabled" } | 
                Sort-Object FeatureName | Format-Table -AutoSize | Out-String
        } else {
            "Get-WindowsOptionalFeature not available on this system"
        }
    } -OutputFile (Join-Path $sysInfoDir "WindowsFeatures.txt")
    
    Write-Log "System information collected" "SUCCESS"
}

function Collect-EventLogs {
    param([string]$OutputDir)
    
    Write-Section "Event Logs"
    $evtxDir = Join-Path $OutputDir "EventLogs"
    New-Item -ItemType Directory -Path $evtxDir -Force | Out-Null
    
    # Copy all .evtx files from the event log directory
    $evtxSource = "$env:SystemRoot\System32\winevt\Logs"
    
    if (Test-Path $evtxSource) {
        Write-Log "Copying event log files from $evtxSource..."
        
        try {
            # Copy entire directory structure
            Copy-Item -Path $evtxSource -Destination $evtxDir -Recurse -Force -ErrorAction SilentlyContinue
            
            # Count collected files
            $evtxCount = (Get-ChildItem -Path $evtxDir -Filter "*.evtx" -Recurse -ErrorAction SilentlyContinue).Count
            Write-Log "Collected $evtxCount event log files" "SUCCESS"
        }
        catch {
            Write-Log "Error copying event logs: $($_.Exception.Message)" "WARN"
            
            # Fallback: try copying individual key files
            Write-Log "Attempting individual file copy..."
            $keyLogs = @(
                "Application.evtx",
                "System.evtx",
                "Setup.evtx",
                "Microsoft-Windows-WindowsUpdateClient%4Operational.evtx",
                "Microsoft-Windows-BitLocker%4BitLocker Management.evtx",
                "Microsoft-Windows-TaskScheduler%4Operational.evtx",
                "Microsoft-Windows-PowerShell%4Operational.evtx"
            )
            
            if ($IncludeSecurityLogs) {
                $keyLogs += "Security.evtx"
            }
            
            $copied = 0
            foreach ($logFile in $keyLogs) {
                $source = Join-Path $evtxSource $logFile
                if (Test-Path $source) {
                    try {
                        Copy-Item -Path $source -Destination $evtxDir -Force -ErrorAction SilentlyContinue
                        $copied++
                    } catch { }
                }
            }
            Write-Log "Copied $copied key event log files" "SUCCESS"
        }
    }
    else {
        Write-Log "Event log directory not found: $evtxSource" "WARN"
    }
}

function Collect-RegistryHives {
    param([string]$OutputDir)
    
    Write-Section "Registry Hives"
    $regDir = Join-Path $OutputDir "RegistryHives"
    New-Item -ItemType Directory -Path $regDir -Force | Out-Null
    
    # Export key registry branches (excludes SAM/SECURITY for privacy)
    $exports = @(
        @{ Name = "HKLM_SYSTEM"; Path = "HKLM\SYSTEM" },
        @{ Name = "HKLM_SOFTWARE"; Path = "HKLM\SOFTWARE" },
        @{ Name = "HKCU"; Path = "HKCU" }
    )
    
    foreach ($export in $exports) {
        Write-Log "Exporting $($export.Name)..."
        $outFile = Join-Path $regDir "$($export.Name).reg"
        try {
            reg export $export.Path $outFile /y 2>&1 | Out-Null
            Write-Log "  Exported $($export.Name)" "SUCCESS"
        }
        catch {
            Write-Log "  Failed to export $($export.Name)" "WARN"
        }
    }
    
    # Copy raw hive files if accessible
    $hiveDir = Join-Path $regDir "RawHives"
    New-Item -ItemType Directory -Path $hiveDir -Force | Out-Null
    
    $hives = @("SYSTEM", "SOFTWARE", "DEFAULT")
    $configPath = "$env:SystemRoot\System32\config"
    
    foreach ($hive in $hives) {
        $hivePath = Join-Path $configPath $hive
        if (Test-Path $hivePath) {
            try {
                # Use robocopy for locked file access
                $dest = Join-Path $hiveDir $hive
                robocopy $configPath $hiveDir $hive /B /R:0 /W:0 2>&1 | Out-Null
                if (Test-Path $dest) {
                    Write-Log "  Copied raw hive: $hive" "SUCCESS"
                }
            }
            catch {
                # Try VSS if robocopy fails
                Write-Log "  Could not copy raw hive $hive (in use)" "WARN"
            }
        }
    }
    
    Write-Log "Registry collection complete" "SUCCESS"
}

function Collect-WindowsLogs {
    param([string]$OutputDir)
    
    Write-Section "Windows Logs"
    $logsDir = Join-Path $OutputDir "Logs"
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
    
    $logPaths = @(
        @{ Name = "WindowsUpdate"; Path = "$env:SystemRoot\Logs\WindowsUpdate" },
        @{ Name = "CBS"; Path = "$env:SystemRoot\Logs\CBS" },
        @{ Name = "DISM"; Path = "$env:SystemRoot\Logs\DISM" },
        @{ Name = "Panther"; Path = "$env:SystemRoot\Panther" },
        @{ Name = "MoSetup"; Path = "$env:SystemRoot\Logs\MoSetup" },
        @{ Name = "DPAPI-MigrationTracker"; Path = "$env:SystemRoot\System32\Microsoft\Protect\Recovery" },
        @{ Name = "SoftwareDistribution"; Path = "$env:SystemRoot\SoftwareDistribution\ReportingEvents.log" },
        @{ Name = "Srt"; Path = "$env:SystemRoot\System32\LogFiles\Srt" }
    )
    
    foreach ($logPath in $logPaths) {
        if (Test-Path $logPath.Path) {
            Write-Log "Collecting $($logPath.Name) logs..."
            $dest = Join-Path $logsDir $logPath.Name
            try {
                if ((Get-Item $logPath.Path).PSIsContainer) {
                    Copy-Item -Path $logPath.Path -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
                } else {
                    New-Item -ItemType Directory -Path $dest -Force | Out-Null
                    Copy-Item -Path $logPath.Path -Destination $dest -Force -ErrorAction SilentlyContinue
                }
                Write-Log "  Collected $($logPath.Name)" "SUCCESS"
            }
            catch {
                Write-Log "  Error collecting $($logPath.Name): $($_.Exception.Message)" "WARN"
            }
        }
    }
    
    # SetupAPI logs
    Write-Log "Collecting SetupAPI logs..."
    $setupApiDir = Join-Path $logsDir "SetupAPI"
    New-Item -ItemType Directory -Path $setupApiDir -Force | Out-Null
    $setupApiLogs = Get-ChildItem -Path "$env:SystemRoot\INF" -Filter "setupapi*.log" -ErrorAction SilentlyContinue
    foreach ($log in $setupApiLogs) {
        Copy-Item -Path $log.FullName -Destination $setupApiDir -Force -ErrorAction SilentlyContinue
    }
    
    # NetSetup logs
    Write-Log "Collecting NetSetup logs..."
    $netSetupDir = Join-Path $logsDir "NetSetup"
    New-Item -ItemType Directory -Path $netSetupDir -Force | Out-Null
    @(
        "$env:SystemRoot\debug\NetSetup.LOG",
        "$env:SystemRoot\debug\NetSetup"
    ) | ForEach-Object {
        if (Test-Path $_) {
            Copy-Item -Path $_ -Destination $netSetupDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    Write-Log "Windows logs collected" "SUCCESS"
}

function Collect-CrashDumps {
    param([string]$OutputDir)
    
    Write-Section "Crash Dumps"
    $dumpDir = Join-Path $OutputDir "CrashDumps"
    New-Item -ItemType Directory -Path $dumpDir -Force | Out-Null
    
    $dumpCount = 0
    $maxDumpSize = 500MB
    
    # Minidumps
    $minidumpPath = "$env:SystemRoot\Minidump"
    if (Test-Path $minidumpPath) {
        Write-Log "Collecting minidumps..."
        $dumps = Get-ChildItem -Path $minidumpPath -Filter "*.dmp" -ErrorAction SilentlyContinue
        foreach ($dump in $dumps) {
            if ($dump.Length -lt $maxDumpSize) {
                Copy-Item -Path $dump.FullName -Destination $dumpDir -Force -ErrorAction SilentlyContinue
                $dumpCount++
            }
        }
    }
    
    # LiveKernelReports
    $lkrPath = "$env:SystemRoot\LiveKernelReports"
    if (Test-Path $lkrPath) {
        Write-Log "Collecting LiveKernelReports..."
        $lkrDir = Join-Path $dumpDir "LiveKernelReports"
        New-Item -ItemType Directory -Path $lkrDir -Force | Out-Null
        $lkrDumps = Get-ChildItem -Path $lkrPath -Filter "*.dmp" -Recurse -ErrorAction SilentlyContinue
        foreach ($dump in $lkrDumps) {
            if ($dump.Length -lt $maxDumpSize) {
                Copy-Item -Path $dump.FullName -Destination $lkrDir -Force -ErrorAction SilentlyContinue
                $dumpCount++
            }
        }
    }
    
    # WER Reports (Windows Error Reporting)
    Write-Log "Collecting WER reports..."
    $werDir = Join-Path $dumpDir "WER"
    New-Item -ItemType Directory -Path $werDir -Force | Out-Null
    
    $werPaths = @(
        "$env:ProgramData\Microsoft\Windows\WER\ReportArchive",
        "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
    )
    
    foreach ($werPath in $werPaths) {
        if (Test-Path $werPath) {
            $subDir = Join-Path $werDir (Split-Path $werPath -Leaf)
            Copy-Item -Path $werPath -Destination $subDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Reliability history
    Write-Log "Collecting reliability data..."
    Invoke-SafeCommand -Description "ReliabilityRecords" -Command {
        Get-CimInstance -ClassName Win32_ReliabilityStabilityMetrics -ErrorAction SilentlyContinue |
            Select-Object TimeGenerated, SystemStabilityIndex |
            Sort-Object TimeGenerated -Descending |
            Select-Object -First 30 |
            Format-Table -AutoSize | Out-String
    } -OutputFile (Join-Path $dumpDir "ReliabilityHistory.txt")
    
    Write-Log "Collected $dumpCount crash dump(s)" "SUCCESS"
}

function Collect-NetworkConfiguration {
    param([string]$OutputDir)
    
    Write-Section "Network Configuration"
    $netDir = Join-Path $OutputDir "Network"
    New-Item -ItemType Directory -Path $netDir -Force | Out-Null
    
    Write-Log "Collecting network configuration..."
    
    Invoke-SafeCommand -Description "ipconfig" -Command {
        ipconfig /all 2>&1 | Out-String
    } -OutputFile (Join-Path $netDir "ipconfig.txt")
    
    Invoke-SafeCommand -Description "route" -Command {
        route print 2>&1 | Out-String
    } -OutputFile (Join-Path $netDir "route.txt")
    
    Invoke-SafeCommand -Description "netstat" -Command {
        netstat -ano 2>&1 | Out-String
    } -OutputFile (Join-Path $netDir "netstat.txt")
    
    Invoke-SafeCommand -Description "arp" -Command {
        arp -a 2>&1 | Out-String
    } -OutputFile (Join-Path $netDir "arp.txt")
    
    Invoke-SafeCommand -Description "DNS" -Command {
        Get-DnsClientServerAddress | Format-Table -AutoSize | Out-String
    } -OutputFile (Join-Path $netDir "DnsServers.txt")
    
    Invoke-SafeCommand -Description "NetworkAdapters" -Command {
        Get-NetAdapter | Format-Table -AutoSize | Out-String
        Get-NetIPAddress | Format-Table -AutoSize | Out-String
    } -OutputFile (Join-Path $netDir "NetworkAdapters.txt")
    
    Invoke-SafeCommand -Description "Firewall" -Command {
        @"
$Script:Divider
FIREWALL STATUS
$Script:Divider
$(netsh advfirewall show allprofiles 2>&1)

$Script:Divider
FIREWALL RULES (Enabled)
$Script:Divider
$((Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Direction, Action, Profile | Format-Table -AutoSize | Out-String))
"@
    } -OutputFile (Join-Path $netDir "Firewall.txt")
    
    Invoke-SafeCommand -Description "Hosts" -Command {
        Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue
    } -OutputFile (Join-Path $netDir "hosts.txt")
    
    # Network shares
    Invoke-SafeCommand -Description "Shares" -Command {
        net share 2>&1 | Out-String
    } -OutputFile (Join-Path $netDir "NetShares.txt")
    
    Write-Log "Network configuration collected" "SUCCESS"
}

function Collect-ProcessesAndServices {
    param([string]$OutputDir)
    
    Write-Section "Processes and Services"
    $procDir = Join-Path $OutputDir "ProcessesServices"
    New-Item -ItemType Directory -Path $procDir -Force | Out-Null
    
    Write-Log "Collecting running processes..."
    Invoke-SafeCommand -Description "Processes" -Command {
        Get-Process | Sort-Object CPU -Descending | 
            Select-Object Id, ProcessName, CPU, WorkingSet64, Path |
            Format-Table -AutoSize | Out-String
    } -OutputFile (Join-Path $procDir "RunningProcesses.txt")
    try {
        Get-Process -ErrorAction SilentlyContinue |
            Select-Object Id, ProcessName, CPU, WorkingSet64, Path |
            Sort-Object CPU -Descending |
            Export-Csv -Path (Join-Path $procDir "RunningProcesses.csv") -NoTypeInformation -Encoding UTF8 -Force
    } catch {
        Write-Log "Failed: RunningProcesses CSV - $($_.Exception.Message)" "WARN"
    }
    
    Invoke-SafeCommand -Description "ProcessDetails" -Command {
        Get-CimInstance Win32_Process | 
            Select-Object ProcessId, Name, CommandLine, CreationDate, ParentProcessId |
            Sort-Object CreationDate -Descending |
            Format-Table -AutoSize -Wrap | Out-String
    } -OutputFile (Join-Path $procDir "ProcessDetails.txt")
    
    Write-Log "Collecting services..."
    Invoke-SafeCommand -Description "Services" -Command {
        Get-Service | Sort-Object Status, Name | 
            Select-Object Status, Name, DisplayName, StartType |
            Format-Table -AutoSize | Out-String
    } -OutputFile (Join-Path $procDir "Services.txt")
    try {
        Get-Service -ErrorAction SilentlyContinue |
            Select-Object Status, Name, DisplayName, StartType |
            Sort-Object Status, Name |
            Export-Csv -Path (Join-Path $procDir "Services.csv") -NoTypeInformation -Encoding UTF8 -Force
    } catch {
        Write-Log "Failed: Services CSV - $($_.Exception.Message)" "WARN"
    }
    
    Invoke-SafeCommand -Description "ServiceDetails" -Command {
        Get-CimInstance Win32_Service | 
            Select-Object Name, State, StartMode, PathName, StartName |
            Sort-Object State, Name |
            Format-Table -AutoSize -Wrap | Out-String
    } -OutputFile (Join-Path $procDir "ServiceDetails.txt")
    
    # Startup items
    Write-Log "Collecting startup items..."
    Invoke-SafeCommand -Description "StartupItems" -Command {
        @"
$Script:Divider
STARTUP ITEMS
$Script:Divider

=== Registry Run Keys (HKLM) ===
$(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Format-List | Out-String)

=== Registry Run Keys (HKCU) ===
$(Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Format-List | Out-String)

=== Startup Folder (All Users) ===
$(Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String)

=== Scheduled Tasks (Root) ===
$(Get-ScheduledTask -TaskPath "\" -ErrorAction SilentlyContinue | Select-Object TaskName, State, TaskPath | Format-Table -AutoSize | Out-String)
"@
    } -OutputFile (Join-Path $procDir "StartupItems.txt")
    
    Write-Log "Processes and services collected" "SUCCESS"
}

function Collect-StorageAndDisk {
    param([string]$OutputDir)
    
    Write-Section "Storage and Disk"
    $diskDir = Join-Path $OutputDir "Storage"
    New-Item -ItemType Directory -Path $diskDir -Force | Out-Null
    
    Write-Log "Collecting disk information..."
    
    Invoke-SafeCommand -Description "Disks" -Command {
        Get-Disk | Format-Table -AutoSize | Out-String
    } -OutputFile (Join-Path $diskDir "Disks.txt")
    try {
        Get-Disk -ErrorAction SilentlyContinue |
            Export-Csv -Path (Join-Path $diskDir "Disks.csv") -NoTypeInformation -Encoding UTF8 -Force
    } catch {
        Write-Log "Failed: Disks CSV - $($_.Exception.Message)" "WARN"
    }
    
    Invoke-SafeCommand -Description "Partitions" -Command {
        Get-Partition | Format-Table -AutoSize | Out-String
    } -OutputFile (Join-Path $diskDir "Partitions.txt")
    try {
        Get-Partition -ErrorAction SilentlyContinue |
            Export-Csv -Path (Join-Path $diskDir "Partitions.csv") -NoTypeInformation -Encoding UTF8 -Force
    } catch {
        Write-Log "Failed: Partitions CSV - $($_.Exception.Message)" "WARN"
    }
    
    Invoke-SafeCommand -Description "Volumes" -Command {
        Get-Volume | Format-Table -AutoSize | Out-String
    } -OutputFile (Join-Path $diskDir "Volumes.txt")
    try {
        Get-Volume -ErrorAction SilentlyContinue |
            Export-Csv -Path (Join-Path $diskDir "Volumes.csv") -NoTypeInformation -Encoding UTF8 -Force
    } catch {
        Write-Log "Failed: Volumes CSV - $($_.Exception.Message)" "WARN"
    }
    
    Invoke-SafeCommand -Description "PhysicalDisks" -Command {
        Get-PhysicalDisk | Select-Object FriendlyName, MediaType, BusType, HealthStatus, OperationalStatus, Size | 
            Format-Table -AutoSize | Out-String
    } -OutputFile (Join-Path $diskDir "PhysicalDisks.txt")
    try {
        Get-PhysicalDisk -ErrorAction SilentlyContinue |
            Select-Object FriendlyName, MediaType, BusType, HealthStatus, OperationalStatus, Size |
            Export-Csv -Path (Join-Path $diskDir "PhysicalDisks.csv") -NoTypeInformation -Encoding UTF8 -Force
    } catch {
        Write-Log "Failed: PhysicalDisks CSV - $($_.Exception.Message)" "WARN"
    }
    
    # SMART data
    Write-Log "Collecting disk health (SMART) data..."
    Invoke-SafeCommand -Description "DiskHealth" -Command {
        @"
$Script:Divider
DISK HEALTH INFORMATION
$Script:Divider

=== Storage Reliability Counters ===
$(Get-PhysicalDisk | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue | Format-List | Out-String)

=== Disk Health Status ===
$(Get-PhysicalDisk | Select-Object FriendlyName, HealthStatus, OperationalStatus, SpindleSpeed, MediaType | Format-Table -AutoSize | Out-String)
"@
    } -OutputFile (Join-Path $diskDir "DiskHealth.txt")
    
    # BitLocker status
    Write-Log "Collecting BitLocker status..."
    Invoke-SafeCommand -Description "BitLocker" -Command {
        if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
            Get-BitLockerVolume | Format-List | Out-String
        } else {
            manage-bde -status 2>&1 | Out-String
        }
    } -OutputFile (Join-Path $diskDir "BitLockerStatus.txt")
    
    # Diskpart info
    Invoke-SafeCommand -Description "Diskpart" -Command {
        $dpScript = Join-Path $env:TEMP "diskpart-collect.txt"
        @("list disk", "list volume", "exit") | Out-File $dpScript -Encoding ASCII
        diskpart /s $dpScript 2>&1 | Out-String
        Remove-Item $dpScript -Force -ErrorAction SilentlyContinue
    } -OutputFile (Join-Path $diskDir "Diskpart.txt")

    # EFI partition file inventory (best-effort)
    $efiCsvPath = Join-Path $diskDir "EfiFiles.csv"
    $mountedByScript = $false
    $efiLetter = $null
    $efiPartition = $null

    try {
        $efiPartition = Get-Partition -ErrorAction SilentlyContinue |
            Where-Object { $_.GptType -eq '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}' } |
            Select-Object -First 1

        if (-not $efiPartition) {
            Write-Log "EFI partition not found; skipping EFI file inventory" "WARN"
        }
        else {
            if ($efiPartition.DriveLetter) {
                $efiLetter = [string]$efiPartition.DriveLetter
                Write-Log "Using existing EFI mount at $efiLetter`:" "INFO"
            }
            else {
                $efiLetter = Get-FreeDriveLetter
                if (-not $efiLetter) {
                    Write-Log "No free drive letter available for EFI mount; skipping EFI file inventory" "WARN"
                }
                else {
                    try {
                        if (Get-Command Set-Partition -ErrorAction SilentlyContinue) {
                            Set-Partition -DiskNumber $efiPartition.DiskNumber -PartitionNumber $efiPartition.PartitionNumber -NewDriveLetter $efiLetter -ErrorAction Stop | Out-Null
                            $mountedByScript = $true
                            Write-Log "Temporarily mounted EFI partition to $efiLetter`:" "INFO"
                            Start-Sleep -Seconds 1
                        }
                        else {
                            Write-Log "Set-Partition not available; skipping EFI file inventory" "WARN"
                            $efiLetter = $null
                        }
                    }
                    catch {
                        Write-Log "Failed to mount EFI partition: $($_.Exception.Message)" "WARN"
                        $efiLetter = $null
                    }
                }
            }

            if ($efiLetter) {
                try {
                    $efiRoot = "$efiLetter`:\"
                    if (Test-Path -LiteralPath $efiRoot) {
                        $efiFiles = Get-ChildItem -LiteralPath $efiRoot -Recurse -Force -ErrorAction SilentlyContinue |
                            Where-Object { -not $_.PSIsContainer } |
                            Select-Object FullName, CreationTimeUtc, LastWriteTimeUtc, Length

                        $efiFiles |
                            Export-Csv -Path $efiCsvPath -NoTypeInformation -Encoding UTF8 -Force
                        Write-Log "EFI file inventory exported: $efiCsvPath" "SUCCESS"

                        $efiLogFiles = $efiFiles | Where-Object {
                            $_.FullName -and $_.FullName.ToLowerInvariant().EndsWith('.log')
                        }

                        if ($efiLogFiles -and $efiLogFiles.Count -gt 0) {
                            $efiLogsDir = Join-Path $diskDir "EfiLogs"
                            New-Item -ItemType Directory -Path $efiLogsDir -Force | Out-Null
                            $copiedLogCount = 0

                            foreach ($logFile in $efiLogFiles) {
                                try {
                                    $relativePath = $logFile.FullName.Substring($efiRoot.Length).TrimStart('\\')
                                    if ([string]::IsNullOrWhiteSpace($relativePath)) {
                                        $relativePath = [System.IO.Path]::GetFileName($logFile.FullName)
                                    }

                                    $destinationFile = Join-Path $efiLogsDir $relativePath
                                    $destinationParent = Split-Path -Parent $destinationFile
                                    if ($destinationParent -and -not (Test-Path -LiteralPath $destinationParent)) {
                                        New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
                                    }

                                    Copy-Item -LiteralPath $logFile.FullName -Destination $destinationFile -Force -ErrorAction Stop
                                    $copiedLogCount++
                                }
                                catch {
                                    Write-Log "Failed to copy EFI log file $($logFile.FullName): $($_.Exception.Message)" "WARN"
                                }
                            }

                            Write-Log "Collected $copiedLogCount EFI *.log file(s) into $efiLogsDir" "SUCCESS"
                        }
                        else {
                            Write-Log "No EFI *.log files found" "INFO"
                        }
                    }
                    else {
                        Write-Log "EFI mount path not accessible: $efiRoot" "WARN"
                    }
                }
                catch {
                    Write-Log "Failed to collect EFI file inventory: $($_.Exception.Message)" "WARN"
                }
            }
        }
    }
    catch {
        Write-Log "EFI inventory error: $($_.Exception.Message)" "WARN"
    }
    finally {
        if ($mountedByScript -and $efiPartition -and $efiLetter) {
            try {
                if (Get-Command Remove-PartitionAccessPath -ErrorAction SilentlyContinue) {
                    Remove-PartitionAccessPath -DiskNumber $efiPartition.DiskNumber -PartitionNumber $efiPartition.PartitionNumber -AccessPath "$efiLetter`:\" -ErrorAction Stop | Out-Null
                    Write-Log "Removed temporary EFI mount $efiLetter`:" "INFO"
                }
            }
            catch {
                Write-Log "Failed to remove temporary EFI drive letter $efiLetter`:: $($_.Exception.Message)" "WARN"
            }
        }
    }
    
    Write-Log "Storage information collected" "SUCCESS"
}

function Collect-SecurityInfo {
    param([string]$OutputDir)
    
    Write-Section "Security Information"
    $secDir = Join-Path $OutputDir "Security"
    New-Item -ItemType Directory -Path $secDir -Force | Out-Null
    
    # Windows Defender
    Write-Log "Collecting Windows Defender status..."
    Invoke-SafeCommand -Description "Defender" -Command {
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
            @"
$Script:Divider
WINDOWS DEFENDER STATUS
$Script:Divider
$(Get-MpComputerStatus | Format-List | Out-String)

=== Threat Detection History ===
$(Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 20 | Format-Table -AutoSize | Out-String)

=== Preference Settings ===
$(Get-MpPreference | Format-List | Out-String)
"@
        } else {
            "Windows Defender cmdlets not available"
        }
    } -OutputFile (Join-Path $secDir "WindowsDefender.txt")
    
    # Local users and groups
    Write-Log "Collecting local users and groups..."
    Invoke-SafeCommand -Description "LocalUsers" -Command {
        Get-LocalUser | Format-Table -AutoSize | Out-String
    } -OutputFile (Join-Path $secDir "LocalUsers.txt")
    
    Invoke-SafeCommand -Description "LocalGroups" -Command {
        Get-LocalGroup | Format-Table -AutoSize | Out-String
        Write-Output ""
        Write-Output "=== Administrators Group Members ==="
        Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String
    } -OutputFile (Join-Path $secDir "LocalGroups.txt")
    
    # Audit policy
    Invoke-SafeCommand -Description "AuditPolicy" -Command {
        auditpol /get /category:* 2>&1 | Out-String
    } -OutputFile (Join-Path $secDir "AuditPolicy.txt")
    
    # TPM
    Write-Log "Collecting TPM information..."
    Invoke-SafeCommand -Description "TPM" -Command {
        if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
            Get-Tpm | Format-List | Out-String
        } else {
            "Get-Tpm not available"
        }
    } -OutputFile (Join-Path $secDir "TPM.txt")
    
    Write-Log "Security information collected" "SUCCESS"
}

function Collect-DriverInfo {
    param([string]$OutputDir)
    
    Write-Section "Driver Information"
    $driverDir = Join-Path $OutputDir "Drivers"
    New-Item -ItemType Directory -Path $driverDir -Force | Out-Null
    
    Write-Log "Collecting driver information..."
    
    Invoke-SafeCommand -Description "Drivers" -Command {
        Get-CimInstance Win32_PnPSignedDriver | 
            Select-Object DeviceName, DriverVersion, Manufacturer, DriverDate, InfName |
            Sort-Object DeviceName |
            Format-Table -AutoSize -Wrap | Out-String
    } -OutputFile (Join-Path $driverDir "InstalledDrivers.txt")
    
    Invoke-SafeCommand -Description "PnPDevices" -Command {
        Get-PnpDevice | Where-Object { $_.Status -eq "Error" -or $_.Status -eq "Degraded" } |
            Select-Object Status, Class, FriendlyName, InstanceId |
            Format-Table -AutoSize | Out-String
    } -OutputFile (Join-Path $driverDir "ProblematicDevices.txt")
    
    Invoke-SafeCommand -Description "DriverQuery" -Command {
        driverquery /v /fo list 2>&1 | Out-String
    } -OutputFile (Join-Path $driverDir "DriverQuery.txt")
    
    Write-Log "Driver information collected" "SUCCESS"
}

function Collect-ScheduledTasks {
    param([string]$OutputDir)
    
    Write-Section "Scheduled Tasks"
    $taskDir = Join-Path $OutputDir "ScheduledTasks"
    New-Item -ItemType Directory -Path $taskDir -Force | Out-Null
    
    Write-Log "Collecting scheduled tasks..."
    
    Invoke-SafeCommand -Description "ScheduledTasks" -Command {
        Get-ScheduledTask | 
            Select-Object TaskName, TaskPath, State, Author |
            Sort-Object TaskPath, TaskName |
            Format-Table -AutoSize | Out-String
    } -OutputFile (Join-Path $taskDir "AllTasks.txt")
    try {
        Get-ScheduledTask -ErrorAction SilentlyContinue |
            Select-Object TaskName, TaskPath, State, Author |
            Sort-Object TaskPath, TaskName |
            Export-Csv -Path (Join-Path $taskDir "AllTasks.csv") -NoTypeInformation -Encoding UTF8 -Force
    } catch {
        Write-Log "Failed: AllTasks CSV - $($_.Exception.Message)" "WARN"
    }
    
    Invoke-SafeCommand -Description "TaskDetails" -Command {
        Get-ScheduledTask | Where-Object { $_.State -eq "Running" -or $_.State -eq "Ready" } |
            ForEach-Object {
                $info = Get-ScheduledTaskInfo $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    Name = $_.TaskName
                    Path = $_.TaskPath
                    State = $_.State
                    LastRun = $info.LastRunTime
                    NextRun = $info.NextRunTime
                    LastResult = $info.LastTaskResult
                }
            } | Format-Table -AutoSize | Out-String
    } -OutputFile (Join-Path $taskDir "ActiveTasks.txt")
    
    # Export task XML for custom tasks
    $customTaskDir = Join-Path $taskDir "TaskExports"
    New-Item -ItemType Directory -Path $customTaskDir -Force | Out-Null
    
    Get-ScheduledTask -TaskPath "\" -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $safeName = Get-SafeFileName $_.TaskName
            Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath |
                Out-File (Join-Path $customTaskDir "$safeName.xml") -Encoding UTF8
        } catch { }
    }
    
    Write-Log "Scheduled tasks collected" "SUCCESS"
}

function Collect-FileInventory {
    param([string]$OutputDir)
    
    Write-Section "File Inventory"
    $inventoryDir = Join-Path $OutputDir "FileInventory"
    New-Item -ItemType Directory -Path $inventoryDir -Force | Out-Null
    
    Write-Log "Collecting file inventory for all partitions..."
    
    # Get all fixed drives (local disks)
    $drives = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" | Select-Object -ExpandProperty DeviceID
    
    foreach ($drive in $drives) {
        $driveLetter = $drive.TrimEnd(':')
        $outputFile = Join-Path $inventoryDir "Inventory_${driveLetter}.txt"
        
        Write-Log "  Scanning $drive ..."
        
        try {
            # Use cmd.exe dir /b /s for performance and compatibility
            $cmdOutput = & cmd.exe /c "dir /b /s `"$drive\`" 2>nul"
            if ($cmdOutput) {
                $cmdOutput | Out-File -FilePath $outputFile -Encoding UTF8
                $lineCount = ($cmdOutput | Measure-Object -Line).Lines
                Write-Log "    $drive : $lineCount files/folders"
            } else {
                Write-Log "    $drive : No files found or access denied" "WARNING"
            }
        } catch {
            Write-Log "    $drive : Error - $($_.Exception.Message)" "WARNING"
        }
    }
    
    Write-Log "File inventory collected" "SUCCESS"
}

# ============================================================================
# Upload Function
# ============================================================================

function Upload-CollectionZip {
    param(
        [string]$ZipPath,
        [string]$Url,
        [string]$Key
    )
    
    Write-Section "Upload"
    
    if (-not (Test-Path $ZipPath)) {
        Write-Log "ZIP file not found: $ZipPath" "ERROR"
        return $false
    }
    
    $fileSize = (Get-Item $ZipPath).Length
    $fileSizeMB = [math]::Round($fileSize / 1MB, 2)
    Write-Log "Uploading $ZipPath ($fileSizeMB MB)..."
    Write-Log "Target: $Url"
    
    try {
        # Ensure TLS 1.2+ for HttpWebRequest (must be set before request creation)
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        } catch {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
        
        $fileName = [System.IO.Path]::GetFileName($ZipPath)
        $boundary = [System.Guid]::NewGuid().ToString()
        
        $request = [System.Net.HttpWebRequest]::Create($Url)
        $request.Method = "POST"
        $request.ContentType = "multipart/form-data; boundary=$boundary"
        $request.Headers.Add("X-Auth-Key", $Key)
        $request.Timeout = 1800000          # 30 minutes
        $request.ReadWriteTimeout = 1800000 # 30 minutes
        $request.AllowWriteStreamBuffering = $false
        
        # Build multipart boundaries
        $headerBytes = [System.Text.Encoding]::UTF8.GetBytes(
            "--$boundary`r`nContent-Disposition: form-data; name=`"file`"; filename=`"$fileName`"`r`nContent-Type: application/octet-stream`r`n`r`n"
        )
        $footerBytes = [System.Text.Encoding]::UTF8.GetBytes("`r`n--$boundary--`r`n")
        $request.ContentLength = $headerBytes.Length + $fileSize + $footerBytes.Length
        
        Write-Log "Sending ($fileSizeMB MB, streaming)..."
        Sync-Log
        
        $reqStream = $request.GetRequestStream()
        try {
            $reqStream.Write($headerBytes, 0, $headerBytes.Length)
            
            $fileStream = [System.IO.File]::OpenRead($ZipPath)
            try {
                $buffer = New-Object byte[] 65536
                while (($read = $fileStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $reqStream.Write($buffer, 0, $read)
                }
            } finally {
                $fileStream.Close()
            }
            
            $reqStream.Write($footerBytes, 0, $footerBytes.Length)
        } finally {
            $reqStream.Close()
        }
        
        $response = $request.GetResponse()
        try {
            $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
            $responseContent = $reader.ReadToEnd()
            $reader.Close()
            $statusCode = [int]$response.StatusCode
            
            if ($statusCode -ge 200 -and $statusCode -lt 300) {
                Write-Log "Upload successful!" "SUCCESS"
                Write-Log "Server response: $responseContent"
                return $true
            } else {
                Write-Log "Upload failed: HTTP $statusCode" "ERROR"
                Write-Log "Response: $responseContent" "ERROR"
                return $false
            }
        } finally {
            $response.Close()
        }
    }
    catch [System.Net.WebException] {
        $ex = $_.Exception
        if ($ex.Response) {
            try {
                $errReader = New-Object System.IO.StreamReader($ex.Response.GetResponseStream())
                $errBody = $errReader.ReadToEnd()
                $errReader.Close()
                Write-Log "Upload failed: HTTP $([int]$ex.Response.StatusCode) $($ex.Response.StatusDescription)" "ERROR"
                Write-Log "Response: $errBody" "ERROR"
            } catch {
                Write-Log "Upload failed: $($ex.Message)" "ERROR"
            }
        } else {
            Write-Log "Upload error: $($ex.Message)" "ERROR"
        }
        return $false
    }
    catch {
        Write-Log "Upload error: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# ============================================================================
# Main Collection Workflow
# ============================================================================

function Invoke-Collection {
    param(
        [string]$WorkDir,
        [string]$UploadUrl,
        [string]$AuthKey
    )
    
    $collectDir = Join-Path $WorkDir "Collection"
    New-Item -ItemType Directory -Path $collectDir -Force | Out-Null

    $customConfig = Get-WindowsCollectorCustomConfig -UploadUrl $UploadUrl -AuthKey $AuthKey -WorkDir $WorkDir
    
    # Run all collection functions (suppress any output to prevent polluting return value)
    Collect-SystemInformation -OutputDir $collectDir | Out-Null
    Collect-EventLogs -OutputDir $collectDir | Out-Null
    Collect-RegistryHives -OutputDir $collectDir | Out-Null
    Collect-WindowsLogs -OutputDir $collectDir | Out-Null
    Collect-CrashDumps -OutputDir $collectDir | Out-Null
    Collect-NetworkConfiguration -OutputDir $collectDir | Out-Null
    Collect-ProcessesAndServices -OutputDir $collectDir | Out-Null
    Collect-StorageAndDisk -OutputDir $collectDir | Out-Null
    Collect-SecurityInfo -OutputDir $collectDir | Out-Null
    Collect-DriverInfo -OutputDir $collectDir | Out-Null
    Collect-ScheduledTasks -OutputDir $collectDir | Out-Null
    Collect-FileInventory -OutputDir $collectDir | Out-Null
    Collect-CustomConfiguredFolders -OutputDir $collectDir -CustomConfig $customConfig | Out-Null
    
    return $collectDir
}

# ============================================================================
# Entry Point
# ============================================================================

try {
    Write-Banner
    
    # Get system identity
    $identity = Get-SystemIdentity
    $zipFileName = Get-ZipFileName -Identity $identity
    
    # Setup working directory
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $workDir = Join-Path "$env:SystemDrive\Windows\Temp" "WindowsCollector-$($identity.Timestamp)"
    }
    else {
        $workDir = $OutputPath
    }
    
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
    
    # Start persisting log to workDir immediately (survives cleanup)
    $Script:LogFilePath = Join-Path $workDir "CollectionLog.txt"
    Sync-Log
    
    Write-Log "Computer: $($identity.ComputerName)"
    Write-Log "Serial: $($identity.SerialNumber)"
    Write-Log "Working directory: $workDir"
    Write-Log ""
    
    # Run collection
    $collectDir = Invoke-Collection -WorkDir $workDir -UploadUrl $UploadUrl -AuthKey $AuthKey
    
    # Flush current log and copy snapshot into collection folder for the ZIP
    Write-Section "Finalizing"
    Sync-Log
    $logSnapshot = Join-Path $collectDir "CollectionLog.txt"
    Copy-Item -Path $Script:LogFilePath -Destination $logSnapshot -Force -ErrorAction SilentlyContinue
    
    # Create collection summary
    $summaryFile = Join-Path $collectDir "CollectionSummary.txt"
    @"
$Script:Divider
WINDOWS DIAGNOSTIC COLLECTION SUMMARY
$Script:Divider
Computer Name: $($identity.ComputerName)
Domain: $($identity.Domain)
Serial Number: $($identity.SerialNumber)
Manufacturer: $($identity.Manufacturer)
Model: $($identity.Model)

Collection Started: $($Script:CollectionStart)
Collection Completed: $(Get-Date)
Duration: $((Get-Date) - $Script:CollectionStart)

Collected As: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
Output File: $zipFileName
$Script:Divider
"@ | Out-File -FilePath $summaryFile -Encoding UTF8 -Force
    
    # Create ZIP
    Write-Log "Creating ZIP archive..."
    $zipPath = Join-Path $workDir $zipFileName
    
    if (Test-Path $zipPath) {
        Remove-Item $zipPath -Force
    }
    
    Compress-Archive -Path "$collectDir\*" -DestinationPath $zipPath -Force
    
    $zipSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
    Write-Log "Created: $zipPath ($zipSize MB)" "SUCCESS"
    Sync-Log
    
    # Upload if not skipped
    if (-not $SkipUpload) {
        # Validate upload URL (use single angle brackets so download endpoint doesn't replace these)
        if ($UploadUrl -match "<SERVERURL>") {
            Write-Log "Upload URL not configured (still contains placeholder)" "WARN"
            Write-Log "ZIP file saved locally: $zipPath"
        }
        elseif ($AuthKey -match "<AUTHKEY>") {
            Write-Log "Auth key not configured (still contains placeholder)" "WARN"
            Write-Log "ZIP file saved locally: $zipPath"
        }
        else {
            $uploaded = Upload-CollectionZip -ZipPath $zipPath -Url $UploadUrl -Key $AuthKey
            if (-not $uploaded) {
                Write-Log "Upload failed - ZIP file saved locally: $zipPath" "WARN"
            }
        }
    }
    else {
        Write-Log "Upload skipped (--SkipUpload specified)"
        Write-Log "ZIP file: $zipPath"
    }
    
    # Cleanup
    if (-not $SkipUpload -and (Test-Path $zipPath)) {
        Write-Log "Cleaning up collection directory..."
        Remove-Item -Path $collectDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    Write-Section "Complete"
    Write-Log "Collection complete!" "SUCCESS"
    Write-Log "Output: $zipPath"
    Write-Log "Full log: $($Script:LogFilePath)"
    Sync-Log
    
    if (-not $Silent) {
        Write-Host ""
        Write-Host "Press any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    
    exit 0
}
catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    Write-Log $_.ScriptStackTrace "ERROR"
    Sync-Log
    
    if (-not $Silent) {
        Write-Host ""
        Write-Host "Press any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    
    exit 1
}
