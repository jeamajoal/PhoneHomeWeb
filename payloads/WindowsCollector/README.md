# Windows Collector

Online Windows diagnostic log collector for running systems. Designed to be deployed via EPM/RMM tools (running as SYSTEM) or executed interactively with Administrator privileges.

## Features

- **Comprehensive Data Collection**: Event logs, registry, crash dumps, network config, and more
- **Identity-Based Naming**: ZIP files named with ComputerName, SerialNumber, and timestamp
- **Silent Mode**: For unattended EPM/RMM deployment
- **Automatic Upload**: Uploads to PhoneHomeWeb server file upload endpoint
- **Privacy-Aware**: Excludes SAM/SECURITY registry hives by default

## Collected Data

| Category | Data |
|----------|------|
| System Info | Hardware, OS version, environment, hotfixes, installed software |
| Event Logs | Application, System, Setup, and operational logs (last 30 days) |
| Registry | SYSTEM, SOFTWARE, DEFAULT hives (exports + raw) |
| Windows Logs | CBS, DISM, WindowsUpdate, Panther, MoSetup, SetupAPI, NetSetup |
| Crash Dumps | Minidumps, LiveKernelReports, WER reports |
| Network | ipconfig, route, netstat, firewall, DNS, hosts |
| Processes | Running processes, services, startup items |
| Storage | Disks, partitions, volumes, SMART health, BitLocker status |
| Security | Defender status, local users/groups, GPResult, audit policy, TPM |
| Drivers | Installed drivers, problematic devices |
| Tasks | All scheduled tasks with exports |

## Deployment Methods

### 1. One-Liner (PowerShell as Admin)

```powershell
irm https://your-server:3500/windowscollector-installer | iex
```

### 2. Silent Mode (EPM/RMM)

```powershell
$env:SILENT = "1"; irm https://your-server:3500/windowscollector-installer | iex
```

### 3. With Parameters via Environment

```powershell
$env:SILENT = "1"
$env:INCLUDE_SECURITY_LOGS = "1"
$env:OUTPUT_PATH = "C:\Logs\Collector"
irm https://your-server:3500/windowscollector-installer | iex
```

### 4. Direct Script Execution

```powershell
.\Windows-Collector.ps1 -UploadUrl "https://server:3500/upload" -AuthKey "yourkey" -Silent
```

### 5. Skip Upload (Local Collection Only)

```powershell
.\Windows-Collector.ps1 -SkipUpload -OutputPath "C:\DiagLogs"
```

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-UploadUrl` | Full upload URL | `<<SERVERURL>>/upload` |
| `-AuthKey` | Authentication key | `<<AUTHKEY>>` |
| `-Silent` | No interactive prompts | `$false` |
| `-SkipUpload` | Don't upload, keep local | `$false` |
| `-OutputPath` | Custom output directory | `%TEMP%\WindowsCollector` |
| `-IncludeSecurityLogs` | Include Security event log | `$false` |
| `-MaxEventLogAgeDays` | Max age of events to export | `30` |

## Environment Variables (for Installer)

| Variable | Description |
|----------|-------------|
| `SILENT` or `WINDOWSCOLLECTOR_SILENT` | Set to `1` for silent mode |
| `SKIP_UPLOAD` or `WINDOWSCOLLECTOR_SKIP_UPLOAD` | Set to `1` to skip upload |
| `OUTPUT_PATH` or `WINDOWSCOLLECTOR_OUTPUT_PATH` | Custom output directory |
| `INCLUDE_SECURITY_LOGS` or `WINDOWSCOLLECTOR_INCLUDE_SECURITY_LOGS` | Set to `1` to include Security log |

## Output

The collector creates a ZIP file with the following naming convention:

```
ComputerName_SerialNumber_YYYYMMDD-HHMMSS_WindowsLogs.zip
```

Example: `DESKTOP-ABC123_5CG1234XYZ_20260202-143052_WindowsLogs.zip`

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1+
- Administrator or SYSTEM privileges
- Network connectivity (for upload)

## Security Considerations

1. **No Credentials Collected**: SAM and SECURITY registry hives are excluded
2. **Security Log Optional**: Must explicitly enable with `-IncludeSecurityLogs`
3. **Auth Key Required**: All uploads require valid authentication key
4. **TLS 1.2**: Enforced for all network communications
5. **Temp Cleanup**: Script cleans up after successful upload

## Comparison with WinPE-Collector

| Feature | Windows-Collector | WinPE-Collector |
|---------|-------------------|-----------------|
| Environment | Running Windows | WinPE (Offline) |
| BitLocker | Already unlocked | Requires recovery key |
| Live Data | Processes, services, network | N/A (offline) |
| Event Logs | Export via wevtutil | Copy .evtx files |
| Registry | Export + raw copy | Raw hive copy only |
| GPResult | Yes | N/A |
| Defender Status | Yes | N/A |

## Troubleshooting

### "Access Denied" errors
Run PowerShell as Administrator or deploy via EPM as SYSTEM.

### Upload fails
1. Check network connectivity: `Test-NetConnection your-server -Port 3500`
2. Verify auth key is correct
3. Check server logs for errors

### Large ZIP file
- Security log adds significant size - only enable if needed
- Reduce `MaxEventLogAgeDays` parameter
- Check for large crash dumps in Minidump folder

## License

MIT
