# File List Collector

A PowerShell script that collects file system listings in two formats for quick review and diagnostics.

## Features

- **Get-ChildItem Format**: Detailed file listing with Mode, LastWriteTime, Length, and FullName
- **dir /s /b Format**: Bare recursive directory listing (compatible with legacy systems)
- Computer name and timestamp in output filenames
- Optional upload to PhoneHomeWeb server
- Configurable root path and output directory
- Error handling and colored console output

## Quick Start

### Basic Usage (No Upload)

Collect file listings from C:\ and save to current directory:

```powershell
.\FileListCollector.ps1
```

### Scan Specific Directory

```powershell
.\FileListCollector.ps1 -RootPath "C:\Users" -OutputPath "C:\Temp"
```

### With Upload to Server

```powershell
.\FileListCollector.ps1 -RootPath "C:\Windows\System32" -ServerUrl "http://your-server:3500" -AuthKey "your-auth-key" -UploadResults
```

### Non-Recursive Scan

```powershell
.\FileListCollector.ps1 -RootPath "C:\Program Files" -IncludeSubdirectories:$false
```

## Parameters

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `ServerUrl` | PhoneHomeWeb server base URL | `<<SERVERURL>>` | No |
| `AuthKey` | Authentication key for uploads | `<<AUTHKEY>>` | No |
| `RootPath` | Root directory to scan | `C:\` | No |
| `OutputPath` | Directory for output files | `.` (current) | No |
| `UploadResults` | Upload results to server | `$false` | No |
| `IncludeSubdirectories` | Recursive scan | `$true` | No |

## Output Files

The script generates two text files per run:

1. **`COMPUTERNAME_FileList_GCI_TIMESTAMP.txt`**
   - Format: Get-ChildItem with LastWriteTime
   - Shows: Mode, LastWriteTime, Length, FullName
   - Best for: Detailed file analysis with timestamps

2. **`COMPUTERNAME_FileList_DIR_TIMESTAMP.txt`**
   - Format: dir /s /b (bare listing)
   - Shows: Full file paths only
   - Best for: Quick path reference and scripting

## Use Cases

### System Diagnostics

Quickly review what files exist on a system and when they were last modified:

```powershell
.\FileListCollector.ps1 -RootPath "C:\Windows\System32\drivers"
```

### User Data Collection

Collect file listings from user directories for inventory:

```powershell
.\FileListCollector.ps1 -RootPath "C:\Users" -UploadResults -ServerUrl "http://server:3500" -AuthKey "key123"
```

### Pre/Post Installation Comparison

Capture file state before and after software installation:

```powershell
# Before installation
.\FileListCollector.ps1 -RootPath "C:\Program Files" -OutputPath "C:\Logs\Before"

# After installation
.\FileListCollector.ps1 -RootPath "C:\Program Files" -OutputPath "C:\Logs\After"
```

## Configuration

Default settings can be customized in `config.json`:

```json
{
  "defaultSettings": {
    "serverUrl": "http://localhost:3500",
    "rootPath": "C:\\",
    "outputPath": ".",
    "uploadResults": false,
    "includeSubdirectories": true
  }
}
```

## Integration with PhoneHomeWeb

When using with the PhoneHomeWeb server:

1. Ensure the server is running on the specified URL
2. Set the authentication key (`X-Auth-Key` header)
3. Use `-UploadResults` switch to automatically upload files
4. Files are uploaded to the `/upload` endpoint

Example:

```powershell
.\FileListCollector.ps1 `
    -RootPath "C:\Important\Data" `
    -ServerUrl "https://diagnostics.company.com:3500" `
    -AuthKey "secure-key-here" `
    -UploadResults
```

## Error Handling

- Inaccessible files/directories are silently skipped
- Upload failures are reported but don't stop the script
- Exit code 0 on success, 1 on failure

## Performance Notes

- Large directories (entire C:\) may take several minutes
- Output file size depends on number of files scanned
- Consider using `-IncludeSubdirectories:$false` for faster scans of large trees

## Requirements

- PowerShell 5.1 or later
- Windows operating system
- Network connectivity (only if using `-UploadResults`)
- Read permissions on target directories

## Examples

### Minimal Example

```powershell
.\FileListCollector.ps1 -RootPath "C:\Temp"
```

### Full Example with All Options

```powershell
.\FileListCollector.ps1 `
    -ServerUrl "http://192.168.1.100:3500" `
    -AuthKey "my-secret-key" `
    -RootPath "C:\Users\JohnDoe\Documents" `
    -OutputPath "C:\Diagnostics\Output" `
    -UploadResults `
    -IncludeSubdirectories
```

## Troubleshooting

### "Access Denied" Errors

Run PowerShell as Administrator to access protected directories.

### Large Output Files

Use `-IncludeSubdirectories:$false` or scan smaller directory trees.

### Upload Failures

- Verify server URL is accessible
- Check authentication key is correct
- Ensure server is running and accepting connections

## License

MIT License - See repository root for details.
