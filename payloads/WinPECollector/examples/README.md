# WinPE-Collector Custom Configuration Examples

This directory contains working example JSON configuration files for the WinPE Collector.

## Usage

1. Choose the example that matches your needs
2. Copy it to the parent directory as `WinPE-Collector.custom.json`
3. Edit the paths to match your requirements

## Examples

### example1-org-folder-only.json
**Most common scenario** - Collect only a single organization/vendor folder from ProgramData.

```json
{
  "orgProgramDataFolder": "My App"
}
```

### example2-extrafolders-only.json
Collect specific custom folders (not from ProgramData).

```json
{
  "extraFolders": [
    {
      "name": "CustomLogs",
      "path": "Users\\Public\\Documents\\MyLogs"
    }
  ]
}
```

### example3-org-and-extrafolders.json
Collect both an org folder AND custom folders.

```json
{
  "orgProgramDataFolder": "My App",
  "extraFolders": [
    {
      "name": "CustomLogs",
      "path": "Users\\Public\\Documents\\MyLogs"
    }
  ]
}
```

### example4-extrafolderpaths.json
Alternative simpler syntax for just path lists (name derived from folder name).

```json
{
  "extraFolderPaths": [
    "Users\\Public\\Documents\\MyLogs",
    "ProgramData\\VendorTool\\Logs"
  ]
}
```

### example5-empty-config.json
Minimal config that collects nothing extra (explicitly disables extra collection).

```json
{}
```

## Important Notes

- **All fields are optional** - only include what you need
- **Paths must be relative** to the Windows drive root (no drive letters like `C:`)
- **Use double backslashes** (`\\`) in all paths for proper JSON formatting
- **All paths are relative** to the offline Windows installation root
- The **"name" field is optional** in extraFolders - defaults to folder name if omitted
- You can **mix and match** orgProgramDataFolder with extraFolders or extraFolderPaths

## Testing Your Config

To test if your JSON is valid:

```powershell
Get-Content -Path "WinPE-Collector.custom.json" -Raw | ConvertFrom-Json
```

If it returns an error, your JSON has a syntax error.
