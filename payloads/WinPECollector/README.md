# WinPECollector payload

This folder contains the WinPE Offline Diagnostic Collector payload and the scripts used to build a bootable WinPE USB.

## Contents

- `install-winpe-usb-builder.ps1`
  - Installer to download the USB builder script to a workstation.

- `Build-WinPE-USB.ps1`
  - Runs on a technician/admin Windows machine with the Windows ADK + WinPE add-on installed.
  - Creates a bootable USB that auto-launches the collector on boot.

- `WinPE-Collector.ps1`
  - Runs in WinPE.
  - Detects Windows installations, detects BitLocker lock state, prompts for a recovery key when needed, collects offline diagnostics, and uploads a ZIP to the server.
  - In WinPE, it may temporarily assign drive letters to fixed partitions (session-only) so locked OS volumes can be detected.

- `install-winpecollector.ps1`
  - One-liner style installer to download/run `WinPE-Collector.ps1` in WinPE.

- `config.json`
  - Payload metadata.

## Prerequisites

For `Build-WinPE-USB.ps1`:

- Windows ADK installed (Deployment Tools)
- Windows PE add-on for ADK installed
- Admin rights
- USB drive (8GB+ recommended)

## Usage

### Build a WinPE USB

Run in an elevated PowerShell prompt:

- `./Build-WinPE-USB.ps1` (interactive disk selection)
- `./Build-WinPE-USB.ps1 -USBDiskNumber 2` (explicit disk number)

Skip the installer step:

- If you already have this repo locally, you can run `Build-WinPE-USB.ps1` directly and skip `install-winpe-usb-builder.ps1`.

Build without a server (offline build):

- Embed the collector script from disk so no server is required during the USB build:
  - `./Build-WinPE-USB.ps1 -USBDiskNumber 2 -CollectorScriptPath .\WinPE-Collector.ps1`
- If you boot the USB without upload connectivity, the collector still creates the ZIP and will print the local save path when upload fails.
  - It prefers saving to a volume labeled `WINPE_DIAG`, otherwise it will try to pick the best writable removable/USB volume automatically; if none are writable it falls back to `X:\WinPECollector`.

### Run the collector in WinPE

USBs built with `Build-WinPE-USB.ps1` auto-start the collector by default.

Manual run:

- `X:\WinPECollector\WinPE-Collector.ps1`

## Notes

- Drive letters assigned by the collector in WinPE are intended to be temporary for the WinPE session. The script does not write offline Windows `MountedDevices` mappings.
- Upload authentication uses an `X-Auth-Key` header; the server URL and auth key are injected at build/deploy time.
- The collector writes a session log (`WinPE-Collector-Session-*.log`) to the working directory. On-screen output is kept intentionally brief; troubleshooting details go to the log.
- By default, registry hive collection is limited to `SYSTEM`, `SOFTWARE`, and `DEFAULT`. The collector intentionally does not copy `SAM` or `SECURITY`.
- If collection fails partway, the collector still tries to ZIP and upload whatever it collected (plus the session/error logs) when networking is available.

## Optional: collect additional folders

Because WinPE is hard to iterate on, the collector supports adding extra folders without rebuilding WinPE.

### Option A (recommended): drop-in config file

Create `WinPE-Collector.custom.json` next to `WinPE-Collector.ps1` (for example `X:\WinPECollector\WinPE-Collector.custom.json`).

Tip: start from the example file in this repo:

- `WinPE-Collector.custom.json.example` (copy/rename to `WinPE-Collector.custom.json`)

Example:

```json
{
  "orgProgramDataFolder": "My App",
  "extraFolders": [
    { "name": "CustomLogs", "path": "Users\\Public\\Documents\\MyLogs" },
    { "name": "VendorTool", "path": "ProgramData\\VendorTool" }
  ]
}
```

- `path` must be **relative to the offline Windows drive root** (no drive letters, no `..`).
- These folders are copied into `ExtraFolders\<name>` inside the collected ZIP.

### Option B: environment variable

Set `EXTRA_OFFLINE_FOLDERS` as a semicolon-separated list of relative paths, optionally `Label=RelativePath`:

- `EXTRA_OFFLINE_FOLDERS=ProgramData\My App;CustomLogs=Users\Public\Documents\MyLogs`

Backward-compatible shortcut:

- `ORG_PROGRAMDATA_FOLDER` (e.g. `My App`) is treated as `ProgramData\My App`.
