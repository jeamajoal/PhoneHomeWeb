# LinuxCollector payload

This folder contains the Linux-based offline Windows diagnostic collector and USB builder. It provides a complete solution for booting Debian Live, unlocking BitLocker drives, and collecting diagnostic data from offline Windows installations.

As of 2026-02, the LinuxCollector USB build process is **Linux-only** (use the Bash builder).

## Overview

The LinuxCollector is the Linux equivalent of the WinPE Collector:

| Component | WinPE Collector | Linux Collector |
|-----------|-----------------|-----------------|
| Boot Environment | Windows PE | Debian Live |
| Collector Script | `WinPE-Collector.ps1` | `Linux-Collector.sh` |
| BitLocker Unlock | `manage-bde` | `dislocker` |
| Installer Endpoint | `/winpecollector-installer` | `/linuxcollector-installer` |
| USB Builder Endpoint | `/winpe-usb-installer` | `/linux-usb-installer` |

## Contents

- `Linux-Collector.sh`
  - **Main collector script** - runs in Debian Live environment
  - Detects and mounts Windows partitions (including BitLocker)
  - Collects event logs, registry hives, crash dumps, system logs
  - Creates ZIP archive and uploads to server

- `Build-Linux-USB.sh`
  - **Bash script for Linux hosts** (including WSL2, if USB passthrough is configured)
  - Lets you pick a Debian Live ISO from the official directory listing
  - Customizes the live environment with recovery and diagnostic tools
  - Creates a multi-partition USB

- `install-linuxcollector.sh`
  - **One-liner installer** for deploying the collector to a running Debian Live system
  - Downloads and runs the collector automatically

- `install-linux-usb-builder.sh`
  - **USB builder installer** for technician workstations
  - Downloads the USB builder to the local machine

- `upload-file.sh`
  - **Standalone upload helper** - live-pull script for uploading files/directories
  - Downloaded from server with credentials injected at runtime

- `collect-windows-logs.sh`
  - **Standalone collector** - live-pull script for collecting Windows logs
  - Full collection capabilities without needing the complete Linux-Collector.sh

- `config.json`
  - Payload metadata

## Quick Start

### Option 1: Deploy Collector to Running Debian Live

If you already have Debian Live running, deploy the collector with one command:

```bash
curl -fsSL https://<server>:3500/linuxcollector-installer -H 'X-Auth-Key: <key>' | sudo bash
```

### Option 2: Create Bootable USB (Technician Workstation)

On a Linux/WSL2 machine, download and run the USB builder:

```bash
curl -fsSL https://<server>:3500/linux-usb-installer -H 'X-Auth-Key: <key>' | sudo bash
```

Then follow the prompts to create a bootable USB with all tools pre-installed.

## Server Endpoints

| Endpoint | Description |
|----------|-------------|
| `/linux-usb-installer` | Downloads USB builder to technician workstation |
| `/linuxcollector-installer` | One-liner deployment of collector to Debian Live |
| `/linux-upload-script` | Live-pull upload helper script (credentials injected) |
| `/linux-collect-logs` | Live-pull Windows log collector (credentials injected) |
| `/payloads/LinuxCollector/download/<file>` | Download individual files |

## Prerequisites

### For `Build-Linux-USB.sh` (Linux):

- Debian/Ubuntu host (or WSL2 with USB passthrough configured)
- Root privileges (sudo)
- Internet connection (to download ISO and packages)
- USB drive (16GB+ recommended for default 10GB persistence; 8GB minimum without persistence)

Required packages (installed automatically if missing):

- parted
- dosfstools
- xorriso
- squashfs-tools
- rsync
- curl

## Usage

### Build from Linux (Bash)

Run with root privileges:

```bash
# Interactive mode - select ISO + device
sudo ./Build-Linux-USB.sh

# Specify device directly (still prompts for ISO selection)
sudo ./Build-Linux-USB.sh --device /dev/sdb

# Use a pre-downloaded Debian Live ISO
sudo ./Build-Linux-USB.sh --device /dev/sdb --debian-iso ~/Downloads/debian-live.iso

# Build with server credentials embedded in all scripts
sudo ./Build-Linux-USB.sh --device /dev/sdb \
    --server-url https://yourserver:3500 \
    --auth-key your-auth-key

# Download the builder from server and run with credentials auto-injected
curl -fsSL https://yourserver:3500/linux-usb-installer -H 'X-Auth-Key: your-key' | sudo bash

# Build without writing to USB (for testing customization)
sudo ./Build-Linux-USB.sh --skip-write --keep-work
```

#### Bash Command-line Options

| Option | Description |
|--------|-------------|
| `--device PATH` | Target USB device (e.g., `/dev/sdb`). Detected interactively if omitted. |
| `--debian-iso PATH` | Path to Debian Live ISO. Downloaded if not provided. |
| `--iso-url URL` | Direct URL to download a specific Debian Live ISO. |
| `--iso-base-url URL` | Base URL for ISO directory listing (for interactive selection). |
| `--server-url URL` | PhoneHomeWeb server URL (only needed for local copies; injected by server at download). |
| `--auth-key KEY` | Authentication key (only needed for local copies; injected by server at download). |
| `--no-persistence` | Disable persistence partition (persistence is ON by default). |
| `--persist-size SIZE` | Persistence partition size in MB (default: 10240 / 10GB). |
| `--skip-write` | Build customization only; do not write to USB. |
| `--work-dir PATH` | Working directory for build files (default: `/tmp/linux-usb-build`). |
| `--keep-work` | Do not delete working directory after build. |
| `--non-interactive` | Do not prompt; exit if required options are missing. |
| `-h, --help` | Show help message. |

#### Credential Injection

When you download `Build-Linux-USB.sh` from the server via the `/linux-usb-installer` endpoint, the server automatically injects your server URL and auth key into the script. This means all scripts written to the USB will have the correct credentials embedded.

If you run the builder from a local copy (without downloading from server), use `--server-url` and `--auth-key` to embed credentials into the USB scripts.

## USB layout

When built, the USB contains:

- `LINUXDIAG` (FAT32): Debian Live boot files and live filesystem
- `LINUX-TOOLS` (FAT32): helper scripts and quick-reference text
- `persistence` (ext4, default 10GB): save changes across reboots (disable with `--no-persistence`)

On the target system after booting, mount the scripts partition and run the helpers:

```bash
lsblk
sudo mount /dev/sdX2 /mnt/tools   # choose the partition labeled LINUX-TOOLS
ls -la /mnt/tools/scripts
```

Persistence is enabled by default. To use it, ensure you boot with persistence enabled:

- If your boot menu has a persistence entry, choose it.
- Otherwise, edit the boot entry and add the kernel parameter `persistence`.

## Included Tools

The bootable USB includes these recovery and diagnostic tools:

### BitLocker / Encrypted Drives

| Tool | Description |
|------|-------------|
| `dislocker` | Unlock BitLocker-encrypted Windows drives |
| `cryptsetup` | LUKS and other encrypted volume support |

### Partition Management

| Tool | Description |
|------|-------------|
| `parted` | Interactive partition editor |
| `gdisk` / `sgdisk` | GPT partition table management and recovery |
| `fdisk` | MBR partition table management |

### Data Recovery

| Tool | Description |
|------|-------------|
| `testdisk` | Partition recovery and file undelete |
| `ddrescue` | Data recovery from failing/damaged drives |

### Filesystem Tools

| Tool | Description |
|------|-------------|
| `ntfs-3g` | NTFS read/write support for Windows drives |
| `e2fsprogs` | ext2/3/4 filesystem tools (e2fsck, etc.) |
| `xfsprogs` | XFS filesystem tools |
| `btrfs-progs` | Btrfs filesystem tools |
| `dosfstools` | FAT/FAT32 filesystem tools |

### Disk Diagnostics

| Tool | Description |
|------|-------------|
| `smartmontools` | SMART disk health monitoring (smartctl) |
| `hdparm` | Disk parameters and benchmarks |
| `nvme-cli` | NVMe drive management |

### System Information

| Tool | Description |
|------|-------------|
| `lshw` | Hardware lister |
| `dmidecode` | DMI/SMBIOS information |
| `pciutils` | PCI device information (lspci) |
| `usbutils` | USB device information (lsusb) |

### Volume Management

| Tool | Description |
|------|-------------|
| `lvm2` | Logical Volume Manager support |
| `mdadm` | Software RAID (MD) support |

### Digital Forensics

| Tool | Description |
|------|-------------|
| `sleuthkit` | Filesystem forensics (fls, icat, mmls, blkcat) |
| `foremost` | File carving and recovery from raw data |
| `binwalk` | Firmware analysis and extraction |
| `exiftool` | Metadata extraction from files |
| `chntpw` | Windows password reset and registry editor |
| `reglookup` | Windows registry file parser |
| `hivex` | Windows registry hive extraction library |
| `libesedb-utils` | Windows ESE database tools (SRUM, etc.) |

### Utilities

| Tool | Description |
|------|-------------|
| `curl`, `wget` | Network file transfer |
| `rsync` | File synchronization |
| `zip`, `unzip` | Archive tools |
| `tmux` | Terminal multiplexer |
| `htop`, `iotop` | Process and I/O monitoring |

## Quick Reference (After Booting)

### Recommended: Run the Collector

The easiest way to collect diagnostics is to run `Linux-Collector.sh`, which handles everything automatically:

```bash
# From the scripts partition (auto-mounted on desktop, or mount manually)
sudo mount /dev/sdX2 /mnt/tools      # Mount LINUX-TOOLS partition
cd /mnt/tools/scripts

# Run the collector - handles BitLocker unlock, mounting, collection, and upload
sudo ./Linux-Collector.sh
```

The collector will:
1. Scan for Windows partitions (including BitLocker-encrypted)
2. Prompt for BitLocker recovery key if needed
3. Mount the partition read-only
4. Collect all diagnostic data
5. Create a ZIP archive and upload to server

### Helper Scripts on the USB

For manual operations, the USB includes these helper scripts in `/mnt/tools/scripts/`:

| Script | Description |
|--------|-------------|
| `Linux-Collector.sh` | Full diagnostic collection (recommended) |
| `detect-bitlocker.sh` | Scan for BitLocker-encrypted partitions |
| `unlock-bitlocker.sh` | Unlock a BitLocker drive with recovery key |
| `mount-windows.sh` | Mount Windows/NTFS partitions |
| `disk-diagnostics.sh` | SMART health checks and disk info |
| `collect-windows-logs.sh` | Collect logs from already-mounted Windows |
| `upload-file.sh` | Upload any file to the server |
| `system-info.sh` | Show hardware and system information |
| `gpt-backup.sh` | Backup GPT partition tables |
| `recover-data.sh` | File recovery with testdisk/photorec |
| `network-setup.sh` | Configure network (DHCP/static IP) |
| `boot-repair.sh` | Boot repair utilities |

**Example workflow using helper scripts:**

```bash
# 1. Detect BitLocker partitions
sudo ./detect-bitlocker.sh

# 2. Unlock BitLocker (prompts for recovery key)
sudo ./unlock-bitlocker.sh /dev/sda3

# 3. Mount the unlocked partition
sudo ./mount-windows.sh /dev/sda3

# 4. Collect logs and upload
sudo ./collect-windows-logs.sh /mnt/windows
```

---

## Manual Commands Reference

For advanced users or when helper scripts aren't available, here are the underlying commands:

<details>
<summary><strong>Unlock a BitLocker Drive (manual)</strong></summary>

```bash
# Create mount points
mkdir -p /mnt/bitlocker /mnt/windows

# Unlock with recovery password (48-digit key)
dislocker -V /dev/sdX1 -p123456-789012-345678-901234-567890-123456-789012-345678 -- /mnt/bitlocker

# Or unlock with password
dislocker -V /dev/sdX1 -uYourPassword -- /mnt/bitlocker

# Mount the unlocked volume
mount -o loop /mnt/bitlocker/dislocker-file /mnt/windows

# Access files
ls /mnt/windows/
```

</details>

<details>
<summary><strong>Mount Windows NTFS Drive (manual)</strong></summary>

```bash
# Read-write mount
mount -t ntfs-3g /dev/sdX1 /mnt/windows

# Read-only mount (safer)
mount -t ntfs-3g -o ro /dev/sdX1 /mnt/windows
```

</details>

<details>
<summary><strong>Check Disk Health (manual)</strong></summary>

```bash
# View SMART data
smartctl -a /dev/sdX

# Run short self-test
smartctl -t short /dev/sdX

# Check test results
smartctl -l selftest /dev/sdX
```

</details>

<details>
<summary><strong>Recover Lost Partitions (manual)</strong></summary>

```bash
# Interactive partition recovery
testdisk /dev/sdX

# Follow the menu to analyze and recover partitions
```

</details>

<details>
<summary><strong>Repair GPT Partition Table (manual)</strong></summary>

```bash
# Interactive GPT editor
gdisk /dev/sdX

# Commands:
#   p - print partition table
#   v - verify disk
#   r - recovery and transformation options
#   w - write changes
```

</details>

<details>
<summary><strong>Clone a Failing Drive (manual)</strong></summary>

```bash
# Clone with error recovery
ddrescue /dev/sdX /dev/sdY rescue.log

# Resume interrupted clone
ddrescue -r3 /dev/sdX /dev/sdY rescue.log
```

</details>

---

## Comparison with WinPE Builder

| Feature | WinPE Builder | Linux Builder |
|---------|---------------|---------------|
| Build Host OS | Windows 10/11 | Linux |
| Boot Environment | Windows PE | Debian Live |
| BitLocker Unlock | Built-in (manage-bde) | dislocker |
| GPT Tools | diskpart | gdisk, sgdisk |
| Partition Recovery | N/A | testdisk |
| Data Recovery | N/A | ddrescue |
| NTFS Support | Native | ntfs-3g |
| SMART Diagnostics | N/A | smartmontools |

## Linux Collector - Data Collection

The `Linux-Collector.sh` script collects the following diagnostic data from offline Windows installations:

### Collected Data

| Category | Contents |
|----------|----------|
| **Event Logs** | All `.evtx` files from `Windows\System32\winevt\Logs` |
| **Registry Hives** | SYSTEM, SOFTWARE, DEFAULT (SAM/SECURITY excluded for privacy) |
| **Windows Update Logs** | `Windows\Logs\WindowsUpdate` |
| **CBS Logs** | Component-Based Servicing (`Windows\Logs\CBS`) |
| **DISM Logs** | Image servicing (`Windows\Logs\DISM`) |
| **Setup Logs** | Panther (`Windows\Panther`) and MoSetup logs |
| **SetupAPI Logs** | Device installation logs (`Windows\INF\setupapi*.log`) |
| **Startup Repair** | SrtTrail logs when present |
| **NetSetup Logs** | Domain join / network history |
| **WER Reports** | Windows Error Reporting archives (system + user profiles) |
| **Boot Config** | BCD stores, bootstat.dat, ntbtlog.txt |
| **Servicing** | Package listings, WinSxS size, pending.xml, Sessions.xml |
| **Network Config** | hosts, lmhosts, networks, services, WLAN profiles |
| **BitLocker Status** | Encryption state and unlock status |
| **Crash Dumps** | Minidumps, MEMORY.DMP (if < 500MB), LiveKernelReports |
| **Disk Health** | SMART data for all drives |
| **Forensic Artifacts** | MFT sample, Prefetch, USN Journal, SRUM, Amcache, browser history |
| **Environment Info** | Linux host network/storage snapshot |

### Output Format

- **Archive Name**: `Linux-Diag-{ComputerName}-{Serial}-{Timestamp}.zip`
- **Upload Methods**: HTTPS, SCP, or local copy

### Collector Usage

When downloaded via `/linuxcollector-installer`, credentials are automatically injected. These flags are only needed when running from a local copy or to override embedded values:

```bash
# Run with default settings (interactive)
sudo ./Linux-Collector.sh

# Skip upload, save archive locally
sudo ./Linux-Collector.sh --no-upload

# Specify custom server URL
sudo ./Linux-Collector.sh --upload-url https://myserver:3500/upload

# Provide auth key on command line
sudo ./Linux-Collector.sh --auth-key YOUR_KEY_HERE
```

### Collector Workflow

1. **Partition Detection** - Scans for NTFS and BitLocker partitions
2. **BitLocker Unlock** - Prompts for 48-digit recovery key if needed
3. **Mount Partition** - Mounts Windows partition read-only
4. **Collect Data** - Copies logs, registry, crash dumps
5. **Create Archive** - Packages everything into a ZIP file
6. **Upload** - Sends to server or offers alternative methods

## Notes

- The USB is formatted with GPT and FAT32 for maximum UEFI compatibility.
- Persistence is enabled by default (10GB partition). Use `--no-persistence` to disable.
- Without persistence, the live environment runs entirely in RAM; changes are lost on reboot.
- With persistence, installed packages, saved files, and configuration changes survive reboots.
- For legacy BIOS boot, you may need to modify the partition table or use a hybrid ISO.
- Some older systems may require disabling Secure Boot to boot from the USB.

## Troubleshooting

### USB not booting

1. Ensure Secure Boot is disabled in BIOS/UEFI settings.
2. Check that the boot order includes USB devices.
3. Try a different USB port (USB 2.0 ports are more compatible).
4. Verify the USB was created successfully by mounting and checking files.

### dislocker fails to unlock

1. Verify you have the correct recovery key (48-digit, 8 groups of 6 digits).
2. Ensure the partition is actually BitLocker-encrypted (not just NTFS).
3. Check if the drive uses TPM-only protection (may require additional steps).

### Packages not installed

If the live environment doesn't have the expected tools, the squashfs customization may have failed. Run with `--keep-work` and check the logs in the work directory.

## Author

jeamajoal

## License

MIT (see repository root)
