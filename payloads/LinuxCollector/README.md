# LinuxCollector payload

This folder contains the Linux USB Builder script, a companion to the Windows WinPE builder that creates a bootable Debian Live USB with recovery and diagnostic tools.

## Contents

- `Build-Linux-USB.sh`
  - Runs on a Debian/Ubuntu Linux host (or WSL2 with USB passthrough).
  - Downloads a Debian Live ISO (or uses a provided one).
  - Customizes the live environment with recovery tools.
  - Creates a bootable USB drive.

- `config.json`
  - Payload metadata.

## Prerequisites

For `Build-Linux-USB.sh`:

- Debian or Ubuntu host (or WSL2 with USB passthrough configured)
- Root privileges (sudo)
- Internet connection (to download ISO and packages)
- USB drive (8GB+ recommended)

Required packages (installed automatically if missing):

- parted
- dosfstools
- xorriso
- squashfs-tools
- rsync
- curl

## Usage

### Build a Linux Diagnostic USB

Run with root privileges:

```bash
# Interactive mode - lists USB devices and prompts for selection
sudo ./Build-Linux-USB.sh

# Specify device directly
sudo ./Build-Linux-USB.sh --device /dev/sdb

# Use a pre-downloaded Debian Live ISO
sudo ./Build-Linux-USB.sh --device /dev/sdb --debian-iso ~/Downloads/debian-live.iso

# Build without writing to USB (for testing customization)
sudo ./Build-Linux-USB.sh --skip-write --keep-work
```

### Command-line Options

| Option | Description |
|--------|-------------|
| `--device PATH` | Target USB device (e.g., `/dev/sdb`). Detected interactively if omitted. |
| `--debian-iso PATH` | Path to Debian Live ISO. Downloaded if not provided. |
| `--iso-url URL` | URL to download Debian Live ISO. |
| `--skip-write` | Build customization only; do not write to USB. |
| `--work-dir PATH` | Working directory for build files (default: `/tmp/linux-usb-build`). |
| `--keep-work` | Do not delete working directory after build. |
| `--non-interactive` | Do not prompt; exit if required options are missing. |
| `-h, --help` | Show help message. |

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

### Utilities

| Tool | Description |
|------|-------------|
| `curl`, `wget` | Network file transfer |
| `rsync` | File synchronization |
| `zip`, `unzip` | Archive tools |
| `tmux` | Terminal multiplexer |
| `htop`, `iotop` | Process and I/O monitoring |

## Quick Reference (After Booting)

### Unlock a BitLocker Drive

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

### Recover Lost Partitions

```bash
# Interactive partition recovery
testdisk /dev/sdX

# Follow the menu to analyze and recover partitions
```

### Repair GPT Partition Table

```bash
# Interactive GPT editor
gdisk /dev/sdX

# Commands:
#   p - print partition table
#   v - verify disk
#   r - recovery and transformation options
#   w - write changes
```

### Check Disk Health

```bash
# View SMART data
smartctl -a /dev/sdX

# Run short self-test
smartctl -t short /dev/sdX

# Check test results
smartctl -l selftest /dev/sdX
```

### Mount Windows NTFS Drive

```bash
# Read-write mount
mount -t ntfs-3g /dev/sdX1 /mnt/windows

# Read-only mount (safer)
mount -t ntfs-3g -o ro /dev/sdX1 /mnt/windows
```

### Clone a Failing Drive

```bash
# Clone with error recovery
ddrescue /dev/sdX /dev/sdY rescue.log

# Resume interrupted clone
ddrescue -r3 /dev/sdX /dev/sdY rescue.log
```

## Comparison with WinPE Builder

| Feature | WinPE Builder | Linux Builder |
|---------|---------------|---------------|
| Host OS | Windows 10/11 | Debian/Ubuntu/WSL2 |
| Boot Environment | Windows PE | Debian Live |
| BitLocker Unlock | Built-in (manage-bde) | dislocker |
| GPT Tools | diskpart | gdisk, sgdisk |
| Partition Recovery | N/A | testdisk |
| Data Recovery | N/A | ddrescue |
| NTFS Support | Native | ntfs-3g |
| SMART Diagnostics | N/A | smartmontools |

## Notes

- The USB is formatted with GPT and FAT32 for maximum UEFI compatibility.
- The live environment runs entirely in RAM; no changes are written to the USB during use.
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
