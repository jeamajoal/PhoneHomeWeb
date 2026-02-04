# PhoneHomeWeb

A secure file upload server and diagnostic collection platform for IT support and system recovery scenarios.

**The Problem:** Collecting diagnostic data from end-user machines is tedious. You either walk them through a dozen steps over the phone, remote in to do it yourself, or hope they can follow a written guide. When a machine won't boot, it gets worse—you need bootable media, recovery tools, and a way to get logs off the system.

**The Solution:** PhoneHomeWeb lets technicians run a single command (or boot a USB) that handles everything automatically. No manual steps, no room for error, no "which folder was that again?" The server injects credentials at download time, so the one-liner just works:

**Windows Collector** (running system):
```powershell
irm https://your-server/windowscollector-installer -H @{"X-Auth-Key"="..."} | iex
```

**WinPE USB Builder** (offline/unbootable systems):
```powershell
irm https://your-server/winpe-usb-installer -H @{"X-Auth-Key"="..."} | iex
```

**Linux USB Builder** (forensics/recovery):
```bash
curl -fsSL https://your-server/linux-usb-installer -H "X-Auth-Key: ..." | sudo bash
```

That's it. Diagnostics collected, zipped, and uploaded.
> ⚠️ **Security is your responsibility.** The auth key is a shared secret—anyone who has it can upload files to your server. Treat it accordingly:
> - **Roll your keys after every use** (or at least regularly). Generate a new key, update `.env`, restart the service.
> - **Don't run the server 24/7** if you don't need to. Spin it up when collecting diagnostics, shut it down when you're done.
> - **Always use TLS.** Self-signed certs are fine for testing, but use [Let's Encrypt](https://letsencrypt.org/) (it's free) for anything real.
> - **Limit who has the key.** Share it per-session if possible, not as a permanent credential.
> - **Never share your high-trust key.** It grants access to download uploaded files. If you must share it, roll it immediately after.
> - **Restrict access by IP if possible.** Use firewall rules or reverse proxy ACLs to limit who can reach your server.
> - **Bootable USB drives contain your keys.** The WinPE and Linux USB builders bake credentials into the scripts on the drive. When the drive is not in active use, roll your keys on the server. Rebuild the USB when you need it again.
>
> Security is layers. No single measure is enough.

---

## What's Included

- **Server** (`server.js`) — Node.js/Express server that accepts authenticated file uploads and serves payload scripts with credentials baked in
- **Windows Collector** — Comprehensive diagnostic collection from running Windows systems (event logs, registry, drivers, crash dumps, and more)
- **WinPE USB Builder** — Create bootable Windows PE drives for offline diagnostics and BitLocker recovery
- **Linux USB Builder** — Create bootable Debian Live drives with forensic and recovery tools (dislocker, testdisk, sleuthkit)
- **File Upload Helper** — Generic authenticated upload for any file or script output

---

## Table of Contents

- [Quick Start](#quick-start)
  - [Option A: Clone and Install (Recommended)](#option-a-clone-and-install-recommended)
  - [Option B: One-Liner Installer](#option-b-one-liner-installer)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Authentication Keys](#authentication-keys)
- [TLS/HTTPS Setup](#tlshttps-setup)
  - [Using Your Own Certificates](#using-your-own-certificates)
  - [Self-Signed Certificates (Development/Testing)](#self-signed-certificates-developmenttesting)
- [Payloads](#payloads)
  - [Windows Collector](#windows-collector)
  - [WinPE Collector (Offline USB)](#winpe-collector-offline-usb)
  - [Linux Collector (Live USB)](#linux-collector-live-usb)
  - [File Upload (Generic)](#file-upload-generic)
- [API Endpoints](#api-endpoints)
  - [Standard Endpoints (AUTH_KEY)](#standard-endpoints-auth_key)
  - [High-Trust Endpoints (AUTH_KEY_HIGH_TRUST)](#high-trust-endpoints-auth_key_high_trust)
  - [Installer Endpoints](#installer-endpoints)
- [Security Model](#security-model)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### Option A: Clone and Install (Recommended)

This gives you full control and easy updates via `git pull`.

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/PhoneHomeWeb.git
cd PhoneHomeWeb

# 2. Run the installer (Debian/Ubuntu with systemd)
sudo bash scripts/Install-PhoneHomeWeb.sh
```

**What the installer does:**

- ✅ Installs Node.js LTS if missing (via NodeSource)
- ✅ Runs `npm install` to fetch dependencies
- ✅ Creates `.env` from `.env.example` if missing
- ✅ **Generates secure random AUTH_KEY and AUTH_KEY_HIGH_TRUST** if placeholders like `CHANGE_ME` are detected
- ✅ Creates a dedicated `phonehomeweb` system user/group
- ✅ Sets proper file permissions for uploads and logs
- ✅ Installs and enables a systemd service

After installation, retrieve your generated keys:

```bash
# View your auth keys (keep these secret!)
sudo grep AUTH_KEY /opt/PhoneHomeWeb/.env
```

### Option B: One-Liner Installer

For quick deployment on a fresh Debian/Ubuntu server:

```bash
curl -fsSL https://raw.githubusercontent.com/yourusername/PhoneHomeWeb/main/scripts/Install-PhoneHomeWeb.sh | sudo bash
```

> ⚠️ **Note:** This downloads and executes a script. Review it first if you're security-conscious.

### Manual Installation (Any OS)

```bash
# Clone and enter directory
git clone https://github.com/yourusername/PhoneHomeWeb.git
cd PhoneHomeWeb

# Install dependencies
npm install

# Create configuration
cp .env.example .env

# Edit .env - set at minimum:
#   AUTH_KEY=your-secret-key-here
#   AUTH_KEY_HIGH_TRUST=another-secret-key-here
#   SERVER_URL=https://your-server:3500

# Start the server
npm start
```

---

## Configuration

### Environment Variables

Configuration is managed through a `.env` file in the repository root. The installer creates this automatically, but for manual setups:

```bash
cp .env.example .env
```

**Key settings:**

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3500` | Server listen port |
| `BIND_HOST` | `0.0.0.0` | Bind address |
| `SERVER_URL` | `http://localhost:3500` | Public URL for client scripts |
| `AUTH_KEY` | *(required)* | Standard authentication key |
| `AUTH_KEY_HIGH_TRUST` | *(optional)* | Key for sensitive operations |
| `MAX_UPLOAD_MB` | `500` | Maximum upload size in MB |
| `UPLOADS_DIR` | `uploads` | Where uploaded files are stored |
| `DISABLE_SSL` | `true` | Set to `false` for HTTPS |

### Authentication Keys

PhoneHomeWeb uses two authentication levels:

1. **AUTH_KEY** (Standard) - Required for all requests
   - File uploads
   - Downloading payloads
   - Running collectors

2. **AUTH_KEY_HIGH_TRUST** (Elevated) - Required for sensitive operations
   - Listing uploaded files (`GET /uploads`)
   - Downloading uploaded files (`GET /download`)

**Generating secure keys:**

```bash
# Using OpenSSL (recommended)
openssl rand -hex 32

# Or Python
python3 -c "import secrets; print(secrets.token_hex(32))"
```

> 🔒 The installer automatically generates cryptographically secure keys if you leave the placeholders.

---

## TLS/HTTPS Setup

**Production deployments should always use HTTPS.** The server supports TLS natively.

### Using Your Own Certificates

If you have certificates from a certificate authority (Let's Encrypt, DigiCert, etc.):

1. Place your certificate files in the `certs/` directory (or specify absolute paths)

2. Update `.env`:

```dotenv
DISABLE_SSL=false
SERVER_URL=https://your-domain.com:3500

# Option 1: PEM files (most common)
TLS_KEY_FILE=privkey.pem
TLS_CERT_FILE=fullchain.pem

# Option 2: PFX/PKCS12 bundle
TLS_PFX_FILE=certificate.pfx
TLS_PFX_PASSPHRASE=your-passphrase
```

**Let's Encrypt example:**

```bash
# After running certbot, symlink or copy:
sudo cp /etc/letsencrypt/live/your-domain/privkey.pem certs/
sudo cp /etc/letsencrypt/live/your-domain/fullchain.pem certs/
sudo chown phonehomeweb:phonehomeweb certs/*.pem
sudo chmod 640 certs/*.pem
```

### Self-Signed Certificates (Development/Testing)

For testing or internal networks, generate self-signed certificates:

**On Linux/macOS (OpenSSL):**

```bash
cd certs

# Generate CA
openssl genrsa -out ca-key.pem 2048
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 365 \
  -subj "/CN=PhoneHomeWeb-CA"

# Generate server certificate
openssl genrsa -out server-key.pem 2048
openssl req -new -key server-key.pem -out server-csr.pem \
  -subj "/CN=your-server-hostname"
openssl x509 -req -in server-csr.pem -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem -days 365

cd ..
```

**On Windows (PowerShell):**

```powershell
# Set your hostname first
$env:PHW_TLS_CN = "your-server-hostname"

# Run the included generator
.\certs\generate-certs.ps1
```

Then update `.env`:

```dotenv
DISABLE_SSL=false
TLS_KEY_FILE=server-key.pem
TLS_CERT_FILE=server-cert.pem
```

> ⚠️ **Self-signed certificates require clients to trust the CA** or bypass verification. For production, use a real certificate authority.

---

## Payloads

PhoneHomeWeb includes ready-to-use diagnostic collection tools for various scenarios.

### Windows Collector

**Purpose:** Collect comprehensive diagnostics from a **running Windows system**.

**Use cases:**
- Remote troubleshooting via RMM/EPM tools
- Silent background collection during support calls
- Automated health checks

**What it collects:**
- Event logs (evtx files)
- Registry hives (SYSTEM, SOFTWARE)
- Windows Update/CBS/DISM logs
- Crash dumps and WER reports
- Network configuration
- Installed software and drivers
- Running processes and services
- Security configuration (Defender, GPO, TPM)

**Deployment (one-liner for RMM/EPM):**

```powershell
# Run as Administrator
Invoke-RestMethod -Uri "https://your-server:3500/windowscollector-installer" `
  -Headers @{"X-Auth-Key"="your-auth-key"} | Invoke-Expression
```

**Interactive use:**

```powershell
# Download with credentials injected
$headers = @{ "X-Auth-Key" = "your-auth-key" }
Invoke-RestMethod -Uri "https://your-server:3500/payloads/WindowsCollector/download/Windows-Collector.ps1" `
  -Headers $headers -OutFile Windows-Collector.ps1

# Run (uploads automatically)
.\Windows-Collector.ps1

# Or collect without uploading
.\Windows-Collector.ps1 -SkipUpload
```

See [payloads/WindowsCollector/README.md](payloads/WindowsCollector/README.md) for full documentation.

---

### WinPE Collector (Offline USB)

**Purpose:** Boot into Windows PE to collect diagnostics from systems that **won't boot** or need **offline analysis**.

**Use cases:**
- Blue screen / boot failure diagnosis
- BitLocker-encrypted drive recovery
- Offline registry and event log extraction
- Pre-OS diagnostics

**Features:**
- Automatic BitLocker detection and unlock (via recovery key)
- Collects from offline Windows installations
- Works on UEFI and Legacy BIOS systems
- Customizable via JSON configuration

**Build a WinPE USB:**

```powershell
# On a Windows machine with Windows ADK installed
Invoke-RestMethod -Uri "https://your-server:3500/winpe-usb-installer" `
  -Headers @{"X-Auth-Key"="your-auth-key"} | Invoke-Expression
```

See [payloads/WinPECollector/README.md](payloads/WinPECollector/README.md) for full documentation.

---

### Linux Collector (Live USB)

**Purpose:** Boot into Debian Live Linux for system recovery and forensic analysis.

> ⚠️ **Build requirements:**
> - Must be built on a **Linux system** (WSL works, but requires USB passthrough via `usbipd-win` to attach and bind the USB device)
> - Uses **Debian Live** ISO — select "Debian" when choosing the ISO
> - Only tested with the **Cinnamon** desktop variant

**Use cases:**
- Unlock BitLocker drives from Linux (dislocker)
- Partition recovery (testdisk, gdisk)
- File system repair
- Digital forensics (sleuthkit, foremost, binwalk)
- Password reset (chntpw)

**Included tools:**
- `dislocker` - BitLocker volume access
- `testdisk` / `photorec` - Partition and file recovery
- `sleuthkit` - Forensic analysis
- `chntpw` - Windows password reset
- `ntfs-3g` - NTFS read/write support
- Network tools for uploading collected data

**Build a Linux USB:**

```bash
# On a Linux machine (or WSL with USB passthrough)
curl -fsSL "https://your-server:3500/linux-usb-installer" \
  -H "X-Auth-Key: your-auth-key" | sudo bash
```

<details>
<summary><strong>WSL USB Passthrough (usbipd-win)</strong></summary>

If building from WSL, you need to pass the USB drive through to the Linux environment:

1. **Install usbipd-win** (on Windows, run as Administrator):
   ```powershell
   winget install usbipd
   ```

2. **List USB devices** (PowerShell as Administrator):
   ```powershell
   usbipd list
   ```
   Find your USB drive (e.g., `BUSID 2-3`).

3. **Bind and attach the device**:
   ```powershell
   usbipd bind --busid 2-3
   usbipd attach --wsl --busid 2-3
   ```

4. **Verify in WSL**:
   ```bash
   lsblk
   ```
   Your USB drive should appear (e.g., `/dev/sdb`).

5. **After building**, detach the device:
   ```powershell
   usbipd detach --busid 2-3
   ```

</details>

See [payloads/LinuxCollector/README.md](payloads/LinuxCollector/README.md) for full documentation.

---

### File Upload (Generic)

**Purpose:** Simple authenticated file upload for any scenario.

**Use cases:**
- Upload arbitrary files from scripts
- Integration with other tools
- Manual file transfer

```powershell
# PowerShell
.\payloads\fileupload\FileUpload.ps1 `
  -ServerUrl "https://your-server:3500" `
  -FilePath "C:\logs\diagnostic.zip" `
  -AuthKey "your-auth-key"
```

```bash
# Bash/curl
curl -X POST "https://your-server:3500/upload" \
  -H "X-Auth-Key: your-auth-key" \
  -F "file=@/path/to/file.zip"
```

---

## API Endpoints

### Standard Endpoints (AUTH_KEY)

These endpoints require the `X-Auth-Key` header with your standard auth key.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/upload` | POST | Upload a file (multipart/form-data) |
| `/payloads` | GET | List available payloads |
| `/payloads/:folder/download/:file` | GET | Download a payload file (with credential injection) |
| `/api/health` | GET | Health check (no auth required) |

### High-Trust Endpoints (AUTH_KEY_HIGH_TRUST)

These endpoints require the `X-Auth-Key` header with your **high-trust** key.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/uploads` | GET | List all uploaded files |
| `/download` | GET | Download an uploaded file (requires `X-Filename` header) |

**Example: List uploaded files**

```bash
curl -s "https://your-server:3500/uploads" \
  -H "X-Auth-Key: your-high-trust-key" | jq
```

**Example: Download an uploaded file**

```bash
curl -s "https://your-server:3500/download" \
  -H "X-Auth-Key: your-high-trust-key" \
  -H "X-Filename: COMPUTER_Serial_20240101-120000_WindowsLogs.zip" \
  -o downloaded.zip
```

### Installer Endpoints

These endpoints serve installer scripts with credentials automatically injected.

| Endpoint | Description |
|----------|-------------|
| `/windowscollector-installer` | Windows Collector one-liner installer |
| `/winpe-usb-installer` | WinPE USB builder installer |
| `/winpecollector-installer` | WinPE Collector installer |
| `/linux-usb-installer` | Linux USB builder installer |
| `/linuxcollector-installer` | Linux Collector installer |
| `/fileupload` | Generic file upload script |

All installer endpoints require the `X-Auth-Key` header. The server replaces `<<SERVERURL>>` and `<<AUTHKEY>>` placeholders in the scripts with actual values.

---

## Security Model

PhoneHomeWeb implements defense-in-depth:

1. **Authentication Required** - All requests must include `X-Auth-Key` header
2. **Two-Tier Keys** - Sensitive operations require a separate high-trust key
3. **Request Logging** - All requests logged to JSONL files (success and blocked)
4. **Path Sanitization** - Upload filenames sanitized to prevent path traversal
5. **No Directory Listing** - Uploads directory is not browsable
6. **TLS Support** - Native HTTPS for encrypted transport
7. **systemd Hardening** - Service runs as dedicated user with restricted privileges
8. **Protected Configuration** - `.env` file is chmod 640, readable only by service user/group

**What gets logged:**

```jsonl
{"timestamp":"2024-01-01T12:00:00.000Z","method":"POST","url":"/upload","ip":"192.168.1.100","filename":"diagnostics.zip","size":1048576}
```

Blocked requests are logged separately with reason codes.

---

## Troubleshooting

**Server won't start - "Missing required env var AUTH_KEY"**

You must set `AUTH_KEY` in `.env`:
```bash
sudo nano /opt/PhoneHomeWeb/.env  # Add AUTH_KEY=your-key
sudo systemctl restart phonehomeweb
```

**Can't edit .env file - "Permission denied"**

After installation, `.env` is protected (chmod 640). Use `sudo` to edit:
```bash
sudo nano /opt/PhoneHomeWeb/.env
sudo systemctl restart phonehomeweb
```

**Upload fails with 413 "Payload Too Large"**

Increase `MAX_UPLOAD_MB` in `.env` (default is 500 MB):
```bash
sudo sed -i 's/MAX_UPLOAD_MB=.*/MAX_UPLOAD_MB=1000/' /opt/PhoneHomeWeb/.env
sudo systemctl restart phonehomeweb
```

**Windows Collector shows "Upload URL not configured"**

The script wasn't downloaded through the credential-injecting endpoint. Use:
```powershell
Invoke-RestMethod -Uri "https://server/windowscollector-installer" -Headers @{"X-Auth-Key"="..."} | iex
```

**Certificate errors with self-signed certs**

Either:
- Add the CA certificate to trusted roots on clients, or
- Use `-SkipCertificateCheck` in PowerShell (testing only), or
- Use a real certificate from a trusted CA (recommended)

**"High-trust authentication key required"**

You're trying to access `/uploads` or `/download` with the standard key. Use `AUTH_KEY_HIGH_TRUST` instead.

---

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please open an issue or pull request.
