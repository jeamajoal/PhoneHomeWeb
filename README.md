# PhoneHomeWeb

Minimal file upload server (Node.js/Express) plus PowerShell payloads for collecting diagnostics (WinPE) and uploading ZIPs/files to a central endpoint.

## What this repo contains

- **Server**: `server.js` (Express + multer) listens on port `3500` by default.
- **Payloads**:
  - `payloads/WinPECollector/` – WinPE offline diagnostic collector (BitLocker-aware) + WinPE USB builder.
  - `payloads/fileupload/` – generic PowerShell file uploader.
- **Install scripts**: `scripts/` includes a Debian/systemd installer.

## Quick start (local)

1) Install dependencies:

```bash
npm install
```

2) Create your local config file:

```bash
copy .env.example .env
```

3) Edit `.env` and set at minimum:

- `AUTH_KEY` (required)
- `AUTH_KEY_HIGH_TRUST` (recommended)

4) Run the server:

```bash
npm start
```

Server default URL:

- `http://localhost:3500/`

## HTTPS/TLS

TLS is supported via environment variables.

- Set `DISABLE_SSL=false`
- Provide either `TLS_PFX_FILE` (a `.pfx/.p12` bundle) or `TLS_KEY_FILE` and `TLS_CERT_FILE` (PEM)
- Optionally set `TLS_CA_FILE`

By default, cert files are expected under `CERTS_DIR` (default: `certs/`).

**Important:** never commit private keys. This repo’s `.gitignore` excludes `.env` and common cert key formats.

## Authentication

Requests are authenticated via the header:

- `X-Auth-Key: <AUTH_KEY>`

The server refuses to start if `AUTH_KEY` is not set.

## Payloads

### WinPE Collector

See `payloads/WinPECollector/README.md` for:

- building a WinPE USB
- running the collector
- optional customization via a drop-in JSON file

### File Upload payload

Multiple upload methods are available in `payloads/fileupload/`:

#### HTTPS Upload (PowerShell) - Recommended

`FileUpload.ps1` uploads a file directly to the server using HTTPS:

```powershell
.\payloads\fileupload\FileUpload.ps1 -ServerUrl "http://localhost:3500" -FilePath "C:\temp\example.zip" -AuthKey "<your key>"
```

#### HTTPS Upload (curl/Bash) - Linux/macOS/WSL

`FileUpload-Curl.sh` provides cross-platform upload via curl:

```bash
./payloads/fileupload/FileUpload-Curl.sh -s "http://localhost:3500" -f "/path/to/file.zip" -k "<your key>"
```

#### FTP Upload

`FileUpload-FTP.ps1` uploads to an FTP server:

```powershell
.\payloads\fileupload\FileUpload-FTP.ps1 -FtpServer "ftp.example.com" -FtpUsername "user" -FtpPassword "pass" -FilePath "C:\temp\example.zip"
```

#### SFTP Upload

`FileUpload-SFTP.ps1` uploads via SFTP (uses OpenSSH, built into Windows 10+):

```powershell
.\payloads\fileupload\FileUpload-SFTP.ps1 -SftpServer "sftp.example.com" -SftpUsername "user" -SftpKeyFile "~/.ssh/id_rsa" -FilePath "C:\temp\example.zip"
```

#### Tech-Assisted Upload (Interactive)

`FileUpload-TechAssist.ps1` provides a guided, interactive upload experience for tech support scenarios:

```powershell
.\payloads\fileupload\FileUpload-TechAssist.ps1
```

Features:
- GUI file picker
- Step-by-step instructions
- Multiple transfer options (HTTPS, network share, manual instructions)
- Designed for technician-assisted remote support

## Deployment (Debian)

Use:

- `scripts/Install-PhoneHomeWeb.sh`

It installs Node.js, writes a `.env`, and sets up a systemd service.

## Repo hygiene

Before publishing or sharing a zip of this repo folder:

- Ensure `.env` contains no sensitive values you don’t want shared
- Remove any local TLS keys/certs you placed under `certs/`
- Confirm `uploads/` and logs are not present

## License

MIT (see individual payload `config.json` files where applicable).
