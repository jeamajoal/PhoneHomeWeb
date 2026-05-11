#!/usr/bin/env bash
# =============================================================================
# Build-Headless-Debian.sh
#
# Builds an UNATTENDED Debian netinst ISO that installs a minimal headless
# Debian system with openssh-server preconfigured. SSH access is granted by
# injecting an authorized_keys public key (default) and/or a password.
#
# Usage:
#   sudo ./Build-Headless-Debian.sh --ssh-key ~/.ssh/id_ed25519.pub [options]
#
# Required:
#   --ssh-key PATH      Path to an SSH public key (id_*.pub) to authorize.
#                       Required unless --allow-password is given.
#
# Common options:
#   --output PATH       Output ISO path (default: ./headless-debian-<date>.iso)
#   --device PATH       Write the ISO to this USB block device (e.g. /dev/sdb).
#                       OMIT to only produce an ISO file.
#   --skip-write        Force ISO-only mode even if --device is set.
#   --hostname NAME     Hostname (default: phw-debian)
#   --username NAME     Sudo user to create (default: phw)
#   --password PASS     User password. Implies --allow-password.
#   --allow-password    Allow password SSH login (default: keys only).
#   --root-password P   Set a root password (default: locked).
#   --timezone TZ       e.g. America/Denver (default: Etc/UTC)
#   --locale LOCALE     e.g. en_US.UTF-8 (default: en_US.UTF-8)
#   --keymap KEY        e.g. us (default: us)
#   --mirror HOST       Debian mirror host (default: deb.debian.org)
#   --extra-packages P  Space-separated extra packages to install.
#   --netinst-iso PATH  Use this netinst ISO instead of downloading.
#   --netinst-url URL   Download netinst ISO from this URL.
#   --work-dir PATH     Working dir (default: /var/tmp/headless-debian-build)
#   --keep-work         Don't delete the work dir.
#   --server-url URL    PhoneHomeWeb server URL (embedded for collector pull).
#   --auth-key KEY      PhoneHomeWeb auth key.
#   --no-collector      Don't embed PhoneHomeWeb collector pull in late_command.
#   --non-interactive   No prompts; fail if required input is missing.
#   -h, --help          Show this help.
#
# Requirements:
#   - Linux host with: xorriso, cpio, gzip, curl, isolinux (for isohdpfx.bin),
#     dosfstools (for EFI image), sed, grep
#   - Root privileges for ISO repack and (optional) USB write
#
# Author: jeamajoal
# =============================================================================

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# -----------------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------------

OUTPUT_ISO=""
DEVICE=""
SKIP_WRITE=0
HOSTNAME_VAL="phw-debian"
USERNAME_VAL="phw"
PASSWORD_VAL=""
ALLOW_PASSWORD=0
ROOT_PASSWORD=""
TIMEZONE="Etc/UTC"
LOCALE_VAL="en_US.UTF-8"
KEYMAP="us"
MIRROR="deb.debian.org"
EXTRA_PACKAGES=""
NETINST_ISO=""
NETINST_URL=""
WORK_DIR="/var/tmp/headless-debian-build"
KEEP_WORK=0
SSH_KEY_PATH=""
NON_INTERACTIVE=0
NO_COLLECTOR=0

# Server creds (placeholders replaced when downloaded from PhoneHomeWeb)
PHW_SERVER_URL="${PHW_SERVER_URL:-<<SERVERURL>>}"
PHW_AUTH_KEY="${PHW_AUTH_KEY:-<<AUTHKEY>>}"

# Default netinst URL — points at the "current" Debian stable amd64 netinst.
# This file is updated by Debian's mirrors with each point release.
DEFAULT_NETINST_URL="https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; GRAY='\033[0;90m'; NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $*" >&2; }
log_ok()      { echo -e "${GREEN}[OK]${NC} $*" >&2; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_detail()  { echo -e "  ${GRAY}$*${NC}" >&2; }
die()         { log_error "$*"; exit 1; }

usage() { sed -n '2,/^# ===/p' "$0" | sed 's/^# \{0,1\}//'; }

# -----------------------------------------------------------------------------
# Arg parsing
# -----------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)          OUTPUT_ISO="$2"; shift 2;;
        --device)          DEVICE="$2"; shift 2;;
        --skip-write)      SKIP_WRITE=1; shift;;
        --hostname)        HOSTNAME_VAL="$2"; shift 2;;
        --username)        USERNAME_VAL="$2"; shift 2;;
        --password)        PASSWORD_VAL="$2"; ALLOW_PASSWORD=1; shift 2;;
        --allow-password)  ALLOW_PASSWORD=1; shift;;
        --root-password)   ROOT_PASSWORD="$2"; shift 2;;
        --timezone)        TIMEZONE="$2"; shift 2;;
        --locale)          LOCALE_VAL="$2"; shift 2;;
        --keymap)          KEYMAP="$2"; shift 2;;
        --mirror)          MIRROR="$2"; shift 2;;
        --extra-packages)  EXTRA_PACKAGES="$2"; shift 2;;
        --netinst-iso)     NETINST_ISO="$2"; shift 2;;
        --netinst-url)     NETINST_URL="$2"; shift 2;;
        --work-dir)        WORK_DIR="$2"; shift 2;;
        --keep-work)       KEEP_WORK=1; shift;;
        --ssh-key)         SSH_KEY_PATH="$2"; shift 2;;
        --server-url)      PHW_SERVER_URL="$2"; shift 2;;
        --auth-key)        PHW_AUTH_KEY="$2"; shift 2;;
        --no-collector)    NO_COLLECTOR=1; shift;;
        --non-interactive) NON_INTERACTIVE=1; shift;;
        -h|--help)         usage; exit 0;;
        *) die "Unknown option: $1 (use --help)";;
    esac
done

# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root (sudo)."

if [[ -z "$SSH_KEY_PATH" && "$ALLOW_PASSWORD" -ne 1 ]]; then
    die "No SSH access configured. Provide --ssh-key PATH and/or --allow-password."
fi

SSH_KEY_CONTENT=""
if [[ -n "$SSH_KEY_PATH" ]]; then
    [[ -f "$SSH_KEY_PATH" ]] || die "SSH key file not found: $SSH_KEY_PATH"
    SSH_KEY_CONTENT="$(set +o pipefail; tr -d '\r' < "$SSH_KEY_PATH" | head -n 1)"
    if [[ ! "$SSH_KEY_CONTENT" =~ ^(ssh-(rsa|ed25519|ecdsa)|ecdsa-sha2-nistp[0-9]+)\  ]]; then
        die "File at $SSH_KEY_PATH does not look like an SSH public key."
    fi
fi

if [[ "$ALLOW_PASSWORD" -eq 1 && -z "$PASSWORD_VAL" ]]; then
    PASSWORD_VAL="$(set +o pipefail; tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)"
    log_warn "Generated random password for user '$USERNAME_VAL' (will be saved next to ISO)."
fi

if [[ -n "$DEVICE" && "$SKIP_WRITE" -eq 0 ]]; then
    [[ -b "$DEVICE" ]] || die "Device not found or not a block device: $DEVICE"
fi

# Dependency check
need_cmds=(xorriso cpio gzip curl sed grep awk dd sha256sum)
missing=()
for c in "${need_cmds[@]}"; do command -v "$c" >/dev/null 2>&1 || missing+=("$c"); done
if (( ${#missing[@]} > 0 )); then
    log_warn "Installing missing dependencies: ${missing[*]}"
    apt-get update -y >/dev/null
    apt-get install -y --no-install-recommends xorriso isolinux syslinux-common cpio curl ca-certificates dosfstools mtools
fi
# isohdpfx.bin (for hybrid MBR) lives in isolinux package
ISOHDPFX=""
for p in /usr/lib/ISOLINUX/isohdpfx.bin /usr/lib/syslinux/isohdpfx.bin /usr/share/syslinux/isohdpfx.bin; do
    [[ -f "$p" ]] && ISOHDPFX="$p" && break
done
[[ -n "$ISOHDPFX" ]] || log_warn "isohdpfx.bin not found; ISO will still boot in UEFI mode."

mkdir -p "$WORK_DIR"
log_info "Work dir: $WORK_DIR"

# -----------------------------------------------------------------------------
# Acquire netinst ISO
# -----------------------------------------------------------------------------

resolve_latest_netinst_url() {
    local base="$DEFAULT_NETINST_URL"
    log_info "Resolving latest netinst ISO from $base..."
    local listing
    listing=$(curl -fsSL "$base") || die "Failed to fetch $base"
    local name
    name=$(echo "$listing" | grep -oE 'debian-[0-9.]+-amd64-netinst\.iso' | sort -u | tail -n 1)
    [[ -n "$name" ]] || die "Could not find a netinst ISO at $base"
    echo "${base}${name}"
}

if [[ -z "$NETINST_ISO" ]]; then
    if [[ -z "$NETINST_URL" ]]; then
        NETINST_URL="$(resolve_latest_netinst_url)"
    fi
    NETINST_ISO="$WORK_DIR/$(basename "$NETINST_URL")"
    if [[ -f "$NETINST_ISO" ]]; then
        log_info "Using cached netinst ISO: $NETINST_ISO"
    else
        log_info "Downloading $NETINST_URL"
        curl -L --progress-bar -o "$NETINST_ISO" "$NETINST_URL" || die "Failed to download netinst ISO."
    fi
fi
[[ -f "$NETINST_ISO" ]] || die "Netinst ISO not available: $NETINST_ISO"
log_ok "Netinst ISO: $NETINST_ISO ($(du -h "$NETINST_ISO" | cut -f1))"

# -----------------------------------------------------------------------------
# Extract ISO
# -----------------------------------------------------------------------------

EXTRACT_DIR="$WORK_DIR/iso-extract"
log_info "Extracting ISO to $EXTRACT_DIR..."
rm -rf "$EXTRACT_DIR"
mkdir -p "$EXTRACT_DIR"
xorriso -osirrox on -indev "$NETINST_ISO" -extract / "$EXTRACT_DIR" 2>&1 | tail -n 5
chmod -R u+w "$EXTRACT_DIR"
log_ok "ISO extracted."

# -----------------------------------------------------------------------------
# Build preseed.cfg
# -----------------------------------------------------------------------------

PRESEED="$WORK_DIR/preseed.cfg"
log_info "Generating preseed.cfg..."

# Hash passwords for security (mkpasswd from whois package; fall back to openssl)
hash_password() {
    local plain="$1"
    if command -v mkpasswd >/dev/null 2>&1; then
        mkpasswd -m sha-512 "$plain"
    elif command -v openssl >/dev/null 2>&1; then
        openssl passwd -6 "$plain"
    else
        apt-get install -y --no-install-recommends whois >/dev/null 2>&1 || true
        if command -v mkpasswd >/dev/null 2>&1; then
            mkpasswd -m sha-512 "$plain"
        else
            die "Cannot hash password (install 'whois' for mkpasswd or 'openssl')."
        fi
    fi
}

USER_PW_HASH=""
ROOT_PW_HASH=""
if [[ -n "$PASSWORD_VAL" ]]; then USER_PW_HASH="$(hash_password "$PASSWORD_VAL")"; fi
if [[ -n "$ROOT_PASSWORD" ]]; then ROOT_PW_HASH="$(hash_password "$ROOT_PASSWORD")"; fi

PACKAGES_BASE="openssh-server sudo curl ca-certificates"
PACKAGES_FINAL="$PACKAGES_BASE"
[[ -n "$EXTRA_PACKAGES" ]] && PACKAGES_FINAL="$PACKAGES_FINAL $EXTRA_PACKAGES"

# Build late_command — runs after install in chroot of the new system.
LATE_CMDS=()
LATE_CMDS+=("in-target systemctl enable ssh")
# SSH key injection
if [[ -n "$SSH_KEY_CONTENT" ]]; then
    SSH_KEY_B64="$(printf '%s\n' "$SSH_KEY_CONTENT" | base64 -w0)"
    LATE_CMDS+=("in-target install -d -m 0700 -o $USERNAME_VAL -g $USERNAME_VAL /home/$USERNAME_VAL/.ssh")
    LATE_CMDS+=("in-target sh -c 'echo $SSH_KEY_B64 | base64 -d >> /home/$USERNAME_VAL/.ssh/authorized_keys'")
    LATE_CMDS+=("in-target chmod 600 /home/$USERNAME_VAL/.ssh/authorized_keys")
    LATE_CMDS+=("in-target chown $USERNAME_VAL:$USERNAME_VAL /home/$USERNAME_VAL/.ssh/authorized_keys")
fi
# SSH daemon hardening
if [[ "$ALLOW_PASSWORD" -eq 1 ]]; then
    LATE_CMDS+=("in-target sh -c 'sed -i \"s/^#*PasswordAuthentication.*/PasswordAuthentication yes/\" /etc/ssh/sshd_config'")
else
    LATE_CMDS+=("in-target sh -c 'sed -i \"s/^#*PasswordAuthentication.*/PasswordAuthentication no/\" /etc/ssh/sshd_config'")
fi
LATE_CMDS+=("in-target sh -c 'sed -i \"s/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/\" /etc/ssh/sshd_config'")
# Sudo NOPASSWD for the user (key-only login otherwise leaves sudo unusable)
LATE_CMDS+=("in-target sh -c 'echo \"$USERNAME_VAL ALL=(ALL) NOPASSWD:ALL\" > /etc/sudoers.d/90-$USERNAME_VAL && chmod 440 /etc/sudoers.d/90-$USERNAME_VAL'")
# Optional: pull PhoneHomeWeb collector after install
if [[ "$NO_COLLECTOR" -ne 1 && -n "$PHW_SERVER_URL" && "$PHW_SERVER_URL" != *"<SERVERURL>"* ]]; then
    LATE_CMDS+=("in-target install -d -m 0755 /opt/phw")
    LATE_CMDS+=("in-target sh -c 'curl -fsSL -H \"X-Auth-Key: $PHW_AUTH_KEY\" $PHW_SERVER_URL/payloads/LinuxCollector/download/Linux-Collector.sh -o /opt/phw/Linux-Collector.sh || true'")
    LATE_CMDS+=("in-target sh -c 'curl -fsSL -H \"X-Auth-Key: $PHW_AUTH_KEY\" $PHW_SERVER_URL/payloads/LinuxCollector/download/upload-file.sh   -o /opt/phw/upload-file.sh   || true'")
    LATE_CMDS+=("in-target chmod +x /opt/phw/*.sh")
fi

# Join late_commands with semicolons (debian-installer joins on newlines via \\)
LATE_JOINED=""
for c in "${LATE_CMDS[@]}"; do
    if [[ -z "$LATE_JOINED" ]]; then LATE_JOINED="$c"; else LATE_JOINED="$LATE_JOINED ; $c"; fi
done

cat > "$PRESEED" <<PRESEED_EOF
#_preseed_V1
# PhoneHomeWeb headless Debian preseed - generated $(date -u +%Y-%m-%dT%H:%M:%SZ)

### Localization
d-i debian-installer/locale string $LOCALE_VAL
d-i keyboard-configuration/xkb-keymap select $KEYMAP

### Network
d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string $HOSTNAME_VAL
d-i netcfg/get_domain string local
d-i netcfg/hostname string $HOSTNAME_VAL

### Mirror
d-i mirror/country string manual
d-i mirror/http/hostname string $MIRROR
d-i mirror/http/directory string /debian
d-i mirror/http/proxy string

### Clock
d-i clock-setup/utc boolean true
d-i time/zone string $TIMEZONE
d-i clock-setup/ntp boolean true

### Accounts
PRESEED_EOF

if [[ -n "$ROOT_PW_HASH" ]]; then
    cat >> "$PRESEED" <<EOF
d-i passwd/root-login boolean true
d-i passwd/root-password-crypted password $ROOT_PW_HASH
EOF
else
    echo "d-i passwd/root-login boolean false" >> "$PRESEED"
fi

cat >> "$PRESEED" <<PRESEED_EOF
d-i passwd/user-fullname string PhoneHomeWeb User
d-i passwd/username string $USERNAME_VAL
PRESEED_EOF

if [[ -n "$USER_PW_HASH" ]]; then
    echo "d-i passwd/user-password-crypted password $USER_PW_HASH" >> "$PRESEED"
else
    # No interactive password — installer requires *some* value, but late_command will
    # lock the password and rely on SSH keys. Set a long random one we discard.
    # NOTE: 'head -c' closes its stdin early, causing SIGPIPE on 'tr' which under
    # 'pipefail' would abort the script with exit 141. Disable pipefail locally.
    RAND_PW="$(set +o pipefail; tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)"
    echo "d-i passwd/user-password-crypted password $(hash_password "$RAND_PW")" >> "$PRESEED"
    LATE_JOINED="in-target passwd -l $USERNAME_VAL ; $LATE_JOINED"
fi

cat >> "$PRESEED" <<PRESEED_EOF
d-i user-setup/allow-password-weak boolean true
d-i user-setup/encrypt-home boolean false

### Partitioning - whole disk, single ext4 + swap, no LVM, no encryption
d-i partman-auto/method string regular
d-i partman-auto/choose_recipe select atomic
d-i partman-lvm/device_remove_lvm boolean true
d-i partman-md/device_remove_md boolean true
d-i partman-auto/disk string /dev/sda /dev/vda /dev/nvme0n1
d-i partman-basicfilesystems/no_swap boolean false
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true

### Base + tasksel - NO desktop, no laptop task; just standard utilities
tasksel tasksel/first multiselect standard, ssh-server
d-i pkgsel/include string $PACKAGES_FINAL
d-i pkgsel/upgrade select full-upgrade
popularity-contest popularity-contest/participate boolean false

### GRUB
d-i grub-installer/only_debian boolean true
d-i grub-installer/with_other_os boolean true
d-i grub-installer/bootdev string default

### Finish
d-i finish-install/reboot_in_progress note

### Late commands
d-i preseed/late_command string $LATE_JOINED
PRESEED_EOF

log_ok "preseed.cfg generated ($(wc -l < "$PRESEED") lines)."

# -----------------------------------------------------------------------------
# Inject preseed into initrd
# -----------------------------------------------------------------------------

INITRD_PATH=""
for p in install.amd/initrd.gz install.amd/gtk/initrd.gz install/initrd.gz; do
    [[ -f "$EXTRACT_DIR/$p" ]] && INITRD_PATH="$EXTRACT_DIR/$p" && break
done
[[ -n "$INITRD_PATH" ]] || die "Could not find initrd in extracted ISO."
log_info "Injecting preseed into $(basename "$(dirname "$INITRD_PATH")")/initrd.gz"

INITRD_WORK="$WORK_DIR/initrd-work"
rm -rf "$INITRD_WORK"
mkdir -p "$INITRD_WORK"
( cd "$INITRD_WORK" && gzip -dc "$INITRD_PATH" | cpio -id --quiet )
cp "$PRESEED" "$INITRD_WORK/preseed.cfg"
chmod 0644 "$INITRD_WORK/preseed.cfg"
( cd "$INITRD_WORK" && find . | cpio --create --format=newc --quiet | gzip -9 ) > "$INITRD_PATH"
log_ok "preseed.cfg embedded in initrd ($(du -h "$INITRD_PATH" | cut -f1))."

# -----------------------------------------------------------------------------
# Add unattended boot entries to isolinux + grub
# -----------------------------------------------------------------------------

ISOLINUX_CFG="$EXTRACT_DIR/isolinux/isolinux.cfg"
TXT_CFG="$EXTRACT_DIR/isolinux/txt.cfg"
GRUB_CFG="$EXTRACT_DIR/boot/grub/grub.cfg"

# Auto-boot the unattended entry after 3s
if [[ -f "$ISOLINUX_CFG" ]]; then
    sed -i 's/^timeout .*/timeout 30/' "$ISOLINUX_CFG"
    grep -q '^default ' "$ISOLINUX_CFG" || echo 'default phw-headless' >> "$ISOLINUX_CFG"
    sed -i 's/^default .*/default phw-headless/' "$ISOLINUX_CFG"
fi

if [[ -f "$TXT_CFG" ]]; then
    cat >> "$TXT_CFG" <<'TXT'

label phw-headless
    menu label ^PhoneHomeWeb Headless Debian (Unattended Install)
    kernel /install.amd/vmlinuz
    append vga=788 initrd=/install.amd/initrd.gz auto=true priority=critical preseed/file=/preseed.cfg quiet ---
TXT
    log_detail "Added isolinux entry: phw-headless"
fi

if [[ -f "$GRUB_CFG" ]]; then
    # Make our entry the GRUB default
    sed -i 's/^set default=.*/set default="0"/' "$GRUB_CFG"
    sed -i 's/^set timeout=.*/set timeout=3/' "$GRUB_CFG"
    # Prepend our entry so it wins index 0
    NEW_GRUB="$WORK_DIR/grub-prepend.cfg"
    cat > "$NEW_GRUB" <<'GRUB'
menuentry --hotkey=p 'PhoneHomeWeb Headless Debian (Unattended Install)' {
    set background_color=black
    linux    /install.amd/vmlinuz vga=788 auto=true priority=critical preseed/file=/preseed.cfg quiet ---
    initrd   /install.amd/initrd.gz
}
GRUB
    # Insert after the first 'set timeout' line (preserves theme/header)
    awk -v entry_file="$NEW_GRUB" '
        BEGIN { inserted=0 }
        { print }
        !inserted && /^set timeout=/ {
            while ((getline line < entry_file) > 0) print line
            close(entry_file)
            inserted=1
        }
    ' "$GRUB_CFG" > "$GRUB_CFG.new" && mv "$GRUB_CFG.new" "$GRUB_CFG"
    log_detail "Added grub entry: phw-headless"
fi

# -----------------------------------------------------------------------------
# Repack ISO (hybrid: BIOS + UEFI)
# -----------------------------------------------------------------------------

if [[ -z "$OUTPUT_ISO" ]]; then
    OUTPUT_ISO="./headless-debian-$(date +%Y%m%d-%H%M%S).iso"
fi
OUTPUT_ISO="$(readlink -f "$OUTPUT_ISO")"
mkdir -p "$(dirname "$OUTPUT_ISO")"

log_info "Repacking ISO to $OUTPUT_ISO ..."

# Re-checksum md5sum.txt so debian-installer's integrity check passes
if [[ -f "$EXTRACT_DIR/md5sum.txt" ]]; then
    log_detail "Updating md5sum.txt"
    ( cd "$EXTRACT_DIR" && find . -type f ! -name md5sum.txt -print0 | xargs -0 md5sum > md5sum.txt )
fi

XORRISO_OPTS=(
    -as mkisofs
    -r -V "PHW-HEADLESS"
    -J -joliet-long
    -cache-inodes
    -b isolinux/isolinux.bin
    -c isolinux/boot.cat
    -boot-load-size 4 -boot-info-table -no-emul-boot
)
# Hybrid MBR for BIOS/USB boot (only if isohdpfx.bin available)
# Insert AFTER `-as mkisofs` (the first two elements) so it stays inside the
# mkisofs personality; otherwise xorriso treats it as the personality name.
if [[ -n "$ISOHDPFX" ]]; then
    XORRISO_OPTS=( "${XORRISO_OPTS[@]:0:2}" -isohybrid-mbr "$ISOHDPFX" "${XORRISO_OPTS[@]:2}" )
fi
# UEFI boot if EFI image is present
if [[ -f "$EXTRACT_DIR/boot/grub/efi.img" ]]; then
    XORRISO_OPTS+=(
        -eltorito-alt-boot
        -e boot/grub/efi.img
        -no-emul-boot
        -isohybrid-gpt-basdat
    )
fi

xorriso "${XORRISO_OPTS[@]}" -o "$OUTPUT_ISO" "$EXTRACT_DIR" 2>&1 | tail -n 5

[[ -f "$OUTPUT_ISO" ]] || die "ISO repack failed."
log_ok "ISO created: $OUTPUT_ISO ($(du -h "$OUTPUT_ISO" | cut -f1))"

ISO_SHA="$(sha256sum "$OUTPUT_ISO" | awk '{print $1}')"
log_detail "SHA256: $ISO_SHA"

# -----------------------------------------------------------------------------
# Save credentials sidecar
# -----------------------------------------------------------------------------

INFO_FILE="${OUTPUT_ISO%.iso}.info.txt"
{
    echo "PhoneHomeWeb Headless Debian Install"
    echo "Generated:    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "ISO:          $OUTPUT_ISO"
    echo "SHA256:       $ISO_SHA"
    echo "Hostname:     $HOSTNAME_VAL"
    echo "Username:     $USERNAME_VAL"
    if [[ -n "$PASSWORD_VAL" ]]; then echo "Password:     $PASSWORD_VAL"; fi
    if [[ -n "$ROOT_PASSWORD" ]]; then echo "Root Password: $ROOT_PASSWORD"; fi
    if [[ -n "$SSH_KEY_PATH" ]]; then echo "SSH key:      $SSH_KEY_PATH"; fi
    echo "Login example: ssh $USERNAME_VAL@<host>"
} > "$INFO_FILE"
chmod 600 "$INFO_FILE"
log_ok "Credentials sidecar: $INFO_FILE"

# -----------------------------------------------------------------------------
# Optional: write to USB
# -----------------------------------------------------------------------------

if [[ -n "$DEVICE" && "$SKIP_WRITE" -ne 1 ]]; then
    echo
    log_warn "About to OVERWRITE $DEVICE with $OUTPUT_ISO"
    lsblk "$DEVICE" -o NAME,SIZE,FSTYPE,MOUNTPOINT,LABEL || true
    if [[ "$NON_INTERACTIVE" -ne 1 ]]; then
        read -r -p "Type 'YES' to continue: " confirm
        [[ "$confirm" == "YES" ]] || die "Aborted by user."
    fi
    for p in "${DEVICE}"*; do mount | grep -q "$p" && umount "$p" || true; done
    log_info "Writing ISO to $DEVICE ..."
    dd if="$OUTPUT_ISO" of="$DEVICE" bs=4M status=progress conv=fsync
    sync
    log_ok "ISO written to $DEVICE"
fi

# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------

if [[ "$KEEP_WORK" -ne 1 ]]; then
    log_info "Cleaning up work dir $WORK_DIR"
    rm -rf "$WORK_DIR"
fi

echo
log_ok "================================================================================"
log_ok " Headless Debian ISO build complete"
log_ok "================================================================================"
echo "  ISO:    $OUTPUT_ISO"
echo "  Info:   $INFO_FILE"
echo "  Login:  ssh $USERNAME_VAL@<host>"
echo
