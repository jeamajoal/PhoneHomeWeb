#!/usr/bin/env bash
set -euo pipefail

phw_log() {
  # shellcheck disable=SC2145
  echo "[PhoneHomeWeb] $*" >&2
}

phw_die() {
  phw_log "ERROR: $*"
  exit 1
}

phw_need_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || phw_die "Missing required command: $cmd"
}

phw_is_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]]
}

phw_require_root() {
  if ! phw_is_root; then
    phw_die "Run this installer with sudo (root required)."
  fi
}

phw_repo_root_from_script() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
  # scripts/.. is repo root
  (cd "$script_dir/.." && pwd -P)
}

phw_prompt_yn() {
  local prompt="$1"
  local default_answer="${2:-n}"
  local answer

  read -r -p "$prompt" answer || true
  answer="${answer:-$default_answer}"
  [[ "$answer" == "y" || "$answer" == "Y" ]]
}

phw_apt_update_once() {
  local stamp="/var/lib/apt/periodic/update-success-stamp"
  if [[ ! -f "$stamp" ]] || find "$stamp" -mmin +60 >/dev/null 2>&1; then
    apt-get update -y
  fi
}

phw_ensure_apt_packages() {
  # Usage: phw_ensure_apt_packages curl ca-certificates
  phw_require_root
  phw_apt_update_once
  apt-get install -y --no-install-recommends "$@"
}

phw_node_version_major() {
  if ! command -v node >/dev/null 2>&1; then
    echo ""
    return
  fi
  local v
  v="$(node --version 2>/dev/null || true)"
  v="${v#v}"
  echo "${v%%.*}"
}

phw_install_node_nodesource_lts() {
  phw_require_root
  phw_ensure_apt_packages curl ca-certificates gnupg
  curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
  apt-get install -y --no-install-recommends nodejs
}

phw_ensure_node() {
  # Installs Node.js LTS if missing. Optionally offers upgrade.
  local offer_upgrade="${1:-0}"

  if command -v node >/dev/null 2>&1; then
    phw_log "Node detected: $(node --version 2>/dev/null || true)"
    if [[ "$offer_upgrade" == "1" ]]; then
      if phw_prompt_yn "Upgrade Node.js to current LTS via NodeSource? (y/N) " "n"; then
        phw_install_node_nodesource_lts
      fi
    fi
    return
  fi

  phw_log "Node.js not found."
  if phw_prompt_yn "Install Node.js LTS via NodeSource now? (y/N) " "n"; then
    phw_install_node_nodesource_lts
  else
    phw_die "Node.js is required. Install Node.js and re-run."
  fi
}

phw_ensure_env_file() {
  local repo_root="$1"
  local env_path="$repo_root/.env"
  local example_path="$repo_root/.env.example"

  [[ -f "$example_path" ]] || phw_die "Missing .env.example at $example_path"

  if [[ ! -f "$env_path" ]]; then
    cp "$example_path" "$env_path"
    phw_log "Created .env from .env.example"
  else
    phw_log ".env already exists"
  fi
}

phw_env_get_raw() {
  # Reads KEY from .env-like file without executing it.
  # Prints value (possibly empty). Returns 0 even if missing.
  local env_file="$1"
  local key="$2"

  [[ -f "$env_file" ]] || { echo ""; return 0; }

  # Match KEY=... ignoring leading whitespace; ignore comments.
  # Strip surrounding quotes if present.
  local line value
  line="$(grep -E "^[[:space:]]*${key}=" "$env_file" | tail -n 1 || true)"
  if [[ -z "$line" ]]; then
    echo ""
    return 0
  fi

  value="${line#*=}"
  value="${value%\r}"
  # Remove surrounding quotes
  if [[ "$value" =~ ^\".*\"$ ]]; then
    value="${value:1:${#value}-2}"
  elif [[ "$value" =~ ^\'.*\'$ ]]; then
    value="${value:1:${#value}-2}"
  fi
  echo "$value"
}

phw_env_set() {
  # Sets KEY=VALUE in env file (adds if missing). Preserves other lines.
  local env_file="$1"
  local key="$2"
  local value="$3"

  [[ -f "$env_file" ]] || phw_die "Env file not found: $env_file"

  local tmp
  tmp="$(mktemp)"

  if grep -qE "^[[:space:]]*${key}=" "$env_file"; then
    # Replace last occurrence
    awk -v k="$key" -v v="$value" '
      BEGIN { last=0 }
      $0 ~ "^[[:space:]]*"k"=" { last=NR }
      { lines[NR]=$0 }
      END {
        for (i=1; i<=NR; i++) {
          if (i==last) {
            print k"="v
          } else {
            print lines[i]
          }
        }
      }
    ' "$env_file" > "$tmp"
  else
    cat "$env_file" > "$tmp"
    echo "" >> "$tmp"
    echo "${key}=${value}" >> "$tmp"
  fi

  mv "$tmp" "$env_file"
}

phw_generate_secret() {
  # 32 bytes hex = 64 chars
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    phw_need_cmd python3
    python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
  fi
}

phw_ensure_auth_keys() {
  local repo_root="$1"
  local env_file="$repo_root/.env"

  local auth_key ht_key
  auth_key="$(phw_env_get_raw "$env_file" "AUTH_KEY")"
  ht_key="$(phw_env_get_raw "$env_file" "AUTH_KEY_HIGH_TRUST")"

  if [[ -z "$auth_key" || "$auth_key" == "CHANGE_ME" || "$auth_key" == "dev-local-key" ]]; then
    local new_key
    new_key="$(phw_generate_secret)"
    phw_env_set "$env_file" "AUTH_KEY" "$new_key"
    phw_log "Generated AUTH_KEY (not printed)."
  fi

  if [[ -z "$ht_key" || "$ht_key" == "CHANGE_ME_HIGH_TRUST" ]]; then
    local new_ht
    new_ht="$(phw_generate_secret)"
    phw_env_set "$env_file" "AUTH_KEY_HIGH_TRUST" "$new_ht"
    phw_log "Generated AUTH_KEY_HIGH_TRUST (not printed)."
  fi
}

phw_npm_install() {
  local repo_root="$1"
  (cd "$repo_root" && {
    if [[ -f package-lock.json ]]; then
      npm ci
    else
      npm install
    fi
  })
}

phw_ensure_user_and_group() {
  phw_require_root

  local user="$1"
  local group="$2"

  if ! getent group "$group" >/dev/null 2>&1; then
    groupadd --system "$group"
    phw_log "Created group: $group"
  fi

  if ! id "$user" >/dev/null 2>&1; then
    useradd --system --gid "$group" --home /nonexistent --shell /usr/sbin/nologin "$user"
    phw_log "Created system user: $user"
  fi
}

phw_grant_repo_access() {
  # Sets group ownership/perms so the service user can read code and write uploads/logs.
  phw_require_root

  local repo_root="$1"
  local user="$2"
  local group="$3"

  # Ensure group ownership and group readability for runtime.
  chgrp -R "$group" "$repo_root"
  chmod -R g+rX "$repo_root"

  # Keep group sticky on dirs so git pulls keep group.
  find "$repo_root" -type d -exec chmod g+s {} \;

  # Lock down .env to group-readable only.
  if [[ -f "$repo_root/.env" ]]; then
    chown "${user}:${group}" "$repo_root/.env"
    chmod 640 "$repo_root/.env"
  fi

  # Ensure writable paths are owned by service user.
  local env_file="$repo_root/.env"
  local uploads_dir rel_uploads
  rel_uploads="$(phw_env_get_raw "$env_file" "UPLOADS_DIR")"
  uploads_dir="$repo_root/${rel_uploads:-uploads}"

  mkdir -p "$uploads_dir"
  chown -R "${user}:${group}" "$uploads_dir"
  chmod -R 770 "$uploads_dir"

  local log_path rel_log
  rel_log="$(phw_env_get_raw "$env_file" "REQUEST_LOG_PATH")"
  log_path="$repo_root/${rel_log:-request_logs.txt}"
  touch "$log_path"
  chown "${user}:${group}" "$log_path"
  chmod 660 "$log_path"
}

phw_install_systemd_service() {
  phw_require_root

  local repo_root="$1"
  local service_name="$2"
  local user="$3"
  local group="$4"

  local node_path
  node_path="$(command -v node || true)"
  [[ -n "$node_path" ]] || phw_die "node not found in PATH"

  local unit_path="/etc/systemd/system/${service_name}.service"

  cat > "$unit_path" <<EOF
[Unit]
Description=PhoneHomeWeb Node server
After=network.target

[Service]
Type=simple
WorkingDirectory=${repo_root}
EnvironmentFile=${repo_root}/.env
ExecStart=${node_path} ${repo_root}/server.js
User=${user}
Group=${group}
Restart=on-failure
RestartSec=2

# Hardening (kept minimal to avoid breaking uploads)
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${repo_root}

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "${service_name}.service"
}

phw_start_systemd_service() {
  phw_require_root
  local service_name="$1"
  systemctl restart "${service_name}.service" || true
  systemctl --no-pager --full status "${service_name}.service" || true
}

# --- Optional: upload helper functions (curl) ---

phw_upload_file() {
  # Usage: phw_upload_file <server_url> <auth_key> <file_path>
  local server_url="$1"
  local auth_key="$2"
  local file_path="$3"

  [[ -f "$file_path" ]] || phw_die "File not found: $file_path"

  curl -fsS \
    -H "X-Auth-Key: ${auth_key}" \
    -F "file=@${file_path}" \
    "${server_url%/}/upload"
}

phw_list_uploads() {
  # Usage: phw_list_uploads <server_url> <high_trust_key>
  local server_url="$1"
  local ht_key="$2"

  curl -fsS \
    -H "X-Auth-Key: ${ht_key}" \
    "${server_url%/}/uploads"
}

# If this file is executed directly, forward to the real installer entrypoint.
# This library is primarily intended to be sourced by scripts/Install-PhoneHomeWeb.sh.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
  exec "${script_dir}/Install-PhoneHomeWeb.sh" "$@"
fi
