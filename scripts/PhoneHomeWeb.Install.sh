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

phw_prompt_text() {
  local prompt="$1"
  local default_value="${2:-}"
  local answer

  if [[ -n "$default_value" ]]; then
    read -r -p "$prompt" answer || true
    answer="${answer:-$default_value}"
  else
    read -r -p "$prompt" answer || true
  fi

  echo "$answer"
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

phw_is_git_repo() {
  local repo_root="$1"
  [[ -d "$repo_root/.git" ]]
}

phw_git_clean_worktree() {
  local repo_root="$1"
  (cd "$repo_root" && git status --porcelain 2>/dev/null | wc -l | tr -d ' ') | grep -qE '^0$'
}

phw_git_current_branch() {
  local repo_root="$1"
  (cd "$repo_root" && git rev-parse --abbrev-ref HEAD 2>/dev/null || true)
}

phw_git_update_repo() {
  # Safely update repo to a given branch.
  # - Refuses to proceed if worktree is dirty (unless user confirms)
  # - Fetches, then checks out branch, then pulls
  local repo_root="$1"
  local remote_name="$2"
  local branch_name="$3"

  phw_need_cmd git
  (cd "$repo_root" && git rev-parse --is-inside-work-tree >/dev/null 2>&1) || phw_die "Not a git repo: $repo_root"

  if ! phw_git_clean_worktree "$repo_root"; then
    phw_log "Git worktree has local changes."
    if ! phw_prompt_yn "Proceed with update anyway? This may fail/overwrite local changes. (y/N) " "n"; then
      phw_log "Skipping git update."
      return 0
    fi
  fi

  phw_log "Fetching updates (remote: ${remote_name})..."
  (cd "$repo_root" && git fetch --prune "$remote_name")

  # Prefer remote tracking branch if it exists.
  if (cd "$repo_root" && git show-ref --verify --quiet "refs/remotes/${remote_name}/${branch_name}"); then
    phw_log "Checking out branch: ${branch_name}"
    (cd "$repo_root" && {
      if git show-ref --verify --quiet "refs/heads/${branch_name}"; then
        git checkout "$branch_name"
      else
        git checkout -b "$branch_name" --track "${remote_name}/${branch_name}"
      fi
    })
  else
    # If the branch doesn't exist remotely, still allow local branch checkout (useful for testing).
    phw_log "Remote branch not found: ${remote_name}/${branch_name}. Attempting local checkout."
    (cd "$repo_root" && git checkout "$branch_name") || phw_die "Branch not found: $branch_name"
  fi

  phw_log "Pulling latest commits..."
  (cd "$repo_root" && git pull "$remote_name" "$branch_name")
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
    phw_log ".env already exists - merging any missing defaults"
    phw_env_merge_missing_defaults "$env_path" "$example_path"
  fi
}

phw_env_key_exists() {
  # Returns 0 if KEY exists (as a key assignment) in env_file.
  local env_file="$1"
  local key="$2"
  [[ -f "$env_file" ]] || return 1
  grep -qE "^[[:space:]]*${key}=" "$env_file"
}

phw_env_merge_missing_defaults() {
  # For each KEY=VALUE in example file, add KEY=VALUE to env file if KEY is missing.
  # Preserves all existing lines/values in the env file.
  local env_file="$1"
  local example_file="$2"

  [[ -f "$env_file" ]] || phw_die "Env file not found: $env_file"
  [[ -f "$example_file" ]] || phw_die "Example env file not found: $example_file"

  local added=0
  local line key value

  # Read example file line-by-line; only consider simple KEY=VALUE lines.
  while IFS= read -r line || [[ -n "$line" ]]; do
    # Trim CR
    line="${line%\r}"
    # Skip comments/empty
    [[ -z "${line//[[:space:]]/}" ]] && continue
    [[ "${line}" =~ ^[[:space:]]*# ]] && continue
    # Only process KEY=VALUE
    if [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"
      value="${BASH_REMATCH[2]}"

      if ! phw_env_key_exists "$env_file" "$key"; then
        echo "" >> "$env_file"
        echo "${key}=${value}" >> "$env_file"
        added=$((added+1))
      fi
    fi
  done < "$example_file"

  if [[ "$added" -gt 0 ]]; then
    phw_log "Merged $added missing .env keys from .env.example"
  else
    phw_log "No missing .env keys to merge"
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
  local log_dir rel_log_dir
  rel_log_dir="$(phw_env_get_raw "$env_file" "REQUEST_LOG_DIR")"
  log_dir="$repo_root/${rel_log_dir:-logs}"

  rel_log="$(phw_env_get_raw "$env_file" "REQUEST_LOG_PATH")"
  log_path="${rel_log:-request_logs.jsonl}"

  # If REQUEST_LOG_PATH is just a filename, place it under REQUEST_LOG_DIR.
  if [[ "$log_path" != /* && "$log_path" != *"/"* ]]; then
    log_path="$log_dir/$log_path"
  elif [[ "$log_path" != /* ]]; then
    # Relative path with directories -> relative to repo root.
    log_path="$repo_root/$log_path"
  fi

  mkdir -p "$(dirname "$log_path")"
  touch "$log_path"
  chown -R "${user}:${group}" "$log_dir" 2>/dev/null || true
  chown "${user}:${group}" "$log_path" 2>/dev/null || true
  chmod -R 770 "$log_dir" 2>/dev/null || true
  chmod 660 "$log_path" 2>/dev/null || true
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
