#!/usr/bin/env bash
set -euo pipefail

# Debian/Linux installer for PhoneHomeWeb
# - Installs/ensures Node.js (optional upgrade prompt)
# - Installs npm deps
# - Ensures .env exists and generates auth keys if placeholders
# - Creates a dedicated system user/group
# - Sets permissions for uploads/logs
# - Installs & enables a systemd service

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=PhoneHomeWeb.Install.sh
source "$SCRIPT_DIR/PhoneHomeWeb.Install.sh"

usage() {
  cat <<'EOF'
Usage:
  sudo bash scripts/Install-PhoneHomeWeb.sh [options]

Options:
  --repo-root PATH         Repo root (default: inferred from script location)
  --service-name NAME      systemd service name (default: phonehomeweb)
  --service-user USER      Service user (default: phonehomeweb)
  --service-group GROUP    Service group (default: phonehomeweb)
  --offer-node-upgrade     If Node exists, offer to upgrade to LTS
  --no-service             Skip systemd service install
  --non-interactive        Do not prompt (installs Node if missing; no upgrade)

Notes:
  - This script is intended for Debian-based systems with systemd.
  - It will generate AUTH_KEY and AUTH_KEY_HIGH_TRUST if placeholders.
EOF
}

REPO_ROOT=""
SERVICE_NAME="phonehomeweb"
SERVICE_USER="phonehomeweb"
SERVICE_GROUP="phonehomeweb"
OFFER_NODE_UPGRADE=0
INSTALL_SERVICE=1
NON_INTERACTIVE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-root)
      REPO_ROOT="$2"; shift 2 ;;
    --service-name)
      SERVICE_NAME="$2"; shift 2 ;;
    --service-user)
      SERVICE_USER="$2"; shift 2 ;;
    --service-group)
      SERVICE_GROUP="$2"; shift 2 ;;
    --offer-node-upgrade)
      OFFER_NODE_UPGRADE=1; shift 1 ;;
    --no-service)
      INSTALL_SERVICE=0; shift 1 ;;
    --non-interactive)
      NON_INTERACTIVE=1; shift 1 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      phw_die "Unknown argument: $1" ;;
  esac
done

if [[ -z "$REPO_ROOT" ]]; then
  REPO_ROOT="$(phw_repo_root_from_script)"
fi

REPO_ROOT="$(cd "$REPO_ROOT" && pwd -P)"
[[ -f "$REPO_ROOT/package.json" ]] || phw_die "package.json not found in repo root: $REPO_ROOT"

phw_log "Repo: $REPO_ROOT"

phw_require_root

# Non-interactive mode: disable prompts by forcing default answers.
if [[ "$NON_INTERACTIVE" == "1" ]]; then
  phw_prompt_yn() { return 0; }
  OFFER_NODE_UPGRADE=0
fi

# 1) Node
phw_ensure_node "$OFFER_NODE_UPGRADE"

# 2) npm deps
phw_need_cmd npm
phw_log "Installing npm dependencies..."
phw_npm_install "$REPO_ROOT"

# 3) .env
phw_log "Ensuring .env exists..."
phw_ensure_env_file "$REPO_ROOT"

# 4) Generate auth keys if placeholders to avoid a non-starting service.
phw_log "Ensuring auth keys..."
phw_ensure_auth_keys "$REPO_ROOT"

# 5) Service user/group + permissions
phw_log "Ensuring service user/group..."
phw_ensure_user_and_group "$SERVICE_USER" "$SERVICE_GROUP"

# Add the invoking sudo user to the group so they can edit .env if needed.
if [[ -n "${SUDO_USER:-}" ]] && id "${SUDO_USER}" >/dev/null 2>&1; then
  usermod -aG "$SERVICE_GROUP" "$SUDO_USER" || true
fi

phw_log "Setting permissions for repo/uploads/logs..."
phw_grant_repo_access "$REPO_ROOT" "$SERVICE_USER" "$SERVICE_GROUP"

# 6) systemd
if [[ "$INSTALL_SERVICE" == "1" ]]; then
  if ! command -v systemctl >/dev/null 2>&1; then
    phw_die "systemctl not found. This installer expects systemd."
  fi

  phw_log "Installing systemd service: $SERVICE_NAME"
  phw_install_systemd_service "$REPO_ROOT" "$SERVICE_NAME" "$SERVICE_USER" "$SERVICE_GROUP"
  phw_log "Starting service..."
  phw_start_systemd_service "$SERVICE_NAME"
fi

phw_log "Done."
phw_log "If you change .env, restart with: sudo systemctl restart ${SERVICE_NAME}.service"
phw_log "Health check: curl -fsS http://localhost:$(phw_env_get_raw "$REPO_ROOT/.env" "PORT")/ || true"
