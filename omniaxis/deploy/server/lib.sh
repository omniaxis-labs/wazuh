# Shared helpers for the SCDC server scripts. Sourced, not run.
# shellcheck shell=bash

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/etc/omniaxis-scdc/config.env}"
DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OMNIAXIS_DIR="$(cd "$DEPLOY_DIR/../.." && pwd)"
STATE_DIR=/root/omniaxis-scdc   # root-only: install archives and admin passwords

say() { echo "[$(date -u +%H:%M:%S)] ${STEP:-scdc}: $*"; }
die() { echo "[$(date -u +%H:%M:%S)] ${STEP:-scdc}: ERROR: $*" >&2; exit 1; }

need_root() { [ "$(id -u)" = 0 ] || die "run as root"; }

need_ubuntu() {
  . /etc/os-release
  [ "${ID:-}" = ubuntu ] || die "Ubuntu LTS expected, found ${ID:-unknown}"
  case "${VERSION_ID:-}" in 22.04|24.04) ;; *) die "Ubuntu 22.04 or 24.04 expected, found ${VERSION_ID:-unknown}" ;; esac
}

load_config() {
  [ -f "$CONFIG_FILE" ] || die "missing $CONFIG_FILE (copy config.env.example)"
  [ "$(stat -c %u "$CONFIG_FILE")" = 0 ] || die "$CONFIG_FILE must be owned by root"
  # shellcheck disable=SC1090
  . "$CONFIG_FILE"
  : "${SCDC_INTAKE_HOSTNAME:?}" "${PORTAL_URL:?}" "${WAZUH_SERIES:?}" "${WAZUH_VERSION:?}" "${NODE_VERSION:?}"
  case "$PORTAL_URL" in https://*) ;; *) die "PORTAL_URL must be https" ;; esac
  case "${DASHBOARD_ACCESS:-tunnel}" in tunnel|allowlist) ;; *) die "DASHBOARD_ACCESS must be tunnel or allowlist" ;; esac
  for c in ${ADMIN_SSH_CIDRS:-} ${AGENT_CIDRS:-} ${DASHBOARD_CIDRS:-}; do
    case "$c" in 0.0.0.0/0|::/0) die "refusing world-open CIDR $c" ;; esac
  done
  install -d -m 0700 "$STATE_DIR"
}

wazuh_installed() { dpkg -s wazuh-manager >/dev/null 2>&1; }

# Replace a "key: value" line in a YAML-ish file, or append it.
set_yaml_key() {
  local file="$1" key="$2" value="$3"
  if grep -qE "^#?\s*${key}:" "$file"; then
    sed -i -E "s|^#?\s*${key}:.*|${key}: ${value}|" "$file"
  else
    printf '%s: %s\n' "$key" "$value" >> "$file"
  fi
}
