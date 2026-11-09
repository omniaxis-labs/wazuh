#!/usr/bin/env bash
# Encrypted off-host copy of the SCDC server's state, with restic.
#   omniaxis-scdc-backup init   create the repository password and repository once
#   omniaxis-scdc-backup run    back up, then keep 14 daily, 8 weekly, 12 monthly
# Settings come from /etc/omniaxis-scdc/backup.env (root, 0600). restic
# encrypts on this host, so the store never sees the contents. Without the
# repository password nobody can restore, the owner included: keep a copy of
# /etc/omniaxis-scdc/restic-password off this server.
set -euo pipefail
ENV_FILE=/etc/omniaxis-scdc/backup.env
PASSWORD_FILE=/etc/omniaxis-scdc/restic-password
PATHS=(
  /root/omniaxis-scdc            # install archive and admin passwords
  /etc/omniaxis-scdc             # server settings
  /etc/omniaxis-intake           # relay keys and API password
  /var/lib/omniaxis-intake       # relay dedupe journal
  /var/ossec/etc                 # manager config, agent keys, portal signing key
  /etc/wazuh-indexer/certs
  /etc/wazuh-dashboard/certs
  /etc/caddy
  /var/lib/wazuh-indexer-snapshots   # the indexer's daily snapshots
)

say() { echo "[$(date -u +%FT%TZ)] backup: $*"; }
die() { say "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root"
[ -f "$ENV_FILE" ] || die "missing $ENV_FILE (see backup.env.example)"
[ "$(stat -c '%u %a' "$ENV_FILE")" = "0 600" ] || die "$ENV_FILE must be root-owned, mode 0600"
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a
: "${RESTIC_REPOSITORY:?set RESTIC_REPOSITORY in $ENV_FILE}"
# Hosting is US only. Refuse the Australian regions by name.
case "$RESTIC_REPOSITORY" in
  *ap-southeast-2*|*ap-southeast-4*|*australia*|*syd*|*mel*) die "RESTIC_REPOSITORY must be in the US" ;;
esac
export RESTIC_PASSWORD_FILE="$PASSWORD_FILE"

case "${1:-run}" in
  init)
    if [ ! -s "$PASSWORD_FILE" ]; then
      ( umask 077; openssl rand -base64 48 | tr -d '\n' > "$PASSWORD_FILE" )
      say "made $PASSWORD_FILE: copy it into the owner's password manager now (never into chat)"
    fi
    if restic cat config >/dev/null 2>&1; then
      say "repository already set up"
    else
      restic init >/dev/null
      say "repository created"
    fi
    ;;
  run)
    existing=()
    for p in "${PATHS[@]}"; do [ -e "$p" ] && existing+=("$p"); done
    restic backup --quiet --tag scdc --host scdc-wazuh "${existing[@]}"
    restic forget --quiet --tag scdc --host scdc-wazuh --keep-daily 14 --keep-weekly 8 --keep-monthly 12 --prune
    # A full read of a fifth of the data once a week, so a broken store shows up.
    if [ "$(date -u +%u)" = 7 ]; then restic check --quiet --read-data-subset=1/5; fi
    say "ok: $(restic snapshots --quiet --tag scdc --latest 1 --compact | sed -n 3p)"
    ;;
  *) die "usage: omniaxis-scdc-backup init|run" ;;
esac
