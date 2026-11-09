#!/usr/bin/env bash
# Retention, indexer snapshots and the off-host backup. Idempotent.
#  - indexer: alert indices deleted after ALERT_INDEX_DAYS (90), archive,
#    monitoring and statistics indices after OTHER_INDEX_DAYS (30), and a
#    daily snapshot of wazuh-* into SNAPSHOT_DIR, SNAPSHOTS_KEPT (14) kept
#  - the manager's own alert and archive logs on disk after ALERT_INDEX_DAYS
#  - an encrypted restic copy of the server's state to an off-host,
#    US-located repository, once /etc/omniaxis-scdc/backup.env exists
export STEP=retention
. "$(dirname "$0")/lib.sh"
need_root; load_config
wazuh_installed || die "run 20-install-wazuh.sh first"
SNAPSHOT_DIR=/var/lib/wazuh-indexer-snapshots
ALERT_DAYS="${ALERT_INDEX_DAYS:-90}"

say "indexer snapshot folder and path.repo"
install -d -o wazuh-indexer -g wazuh-indexer -m 0750 "$SNAPSHOT_DIR"
OS_YML=/etc/wazuh-indexer/opensearch.yml
if ! grep -qE "^path.repo: *\[\"?${SNAPSHOT_DIR}\"?\]" "$OS_YML"; then
  set_yaml_key "$OS_YML" path.repo "[\"${SNAPSHOT_DIR}\"]"
  say "restarting wazuh-indexer for path.repo"
  systemctl restart wazuh-indexer
fi

say "indexer admin password (root only)"
if [ ! -s "$STATE_DIR/wazuh-indexer-admin" ]; then
  ( umask 077
    tar -O -xf "$STATE_DIR/wazuh-install-files.tar" wazuh-install-files/wazuh-passwords.txt \
      | grep -A1 -E "indexer_username: 'admin'\s*$" | sed -n -E "s/^\s*indexer_password: '(.*)'\s*$/\1/p" | head -n1 \
      > "$STATE_DIR/wazuh-indexer-admin" )
  [ -s "$STATE_DIR/wazuh-indexer-admin" ] || die "could not read the indexer admin password from the install archive"
fi

say "waiting for the indexer"
for _ in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --cacert /etc/wazuh-indexer/certs/root-ca.pem https://127.0.0.1:9200/ || true)"
  [ "$code" = 401 ] || [ "$code" = 200 ] && break
  sleep 3
done

say "index retention and daily snapshots"
ALERT_INDEX_DAYS="$ALERT_DAYS" OTHER_INDEX_DAYS="${OTHER_INDEX_DAYS:-30}" SNAPSHOTS_KEPT="${SNAPSHOTS_KEPT:-14}" \
  python3 -B "$DEPLOY_DIR/indexer_lifecycle.py" apply --url https://127.0.0.1:9200 \
    --user admin --password-file "$STATE_DIR/wazuh-indexer-admin" \
    --cacert /etc/wazuh-indexer/certs/root-ca.pem

say "on-disk alert and archive logs kept ${ALERT_DAYS} days"
cat > /etc/systemd/system/omniaxis-scdc-log-retention.service <<UNIT
[Unit]
Description=OmniAxis SCDC: remove Wazuh alert and archive logs older than ${ALERT_DAYS} days

[Service]
Type=oneshot
ExecStart=/usr/bin/find /var/ossec/logs/alerts /var/ossec/logs/archives -mindepth 2 -type f -mtime +${ALERT_DAYS} -delete
ExecStart=/usr/bin/find /var/ossec/logs/alerts /var/ossec/logs/archives -mindepth 1 -type d -empty -delete
UNIT
cat > /etc/systemd/system/omniaxis-scdc-log-retention.timer <<'UNIT'
[Unit]
Description=OmniAxis SCDC: daily log retention

[Timer]
OnCalendar=*-*-* 04:15:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
UNIT

say "off-host backup (restic)"
command -v restic >/dev/null || { DEBIAN_FRONTEND=noninteractive apt-get install -y -qq restic >/dev/null; }
install -m 0750 "$DEPLOY_DIR/omniaxis-scdc-backup.sh" /usr/local/sbin/omniaxis-scdc-backup
install -m 0644 "$DEPLOY_DIR/omniaxis-scdc-backup.service" /etc/systemd/system/
install -m 0644 "$DEPLOY_DIR/omniaxis-scdc-backup.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now omniaxis-scdc-log-retention.timer >/dev/null
BACKUP_ENV=/etc/omniaxis-scdc/backup.env
if [ -f "$BACKUP_ENV" ]; then
  [ "$(stat -c '%u %a' "$BACKUP_ENV")" = "0 600" ] || die "$BACKUP_ENV must be root-owned, mode 0600"
  /usr/local/sbin/omniaxis-scdc-backup init
  systemctl enable --now omniaxis-scdc-backup.timer >/dev/null
  say "off-host backup on: daily at 05:00 UTC"
else
  systemctl disable --now omniaxis-scdc-backup.timer >/dev/null 2>&1 || true
  say "off-host backup NOT configured: copy backup.env.example to $BACKUP_ENV (root, 0600), fill it in, and run this step again"
fi
say "done"
