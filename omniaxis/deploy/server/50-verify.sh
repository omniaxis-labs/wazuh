#!/usr/bin/env bash
# Read-only checks of a finished SCDC server. Exit 1 on any failure.
export STEP=verify
. "$(dirname "$0")/lib.sh"
need_root; load_config
fail=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; fail=1; }
warn() { echo "  WARN $*"; }

listeners="$(ss -H -ltn | awk '{print $4}')"
public_port() { echo "$listeners" | grep -E "^(0\.0\.0\.0|\*|\[::\]):$1$" >/dev/null; }
local_port() { echo "$listeners" | grep -E "^(127\.0\.0\.1|\[::1\]):$1$" >/dev/null; }

for p in 55000 9200 9300 8787; do
  if public_port "$p"; then bad "port $p listens on all interfaces"; elif local_port "$p"; then ok "port $p is loopback only"; else bad "port $p is not listening"; fi
done
if [ "${DASHBOARD_ACCESS:-tunnel}" = tunnel ]; then
  if public_port 8443; then bad "dashboard listens on all interfaces"; elif local_port 8443; then ok "dashboard is loopback only (8443)"; else bad "dashboard not listening on 8443"; fi
else
  public_port 8443 && ok "dashboard on 8443, limited by ufw to DASHBOARD_CIDRS" || bad "dashboard not listening on 8443"
fi
public_port 443 && ok "Caddy listening on 443" || bad "nothing on 443"

ufw status | grep -q "Status: active" && ok "ufw active" || bad "ufw inactive"
ufw status | grep -E '^(1514|1515)/tcp +ALLOW +Anywhere' >/dev/null && bad "agent ports open to anywhere" || ok "agent ports limited to AGENT_CIDRS"
ufw status | grep -E '^22/tcp +ALLOW +Anywhere' >/dev/null && bad "SSH open to anywhere" || ok "SSH limited"

sshd -T 2>/dev/null | grep -qx 'passwordauthentication no' && ok "SSH password login off" || bad "SSH password login on"
systemctl is-active -q unattended-upgrades && ok "unattended-upgrades active" || bad "unattended-upgrades inactive"

for s in wazuh-manager wazuh-indexer wazuh-dashboard omniaxis-intake-relay caddy; do
  systemctl is-active -q "$s" && ok "$s active" || bad "$s not active"
done

grep -q '<use_password>yes</use_password>' /var/ossec/etc/ossec.conf && ok "agent enrolment needs a password" || bad "agent enrolment open"
grep -q 'omniaxis:begin' /var/ossec/etc/ossec.conf && ok "omniaxis ossec.conf block present" || bad "omniaxis block missing"
[ -f /var/ossec/etc/rules/0900-omniaxis_scdc_rules.xml ] && ok "SCDC rules installed" || bad "SCDC rules missing"
[ "$(stat -c '%a %U' /etc/omniaxis-intake/api-password 2>/dev/null)" = "400 scdc-intake" ] && ok "relay API password file 0400" || bad "relay API password file permissions"
[ "$(stat -c '%a' /var/ossec/etc/omniaxis/portal-signing.key 2>/dev/null)" = 640 ] && ok "portal signing key 0640 root:wazuh" || bad "portal signing key permissions"

# Retention, snapshots and the off-host copy (45-retention-backup.sh).
grep -qE '^path.repo: *\["?/var/lib/wazuh-indexer-snapshots"?\]' /etc/wazuh-indexer/opensearch.yml && ok "indexer snapshot path set" || bad "indexer path.repo missing"
idx() { curl -s --cacert /etc/wazuh-indexer/certs/root-ca.pem -K <(printf 'user = "admin:%s"\n' "$(cat "$STATE_DIR/wazuh-indexer-admin")") "https://127.0.0.1:9200$1"; }
for p in omniaxis-alerts omniaxis-other; do
  idx "/_plugins/_ism/policies/$p" | grep -q '"policy_id":"'"$p"'"' && ok "retention policy $p" || bad "retention policy $p missing"
done
idx /_plugins/_sm/policies/omniaxis-daily | grep -q '"enabled":true' && ok "daily indexer snapshots on" || bad "snapshot policy missing or off"
systemctl is-active -q omniaxis-scdc-log-retention.timer && ok "log retention timer active" || bad "log retention timer inactive"
if [ -f /etc/omniaxis-scdc/backup.env ]; then
  systemctl is-active -q omniaxis-scdc-backup.timer && ok "off-host backup timer active" || bad "off-host backup timer inactive"
  [ "$(systemctl show -p Result --value omniaxis-scdc-backup.service)" = success ] && ok "last off-host backup succeeded (or none yet)" || bad "last off-host backup failed: journalctl -u omniaxis-scdc-backup"
else
  warn "off-host backup not configured (/etc/omniaxis-scdc/backup.env)"
fi

# The relay refuses an unsigned request and logs it for Wazuh.
before="$(wc -l < /var/log/omniaxis-scdc/relay.log)"
code="$(curl -s -o /dev/null -w '%{http_code}' -H 'content-type: application/json' -d '{}' http://127.0.0.1:8787/api/intake/v1)"
[ "$code" = 400 ] && ok "relay refuses an unsigned request (400)" || bad "relay answered $code to an unsigned request"
sleep 1
[ "$(wc -l < /var/log/omniaxis-scdc/relay.log)" -gt "$before" ] && ok "refusal logged to relay.log" || bad "refusal not logged"

code="$(curl -s -o /dev/null -w '%{http_code}' "https://${SCDC_INTAKE_HOSTNAME}/" || true)"
[ "$code" = 404 ] && ok "public host serves nothing but /api/intake/v1" || bad "https://${SCDC_INTAKE_HOSTNAME}/ answered $code"

[ $fail = 0 ] && say "all checks passed" || die "some checks failed"
