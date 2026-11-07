#!/usr/bin/env bash
# End-to-end test of the SCDC path on a local Wazuh 4.14.9 manager:
#   signed product event -> intake relay -> Wazuh API POST /events -> OmniAxis rules
#   -> alert -> integratord custom-scdc-portal -> signed POST to a mock portal
# Needs Docker and Node 24. Cleans up after itself (KEEP=1 keeps the stack).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
export RELAY_CONFIG="$TMP/config.json"
# Random per run; the stack is torn down afterwards. Meets Wazuh's password rules.
E2E_API_PASSWORD="E2e.$(openssl rand -hex 12)Aa1"; export E2E_API_PASSWORD
export RELAY_PORT="${RELAY_PORT:-18787}" MOCK_PORTAL_PORT="${MOCK_PORTAL_PORT:-19000}"
DC=(docker compose -f "$HERE/docker-compose.yml")
EXEC=("${DC[@]}" exec -T wazuh-manager)
say() { echo "[e2e] $*"; }

cleanup() {
  status=$?
  if [ $status -ne 0 ]; then
    say "FAILED; recent manager log:"
    "${EXEC[@]}" tail -n 30 /var/ossec/logs/ossec.log 2>/dev/null || true
    "${EXEC[@]}" tail -n 20 /var/ossec/logs/integrations.log 2>/dev/null || true
    "${DC[@]}" --profile relay logs --tail 20 intake-relay 2>/dev/null || true
  fi
  if [ "${KEEP:-0}" != "1" ]; then "${DC[@]}" --profile relay down -v >/dev/null 2>&1 || true; fi
  rm -rf "$TMP"
  exit $status
}
trap cleanup EXIT

node "$HERE/e2e-driver.mjs" keygen "$TMP"
"${DC[@]}" --profile relay down -v >/dev/null 2>&1 || true
"${DC[@]}" up -d wazuh-manager mock-portal

say "waiting for the Wazuh API to accept logins (every daemon up)"
for _ in $(seq 1 120); do
  code="$("${EXEC[@]}" curl -sk -o /dev/null -w '%{http_code}' -u "wazuh-wui:$E2E_API_PASSWORD" -X POST https://127.0.0.1:55000/security/user/authenticate 2>/dev/null || true)"
  [ "$code" = "200" ] && break
  sleep 2
done
[ "$code" = "200" ] || { say "API never became ready"; "${EXEC[@]}" /var/ossec/bin/wazuh-control status || true; exit 1; }

say "creating the least-privilege intake API user"
# The per-run API admin; production reads its own from a root-only file.
"${EXEC[@]}" bash -c 'umask 077; printf %s "$API_PASSWORD" > /tmp/admin-pw && \
  /var/ossec/framework/python/bin/python3 /omniaxis/deploy/server/create-intake-api-user.py \
    --admin-user wazuh-wui --admin-password-file /tmp/admin-pw \
    --password-file /run/omniaxis-intake/api-password --owner 1000 && rm -f /tmp/admin-pw'

say "the intake user can ingest but cannot see agents (RBAC filters to zero items)"
sleep 3  # the API caches security lookups briefly after a new user is created
"${EXEC[@]}" bash -c 'P=$(cat /run/omniaxis-intake/api-password); T=$(curl -sk -u "scdc-intake:$P" -X POST https://127.0.0.1:55000/security/user/authenticate | /var/ossec/framework/python/bin/python3 -c "import sys,json;print(json.load(sys.stdin)[\"data\"][\"token\"])"); \
  curl -sk -H "Authorization: Bearer $T" https://127.0.0.1:55000/agents | /var/ossec/framework/python/bin/python3 -c "import sys,json; d=json.load(sys.stdin)[\"data\"]; assert d[\"total_affected_items\"]==0, d; print(\"GET /agents as scdc-intake -> 0 items\")"'

"${DC[@]}" --profile relay up -d intake-relay
say "waiting for the relay"
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$RELAY_PORT/healthz" >/dev/null 2>&1 && break
  sleep 1
done

E2E_RUN="$(date +%s)" node "$HERE/e2e-driver.mjs" send "$TMP" "http://127.0.0.1:$RELAY_PORT"

say "waiting for the alerts"
found=0
for _ in $(seq 1 45); do
  if "${EXEC[@]}" grep -q '"id":"100111"' /var/ossec/logs/alerts/alerts.json 2>/dev/null \
     && "${EXEC[@]}" grep -q '"id":"100901"' /var/ossec/logs/alerts/alerts.json 2>/dev/null; then found=1; break; fi
  sleep 2
done
[ $found = 1 ] || { say "expected alerts 100111 and 100901 in alerts.json"; "${EXEC[@]}" tail -n 5 /var/ossec/logs/alerts/alerts.json || true; exit 1; }
say "alerts.json has the SEV1 alert (100111) and the relay refusal (100901)"
"${EXEC[@]}" grep '"id":"100111"' /var/ossec/logs/alerts/alerts.json | tail -1 | \
  "${EXEC[@]}" /var/ossec/framework/python/bin/python3 -c 'import sys,json; a=json.loads(sys.stdin.readline()); assert a["data"]["product"]=="musterward", a; assert a["location"]=="API-Webhook"; assert a["rule"]["level"]==13; print("alert carries product=musterward at level 13 from API-Webhook")'

say "waiting for the signed portal push"
PUB="$("${EXEC[@]}" cat /var/ossec/etc/omniaxis/portal-signing.pub)"
for _ in $(seq 1 30); do
  if node "$HERE/e2e-driver.mjs" check-portal "http://127.0.0.1:$MOCK_PORTAL_PORT" "$PUB" "$TMP" 2>/dev/null; then ok=1; break; fi
  sleep 2
done
[ "${ok:-0}" = 1 ] || node "$HERE/e2e-driver.mjs" check-portal "http://127.0.0.1:$MOCK_PORTAL_PORT" "$PUB" "$TMP"

say "PASS"
