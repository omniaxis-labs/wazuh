#!/usr/bin/env bash
# Applies the retention and snapshot settings to a real wazuh-indexer 4.14.9
# (OpenSearch 2.19.6) twice, then checks what the indexer holds. The security
# plugin is off here only because the server's certificates are not; the
# requests and bodies are the ones 45-retention-backup.sh sends.
#   omniaxis/deploy/server/tests/test_indexer_lifecycle.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE=wazuh/wazuh-indexer:4.14.9
NAME="scdc-lifecycle-test-$$"
PORT="${PORT:-19200}"
CONF="$(mktemp -d)"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$CONF"; }
trap cleanup EXIT

cat > "$CONF/opensearch.yml" <<'EOF'
network.host: 0.0.0.0
discovery.type: single-node
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer
path.repo: ["/var/lib/wazuh-indexer-snapshots"]
plugins.security.disabled: true
compatibility.override_main_response_version: true
EOF

docker run -d --name "$NAME" -p "127.0.0.1:$PORT:9200" \
  -e OPENSEARCH_JAVA_OPTS="-Xms512m -Xmx512m" \
  -v "$CONF/opensearch.yml:/usr/share/wazuh-indexer/config/opensearch.yml:ro" \
  --tmpfs /var/lib/wazuh-indexer-snapshots:uid=1000,gid=1000 \
  "$IMAGE" >/dev/null
URL="http://127.0.0.1:$PORT"
for _ in $(seq 1 90); do
  curl -sf "$URL/_cluster/health?wait_for_status=yellow&timeout=2s" >/dev/null 2>&1 && break
  sleep 2
done
curl -sf "$URL/_cluster/health?wait_for_status=yellow&timeout=30s" >/dev/null || { docker logs "$NAME" | tail -n 30; exit 1; }

fail=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; fail=1; }
q() { curl -sf "$URL$1"; }
put_index() { curl -sf -X PUT "$URL/$1" -H 'content-type: application/json' -d '{"settings":{"number_of_replicas":0}}' >/dev/null; }

# An index from before the policy existed must be brought under it too.
put_index wazuh-alerts-4.x-2026.11.01
put_index wazuh-monitoring-2026.44w

python3 -B "$HERE/../indexer_lifecycle.py" apply --url "$URL"
python3 -B "$HERE/../indexer_lifecycle.py" apply --url "$URL"   # converges

# A new day's index is caught by the template.
put_index wazuh-alerts-4.x-2026.11.02
sleep 2

j() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
[ "$(q /_plugins/_ism/policies/omniaxis-alerts | j "d['policy']['states'][0]['transitions'][0]['conditions']['min_index_age']")" = 90d ] \
  && ok "alert indices deleted after 90 days" || bad "alerts policy"
[ "$(q /_plugins/_ism/policies/omniaxis-other | j "d['policy']['states'][0]['transitions'][0]['conditions']['min_index_age']")" = 30d ] \
  && ok "archives, monitoring and statistics after 30 days" || bad "other policy"
for i in wazuh-alerts-4.x-2026.11.01 wazuh-alerts-4.x-2026.11.02; do
  [ "$(q "/_plugins/_ism/explain/$i" | j "d['$i'].get('index.plugins.index_state_management.policy_id') or d['$i'].get('policy_id')")" = omniaxis-alerts ] \
    && ok "$i managed by omniaxis-alerts" || bad "$i not managed"
done
[ "$(q /_plugins/_ism/explain/wazuh-monitoring-2026.44w | j "d['wazuh-monitoring-2026.44w'].get('index.plugins.index_state_management.policy_id') or d['wazuh-monitoring-2026.44w'].get('policy_id')")" = omniaxis-other ] \
  && ok "existing monitoring index managed by omniaxis-other" || bad "monitoring index not managed"
[ "$(q /_snapshot/omniaxis-fs | j "d['omniaxis-fs']['type']")" = fs ] && ok "snapshot repository registered" || bad "repository"
[ "$(q /_plugins/_sm/policies/omniaxis-daily | j "d['sm_policy']['deletion']['condition']['max_count']")" = 14 ] \
  && ok "daily snapshots, 14 kept" || bad "snapshot policy"
[ "$(q /_plugins/_sm/policies/omniaxis-daily | j "d['sm_policy']['enabled']")" = True ] && ok "snapshot policy enabled" || bad "snapshot policy disabled"
curl -sf -X PUT "$URL/_snapshot/omniaxis-fs/test-now?wait_for_completion=true" -H 'content-type: application/json' \
  -d '{"indices":"wazuh-*","include_global_state":false}' | j "d['snapshot']['state']" | grep -qx SUCCESS \
  && ok "a snapshot into the repository succeeds" || bad "snapshot failed"

[ $fail = 0 ] && echo "  indexer lifecycle: all passed" || exit 1
