#!/usr/bin/env bash
# Builds the golden set in a throwaway Wazuh 4.14.9 manager with the SCDC
# ruleset loaded, then checks it: every scenario raised an alert, both labels
# appear in every class, injection items are present, and the file matches
# the shape the admin portal's importer accepts.
#   omniaxis/golden/test_export.sh [out.json]
set -euo pipefail
IMAGE="${WAZUH_MANAGER_IMAGE:-wazuh/wazuh-manager:4.14.9}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULESET="$(cd "$HERE/../ruleset" && pwd)"
OUT="${1:-$(mktemp -d)/golden.json}"
NAME="omniaxis-golden-$$"
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$NAME" \
  -v "$RULESET/decoders/0900-omniaxis_scdc_decoders.xml:/var/ossec/etc/decoders/0900-omniaxis_scdc_decoders.xml:ro" \
  -v "$RULESET/rules/0900-omniaxis_scdc_rules.xml:/var/ossec/etc/rules/0900-omniaxis_scdc_rules.xml:ro" \
  -v "$RULESET/tests:/omniaxis/ruleset/tests:ro" \
  -v "$HERE:/omniaxis/golden:ro" \
  "$IMAGE" >/dev/null
for _ in $(seq 1 90); do
  docker exec "$NAME" test -S /var/ossec/queue/sockets/logtest 2>/dev/null && break
  sleep 2
done
docker exec "$NAME" test -S /var/ossec/queue/sockets/logtest || { echo "logtest socket never appeared" >&2; exit 1; }

docker exec "$NAME" /var/ossec/framework/python/bin/python3 -B /omniaxis/golden/export_golden.py \
  "${GOLDEN_SET_VERSION:-2026.11.10-1}" /tmp/golden.json ${GOLDEN_REPORT:+--report}
docker cp "$NAME:/tmp/golden.json" "$OUT" >/dev/null

python3 -B - "$OUT" <<'PY'
import json, re, sys
d = json.load(open(sys.argv[1]))
fail = 0
def ok(c, m):
    global fail
    print(("  ok   " if c else "  FAIL ") + m)
    fail |= not c
items = d["items"]
CLASSES = {"credential_attack", "privilege_misuse", "web_attack", "malware_or_integrity", "recon", "product_security_event", "system_change"}
ok(re.fullmatch(r"[0-9A-Za-z.\-]{1,40}", d["set_version"]) is not None, f"set version {d['set_version']}")
ok(len(items) >= 50, f"{len(items)} scenarios (at least 50)")
ok(all(re.fullmatch(r"g_[a-z0-9_]{1,60}", i["id"]) for i in items), "ids match the importer's pattern")
ok(all(i["alert_class"] in CLASSES for i in items), "every class is one the agents know")
ok(all(i["alert"]["id"] in {b["id"] for b in i["bundle"]} for i in items), "every shown alert is in its bundle")
ok(all(i["alert"]["rule"].get("level", 0) > 0 for i in items), "every scenario raised an alert")
used = {i["alert_class"] for i in items}
for c in sorted(used):
    labels = {i["label"] for i in items if i["alert_class"] == c}
    ok(labels == {"malicious", "benign"}, f"{c}: both malicious and benign look-alikes")
ok(sum(i["injection"] for i in items) >= 3, "injection scenarios present")
ok(all(i["label"] == "malicious" for i in items if i["injection"]), "injection scenarios stay labelled malicious")
print(f"  golden set: {len(items)} items, {sum(i['label'] == 'malicious' for i in items)} malicious, written to {sys.argv[1]}")
sys.exit(1 if fail else 0)
PY
