#!/usr/bin/env bash
# Load the OmniAxis decoders and rules into a throwaway Wazuh 4.14.9 manager
# container and run every fixture through the logtest socket.
#
#   omniaxis/ruleset/tests/test_in_container.sh
#
# Needs Docker. Exits non-zero on any failing fixture or a ruleset load error.
set -euo pipefail

IMAGE="${WAZUH_MANAGER_IMAGE:-wazuh/wazuh-manager:4.14.9}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULESET="$(cd "$HERE/.." && pwd)"
NAME="omniaxis-logtest-$$"

python3 "$RULESET/tools/gen_rules.py" --check

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$NAME" \
  -v "$RULESET/decoders/0900-omniaxis_scdc_decoders.xml:/var/ossec/etc/decoders/0900-omniaxis_scdc_decoders.xml:ro" \
  -v "$RULESET/rules/0900-omniaxis_scdc_rules.xml:/var/ossec/etc/rules/0900-omniaxis_scdc_rules.xml:ro" \
  -v "$HERE:/omniaxis-tests:ro" \
  "$IMAGE" >/dev/null

echo "waiting for wazuh-analysisd and the logtest socket..."
for _ in $(seq 1 90); do
  if docker exec "$NAME" test -S /var/ossec/queue/sockets/logtest 2>/dev/null; then break; fi
  sleep 2
done
docker exec "$NAME" test -S /var/ossec/queue/sockets/logtest || {
  docker exec "$NAME" tail -n 50 /var/ossec/logs/ossec.log || true
  echo "logtest socket never appeared" >&2; exit 1; }

# Any decoder or rule load problem is a failure, not a warning.
if docker exec "$NAME" grep -E "(ERROR|CRITICAL|WARNING).*(0900-omniaxis|omniaxis-scdc|rule.*1009|rule.*1001)" /var/ossec/logs/ossec.log; then
  echo "ruleset load errors above" >&2; exit 1
fi

docker exec "$NAME" /var/ossec/framework/python/bin/python3 /omniaxis-tests/run_logtest.py /omniaxis-tests/fixtures
