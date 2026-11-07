#!/usr/bin/env bash
# Every OmniAxis test, in order. Needs Docker and Node 24.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
step() { printf '\n=== %s\n' "$*"; }

step "ruleset: generator in sync"
python3 "$ROOT/ruleset/tools/gen_rules.py" --check

step "ruleset: wazuh-logtest fixtures (4.14.9 container)"
"$ROOT/ruleset/tests/test_in_container.sh" | tail -n 3

step "intake relay: typecheck and unit tests"
( cd "$ROOT/intake-relay" && npm ci --no-audit --no-fund --silent && npm run -s typecheck && npm test 2>&1 | grep -E '^ℹ (tests|pass|fail)' )

step "shared verifier: the portal package's own tests (vendored)"
( cd "$ROOT/intake-relay" && npm run -s test:vendor 2>&1 | grep -E 'Tests ' )

step "portal integration: unit tests (Wazuh's bundled Python)"
# The whole folder is mounted: the signer is checked against the vendored test vector.
docker run --rm -v "$ROOT:/o:ro" --entrypoint /var/ossec/framework/python/bin/python3 \
  wazuh/wazuh-manager:4.14.9 -m unittest discover -s /o/integrations/custom-scdc-portal/tests 2>&1 | tail -n 3

step "deploy: script syntax and config edits"
for f in "$ROOT"/deploy/server/*.sh "$ROOT"/deploy/agent/*.sh "$ROOT"/deploy/docker/*.sh; do bash -n "$f"; done
"$ROOT/deploy/server/tests/test_text_edits.sh"

step "end to end: relay -> Wazuh API -> rules -> signed portal push"
"$ROOT/deploy/docker/e2e.sh" 2>&1 | grep -E '^\[e2e\]|ok|->|product'

printf '\nALL TESTS PASSED\n'
