#!/usr/bin/env bash
# Checks the config-file edits the server scripts make, against the real
# Wazuh 4.14.9 files (api.yaml and ossec.conf from the manager image) and the
# documented formats of the dashboard config and wazuh-passwords.txt.
# Runs inside the manager image so the edits meet the real files and parsers.
#   omniaxis/deploy/server/tests/test_text_edits.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker run --rm -v "$HERE/..:/srv:ro" --entrypoint bash wazuh/wazuh-manager:4.14.9 -c '
set -euo pipefail
fail=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; fail=1; }
eval "$(sed -n "/^set_yaml_key()/,/^}/p" /srv/lib.sh)"
T=$(mktemp -d)

# 1. API bound to loopback, parsed by Wazuh API config loader.
cp /var/ossec/api/configuration/api.yaml $T/api.yaml
set_yaml_key $T/api.yaml host "['"'"'127.0.0.1'"'"']"
set_yaml_key $T/api.yaml host "['"'"'127.0.0.1'"'"']"   # idempotent
cd /var/ossec/api && /var/ossec/framework/python/bin/python3 -c "
import sys, yaml
c = yaml.safe_load(open(\"$T/api.yaml\"))
assert c[\"host\"] == [\"127.0.0.1\"], c
print(\"  ok   api.yaml host -> [127.0.0.1] (one key, parsed)\")"
[ "$(grep -c "^host:" $T/api.yaml)" = 1 ] && ok "single host line" || bad "duplicate host lines"

# 2. Dashboard bind and port.
printf "server.host: 0.0.0.0\nopensearch.hosts: https://127.0.0.1:9200\nserver.port: 443\nopensearch.ssl.verificationMode: certificate\n" > $T/dash.yml
set_yaml_key $T/dash.yml server.host 127.0.0.1
set_yaml_key $T/dash.yml server.port 8443
grep -qx "server.host: 127.0.0.1" $T/dash.yml && grep -qx "server.port: 8443" $T/dash.yml && grep -q "^opensearch.hosts: https://127.0.0.1:9200" $T/dash.yml \
  && ok "dashboard -> 127.0.0.1:8443, other keys untouched" || { cat $T/dash.yml; bad "dashboard edit"; }

# 3. API admin password from wazuh-passwords.txt (format of the 4.x assistant).
cat > $T/pw.txt <<EOF
# Admin user for the web user interface and Wazuh indexer. Use this user to log in to Wazuh dashboard
  indexer_username: '"'"'admin'"'"'
  indexer_password: '"'"'Idx.Pass*1'"'"'

# Password for wazuh API user
  api_username: '"'"'wazuh'"'"'
  api_password: '"'"'Api.Adm1n*Pw?'"'"'

# Password for wazuh-wui API user
  api_username: '"'"'wazuh-wui'"'"'
  api_password: '"'"'Wui.Pw*2'"'"'
EOF
got=$(grep -A1 -E "api_username: '"'"'wazuh'"'"'\s*$" $T/pw.txt | sed -n -E "s/^\s*api_password: '"'"'(.*)'"'"'\s*$/\1/p" | head -n1)
[ "$got" = "Api.Adm1n*Pw?" ] && ok "API admin password extracted (not wazuh-wui, not indexer)" || bad "password extraction got [$got]"
got=$(grep -A1 -E "indexer_username: '"'"'admin'"'"'\s*$" $T/pw.txt | sed -n -E "s/^\s*indexer_password: '"'"'(.*)'"'"'\s*$/\1/p" | head -n1)
[ "$got" = "Idx.Pass*1" ] && ok "indexer admin password extracted" || bad "indexer password extraction got [$got]"

# 3b. Indexer snapshot path, as 45-retention-backup.sh sets it.
printf "network.host: \"127.0.0.1\"\nnode.name: \"node-1\"\npath.data: /var/lib/wazuh-indexer\n" > $T/os.yml
set_yaml_key $T/os.yml path.repo "[\"/var/lib/wazuh-indexer-snapshots\"]"
set_yaml_key $T/os.yml path.repo "[\"/var/lib/wazuh-indexer-snapshots\"]"
[ "$(grep -c "^path.repo:" $T/os.yml)" = 1 ] && grep -qx "path.repo: \[\"/var/lib/wazuh-indexer-snapshots\"\]" $T/os.yml && grep -qx "path.data: /var/lib/wazuh-indexer" $T/os.yml \
  && ok "indexer path.repo set once, path.data untouched" || { cat $T/os.yml; bad "path.repo edit"; }

# 4. Agent enrolment password switch on the real ossec.conf.
cp /var/ossec/etc/ossec.conf $T/ossec.conf
sed -i -E "0,/<use_password>no<\/use_password>/s//<use_password>yes<\/use_password>/" $T/ossec.conf
[ "$(grep -c "<use_password>yes</use_password>" $T/ossec.conf)" = 1 ] && ok "auth use_password -> yes" || bad "use_password edit"

exit $fail
'
