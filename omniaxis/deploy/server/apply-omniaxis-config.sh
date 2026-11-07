#!/usr/bin/env bash
# Install the OmniAxis ruleset, the portal integration and the managed
# ossec.conf block into a Wazuh 4.14 manager. Idempotent: run it again after
# any change in omniaxis/ and it converges. Used by install.sh on the server
# and by the docker-compose test stack.
#
# Env:
#   OMNIAXIS_DIR    path to the repo's omniaxis/ folder (default: two levels up)
#   PORTAL_URL      e.g. https://admin.omniaxislabs.com/api/wazuh/alerts
#   PORTAL_KEY_ID   label for the portal signing key (default scdc-wazuh-1)
#   NO_RESTART=1    do not restart the manager (the caller will)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OMNIAXIS_DIR="${OMNIAXIS_DIR:-$(cd "$HERE/../.." && pwd)}"
PORTAL_URL="${PORTAL_URL:?set PORTAL_URL}"
PORTAL_KEY_ID="${PORTAL_KEY_ID:-scdc-wazuh-1}"
W=/var/ossec
PY="$W/framework/python/bin/python3"
say() { echo "[omniaxis] $*"; }

[ -x "$W/bin/wazuh-control" ] || { echo "Wazuh manager is not installed at $W" >&2; exit 1; }
case "$PORTAL_URL" in https://*|http://mock-portal:*) ;; *) echo "PORTAL_URL must be https" >&2; exit 1 ;; esac
[[ "$PORTAL_KEY_ID" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || { echo "bad PORTAL_KEY_ID" >&2; exit 1; }

# 1. Decoders and rules.
install -o wazuh -g wazuh -m 0660 "$OMNIAXIS_DIR/ruleset/decoders/0900-omniaxis_scdc_decoders.xml" "$W/etc/decoders/"
install -o wazuh -g wazuh -m 0660 "$OMNIAXIS_DIR/ruleset/rules/0900-omniaxis_scdc_rules.xml" "$W/etc/rules/"
say "ruleset installed"

# 2. Portal integration.
install -o root -g wazuh -m 0750 "$OMNIAXIS_DIR/integrations/custom-scdc-portal/custom-scdc-portal" "$W/integrations/"
install -o root -g wazuh -m 0750 "$OMNIAXIS_DIR/integrations/custom-scdc-portal/custom-scdc-portal.py" "$W/integrations/"
install -d -o wazuh -g wazuh -m 0750 "$W/var/omniaxis" "$W/var/omniaxis/portal-spool"
say "integration installed"

# 3. Portal signing key (Ed25519). Generated once on this host; only the
#    public half ever leaves it.
install -d -o root -g wazuh -m 0750 "$W/etc/omniaxis"
KEY="$W/etc/omniaxis/portal-signing.key"
if [ ! -s "$KEY" ]; then
  umask 077
  "$PY" - "$KEY" <<'PY'
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
k = Ed25519PrivateKey.generate()
open(sys.argv[1], "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
PY
  say "portal signing key generated"
fi
chown root:wazuh "$KEY"; chmod 0640 "$KEY"
PUB="$("$PY" - "$KEY" <<'PY'
import sys, base64
from cryptography.hazmat.primitives import serialization
k = serialization.load_pem_private_key(open(sys.argv[1], "rb").read(), password=None)
print(base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode())
PY
)"
echo "$PUB" > "$W/etc/omniaxis/portal-signing.pub"
chmod 0644 "$W/etc/omniaxis/portal-signing.pub"
say "portal public key ($PORTAL_KEY_ID): $PUB"

# 4. Relay log directory read by logcollector (which runs as root).
install -d -m 2750 /var/log/omniaxis-scdc
if id scdc-intake >/dev/null 2>&1; then chown scdc-intake:wazuh /var/log/omniaxis-scdc; fi
touch /var/log/omniaxis-scdc/intake.log /var/log/omniaxis-scdc/relay.log
if id scdc-intake >/dev/null 2>&1; then chown scdc-intake:wazuh /var/log/omniaxis-scdc/*.log; fi
chmod 0640 /var/log/omniaxis-scdc/*.log

# 5. Managed ossec.conf block: drop the old one, append the new one.
CONF="$W/etc/ossec.conf"
TMP="$(mktemp)"
sed '/<!-- omniaxis:begin/,/<!-- omniaxis:end -->/d' "$CONF" > "$TMP"
sed -e "s#@PORTAL_URL@#${PORTAL_URL}#" -e "s#@PORTAL_KEY_ID@#${PORTAL_KEY_ID}#" \
  "$HERE/ossec-omniaxis.conf.tmpl" >> "$TMP"
if ! cmp -s "$TMP" "$CONF"; then
  cp -p "$CONF" "$CONF.omniaxis-backup"
  cat "$TMP" > "$CONF"
  say "ossec.conf updated (previous copy: $CONF.omniaxis-backup)"
fi
rm -f "$TMP"

# 6. Check the configuration before restarting.
"$W/bin/wazuh-analysisd" -t >/dev/null 2>&1 || { "$W/bin/wazuh-analysisd" -t; echo "analysisd config test failed" >&2; exit 1; }
say "configuration test passed"

if [ "${NO_RESTART:-0}" != "1" ]; then
  if command -v systemctl >/dev/null 2>&1 && systemctl is-enabled wazuh-manager >/dev/null 2>&1; then
    systemctl restart wazuh-manager
  else
    "$W/bin/wazuh-control" restart >/dev/null
  fi
  say "wazuh-manager restarted"
fi
