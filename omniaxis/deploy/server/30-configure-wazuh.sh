#!/usr/bin/env bash
# OmniAxis configuration on top of the stock manager. Idempotent.
#  - ruleset, portal integration, signing key, managed ossec.conf block
#  - agent enrolment protected by a password
#  - the relay's least-privilege API user
export STEP=configure
. "$(dirname "$0")/lib.sh"
need_root; load_config
wazuh_installed || die "run 20-install-wazuh.sh first"

say "relay system user"
id scdc-intake >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin scdc-intake
install -d -o root -g scdc-intake -m 0750 /etc/omniaxis-intake

say "ruleset, integration and ossec.conf block"
OMNIAXIS_DIR="$OMNIAXIS_DIR" PORTAL_URL="$PORTAL_URL" PORTAL_KEY_ID="${PORTAL_KEY_ID:-scdc-wazuh-1}" NO_RESTART=1 \
  bash "$DEPLOY_DIR/apply-omniaxis-config.sh"

say "agent enrolment requires a password"
AUTHD_PASS=/var/ossec/etc/authd.pass
if [ ! -s "$AUTHD_PASS" ]; then
  ( umask 077; openssl rand -base64 32 | tr -d '\n' > "$AUTHD_PASS" )
  say "generated $AUTHD_PASS (copy it to the agent host out of band; never paste it into chat)"
fi
chown root:wazuh "$AUTHD_PASS"; chmod 0640 "$AUTHD_PASS"
CONF=/var/ossec/etc/ossec.conf
if ! grep -q '<use_password>yes</use_password>' "$CONF"; then
  sed -i -E '0,/<use_password>no<\/use_password>/s//<use_password>yes<\/use_password>/' "$CONF"
fi
grep -q '<use_password>yes</use_password>' "$CONF" || die "could not enable <use_password> in the <auth> block"

say "restarting wazuh-manager"
/var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1 || { /var/ossec/bin/wazuh-analysisd -t; die "config test failed"; }
systemctl restart wazuh-manager

say "waiting for the API"
for _ in $(seq 1 60); do
  code="$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:55000/ || true)"
  [ "$code" = 401 ] && break
  sleep 3
done
sleep 10  # every daemon must be up before the API accepts logins

say "relay API user (event:ingest only)"
/var/ossec/framework/python/bin/python3 "$DEPLOY_DIR/create-intake-api-user.py" \
  --admin-user wazuh --admin-password-file "$STATE_DIR/wazuh-api-admin" \
  --password-file /etc/omniaxis-intake/api-password --owner scdc-intake

# The relay pins the API's own certificate; give it a copy it can read.
install -o root -g scdc-intake -m 0640 /var/ossec/api/configuration/ssl/server.crt /etc/omniaxis-intake/wazuh-api.crt

say "portal public key, for the portal's configuration:"
echo "    key id: ${PORTAL_KEY_ID:-scdc-wazuh-1}"
echo "    public: $(cat /var/ossec/etc/omniaxis/portal-signing.pub)"
say "done"
