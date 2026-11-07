#!/usr/bin/env bash
# Enrol a company host (first: the gate host) as a Wazuh 4.14 agent of the
# SCDC, with a product label carried on every alert. Idempotent.
#
#   sudo SCDC_MANAGER=<scdc server address> PRODUCT=company \
#        ENROL_PASSWORD_FILE=/root/scdc-authd.pass ./enrol-agent.sh
#
# The enrolment password file is copied from the SCDC server
# (/var/ossec/etc/authd.pass) out of band and deleted after enrolment.
#
# The gate host is busy (CI and the gate coordinator), so the agent runs
# with a CPU and memory cap and at low priority.
set -euo pipefail

SCDC_MANAGER="${SCDC_MANAGER:?address of the SCDC server}"
# The portal accepts musterward, omniaxis, rackhand, crosswalk or company.
# Shared company hosts such as the gate host are "company".
PRODUCT="${PRODUCT:-company}"
ENROL_PASSWORD_FILE="${ENROL_PASSWORD_FILE:?path to the enrolment password file}"
AGENT_NAME="${AGENT_NAME:-$(hostname -s)}"
WAZUH_VERSION="${WAZUH_VERSION:-4.14.9}"
CPU_QUOTA="${CPU_QUOTA:-25%}"
MEMORY_MAX="${MEMORY_MAX:-512M}"
say() { echo "[agent] $*"; }

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
case "$PRODUCT" in musterward|omniaxis|rackhand|crosswalk|company) ;; *) echo "PRODUCT must be musterward, omniaxis, rackhand, crosswalk or company" >&2; exit 1 ;; esac
[[ "$AGENT_NAME" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || { echo "bad AGENT_NAME" >&2; exit 1; }
[ -s "$ENROL_PASSWORD_FILE" ] || { echo "missing $ENROL_PASSWORD_FILE" >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive

if [ ! -f /usr/share/keyrings/wazuh.gpg ]; then
  say "adding the Wazuh signed apt repository"
  curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
  chmod 644 /usr/share/keyrings/wazuh.gpg
fi
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update -q

if ! dpkg -s wazuh-agent >/dev/null 2>&1; then
  say "installing wazuh-agent $WAZUH_VERSION"
  WAZUH_MANAGER="$SCDC_MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" \
  WAZUH_REGISTRATION_PASSWORD="$(cat "$ENROL_PASSWORD_FILE")" \
    apt-get -y -q install "wazuh-agent=${WAZUH_VERSION}-1"
fi
echo "wazuh-agent hold" | dpkg --set-selections

say "product label: $PRODUCT"
CONF=/var/ossec/etc/ossec.conf
TMP="$(mktemp)"
sed '/<!-- omniaxis:begin/,/<!-- omniaxis:end -->/d' "$CONF" > "$TMP"
cat >> "$TMP" <<EOF
<!-- omniaxis:begin (managed by omniaxis/deploy/agent/enrol-agent.sh) -->
<ossec_config>
  <labels>
    <label key="product">${PRODUCT}</label>
  </labels>
</ossec_config>
<!-- omniaxis:end -->
EOF
if ! cmp -s "$TMP" "$CONF"; then cat "$TMP" > "$CONF"; fi
rm -f "$TMP"

say "resource caps for a busy host: CPUQuota=$CPU_QUOTA MemoryMax=$MEMORY_MAX"
install -d /etc/systemd/system/wazuh-agent.service.d
cat > /etc/systemd/system/wazuh-agent.service.d/10-omniaxis-limits.conf <<EOF
[Service]
CPUQuota=${CPU_QUOTA}
MemoryMax=${MEMORY_MAX}
Nice=10
IOSchedulingClass=idle
EOF
systemctl daemon-reload
systemctl enable wazuh-agent >/dev/null
systemctl restart wazuh-agent
sleep 5
if grep -q "Valid key received" /var/ossec/logs/ossec.log || [ -s /var/ossec/etc/client.keys ]; then
  say "enrolled as $AGENT_NAME; delete $ENROL_PASSWORD_FILE now"
else
  say "not enrolled yet; check /var/ossec/logs/ossec.log and that this host's address is in AGENT_CIDRS"
  exit 1
fi
