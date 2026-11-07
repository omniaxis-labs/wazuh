#!/usr/bin/env bash
# Install Wazuh 4.14 (indexer, manager, dashboard) on this one node with the
# official installation assistant, which installs the signed packages from
# packages.wazuh.com. Idempotent: skipped when wazuh-manager is installed.
# Then binds every Wazuh listener that is not for agents to loopback.
export STEP=wazuh
. "$(dirname "$0")/lib.sh"
need_root; need_ubuntu; load_config

cd "$STATE_DIR"

if wazuh_installed; then
  say "wazuh-manager $(dpkg-query -W -f='${Version}' wazuh-manager) already installed; skipping the assistant"
else
  say "downloading the Wazuh $WAZUH_SERIES installation assistant"
  curl -fsSLo wazuh-install.sh "https://packages.wazuh.com/${WAZUH_SERIES}/wazuh-install.sh"
  sum="$(sha256sum wazuh-install.sh | cut -d' ' -f1)"
  say "wazuh-install.sh sha256 $sum"
  if [ -n "${WAZUH_INSTALL_SHA256:-}" ] && [ "$sum" != "$WAZUH_INSTALL_SHA256" ]; then
    die "wazuh-install.sh checksum mismatch"
  fi
  say "running the all-in-one install (15-30 minutes)"
  # Output goes to a root-only log: the summary prints the admin password.
  ( umask 077; bash ./wazuh-install.sh -a > "$STATE_DIR/wazuh-install.log" 2>&1 ) \
    || { tail -n 20 "$STATE_DIR/wazuh-install.log" | grep -viE 'password' >&2; die "installation assistant failed (log: $STATE_DIR/wazuh-install.log)"; }
  chmod 600 wazuh-install-files.tar "$STATE_DIR/wazuh-install.log"
  say "installed; passwords are in $STATE_DIR/wazuh-install-files.tar (root only)"
fi

installed="$(dpkg-query -W -f='${Version}' wazuh-manager)"
case "$installed" in
  "${WAZUH_VERSION}"-*) ;;
  *) say "WARNING: wazuh-manager is $installed, config pins $WAZUH_VERSION (see runbook: Upgrades)" ;;
esac

# Keep the stack on the pinned series: no unattended jumps.
for p in wazuh-manager wazuh-indexer wazuh-dashboard; do echo "$p hold" | dpkg --set-selections; done

# Admin API password, for scripts that manage the API (root only).
if [ ! -s "$STATE_DIR/wazuh-api-admin" ]; then
  ( umask 077
    tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt \
      | grep -A1 -E "api_username: 'wazuh'\s*$" | sed -n -E "s/^\s*api_password: '(.*)'\s*$/\1/p" | head -n1 \
      > "$STATE_DIR/wazuh-api-admin" )
  [ -s "$STATE_DIR/wazuh-api-admin" ] || die "could not read the API admin password from the install archive"
fi

changed=0
say "binding the Wazuh API to 127.0.0.1"
API_YAML=/var/ossec/api/configuration/api.yaml
if ! grep -qE "^host: *\['127.0.0.1'\]" "$API_YAML"; then
  set_yaml_key "$API_YAML" host "['127.0.0.1']"
  changed=1
fi

say "binding the dashboard to 127.0.0.1:8443 (private)"
DASH=/etc/wazuh-dashboard/opensearch_dashboards.yml
want_host=127.0.0.1
[ "${DASHBOARD_ACCESS:-tunnel}" = allowlist ] && want_host=0.0.0.0   # ufw limits it to DASHBOARD_CIDRS
if ! grep -qE "^server.host: *\"?${want_host}\"?$" "$DASH" || ! grep -qE '^server.port: *8443$' "$DASH"; then
  set_yaml_key "$DASH" server.host "$want_host"
  set_yaml_key "$DASH" server.port 8443
  systemctl restart wazuh-dashboard
fi

say "checking the indexer is loopback only"
grep -qE '^network.host: *"?127.0.0.1"?' /etc/wazuh-indexer/opensearch.yml \
  || die "wazuh-indexer network.host is not 127.0.0.1; fix /etc/wazuh-indexer/opensearch.yml"

if [ $changed = 1 ]; then systemctl restart wazuh-manager; fi
say "done"
