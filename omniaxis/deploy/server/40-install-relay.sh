#!/usr/bin/env bash
# Install the intake relay (Node, pinned and checksum-verified), its systemd
# unit, and Caddy (official signed apt repository) in front of it. Idempotent.
export STEP=relay
. "$(dirname "$0")/lib.sh"
need_root; need_ubuntu; load_config
id scdc-intake >/dev/null 2>&1 || die "run 30-configure-wazuh.sh first"
export DEBIAN_FRONTEND=noninteractive

# --- Node -------------------------------------------------------------------
case "$(uname -m)" in x86_64) NARCH=x64 ;; aarch64) NARCH=arm64 ;; *) die "unsupported CPU $(uname -m)" ;; esac
NODE_DIR="/opt/node-v${NODE_VERSION}-linux-${NARCH}"
if [ ! -x "$NODE_DIR/bin/node" ]; then
  say "installing Node $NODE_VERSION"
  tmp="$(mktemp -d)"
  base="https://nodejs.org/dist/v${NODE_VERSION}"
  tarball="node-v${NODE_VERSION}-linux-${NARCH}.tar.xz"
  curl -fsSLo "$tmp/$tarball" "$base/$tarball"
  curl -fsSLo "$tmp/SHASUMS256.txt" "$base/SHASUMS256.txt"
  (cd "$tmp" && grep " ${tarball}\$" SHASUMS256.txt | sha256sum -c -) || die "Node checksum mismatch"
  tar -xJf "$tmp/$tarball" -C /opt
  chown -R root:root "$NODE_DIR"
  rm -rf "$tmp"
fi
ln -sfn "$NODE_DIR" /opt/node
"$NODE_DIR/bin/node" --version | grep -qx "v${NODE_VERSION}" || die "node version mismatch"

# --- Relay code ---------------------------------------------------------------
say "installing relay code to /opt/omniaxis-intake-relay"
install -d -o root -g root -m 0755 /opt/omniaxis-intake-relay
rsync_like() { rm -rf /opt/omniaxis-intake-relay/src && cp -r "$OMNIAXIS_DIR/intake-relay/src" /opt/omniaxis-intake-relay/src; }
rsync_like
install -o root -g root -m 0644 "$OMNIAXIS_DIR/intake-relay/package.json" /opt/omniaxis-intake-relay/
[ -f "$OMNIAXIS_DIR/intake-relay/README.md" ] && install -o root -g root -m 0644 "$OMNIAXIS_DIR/intake-relay/README.md" /opt/omniaxis-intake-relay/
chown -R root:root /opt/omniaxis-intake-relay; chmod -R go-w /opt/omniaxis-intake-relay

# --- Relay config (public keys only) -------------------------------------------
CFG=/etc/omniaxis-intake/config.json
if [ ! -f "$CFG" ]; then
  say "writing $CFG with no product keys yet (add them per the runbook)"
  products="$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["products"]))' "$OMNIAXIS_DIR/ruleset/tools/products.json")"
  cat > "$CFG" <<EOF
{
  "listen": { "host": "127.0.0.1", "port": 8787 },
  "path": "/v1/events",
  "products": $products,
  "keys": [],
  "sink": "api",
  "api": {
    "baseUrl": "https://127.0.0.1:55000",
    "user": "scdc-intake",
    "passwordFile": "/etc/omniaxis-intake/api-password",
    "caFile": "/etc/omniaxis-intake/wazuh-api.crt"
  },
  "intakeLog": "/var/log/omniaxis-scdc/intake.log",
  "relayLog": "/var/log/omniaxis-scdc/relay.log",
  "ratePerMinute": 600
}
EOF
fi
chown root:scdc-intake "$CFG"; chmod 0640 "$CFG"
# Validate before (re)starting: refuses unknown products and bad keys.
sudo -u scdc-intake /opt/node/bin/node --disable-warning=ExperimentalWarning -e '
  import("/opt/omniaxis-intake-relay/src/config.ts").then(m => { const c = m.loadConfig(process.argv[1]); console.log(`config ok: ${c.keys.length} key(s), sink=${c.sink}`); })
' "$CFG" || die "relay config is invalid"

# --- Log rotation -----------------------------------------------------------
cat > /etc/logrotate.d/omniaxis-scdc <<'EOF'
/var/log/omniaxis-scdc/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 scdc-intake wazuh
}
EOF

# --- systemd unit -----------------------------------------------------------
install -o root -g root -m 0644 "$DEPLOY_DIR/omniaxis-intake-relay.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable omniaxis-intake-relay >/dev/null
systemctl restart omniaxis-intake-relay
sleep 2
curl -sf http://127.0.0.1:8787/healthz >/dev/null || { journalctl -u omniaxis-intake-relay -n 20 --no-pager; die "relay did not come up"; }
say "relay up on 127.0.0.1:8787"

# --- Caddy (TLS on 443, one path) ----------------------------------------------
if ! dpkg -s caddy >/dev/null 2>&1; then
  say "installing Caddy from its signed apt repository"
  curl -fsSL 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -fsSL 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  grep -q 'signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg' /etc/apt/sources.list.d/caddy-stable.list || die "unexpected Caddy repo file"
  apt-get update -q
  apt-get -y -q install caddy
fi
install -d -o caddy -g caddy -m 0750 /var/log/caddy
sed -e "s/@HOSTNAME@/${SCDC_INTAKE_HOSTNAME}/" -e "s/@ACME_EMAIL@/${ACME_EMAIL}/" "$DEPLOY_DIR/Caddyfile.tmpl" > /etc/caddy/Caddyfile.new
caddy validate --config /etc/caddy/Caddyfile.new --adapter caddyfile >/dev/null || die "Caddyfile invalid"
mv /etc/caddy/Caddyfile.new /etc/caddy/Caddyfile
# The admin endpoint is off, so restart rather than reload.
systemctl enable caddy >/dev/null
systemctl restart caddy
say "Caddy serving https://${SCDC_INTAKE_HOSTNAME}/v1/events"
say "done"
