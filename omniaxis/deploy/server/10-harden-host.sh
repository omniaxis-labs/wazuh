#!/usr/bin/env bash
# Host hardening for the SCDC server. Idempotent.
#  - security updates applied now and unattended from then on
#  - SSH: keys only, no root password login (with a lock-out guard)
#  - ufw: deny incoming by default; open only what the SCDC needs
#  - a few kernel network settings
export STEP=harden
. "$(dirname "$0")/lib.sh"
need_root; need_ubuntu; load_config

export DEBIAN_FRONTEND=noninteractive

say "updating packages"
apt-get update -q
apt-get -y -q upgrade
apt-get -y -q install unattended-upgrades apt-listchanges ufw curl gnupg ca-certificates jq openssl debian-keyring

say "unattended security updates"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
cat > /etc/apt/apt.conf.d/52omniaxis-unattended <<'EOF'
// Security updates only; Wazuh, Caddy and Node are pinned and upgraded by hand
// (runbook: "Upgrades"), so a stack upgrade never happens unattended.
Unattended-Upgrade::Allowed-Origins {
  "${distro_id}:${distro_codename}-security";
  "${distro_id}ESMApps:${distro_codename}-apps-security";
  "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist { "wazuh-.*"; "caddy"; };
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "09:30";
EOF
# 09:30 UTC is 04:30/05:30 US Eastern.
systemctl enable --now unattended-upgrades >/dev/null

say "SSH: keys only"
# Lock-out guard: refuse to turn passwords off unless root or a sudo user
# already has an authorised key.
has_key=0
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -s "$f" ] && grep -qE '^(ssh-(ed25519|rsa)|ecdsa-|sk-)' "$f" && has_key=1
done
[ $has_key = 1 ] || die "no authorised SSH key found; add one before hardening SSH"
cat > /etc/ssh/sshd_config.d/10-omniaxis-scdc.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding local
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
sshd -t || die "sshd configuration test failed"
systemctl reload ssh 2>/dev/null || systemctl reload sshd

say "firewall"
ufw --force default deny incoming >/dev/null
ufw --force default allow outgoing >/dev/null
# Rebuild our rules from config each run so removed CIDRs are closed again.
for n in $(ufw status numbered | grep -E 'omniaxis-scdc' | sed -E 's/^\[ *([0-9]+)\].*/\1/' | sort -rn); do
  ufw --force delete "$n" >/dev/null
done
for c in ${ADMIN_SSH_CIDRS:-}; do ufw allow from "$c" to any port 22 proto tcp comment 'omniaxis-scdc ssh' >/dev/null; done
for c in ${AGENT_CIDRS:-}; do
  ufw allow from "$c" to any port 1514 proto tcp comment 'omniaxis-scdc agent events' >/dev/null
  ufw allow from "$c" to any port 1515 proto tcp comment 'omniaxis-scdc agent enrolment' >/dev/null
done
if [ "${DASHBOARD_ACCESS:-tunnel}" = allowlist ]; then
  for c in ${DASHBOARD_CIDRS:-}; do ufw allow from "$c" to any port 8443 proto tcp comment 'omniaxis-scdc dashboard' >/dev/null; done
fi
# Public: the intake relay only (Caddy). 80 serves the ACME challenge and
# redirects to 443.
ufw allow 443/tcp comment 'omniaxis-scdc intake' >/dev/null
ufw allow 80/tcp comment 'omniaxis-scdc acme' >/dev/null
if [ "${TAILSCALE:-no}" = yes ]; then ufw allow in on tailscale0 comment 'omniaxis-scdc tailscale' >/dev/null; fi
if [ -z "${ADMIN_SSH_CIDRS:-}" ] && [ "${TAILSCALE:-no}" != yes ]; then
  die "no SSH path would remain: set ADMIN_SSH_CIDRS or TAILSCALE=yes"
fi
ufw --force enable >/dev/null
ufw status verbose | sed 's/^/    /'

say "kernel network settings"
cat > /etc/sysctl.d/60-omniaxis-scdc.conf <<'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
# Wazuh indexer (OpenSearch) needs this.
vm.max_map_count = 262144
EOF
sysctl -q --system

say "done"
