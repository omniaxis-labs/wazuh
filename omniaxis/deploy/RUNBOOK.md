# SCDC server runbook (Wazuh 4.14, single node)

The SCDC server runs the Wazuh indexer, manager and dashboard on one dedicated host. It is **Hetzner, US East (Ashburn)**, near Neon `us-east-1`. **Never an Australian region.** The intake relay is its only public endpoint.

Nothing here has run against a real server yet. The scripts are checked with `bash -n`, shellcheck and the config-edit tests, and the Wazuh-facing parts run end to end in the compose stack. The first real install is the owner's step 2 below.

## 0. What the owner does (each needs the owner's yes)

1. **Create the server.** Hetzner Cloud, location **Ashburn (ash)**, Ubuntu 24.04. Take at least CPX41 (8 vCPU, 16 GB) or CCX23. Wazuh's own floor for 1 to 25 agents and 90 days of alerts is 4 vCPU, 8 GiB and 50 GB (documentation.wazuh.com/4.14/quickstart.html). The indexer is the memory user, so take the larger size. Add your SSH key at creation. Enable backups.
2. **DNS.** Add an A record (and AAAA if you use IPv6) for `intake.security.omniaxislabs.com`, pointing at the server.
3. **Hetzner Cloud firewall** (optional, a second layer behind ufw). Allow 22 from your admin addresses, 80 and 443 from anywhere, and 1514-1515 from the gate host.

## 1. Install

```bash
# on the server, as root
git clone --branch omniaxis/4.14 --filter=blob:none https://github.com/omniaxis-labs/wazuh.git /opt/omniaxis-wazuh
install -d -m 0700 /etc/omniaxis-scdc
cp /opt/omniaxis-wazuh/omniaxis/deploy/server/config.env.example /etc/omniaxis-scdc/config.env
chmod 600 /etc/omniaxis-scdc/config.env
${EDITOR:-nano} /etc/omniaxis-scdc/config.env   # admin CIDRs, gate host IP, hostname
/opt/omniaxis-wazuh/omniaxis/deploy/server/install.sh
```

The steps can each be run again on their own; every one converges:

| Script | Does |
|---|---|
| `10-harden-host.sh` | Security updates now and unattended (security only; Wazuh and Caddy excluded). SSH keys only, with a guard that refuses if no key is installed. ufw denies everything incoming except 22 from `ADMIN_SSH_CIDRS`, 1514-1515 from `AGENT_CIDRS`, and 80/443. Kernel network settings. |
| `20-install-wazuh.sh` | Official installation assistant (`packages.wazuh.com/4.14/wazuh-install.sh -a`), which installs the signed packages. Holds the packages so they never upgrade unattended. Binds the API to `127.0.0.1:55000` and the dashboard to `127.0.0.1:8443`, and checks that the indexer is on `127.0.0.1`. Passwords stay in `/root/omniaxis-scdc/wazuh-install-files.tar`. |
| `30-configure-wazuh.sh` | OmniAxis ruleset, portal integration and its Ed25519 signing key, the managed `ossec.conf` block (product label `scdc` on the server's own alerts, relay log files, the integration), password-protected agent enrolment, and the relay's API user (`event:ingest` only). |
| `40-install-relay.sh` | Node (pinned, SHA-256 checked) in `/opt/node`, the relay in `/opt/omniaxis-intake-relay`, its sandboxed systemd unit, and Caddy (official signed repository) on 443 with one path, a 16 KB body limit and automatic TLS. |
| `50-verify.sh` | Read-only checks: every internal port is loopback only, firewall, SSH, services, file permissions, and that the relay refuses and logs an unsigned request. |

At the end, `30-configure-wazuh.sh` prints the **portal public key**. Give it, with its key id, to the portal (omniaxis-labs/omniaxislabs-admin) as the trusted key for `/api/wazuh/alerts`. The private half never leaves the server.

## 2. Reaching the dashboard (private only)

The default, `DASHBOARD_ACCESS=tunnel`, binds the dashboard to loopback:

```bash
ssh -L 8443:127.0.0.1:8443 root@<scdc-server>
# then open https://127.0.0.1:8443 (self-signed certificate)
```

With Tailscale, `tailscale serve` can publish it on the tailnet instead. `DASHBOARD_ACCESS=allowlist` opens 8443 to `DASHBOARD_CIDRS` only. The dashboard is never public.

The dashboard `admin` password is in `wazuh-passwords.txt` inside `/root/omniaxis-scdc/wazuh-install-files.tar`. Read it on the server only:

```bash
tar -O -xf /root/omniaxis-scdc/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt | less
```

## 3. Adding a product key to the relay

Each product signs with its own Ed25519 key per environment. The SCDC holds **public keys only**.

1. The product generates its key pair in its own secret store and hands over the **public** key as raw 32-byte base64.
2. Add it to `/etc/omniaxis-intake/config.json` under `keys`:
   ```json
   { "source": "musterward", "environment": "production", "keyId": "mw-prod-2026-11", "publicKey": "<base64>" }
   ```
3. Run `40-install-relay.sh`. It validates the config and restarts the relay.

**Rotation.** Add the new key next to the old one. The product then sends both signatures (`v1a,<old> v1a,<new>`). Remove the old key once the product has switched.

**A new product** goes in `ruleset/tools/products.json`; append only, never reorder. Then run `python3 ruleset/tools/gen_rules.py`, run the tests, merge, and run `30-configure-wazuh.sh` and `40-install-relay.sh` on the server.

## 4. Enrolling the gate host

On the SCDC server:
- Make sure the gate host's address is in `AGENT_CIDRS`, then re-run `10-harden-host.sh`.
- Copy `/var/ossec/etc/authd.pass` to the gate host out of band, for example with `scp` from your machine. **Never paste it into chat.**

On the gate host, as root:

```bash
git clone --branch omniaxis/4.14 --filter=blob:none https://github.com/omniaxis-labs/wazuh.git /opt/omniaxis-wazuh
SCDC_MANAGER=<scdc server address> PRODUCT=gate ENROL_PASSWORD_FILE=/root/scdc-authd.pass \
  /opt/omniaxis-wazuh/omniaxis/deploy/agent/enrol-agent.sh
shred -u /root/scdc-authd.pass
```

The agent carries `product: gate` on every alert. It runs capped at 25% of one CPU and 512 MB, at low priority, because the gate host is busy.

Once it reports, **retire the OmniAxis SSH forwarder** on the gate host. Do that only after a week of overlap, when the SCDC's sshd alerts match.

## 5. Upgrades

- **Ubuntu security updates** apply on their own, with a reboot at 09:30 UTC if one is needed.
- **Wazuh.**
  1. Take the next `v4.14.x` tag into the fork: `git merge v4.14.x` into `omniaxis/4.14-base`, then into `omniaxis/4.14`. It merges cleanly, because everything of ours lives in `omniaxis/`.
  2. Run the tests against the new image tag.
  3. On the server, unhold the packages (`apt-mark unhold wazuh-manager wazuh-indexer wazuh-dashboard`), upgrade by following Wazuh's upgrade guide, then hold them again.
  4. Re-run `30-configure-wazuh.sh` and `50-verify.sh`.
- **Node.** Change `NODE_VERSION` and run `40-install-relay.sh`.
- **Caddy.** `apt-get install --only-upgrade caddy`.

## 6. Day to day

| What | Where |
|---|---|
| Relay refusals and health | `/var/log/omniaxis-scdc/relay.log` (also alerts 100901-100905) |
| Events that fell back to file | `/var/log/omniaxis-scdc/intake.log` (read by Wazuh, so nothing is lost) |
| Portal hand-off errors | `/var/ossec/logs/integrations.log`; undelivered alerts wait in `/var/ossec/var/omniaxis/portal-spool/` and are re-sent on the next alert |
| Alerts | Dashboard, or `/var/ossec/logs/alerts/alerts.json` |
| Re-key the relay's API password | `create-intake-api-user.py … --rotate`, then `systemctl restart omniaxis-intake-relay` |

## 7. Limits worth knowing

- **Event rate.** Wazuh's `POST /events` is capped at 30 requests a minute; the cap is hard-coded in 4.14.9 (`api/api/middlewares.py`). Each request carries at most 100 events. The relay batches every 2.2 s, about 2,700 events a minute. Above that, or whenever the API fails, events go to `intake.log`, which Wazuh reads directly. Nothing is dropped.
- **Dedupe** is per `(source, id)` for 7 days, kept in `/var/lib/omniaxis-intake/dedupe.journal`.
- **Not done yet.**
  - Indexer snapshots and backups beyond Hetzner's server backups.
  - Alert retention policy (Wazuh's index lifecycle).
  - An off-host copy of `/root/omniaxis-scdc`.
