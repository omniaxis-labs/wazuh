#!/usr/bin/env bash
# Runs omniaxis-scdc-backup in Ubuntu 24.04 (the server's release) against a
# local restic repository: init twice, back up, restore a file and compare,
# and the guards (env file mode, Australian regions refused).
#   omniaxis/deploy/server/tests/test_backup.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker run --rm -v "$HERE/..:/srv:ro" ubuntu:24.04 bash -c '
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq restic openssl >/dev/null
fail=0; ok() { echo "  ok   $*"; }; bad() { echo "  FAIL $*"; fail=1; }
B=/srv/omniaxis-scdc-backup.sh
mkdir -p /etc/omniaxis-scdc /root/omniaxis-scdc /var/ossec/etc
echo "admin-archive" > /root/omniaxis-scdc/marker
echo "<ossec_config/>" > /var/ossec/etc/ossec.conf
printf "RESTIC_REPOSITORY=/backup/repo\n" > /etc/omniaxis-scdc/backup.env

chmod 0644 /etc/omniaxis-scdc/backup.env
bash $B init 2>/dev/null && bad "accepted a world-readable backup.env" || ok "refuses a backup.env that is not 0600"
chmod 0600 /etc/omniaxis-scdc/backup.env

bash $B init | grep -q "repository created" && ok "init creates the repository" || bad "init"
[ "$(stat -c %a /etc/omniaxis-scdc/restic-password)" = 600 ] && ok "repository password file 0600" || bad "password file mode"
bash $B init | grep -q "already set up" && ok "init again changes nothing" || bad "second init"

bash $B run | grep -q "backup: ok" && ok "backup runs" || bad "backup run"
export RESTIC_REPOSITORY=/backup/repo RESTIC_PASSWORD_FILE=/etc/omniaxis-scdc/restic-password
restic restore latest --quiet --target /restore >/dev/null
cmp -s /restore/root/omniaxis-scdc/marker /root/omniaxis-scdc/marker && cmp -s /restore/var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf \
  && ok "a restore gives back the same files" || bad "restore differs"

printf "RESTIC_REPOSITORY=s3:https://s3.ap-southeast-2.amazonaws.com/b/scdc\n" > /etc/omniaxis-scdc/backup.env
out=$(bash $B run 2>&1 || true); echo "$out" | grep -q "must be in the US" && ok "refuses an Australian region" || bad "accepted ap-southeast-2"
[ $fail = 0 ] && echo "  backup: all passed" || exit 1
'
