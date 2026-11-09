#!/usr/bin/env bash
# One-shot, re-runnable install of the SCDC server. See ../RUNBOOK.md.
#   sudo CONFIG_FILE=/etc/omniaxis-scdc/config.env ./install.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
for step in 10-harden-host 20-install-wazuh 30-configure-wazuh 40-install-relay 50-verify; do
  bash "$HERE/$step.sh"
done
