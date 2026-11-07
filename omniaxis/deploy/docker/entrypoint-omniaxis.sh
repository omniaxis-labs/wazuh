#!/usr/bin/env bash
# Runs inside the wazuh-manager test container before Wazuh starts
# (the image runs /entrypoint-scripts/*.sh from its init).
set -euo pipefail

# The relay container runs as uid 1000; give it a matching user here so the
# shared log and secrets directories get the same ownership as production.
id scdc-intake >/dev/null 2>&1 || useradd --system --uid 1000 --no-create-home --shell /usr/sbin/nologin scdc-intake
install -d -o scdc-intake -g scdc-intake -m 0700 /run/omniaxis-intake

OMNIAXIS_DIR=/omniaxis NO_RESTART=1 bash /omniaxis/deploy/server/apply-omniaxis-config.sh
