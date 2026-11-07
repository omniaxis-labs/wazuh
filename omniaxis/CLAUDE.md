# OmniAxis Labs SCDC on Wazuh

This fork is OmniAxis Labs' Security Cyber Defence Centre (SCDC) on Wazuh 4.14. Everything of ours lives in `omniaxis/` (see `README.md` here), plus the gate checks file `scripts/ci/gate/coordinator.json`. Work on `omniaxis/4.14`, which is cut from a `v4.14.x` tag; never from upstream's `main`. Leave the rest of the tree, upstream's `.github/workflows` included, as upstream ships it.

## CI: the Musterward Gate, not GitHub Actions

- OmniAxis Labs does **not** use GitHub CI. Do not add or rely on `.github/workflows`, and do not report "CI blocked" or "no checks" because GitHub Actions did not run. The workflows in this fork are upstream Wazuh's; they are not ours and are not run for OmniAxis changes.
- Checks run on the **Musterward Gate** (Musterward Gatehouse, the gate coordinator on the company gate server). It polls GitHub for open pull requests, runs the repository's checks in containers and posts each result as a commit status. GitHub is only where pull requests are pushed and merge conflicts are checked.
- The checks a repository needs are listed in its checks file, `scripts/ci/gate/coordinator.json`. The gate runs the copy installed on the gate server, so a change to the file here is only a proposal until the owner installs it.
- Keep a pull request in draft while you iterate. Marking it ready runs the full set, which must pass before a merge.
- How the gate works: `docs/runbooks/gate-coordinator.md` and `docs/runbooks/gatehouse.md` in `omniaxis-labs/musterward`.

The gate runs four checks, each in a container with no Docker:

| Check | What |
|---|---|
| `scdc-rules` | The generated rules file is in sync with `ruleset/tools/products.json` |
| `scdc-relay` | Relay typecheck and tests, and the vendored shared verifier's own tests |
| `scdc-portal-push` | The portal integration's tests under Wazuh's bundled Python (the gate maps it to the `wazuh/wazuh-manager:4.14.9` image) |
| `scdc-scripts` | Syntax of every shell, Node and Python script in `omniaxis/` |

The tests that need Docker (the `wazuh-logtest` fixtures, the config-edit tests and the compose end-to-end run) cannot run inside a gate job, so run the whole suite locally before marking a pull request ready.

Run these locally before pushing (Docker and Node 24):

```bash
python3 omniaxis/ruleset/tools/gen_rules.py --check
(cd omniaxis/intake-relay && npm ci && npm run typecheck && npm test && npm run test:vendor)
omniaxis/run-tests.sh
```

`run-tests.sh` runs everything: the gate's four checks plus the logtest fixtures, the config-edit tests and the end-to-end path.

## Rules

- British English. Times shown to the owner are in Sydney time; hosting is US-only (never Australian regions). The SCDC server is Hetzner Ashburn.
- No secrets in files, chat or screenshots. No AI attribution in commits or pull requests.
- No merges, production changes or account sign-ups without the owner's typed yes. Do not provision servers, cloud accounts or DNS.
- The shared verifier in `intake-relay/vendor/scdc-verifier` is a pinned copy of the portal's package; never edit it here (see its `VENDORED.md`). Products are appended to `ruleset/tools/products.json` only after the verifier's list, never reordered.
- GitHub: `gh` with `GH_CONFIG_DIR=$HOME/.config/gh-omniaxis-labs`.
