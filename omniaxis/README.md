# OmniAxis Labs SCDC on Wazuh

This folder holds everything OmniAxis Labs adds to Wazuh to build the company's Security Cyber Defence Centre (SCDC).

The branch `omniaxis/4.14` is cut from tag `v4.14.9`, the latest stable release. Nothing outside this folder is changed except the gate checks file `scripts/ci/gate/coordinator.json`, a path upstream does not use, so taking the next `v4.14.x` tag is a clean merge. Servers install the **official signed Wazuh packages**; this fork carries configuration only, not a build.

```
product (signed event) --> intake-relay --> Wazuh API /events --> ruleset --> alert
                                                                              |
                         staff portal <-- signed push (SEV3+) <-- integrations/custom-scdc-portal
gate host (wazuh-agent, product label) ----------------------------^
```

| Folder | What |
|---|---|
| `ruleset/` | Decoders and rules for SCDC contract events: one group per product, SEV bands (SEV1 = level 13+, SEV2 = 10-12, SEV3 = 7-9, SEV4 = 3-6), escalation on repeats, forgery and relay-health rules. Rules are generated from `tools/products.json`. |
| `intake-relay/` | The SCDC's only public endpoint. It verifies the signed intake contract with the portal's shared verifier (vendored, pinned) and hands events to Wazuh on localhost. |
| `integrations/custom-scdc-portal/` | integratord script that pushes alerts at level 7 and above to `admin.omniaxislabs.com/api/wazuh/alerts` as the portal's `scdc-alert/1` envelope (`source: "wazuh"`), signed with Ed25519. |
| `deploy/server/` | Idempotent single-node install for an Ubuntu LTS server at Hetzner US: hardening, Wazuh, OmniAxis config, relay with Caddy, verification. |
| `deploy/agent/` | Agent enrolment with a product label (first: the gate host). |
| `deploy/docker/` | Local single-node test stack and the end-to-end test. |
| `deploy/RUNBOOK.md` | How to install, operate and upgrade. |
| `docs/github-audit-coverage.md` | Whether Wazuh's GitHub module can replace the OmniAxis org webhook (no; see the document). |

## Tests

```bash
omniaxis/run-tests.sh   # needs Docker and Node 24
```

It runs:
- the rules generator check;
- 28 `wazuh-logtest` fixtures in a 4.14.9 manager container;
- 20 relay tests and the typecheck;
- the shared verifier's own 47 tests (vendored from the portal);
- 13 integration tests under Wazuh's bundled Python, including the portal's signing test vector byte for byte;
- the config-edit tests;
- the end-to-end path: signed event → relay → API → rules → signed portal push, with every push checked by the portal's own verifier.

Pull requests are checked by the Musterward Gate, not GitHub Actions (see `CLAUDE.md`). It runs the parts that need no Docker: the generator check, the relay and verifier tests, the integration tests and script syntax, as listed in `scripts/ci/gate/coordinator.json`.
