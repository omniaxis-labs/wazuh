# SCDC intake relay

This is the only public endpoint of the OmniAxis Labs SCDC. Products POST signed events to it. The relay checks them against the intake contract (SCDC design, section 4) and hands them to Wazuh on localhost.

```
product --HTTPS--> Caddy :443 /api/intake/v1 --> relay 127.0.0.1:8787
        --> Wazuh API POST /events (127.0.0.1:55000, batched)   location "API-Webhook"
        \-> /var/log/omniaxis-scdc/intake.log (fallback, read by <localfile>)
```

## What it checks, in order

The contract checks are the portal's shared verifier, `@omniaxis-labs/scdc-verifier`. It is vendored unchanged in `vendor/scdc-verifier`, at the commit named in `VENDORED.md`, so the relay and the portal cannot drift. The relay adds the steps before and after it.

| Check | Refusal | HTTP |
|---|---|---|
| Per-client rate (600 a minute by default) | `rate_limited` | 429 |
| `content-type: application/json` | `bad_content_type` | 415 |
| Body at most 16 KB | `too_large` | 413 |
| `webhook-id`, `webhook-timestamp` and `webhook-signature` present | `missing_headers` | 400 |
| Headers well formed; a repeated header counts as malformed | `malformed` | 400 |
| Timestamp within ±300 s | `stale` | 401 |
| One `v1a,<std base64>` Ed25519 signature over `id.timestamp.body` verifies against a configured key. This also covers an unknown product, which has no key. | `bad_signature` | 401 |
| Nothing secret-shaped anywhere in the raw body | `secret_detected` | 422 |
| Body is JSON | `invalid_json` | 400 |
| Body passes the `scdc/1` allowlist (unknown fields are dropped) | `invalid_body` (with `field`) | 422 |
| Body `id` equals `webhook-id` | `id_mismatch` | 422 |
| `source` equals the signing key's product | `source_mismatch` | 403 |
| `environment` equals the signing key's environment | `environment_mismatch` | 403 |
| `(source, id)` not seen in the last 7 days | (accepted, not stored again) | 200 `duplicate` |
| Handed to Wazuh | | 202 `accepted` |

Every refusal is written to `relay.log` as `omniaxis-scdc-relay: {json}`. Wazuh reads it and raises:
- **100901** for a single refusal (level 4);
- **100902** when a valid key signs for another product or environment (SEV2);
- **100903** for 20 refusals from one address within 2 minutes (SEV2);
- **100904** when the API hand-off fails (SEV2).

## Why the Wazuh API, and what it allows (checked in 4.14.9)

`POST /events` takes `{"events": ["<string>", ...]}`, with at most 100 events per request. It needs a JWT with RBAC action `event:ingest`. It is limited to **30 requests a minute**: `MAX_REQUESTS_EVENTS_DEFAULT` in `api/api/middlewares.py` is the ceiling, and configuration can only lower it.

The relay sends one batch at most every 2.2 s. That gives about 2,700 events a minute, far above the expected product volume. If the API refuses, is down, or the queue passes 300 events, the batch goes to `intake.log` instead. Wazuh reads that file with `<localfile>` and `only-future-events=no`, so events written while Wazuh is stopped are still read. The rules accept either location; any other location is flagged as a forgery (rule 100102).

The relay's API user (`scdc-intake`) has one role, `event:ingest` only. Its password is in `/etc/omniaxis-intake/api-password` (0400). The API certificate is pinned with `caFile`.

## Sharing the verifier

There is one implementation of the contract: the portal's `packages/verifier` in omniaxis-labs/omniaxislabs-admin. It is copied unchanged into `vendor/scdc-verifier`, and the commit is recorded in `VENDORED.md`, which also gives the refresh command. The repository is private, so it is vendored rather than installed from a git URL. `src/verify.ts` here only adapts Node's headers and validates the relay's keys.

Keys in `/etc/omniaxis-intake/config.json` use the verifier's format:

```json
{ "id": "mw-prod-2026-11", "source": "musterward", "environment": "production", "publicKey": "whpk_<base64 of 32 raw bytes>" }
```

## Run and test

```bash
npm ci            # dev tools only: typescript, @types/node, vitest
npm test          # relay tests (node:test)
npm run test:vendor  # the shared verifier's own tests (vitest)
npm run typecheck
node --disable-warning=ExperimentalWarning src/main.ts /etc/omniaxis-intake/config.json
```

Node 24 runs the TypeScript directly (type stripping), so there is no build step and there are no runtime dependencies.
