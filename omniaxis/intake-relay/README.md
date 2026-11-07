# SCDC intake relay

This is the only public endpoint of the OmniAxis Labs SCDC. Products POST signed events to it. The relay checks them against the intake contract (SCDC design, section 4) and hands them to Wazuh on localhost.

```
product --HTTPS--> Caddy :443 /v1/events --> relay 127.0.0.1:8787
        --> Wazuh API POST /events (127.0.0.1:55000, batched)   location "API-Webhook"
        \-> /var/log/omniaxis-scdc/intake.log (fallback, read by <localfile>)
```

## What it checks, in order

| Check | Refusal | HTTP |
|---|---|---|
| Per-client rate (600 a minute by default) | `rate_limited` | 429 |
| `content-type: application/json` | `bad_content_type` | 415 |
| Body at most 16 KB | `too_large` | 413 |
| `webhook-id`, `webhook-timestamp` and `webhook-signature` present and well formed | `bad_headers` | 400 |
| Timestamp within ±300 s | `stale` | 400 |
| At least one `v1a,<std base64>` Ed25519 signature over `id.timestamp.body` verifies against a configured public key | `bad_signature` | 401 |
| Body is JSON and passes the field allowlist (unknown fields are dropped) | `bad_body` | 400 |
| `source` is a listed product | `unknown_source` | 403 |
| `source` equals the signing key's product | `source_mismatch` | 403 |
| `environment` equals the key's environment, if the key has one | `environment_mismatch` | 403 |
| Body `id` equals `webhook-id` | `id_mismatch` | 400 |
| No text that looks like a credential | `secret_like` | 422 |
| `(source, id)` not seen in the last 7 days | (accepted, not stored again) | 200 `duplicate` |
| Handed to Wazuh | | 202 `accepted` |

Every refusal is written to `relay.log` as `omniaxis-scdc-relay: {json}`. Wazuh reads it and raises:
- **100901** for a single refusal (level 4);
- **100902** when a valid key signs for another product (SEV2);
- **100903** for 20 refusals from one address within 2 minutes (SEV2);
- **100904** when the API hand-off fails (SEV2).

## Why the Wazuh API, and what it allows (checked in 4.14.9)

`POST /events` takes `{"events": ["<string>", ...]}`, with at most 100 events per request. It needs a JWT with RBAC action `event:ingest`. It is limited to **30 requests a minute**: `MAX_REQUESTS_EVENTS_DEFAULT` in `api/api/middlewares.py` is the ceiling, and configuration can only lower it.

The relay sends one batch at most every 2.2 s. That gives about 2,700 events a minute, far above the expected product volume. If the API refuses, is down, or the queue passes 300 events, the batch goes to `intake.log` instead. Wazuh reads that file with `<localfile>` and `only-future-events=no`, so events written while Wazuh is stopped are still read. The rules accept either location; any other location is flagged as a forgery (rule 100102).

The relay's API user (`scdc-intake`) has one role, `event:ingest` only. Its password is in `/etc/omniaxis-intake/api-password` (0400). The API certificate is pinned with `caFile`.

## Sharing the verifier

`src/verify.ts` is the reference verifier for the section 4 contract. The staff portal (omniaxis-labs/omniaxislabs-admin) must not carry a second, different one. That repository has no package yet (checked 7 Nov 2026: no commits). The intended path:

1. The portal session publishes `verify.ts` as its shared intake package. Name it, for example, `@omniaxis-labs/scdc-intake`, with the same `verifyIntake()` API and `test/verify.test.ts` as its tests.
2. This relay then imports that package (pinned by commit), and `src/verify.ts` here becomes a re-export.

Until then, any change to the contract lands here and in the portal together.

## Run and test

```bash
npm ci            # dev tools only: typescript, @types/node
npm test          # 31 unit tests (node:test)
npm run typecheck
node --disable-warning=ExperimentalWarning src/main.ts /etc/omniaxis-intake/config.json
```

Node 24 runs the TypeScript directly (type stripping), so there is no build step and there are no runtime dependencies.
