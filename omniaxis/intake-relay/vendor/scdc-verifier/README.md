# @omniaxis-labs/scdc-verifier

Verifies signed requests to the OmniAxis Labs Security Cyber Defence Centre (SCDC), to the contract in section 4 of the SCDC design (7 Nov 2026). No runtime dependencies: Node 24 `node:crypto` only. The admin portal uses it for `POST /api/wazuh/alerts`, and the intake relay on the Wazuh server uses it for `POST /api/intake/v1`.

## The contract

Headers (Standard Webhooks):

| Header | Value |
|---|---|
| `webhook-id` | Unique per event; the idempotency key. Must equal the body's `id`. |
| `webhook-timestamp` | Unix seconds. Accepted within ±300 s. |
| `webhook-signature` | `v1a,<standard base64 Ed25519 signature>` over `${id}.${timestamp}.${raw body}`. Several space-separated signatures are allowed during key rotation; entries of other versions (such as HMAC `v1`) are ignored. |

Checks, in order: body over 16 KB → 413; missing or malformed headers → 400; stale → 401; no signature verifies against any active key → 401; anything shaped like a secret anywhere in the raw body → 422; not JSON → 400; fails the field allowlist → 422; `id` differs from `webhook-id` → 422; `source` or `environment` differs from the signing key's → 403.

Keys are raw 32-byte Ed25519 public keys in standard base64, written `whpk_<base64>`. One key per source per environment. The SCDC never holds a private key.

Dedupe on `(source, id)` is the caller's job after verification: the portal uses a unique index; the relay can use `MemoryDedupeStore` (7 days, capped).

### `scdc/1`: product events (to the relay)

As in the design, section 4: `specversion`, `id`, `source` (musterward, omniaxis, rackhand, crosswalk), `environment` (production, preview), `type` (dotted), `time` (ISO 8601 UTC), `severity` (sev1–sev4), `dedupe_key`, `title`, `refs` (`tenant_ref`, `actor_ref`, `resource`), `counts` (up to 16 non-negative integers), `reason` (dotted code), `ocsf_class_uid` (reserved).

### `scdc-alert/1`: Wazuh alerts (to the portal)

```json
{
  "specversion": "scdc-alert/1",
  "id": "wz_1794028600.123456",
  "source": "wazuh",
  "environment": "production",
  "time": "2026-11-07T05:12:50Z",
  "product": "musterward",
  "product_environment": "production",
  "type": "auth.step_up_failed",
  "title": "Staff step-up failed",
  "dedupe_key": "auth.step_up_failed:s_7",
  "severity": "sev2",
  "rule": { "id": "100210", "level": 10, "groups": ["scdc", "auth"] },
  "agent": { "name": "gate" },
  "event_id": "evt_01J...",
  "refs": { "actor_ref": "s_7", "resource": "musterward-web" },
  "counts": { "attempts": 3 },
  "reason": "no_permission"
}
```

- `environment` is the Wazuh deployment's and must match the Wazuh key. `product_environment` is the environment of the product the alert is about.
- `product` may also be `company` for the shared company accounts.
- Severity comes from `rule.level`: 13+ SEV1, 10–12 SEV2, 7–9 SEV3, 3–6 SEV4. `severity` may be left out; if sent, it must agree.
- `agent`, `event_id`, `refs`, `counts` and `reason` are optional. Everything else not listed is dropped.
- The portal groups alerts into one open incident per `(product, product_environment, dedupe_key)`.

## Test vector

`TEST_VECTOR` in `src/test-vectors.ts` holds a public seed, its key, a body and the expected signature header, so a signer in another language (the Python integration on the Wazuh server, a product's producer) can check its bytes. Never sign anything real with that seed.

## Use

```ts
import { verifyRequest } from "@omniaxis-labs/scdc-verifier";

const v = verifyRequest({ headers: req.headers, rawBody, keys, nowMs: Date.now(), kind: "event" });
if (!v.ok) return new Response(JSON.stringify({ error: v.reason }), { status: v.status });
```
