import { test } from "node:test";
import assert from "node:assert/strict";
import { sign } from "node:crypto";
import { verifyIntake, parseSignatures, validateEvent, loadKey } from "../src/verify.ts";
import { producer, event, signedHeaders } from "./helpers.ts";

const mw = producer("musterward");
const ox = producer("omniaxis");
const allowed = new Set(["musterward", "omniaxis", "rackhand", "crosswalk"]);
const keys = [mw.key, ox.key];

function run(body: string, headers: Record<string, string>, nowSeconds?: number) {
  return verifyIntake({ headers, rawBody: Buffer.from(body), keys, allowedSources: allowed, nowSeconds });
}

test("accepts a correctly signed contract event", () => {
  const body = JSON.stringify(event());
  const r = run(body, signedHeaders(mw, body));
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.key.keyId, "musterward-test");
    assert.equal(r.event.source, "musterward");
    assert.deepEqual(r.event.refs, { tenant_ref: "t_9f2c00112233445566778899aabbccdd", actor_ref: "s_7", resource: "musterward-web" });
  }
});

test("accepts when any one of several signatures is valid (key rotation)", () => {
  const body = JSON.stringify(event());
  const other = producer("musterward", "old");
  const oldSig = sign(null, Buffer.from("x"), other.privateKey).toString("base64");
  const r = run(body, signedHeaders(mw, body, { extraSigs: [`v1a,${oldSig}`, "v1,c29tZXRoaW5n"] }));
  assert.equal(r.ok, true);
});

test("refuses a tampered body", () => {
  const body = JSON.stringify(event());
  const h = signedHeaders(mw, body);
  const r = run(body.replace("sev3", "sev4"), h);
  assert.deepEqual(r, { ok: false, reason: "bad_signature" });
});

test("refuses a signature from a key we do not hold", () => {
  const stranger = producer("musterward", "stranger");
  const body = JSON.stringify(event());
  assert.equal((run(body, signedHeaders(stranger, body)) as { reason: string }).reason, "bad_signature");
});

test("refuses stale and future timestamps beyond 300 s, accepts at the edge", () => {
  const body = JSON.stringify(event());
  const now = 1_794_028_600;
  assert.equal((run(body, signedHeaders(mw, body, { ts: now - 301 }), now) as { reason: string }).reason, "stale");
  assert.equal((run(body, signedHeaders(mw, body, { ts: now + 301 }), now) as { reason: string }).reason, "stale");
  assert.equal(run(body, signedHeaders(mw, body, { ts: now - 300 }), now).ok, true);
});

test("refuses bodies over 16 KB before any crypto", () => {
  const body = JSON.stringify(event({ title: "x".repeat(17_000) }));
  assert.equal((run(body, signedHeaders(mw, body)) as { reason: string }).reason, "too_large");
});

test("refuses a source that does not match the signing key", () => {
  const body = JSON.stringify(event({ source: "omniaxis" }));
  const r = run(body, signedHeaders(mw, body));
  assert.equal(r.ok, false);
  if (!r.ok) {
    assert.equal(r.reason, "source_mismatch");
    assert.equal(r.claimedSource, "omniaxis");
    assert.equal(r.key?.source, "musterward");
  }
});

test("refuses an unknown source even when signed by a known key", () => {
  const body = JSON.stringify(event({ source: "acme" }));
  assert.equal((run(body, signedHeaders(mw, body)) as { reason: string }).reason, "unknown_source");
});

test("refuses an environment the key is not for", () => {
  const prodOnly = producer("rackhand", "rh-prod", "production");
  const body = JSON.stringify(event({ source: "rackhand", environment: "preview" }));
  const r = verifyIntake({ headers: signedHeaders(prodOnly, body), rawBody: Buffer.from(body), keys: [prodOnly.key], allowedSources: allowed });
  assert.equal((r as { reason: string }).reason, "environment_mismatch");
});

test("refuses when body id differs from webhook-id", () => {
  const body = JSON.stringify(event());
  const r = run(body, signedHeaders(mw, body, { id: "evt_other" }));
  assert.equal((r as { reason: string }).reason, "id_mismatch");
});

test("refuses missing or malformed headers", () => {
  const body = JSON.stringify(event());
  const h = signedHeaders(mw, body);
  for (const drop of ["webhook-id", "webhook-timestamp", "webhook-signature"]) {
    const copy = { ...h };
    delete (copy as Record<string, string>)[drop];
    assert.equal((run(body, copy) as { reason: string }).reason, "bad_headers", drop);
  }
  assert.equal((run(body, { ...h, "webhook-signature": "v1,abc" }) as { reason: string }).reason, "bad_headers");
  assert.equal((run(body, { ...h, "webhook-id": "evt bad\nid" }) as { reason: string }).reason, "bad_headers");
});

test("bare base64url signatures (Musterward's internal form) are not accepted", () => {
  const body = JSON.stringify(event());
  const h = signedHeaders(mw, body);
  const urlsafe = h["webhook-signature"].replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "").replace(/^v1a,/, "");
  // Only refuse if the conversion changed the string; otherwise it is identical std base64.
  if (urlsafe !== h["webhook-signature"].slice(4)) {
    assert.equal(run(body, { ...h, "webhook-signature": urlsafe }).ok, false);
  }
});

test("drops unknown fields and keeps allowlisted ones", () => {
  const body = JSON.stringify(event({ email: "someone@example.com", extra: { a: 1 } }));
  const r = run(body, signedHeaders(mw, body));
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal("email" in r.event, false);
    assert.equal("extra" in r.event, false);
  }
});

test("refuses events that look like they carry a secret", () => {
  for (const title of ["token ghp_abcdefghijklmnopqrstuvwxyz0123", "key AKIAABCDEFGHIJKLMNOP", "-----BEGIN PRIVATE KEY-----"]) {
    const body = JSON.stringify(event({ title }));
    assert.equal((run(body, signedHeaders(mw, body)) as { reason: string }).reason, "secret_like", title);
  }
});

test("validateEvent enforces field shapes", () => {
  assert.equal(validateEvent(event({ severity: "critical" })), "severity");
  assert.equal(validateEvent(event({ specversion: "scdc/2" })), "specversion");
  assert.equal(validateEvent(event({ environment: "staging" })), "environment");
  assert.equal(validateEvent(event({ time: "yesterday" })), "time");
  assert.equal(validateEvent(event({ title: "line\nbreak" })), "title");
  assert.equal(validateEvent(event({ refs: { tenant_ref: "t_short", resource: "x" } })), "refs.tenant_ref");
  assert.equal(validateEvent(event({ refs: { actor_ref: "s_7" } })), "refs.resource");
  assert.equal(validateEvent(event({ counts: { attempts: -1 } })), "counts.attempts");
  assert.equal(validateEvent(event({ counts: { attempts: 1.5 } })), "counts.attempts");
  assert.equal(validateEvent(event({ type: "Auth Step" })), "type");
  assert.equal(validateEvent([]), "body is not an object");
  const ok = validateEvent(event({ refs: { resource: "musterward-web" }, counts: undefined, reason: undefined }));
  assert.equal(typeof ok, "object");
});

test("parseSignatures ignores other schemes and bad lengths", () => {
  const good = Buffer.alloc(64, 1).toString("base64");
  assert.equal(parseSignatures(`v1,${good} v1a,${good} v1a,AAAA v1a,!!!`).length, 1);
});

test("loadKey accepts raw base64, base64url and PEM, and rejects other key types", () => {
  const p = producer("musterward");
  const pem = p.key.keyObject.export({ format: "pem", type: "spki" }).toString();
  assert.equal(loadKey({ source: "musterward", keyId: "pem", publicKey: pem }).keyObject.asymmetricKeyType, "ed25519");
  const raw = p.key.keyObject.export({ format: "der", type: "spki" }).subarray(12);
  const url = raw.toString("base64url");
  assert.equal(loadKey({ source: "musterward", keyId: "url", publicKey: url }).keyObject.asymmetricKeyType, "ed25519");
  assert.throws(() => loadKey({ source: "musterward", keyId: "short", publicKey: "AAAA" }));
});
