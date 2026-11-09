// The contract itself is tested by the vendored package's own suite
// (vendor/scdc-verifier/test, `npm run test:vendor`). These tests cover the
// relay's adapter: Node headers, key validation, and agreement with the
// ruleset's product list.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { verifyEvent, checkKey, headerLookup, PRODUCTS } from "../src/verify.ts";
import { TEST_VECTOR } from "../vendor/scdc-verifier/src/index.ts";
import { producer, event, signedHeaders } from "./helpers.ts";

const mw = producer("musterward");

test("the published test vector verifies through the relay adapter", () => {
  const key = checkKey({ id: "tv", source: "musterward", environment: "preview", publicKey: TEST_VECTOR.publicKey });
  const headers = {
    "webhook-id": TEST_VECTOR.id,
    "webhook-timestamp": TEST_VECTOR.timestamp,
    "webhook-signature": TEST_VECTOR.signature,
  };
  const r = verifyEvent(headers, Buffer.from(TEST_VECTOR.body), [key], Number(TEST_VECTOR.timestamp) * 1000);
  assert.equal(r.ok, true);
});

test("accepts a signed event and returns the allowlisted body and signing key", () => {
  const body = JSON.stringify(event({ email: "dropped@example.com" }));
  const r = verifyEvent(signedHeaders(mw, body), Buffer.from(body), [mw.key], Date.now());
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.key.id, "musterward-test");
    assert.equal("email" in r.body, false);
  }
});

test("maps refusals to the contract's statuses", () => {
  const body = JSON.stringify(event({ source: "omniaxis" }));
  const r = verifyEvent(signedHeaders(mw, body), Buffer.from(body), [mw.key], Date.now());
  assert.deepEqual(r.ok ? null : [r.status, r.reason], [403, "source_mismatch"]);
  const stale = JSON.stringify(event());
  const s = verifyEvent(signedHeaders(mw, stale, { ts: 1 }), Buffer.from(stale), [mw.key], Date.now());
  assert.deepEqual(s.ok ? null : [s.status, s.reason], [401, "stale"]);
});

test("a repeated webhook header is refused as malformed, not picked from", () => {
  const body = JSON.stringify(event());
  const h = signedHeaders(mw, body);
  const r = verifyEvent({ ...h, "webhook-id": [h["webhook-id"], "evt_other"] }, Buffer.from(body), [mw.key], Date.now());
  assert.deepEqual(r.ok ? null : r.reason, "malformed");
  assert.equal(headerLookup({ "webhook-id": "x" }).get("Webhook-Id"), "x");
});

test("checkKey requires id, a listed product, an environment and a whpk key", () => {
  assert.throws(() => checkKey({ source: "musterward", environment: "production", publicKey: mw.key.publicKey }), /id/);
  assert.throws(() => checkKey({ ...mw.key, source: "wazuh" }), /source/);
  assert.throws(() => checkKey({ ...mw.key, environment: undefined }), /environment/);
  assert.throws(() => checkKey({ ...mw.key, publicKey: "-----BEGIN PUBLIC KEY-----" }), /whpk/);
});

test("the ruleset's product list matches the contract's", () => {
  const rules = JSON.parse(readFileSync(new URL("../../ruleset/tools/products.json", import.meta.url), "utf8")) as { products: string[] };
  assert.deepEqual(rules.products, [...PRODUCTS]);
});
