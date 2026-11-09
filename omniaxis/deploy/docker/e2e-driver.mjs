// End-to-end driver for the test stack. Modes:
//   node e2e-driver.mjs keygen <dir>          writes producer key + relay config
//   node e2e-driver.mjs send <dir> <relayUrl> sends signed and bad events, checks statuses
//   node e2e-driver.mjs check-portal <portalUrl> <portalPubB64>
//                                              verifies what the portal received
import { generateKeyPairSync, createPrivateKey } from "node:crypto";
// The portal's own verifier (vendored): the e2e test checks pushes exactly as the portal will.
import { encodePublicKey, signPayload, verifyRequest } from "../../intake-relay/vendor/scdc-verifier/src/index.ts";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";

const [mode, ...args] = process.argv.slice(2);
const RUN = process.env.E2E_RUN ?? String(Date.now());

if (mode === "keygen") {
  const dir = args[0];
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  writeFileSync(join(dir, "producer.pem"), privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  const config = {
    keys: [{ id: "mw-e2e", source: "musterward", environment: "production", publicKey: encodePublicKey(publicKey) }],
    sink: "api",
    api: { baseUrl: "https://127.0.0.1:55000", user: "scdc-intake" },
    listen: { port: 8787 },
  };
  writeFileSync(join(dir, "config.json"), JSON.stringify(config, null, 2), { mode: 0o644 });
  console.log("keygen ok");
} else if (mode === "send") {
  const [dir, relay] = args;
  const key = createPrivateKey(readFileSync(join(dir, "producer.pem")));
  const ev = (over) => ({
    specversion: "scdc/1", id: `evt_e2e_${RUN}_${over.n}`, source: "musterward", environment: "production",
    type: over.type, time: new Date().toISOString().replace(/\.\d+Z$/, "Z"), severity: over.severity,
    dedupe_key: `${over.type}:e2e`, title: over.title, refs: { resource: "musterward-web" }, ...(over.extra ?? {}),
  });
  const post = async (body, { tamper = false, id } = {}) => {
    const text = JSON.stringify(body);
    const ts = String(Math.floor(Date.now() / 1000));
    const wid = id ?? body.id;
    const sig = signPayload({ id: wid, timestamp: ts, body: text, privateKey: key });
    const res = await fetch(`${relay}/api/intake/v1`, {
      method: "POST",
      headers: { "content-type": "application/json", "webhook-id": wid, "webhook-timestamp": ts, "webhook-signature": sig },
      body: tamper ? text.replace("sev", "SEV") : text,
    });
    return res.status;
  };
  const sev1 = ev({ n: 1, type: "audit.chain_broken", severity: "sev1", title: "E2E audit chain broken" });
  const sev4 = ev({ n: 2, type: "auth.sign_in", severity: "sev4", title: "E2E routine sign in" });
  const results = {
    sev1: await post(sev1),
    duplicate: await post(sev1),
    sev4: await post(sev4),
    tampered: await post(ev({ n: 3, type: "x.y", severity: "sev2", title: "E2E tampered" }), { tamper: true }),
    mismatch: await post(ev({ n: 4, type: "x.y", severity: "sev2", title: "E2E mismatch", extra: { source: "omniaxis" } })),
  };
  console.log(JSON.stringify(results));
  assert.deepEqual(results, { sev1: 202, duplicate: 200, sev4: 202, tampered: 401, mismatch: 403 });
  writeFileSync(join(dir, "sent.json"), JSON.stringify({ sev1: sev1.id, sev4: sev4.id }));
  console.log("send ok");
} else if (mode === "check-portal") {
  const [portal, pub, dir] = args;
  const sent = JSON.parse(readFileSync(join(dir, "sent.json"), "utf8"));
  const key = { id: "scdc-wazuh-test", source: "wazuh", environment: "production", publicKey: pub };
  const got = await (await fetch(`${portal}/received`)).json();
  const bodies = [];
  for (const r of got) {
    const headers = new Headers(r.headers);
    const v = verifyRequest({ headers, rawBody: new TextEncoder().encode(r.body), keys: [key], nowMs: Date.now(), kind: "alert" });
    assert.ok(v.ok, `portal verifier refused a push: ${JSON.stringify(v)} body=${r.body.slice(0, 300)}`);
    bodies.push(v.body);
  }
  const sev1 = bodies.find((b) => b.event_id === sent.sev1);
  assert.ok(sev1, `portal did not receive the SEV1 alert; got rules ${bodies.map((b) => b.rule.id).join(",")}`);
  assert.equal(sev1.product, "musterward");
  assert.equal(sev1.product_environment, "production");
  assert.equal(sev1.severity, "sev1");
  assert.equal(sev1.type, "audit.chain_broken");
  assert.equal(sev1.rule.id, "100111");
  assert.equal(sev1.rule.level, 13);
  assert.equal(bodies.some((b) => b.event_id === sent.sev4), false, "SEV4 must not be pushed");
  assert.equal(bodies.filter((b) => b.event_id === sent.sev1).length, 1, "duplicate must not produce a second alert");
  const host = bodies.filter((b) => b.event_id === undefined);
  const wrong = host.filter((b) => b.product !== "company");
  assert.equal(wrong.length, 0, `host alerts not labelled company: ${wrong.map((b) => b.rule.id).join(",")}`);
  console.log(`host alerts from the manager: ${host.length}, all product=company`);
  console.log(`portal ok: ${bodies.length} push(es), every one accepted by the portal's verifier (scdc-alert/1); SEV1 present for musterward, SEV4 absent`);
} else {
  console.error("unknown mode");
  process.exit(2);
}
