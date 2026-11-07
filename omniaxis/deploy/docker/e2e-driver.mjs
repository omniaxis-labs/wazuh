// End-to-end driver for the test stack. Modes:
//   node e2e-driver.mjs keygen <dir>          writes producer key + relay config
//   node e2e-driver.mjs send <dir> <relayUrl> sends signed and bad events, checks statuses
//   node e2e-driver.mjs check-portal <portalUrl> <portalPubB64>
//                                              verifies what the portal received
import { generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";

const [mode, ...args] = process.argv.slice(2);
const RUN = process.env.E2E_RUN ?? String(Date.now());

if (mode === "keygen") {
  const dir = args[0];
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  writeFileSync(join(dir, "producer.pem"), privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(12).toString("base64");
  const config = {
    products: ["musterward", "omniaxis", "rackhand", "crosswalk"],
    keys: [{ source: "musterward", keyId: "mw-e2e", environment: "production", publicKey: raw }],
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
    const sig = sign(null, Buffer.from(`${wid}.${ts}.${text}`), key).toString("base64");
    const res = await fetch(`${relay}/v1/events`, {
      method: "POST",
      headers: { "content-type": "application/json", "webhook-id": wid, "webhook-timestamp": ts, "webhook-signature": `v1a,${sig}` },
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
  const [portal, pubB64, dir] = args;
  const sent = JSON.parse(readFileSync(join(dir, "sent.json"), "utf8"));
  const pub = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(pubB64, "base64")]), format: "der", type: "spki" });
  const got = await (await fetch(`${portal}/received`)).json();
  const bodies = [];
  for (const r of got) {
    const h = r.headers;
    const [scheme, sig] = h["webhook-signature"].split(",");
    assert.equal(scheme, "v1a");
    assert.ok(verify(null, Buffer.from(`${h["webhook-id"]}.${h["webhook-timestamp"]}.${r.body}`), pub, Buffer.from(sig, "base64")), "portal signature must verify");
    bodies.push(JSON.parse(r.body));
  }
  const sev1 = bodies.find((b) => b.alert?.data?.id === sent.sev1);
  assert.ok(sev1, `portal did not receive the SEV1 alert; got ${bodies.map((b) => b.alert?.rule?.id).join(",")}`);
  assert.equal(sev1.product, "musterward");
  assert.equal(sev1.severity, "sev1");
  assert.equal(sev1.alert.rule.id, "100111");
  assert.equal(sev1.alert.rule.level, 13);
  assert.equal(sev1.alert.location, "API-Webhook");
  assert.equal(bodies.some((b) => b.alert?.data?.id === sent.sev4), false, "SEV4 must not be pushed");
  assert.equal(bodies.filter((b) => b.alert?.data?.id === sent.sev1).length, 1, "duplicate must not produce a second alert");
  const host = bodies.filter((b) => !b.alert?.rule?.groups?.includes("scdc") && b.alert?.agent?.id === "000");
  const unlabelled = host.filter((b) => b.product !== "scdc");
  assert.equal(unlabelled.length, 0, `manager alerts without product=scdc: ${unlabelled.map((b) => b.alert.rule.id).join(",")}`);
  console.log(`host alerts from the manager: ${host.length}, all product=scdc`);
  console.log(`portal ok: ${bodies.length} signed alert(s), SEV1 present with product musterward, SEV4 absent`);
} else {
  console.error("unknown mode");
  process.exit(2);
}
