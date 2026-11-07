import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { loadKey, type LoadedKey } from "../src/verify.ts";

export interface TestProducer {
  privateKey: KeyObject;
  key: LoadedKey;
}

export function producer(source: string, keyId = `${source}-test`, environment?: string): TestProducer {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(12).toString("base64");
  return { privateKey, key: loadKey({ source, keyId, publicKey: raw, environment }) };
}

export function event(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    specversion: "scdc/1",
    id: "evt_01JTEST000000000000000001",
    source: "musterward",
    environment: "production",
    type: "auth.step_up_failed",
    time: "2026-11-07T05:12:49Z",
    severity: "sev3",
    dedupe_key: "auth.step_up_failed:staff_7",
    title: "Staff step-up failed",
    refs: { tenant_ref: "t_9f2c00112233445566778899aabbccdd", actor_ref: "s_7", resource: "musterward-web" },
    counts: { attempts: 3 },
    reason: "no_permission",
    ocsf_class_uid: null,
    ...over,
  };
}

export function signedHeaders(
  p: TestProducer,
  body: string,
  opts: { id?: string; ts?: number; extraSigs?: string[] } = {},
): Record<string, string> {
  const id = opts.id ?? (JSON.parse(body) as { id: string }).id;
  const ts = String(opts.ts ?? Math.floor(Date.now() / 1000));
  const sig = sign(null, Buffer.from(`${id}.${ts}.${body}`), p.privateKey).toString("base64");
  return {
    "webhook-id": id,
    "webhook-timestamp": ts,
    "webhook-signature": [...(opts.extraSigs ?? []), `v1a,${sig}`].join(" "),
    "content-type": "application/json",
  };
}
