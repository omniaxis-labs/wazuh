import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { encodePublicKey, signPayload } from "../vendor/scdc-verifier/src/index.ts";
import type { PublicKeyRecord } from "../src/verify.ts";

export interface TestProducer {
  privateKey: KeyObject;
  key: PublicKeyRecord;
}

export function producer(
  source: PublicKeyRecord["source"],
  id = `${source}-test`,
  environment: PublicKeyRecord["environment"] = "production",
): TestProducer {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { privateKey, key: { id, source, environment, publicKey: encodePublicKey(publicKey) } };
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
  const sig = signPayload({ id, timestamp: ts, body, privateKey: p.privateKey });
  return {
    "webhook-id": id,
    "webhook-timestamp": ts,
    "webhook-signature": [...(opts.extraSigs ?? []), sig].join(" "),
    "content-type": "application/json",
  };
}
