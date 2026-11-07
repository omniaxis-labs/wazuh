// The relay's view of the SCDC intake contract (design section 4).
//
// The verifier itself is the portal's package, @omniaxis-labs/scdc-verifier,
// vendored unchanged in ../vendor/scdc-verifier (pinned commit in
// vendor/scdc-verifier/VENDORED.md). This file only adapts Node's request
// headers to it and validates the relay's key list, so there is exactly one
// implementation of the contract across the SCDC.

import type { IncomingHttpHeaders } from "node:http";
import {
  decodePublicKey,
  ENVIRONMENTS,
  PRODUCTS,
  verifyRequest,
  type PublicKeyRecord,
  type Refusal,
  type ScdcEvent,
  type Verified,
} from "../vendor/scdc-verifier/src/index.ts";

export { MAX_BODY_BYTES, PRODUCTS, TOLERANCE_SECONDS } from "../vendor/scdc-verifier/src/index.ts";
export type { PublicKeyRecord, Refusal, ScdcEvent };

export type VerifyResult = Verified<ScdcEvent> | Refusal;

/** Node lower-cases header names; repeated headers are refused as malformed. */
export function headerLookup(h: IncomingHttpHeaders): { get(name: string): string | null } {
  return {
    get(name: string) {
      const v = h[name.toLowerCase()];
      if (v === undefined) return null;
      if (Array.isArray(v)) return v.length === 1 ? v[0] : "\u0000repeated";
      return v;
    },
  };
}

export function verifyEvent(
  headers: IncomingHttpHeaders,
  rawBody: Uint8Array,
  keys: readonly PublicKeyRecord[],
  nowMs: number,
): VerifyResult {
  return verifyRequest({ headers: headerLookup(headers), rawBody, keys, nowMs, kind: "event" });
}

/** Validate one configured key; throws with a reason that names the key id. */
export function checkKey(k: unknown): PublicKeyRecord {
  const r = k as Partial<PublicKeyRecord>;
  if (!r || typeof r.id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/.test(r.id)) {
    throw new Error("config: every key needs an id");
  }
  if (!(PRODUCTS as readonly string[]).includes(r.source as string)) {
    throw new Error(`config: key ${r.id}: source must be one of ${PRODUCTS.join(", ")}`);
  }
  if (!(ENVIRONMENTS as readonly string[]).includes(r.environment as string)) {
    throw new Error(`config: key ${r.id}: environment must be one of ${ENVIRONMENTS.join(", ")}`);
  }
  if (typeof r.publicKey !== "string" || decodePublicKey(r.publicKey) === null) {
    throw new Error(`config: key ${r.id}: publicKey must be whpk_<base64 of 32 raw bytes>`);
  }
  return { id: r.id, source: r.source as PublicKeyRecord["source"], environment: r.environment as PublicKeyRecord["environment"], publicKey: r.publicKey };
}
