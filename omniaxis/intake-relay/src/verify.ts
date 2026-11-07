// SCDC intake contract verifier (design section 4).
//
// SHARED CODE: this module is the reference verifier for the signed intake
// contract. The admin portal (omniaxis-labs/omniaxislabs-admin) must use the
// same logic. When the portal's package is published, this file is replaced
// by an import of it; until then, keep the two byte-for-byte equivalent in
// behaviour and run test/verify.test.ts against both. See README "Sharing the
// verifier".
//
// Contract: Standard Webhooks headers, Ed25519 ("v1a"):
//   webhook-id, webhook-timestamp (unix seconds, +/-300 s),
//   webhook-signature: one or more space-separated "v1a,<std base64 sig>"
//   signed content: `${id}.${timestamp}.${rawBody}`
// Public keys only; a key belongs to exactly one product (and optionally one
// environment). The event's `source` must equal the key's product.

import { createPublicKey, verify as edVerify, type KeyObject } from "node:crypto";

export type RefusalReason =
  | "too_large"
  | "bad_headers"
  | "stale"
  | "bad_signature"
  | "unknown_source"
  | "source_mismatch"
  | "environment_mismatch"
  | "bad_body"
  | "id_mismatch"
  | "secret_like";

export interface ProductKey {
  /** Product name, e.g. "musterward". Must be in the allowed product list. */
  source: string;
  /** "production" | "preview"; when set, the event's environment must match. */
  environment?: string;
  /** Free label for rotation, e.g. "mw-prod-2026-11". Logged, never secret. */
  keyId: string;
  /** Raw 32-byte Ed25519 public key, standard or url-safe base64, or SPKI PEM. */
  publicKey: string;
}

export interface VerifyInput {
  headers: Record<string, string | string[] | undefined>;
  rawBody: Buffer;
  keys: LoadedKey[];
  allowedSources: ReadonlySet<string>;
  nowSeconds?: number;
  toleranceSeconds?: number;
  maxBytes?: number;
}

export interface ScdcEvent {
  specversion: "scdc/1";
  id: string;
  source: string;
  environment: "production" | "preview";
  type: string;
  time: string;
  severity: "sev1" | "sev2" | "sev3" | "sev4";
  dedupe_key: string;
  title: string;
  refs: { resource: string; tenant_ref?: string; actor_ref?: string };
  counts?: Record<string, number>;
  reason?: string;
  ocsf_class_uid?: number | null;
}

export type VerifyResult =
  | { ok: true; event: ScdcEvent; key: LoadedKey }
  | { ok: false; reason: RefusalReason; detail?: string; key?: LoadedKey; claimedSource?: string };

export interface LoadedKey extends ProductKey {
  keyObject: KeyObject;
}

export const DEFAULT_TOLERANCE_S = 300;
export const DEFAULT_MAX_BYTES = 16 * 1024;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function loadKey(k: ProductKey): LoadedKey {
  let keyObject: KeyObject;
  if (k.publicKey.includes("BEGIN PUBLIC KEY")) {
    keyObject = createPublicKey(k.publicKey);
  } else {
    const raw = Buffer.from(k.publicKey.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    if (raw.length !== 32) throw new Error(`key ${k.keyId}: Ed25519 public key must be 32 bytes`);
    keyObject = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
  }
  if (keyObject.asymmetricKeyType !== "ed25519") throw new Error(`key ${k.keyId}: not an Ed25519 key`);
  return { ...k, keyObject };
}

function header(h: VerifyInput["headers"], name: string): string | undefined {
  const v = h[name] ?? h[name.toLowerCase()];
  if (Array.isArray(v)) return v.length === 1 ? v[0] : undefined;
  return v;
}

const ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
const TS_RE = /^[0-9]{1,12}$/;

/** Parse "v1a,<b64> v1a,<b64> v1,<...>" and return the v1a signatures. */
export function parseSignatures(value: string): Buffer[] {
  const out: Buffer[] = [];
  for (const part of value.trim().split(/\s+/).slice(0, 8)) {
    const comma = part.indexOf(",");
    if (comma < 0) continue;
    if (part.slice(0, comma) !== "v1a") continue;
    const b64 = part.slice(comma + 1);
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) continue;
    const sig = Buffer.from(b64, "base64");
    if (sig.length === 64) out.push(sig);
  }
  return out;
}

export function verifyIntake(input: VerifyInput): VerifyResult {
  const maxBytes = input.maxBytes ?? DEFAULT_MAX_BYTES;
  const tolerance = input.toleranceSeconds ?? DEFAULT_TOLERANCE_S;
  const now = input.nowSeconds ?? Math.floor(Date.now() / 1000);

  if (input.rawBody.length > maxBytes) return { ok: false, reason: "too_large" };

  const id = header(input.headers, "webhook-id");
  const ts = header(input.headers, "webhook-timestamp");
  const sigHeader = header(input.headers, "webhook-signature");
  if (!id || !ts || !sigHeader || !ID_RE.test(id) || !TS_RE.test(ts)) {
    return { ok: false, reason: "bad_headers" };
  }
  const tsNum = Number(ts);
  if (Math.abs(now - tsNum) > tolerance) return { ok: false, reason: "stale" };

  const sigs = parseSignatures(sigHeader);
  if (sigs.length === 0) return { ok: false, reason: "bad_headers", detail: "no v1a signature" };

  const signed = Buffer.concat([Buffer.from(`${id}.${ts}.`, "utf8"), input.rawBody]);
  let matched: LoadedKey | undefined;
  outer: for (const key of input.keys) {
    for (const sig of sigs) {
      if (edVerify(null, signed, key.keyObject, sig)) {
        matched = key;
        break outer;
      }
    }
  }
  if (!matched) return { ok: false, reason: "bad_signature" };

  let body: unknown;
  try {
    body = JSON.parse(input.rawBody.toString("utf8"));
  } catch {
    return { ok: false, reason: "bad_body", detail: "not JSON", key: matched };
  }
  const parsed = validateEvent(body);
  if (typeof parsed === "string") return { ok: false, reason: "bad_body", detail: parsed, key: matched };

  if (!input.allowedSources.has(parsed.source)) {
    return { ok: false, reason: "unknown_source", key: matched, claimedSource: parsed.source };
  }
  if (parsed.source !== matched.source) {
    return { ok: false, reason: "source_mismatch", key: matched, claimedSource: parsed.source };
  }
  if (matched.environment && parsed.environment !== matched.environment) {
    return { ok: false, reason: "environment_mismatch", key: matched, claimedSource: parsed.source };
  }
  if (parsed.id !== id) return { ok: false, reason: "id_mismatch", key: matched };
  if (looksLikeSecret(parsed)) return { ok: false, reason: "secret_like", key: matched };

  return { ok: true, event: parsed, key: matched };
}

// ---------------------------------------------------------------------------
// Field allowlist. Anything not listed is dropped; anything malformed refuses
// the event. Limits keep a single event well under the 16 KB body cap.

const SOURCE_RE = /^[a-z][a-z0-9-]{1,30}$/;
const TYPE_RE = /^[a-z0-9_]+(\.[a-z0-9_]+){0,5}$/;
const SEVERITIES = new Set(["sev1", "sev2", "sev3", "sev4"]);
const ENVIRONMENTS = new Set(["production", "preview"]);
const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;
const TENANT_RE = /^t_[0-9a-f]{32}$/;
const REF_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
const REASON_RE = /^[a-z0-9_.-]{1,64}$/;
const COUNT_NAME_RE = /^[a-z][a-z0-9_]{0,31}$/;
const PRINTABLE_RE = /^[^\u0000-\u001f\u007f]*$/;

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function text(v: unknown, max: number): string | undefined {
  if (typeof v !== "string" || v.length === 0 || v.length > max || !PRINTABLE_RE.test(v)) return undefined;
  return v;
}

/** Returns the cleaned event, or a short reason string. */
export function validateEvent(b: unknown): ScdcEvent | string {
  if (!isObj(b)) return "body is not an object";
  if (b.specversion !== "scdc/1") return "specversion";
  if (typeof b.id !== "string" || !ID_RE.test(b.id)) return "id";
  if (typeof b.source !== "string" || !SOURCE_RE.test(b.source)) return "source";
  if (typeof b.environment !== "string" || !ENVIRONMENTS.has(b.environment)) return "environment";
  if (typeof b.type !== "string" || b.type.length > 96 || !TYPE_RE.test(b.type)) return "type";
  if (typeof b.time !== "string" || !TIME_RE.test(b.time) || Number.isNaN(Date.parse(b.time))) return "time";
  if (typeof b.severity !== "string" || !SEVERITIES.has(b.severity)) return "severity";
  const dedupe = text(b.dedupe_key, 200);
  if (!dedupe) return "dedupe_key";
  const title = text(b.title, 200);
  if (!title) return "title";
  if (!isObj(b.refs)) return "refs";
  const resource = typeof b.refs.resource === "string" && REF_RE.test(b.refs.resource) ? b.refs.resource : undefined;
  if (!resource) return "refs.resource";
  const refs: ScdcEvent["refs"] = { resource };
  if (b.refs.tenant_ref !== undefined) {
    if (typeof b.refs.tenant_ref !== "string" || !TENANT_RE.test(b.refs.tenant_ref)) return "refs.tenant_ref";
    refs.tenant_ref = b.refs.tenant_ref;
  }
  if (b.refs.actor_ref !== undefined) {
    if (typeof b.refs.actor_ref !== "string" || !REF_RE.test(b.refs.actor_ref)) return "refs.actor_ref";
    refs.actor_ref = b.refs.actor_ref;
  }
  const ev: ScdcEvent = {
    specversion: "scdc/1",
    id: b.id,
    source: b.source,
    environment: b.environment as ScdcEvent["environment"],
    type: b.type,
    time: b.time,
    severity: b.severity as ScdcEvent["severity"],
    dedupe_key: dedupe,
    title,
    refs,
  };
  if (b.counts !== undefined) {
    if (!isObj(b.counts)) return "counts";
    const entries = Object.entries(b.counts);
    if (entries.length > 20) return "counts";
    const counts: Record<string, number> = {};
    for (const [k, v] of entries) {
      if (!COUNT_NAME_RE.test(k) || typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) return `counts.${k}`;
      counts[k] = v;
    }
    ev.counts = counts;
  }
  if (b.reason !== undefined && b.reason !== null) {
    if (typeof b.reason !== "string" || !REASON_RE.test(b.reason)) return "reason";
    ev.reason = b.reason;
  }
  if (b.ocsf_class_uid !== undefined && b.ocsf_class_uid !== null) {
    if (typeof b.ocsf_class_uid !== "number" || !Number.isSafeInteger(b.ocsf_class_uid)) return "ocsf_class_uid";
    ev.ocsf_class_uid = b.ocsf_class_uid;
  }
  return ev;
}

// ---------------------------------------------------------------------------
// Secret filter: refuse events whose text looks like it carries a credential.
// Products must send ids only; this is a backstop, not the control.

const SECRET_PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/, // AWS access key id
  /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}/, // GitHub tokens
  /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/, // Stripe
  /\bxox[abposr]-[A-Za-z0-9-]{10,}/, // Slack
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/, // JWT
  /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s:@]+:[^\s@]+@/, // URL with password
  /\bnpm_[A-Za-z0-9]{36}\b/,
  /\bAIza[0-9A-Za-z_-]{35}\b/, // Google API key
  /\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b/, // Telegram bot token
];

export function looksLikeSecret(ev: ScdcEvent): boolean {
  const strings: string[] = [ev.title, ev.dedupe_key, ev.type, ev.reason ?? "", ...Object.values(ev.refs)];
  return strings.some((s) => SECRET_PATTERNS.some((re) => re.test(s)));
}
