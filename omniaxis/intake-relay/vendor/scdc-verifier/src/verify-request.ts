import type { KeyObject } from "node:crypto";
import {
	decodePublicKey,
	parseSignatureHeader,
	verifySignature,
} from "./ed25519.ts";
import {
	type Environment,
	InvalidBody,
	parseAlert,
	parseEvent,
	type ScdcAlert,
	type ScdcEvent,
	type Source,
} from "./schema.ts";
import { findSecret } from "./secret-filter.ts";

/** Bodies over 16 KB are refused before they are read any further. */
export const MAX_BODY_BYTES = 16_384;
/** The replay window: the timestamp must be within 300 s of now, either way. */
export const TOLERANCE_SECONDS = 300;

/** One stored public key. Keys are scoped to one source and one environment. */
export type PublicKeyRecord = {
	id: string;
	source: Source;
	environment: Environment;
	/** Raw 32-byte Ed25519 public key, standard base64, optionally `whpk_`-prefixed. */
	publicKey: string;
};

export type RefusalReason =
	| "too_large"
	| "missing_headers"
	| "malformed"
	| "stale"
	| "bad_signature"
	| "invalid_json"
	| "invalid_body"
	| "id_mismatch"
	| "source_mismatch"
	| "environment_mismatch"
	| "secret_detected";

export type Refusal = {
	ok: false;
	status: 400 | 401 | 403 | 413 | 422;
	reason: RefusalReason;
	/** For invalid_body: the field that failed. Never a value. */
	field?: string;
};

export type Verified<B> = {
	ok: true;
	key: PublicKeyRecord;
	webhookId: string;
	timestamp: number;
	body: B;
};

/** Anything with a case-insensitive `get`, such as the Fetch `Headers`. */
export type HeaderLookup = { get(name: string): string | null };

export type VerifyInput = {
	headers: HeaderLookup;
	rawBody: Uint8Array;
	/** The keys that may have signed this request; normally all active keys. */
	keys: readonly PublicKeyRecord[];
	nowMs: number;
};

const WEBHOOK_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;

const refuse = (
	status: Refusal["status"],
	reason: RefusalReason,
	field?: string,
): Refusal =>
	field === undefined
		? { ok: false, status, reason }
		: { ok: false, status, reason, field };

/**
 * Verifies one signed intake request (design section 4). In order:
 *
 * 1. size: over 16 KB is refused (413) before anything else is done;
 * 2. the three Standard Webhooks headers must be present and well formed;
 * 3. the timestamp must be within ±300 s of `nowMs` (the replay window);
 * 4. one of the `v1a` signatures must verify against one of `keys` over
 *    `id.timestamp.body` (several signatures are allowed during rotation);
 * 5. the raw body must not contain anything shaped like a secret, checked
 *    before parsing so a secret in a field the allowlist would drop is still
 *    refused, never silently stored or passed on;
 * 6. the body must parse and pass the field allowlist;
 * 7. the body's `id` must equal `webhook-id`, and its `source` and
 *    `environment` must equal those of the key that signed it, so one
 *    product's key can never write another product's events.
 *
 * Deduplication on (source, id) is the caller's job, after this succeeds.
 */
export function verifyRequest(
	input: VerifyInput & { kind: "event" },
): Verified<ScdcEvent> | Refusal;
export function verifyRequest(
	input: VerifyInput & { kind: "alert" },
): Verified<ScdcAlert> | Refusal;
export function verifyRequest(
	input: VerifyInput & { kind: "event" | "alert" },
): Verified<ScdcEvent | ScdcAlert> | Refusal;
export function verifyRequest(
	input: VerifyInput & { kind: "event" | "alert" },
): Verified<ScdcEvent | ScdcAlert> | Refusal {
	const { headers, rawBody, keys, nowMs } = input;
	if (rawBody.byteLength > MAX_BODY_BYTES) return refuse(413, "too_large");

	const id = headers.get("webhook-id");
	const ts = headers.get("webhook-timestamp");
	const sigHeader = headers.get("webhook-signature");
	if (!id || !ts || !sigHeader) return refuse(400, "missing_headers");
	if (!WEBHOOK_ID.test(id) || !/^\d{1,15}$/.test(ts) || sigHeader.length > 2048)
		return refuse(400, "malformed");

	const timestamp = Number(ts);
	const skew = Math.abs(nowMs / 1000 - timestamp);
	// A non-finite clock or timestamp fails closed.
	if (!Number.isFinite(skew) || skew > TOLERANCE_SECONDS)
		return refuse(401, "stale");

	const signatures = parseSignatureHeader(sigHeader);
	let signer: PublicKeyRecord | undefined;
	outer: for (const record of keys) {
		const key: KeyObject | null = decodePublicKey(record.publicKey);
		if (!key) continue;
		for (const sig of signatures) {
			if (verifySignature(key, id, ts, rawBody, sig)) {
				signer = record;
				break outer;
			}
		}
	}
	if (!signer) return refuse(401, "bad_signature");

	let text: string;
	try {
		text = new TextDecoder("utf-8", { fatal: true }).decode(rawBody);
	} catch {
		return refuse(400, "invalid_json");
	}
	if (findSecret(text) !== null) return refuse(422, "secret_detected");

	let json: unknown;
	try {
		json = JSON.parse(text);
	} catch {
		return refuse(400, "invalid_json");
	}

	let body: ScdcEvent | ScdcAlert;
	try {
		body = input.kind === "alert" ? parseAlert(json) : parseEvent(json);
	} catch (e) {
		if (e instanceof InvalidBody) return refuse(422, "invalid_body", e.field);
		throw e;
	}

	if (body.id !== id) return refuse(422, "id_mismatch");
	if (body.source !== signer.source) return refuse(403, "source_mismatch");
	if (body.environment !== signer.environment)
		return refuse(403, "environment_mismatch");

	return { ok: true, key: signer, webhookId: id, timestamp, body };
}
