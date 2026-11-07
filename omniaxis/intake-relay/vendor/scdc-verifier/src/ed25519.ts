import {
	createPublicKey,
	type KeyObject,
	sign,
	timingSafeEqual,
	verify,
} from "node:crypto";

/** ASN.1 SubjectPublicKeyInfo header that precedes a raw 32-byte Ed25519 key. */
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const KEY_BYTES = 32;
export const SIGNATURE_BYTES = 64;
/** At most this many signatures are tried from one header (rotation needs two). */
export const MAX_SIGNATURES = 8;
const STD_BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Decodes standard base64 (RFC 4648 section 4, with padding) only when the
 * input is the canonical encoding of the bytes. Base64url is refused: the
 * Standard Webhooks `v1a` form is standard base64.
 */
export function decodeStdBase64(s: string): Buffer | null {
	if (s.length === 0 || s.length % 4 !== 0 || !STD_BASE64.test(s)) return null;
	const bytes = Buffer.from(s, "base64");
	return bytes.toString("base64") === s ? bytes : null;
}

/**
 * A public key object from a raw 32-byte Ed25519 key in standard base64,
 * with or without the Standard Webhooks `whpk_` prefix. Null if invalid.
 */
export function decodePublicKey(encoded: string): KeyObject | null {
	const raw = decodeStdBase64(
		encoded.startsWith("whpk_") ? encoded.slice(5) : encoded,
	);
	if (!raw || raw.length !== KEY_BYTES) return null;
	try {
		return createPublicKey({
			key: Buffer.concat([SPKI_PREFIX, raw]),
			format: "der",
			type: "spki",
		});
	} catch {
		return null;
	}
}

/** `whpk_<standard base64>` of the raw 32-byte public key. */
export function encodePublicKey(key: KeyObject): string {
	const der = key.export({ format: "der", type: "spki" });
	const raw = der.subarray(der.length - KEY_BYTES);
	if (
		der.length !== SPKI_PREFIX.length + KEY_BYTES ||
		!timingSafeEqual(der.subarray(0, SPKI_PREFIX.length), SPKI_PREFIX)
	)
		throw new Error("not an Ed25519 public key");
	return `whpk_${raw.toString("base64")}`;
}

/**
 * The signature entries of a `webhook-signature` header: space-separated
 * `<version>,<signature>` pairs. Only `v1a` entries whose value is canonical
 * standard base64 of 64 bytes are kept; others (such as HMAC `v1`) are
 * ignored, so a sender may include them for other receivers.
 */
export function parseSignatureHeader(header: string): Buffer[] {
	const out: Buffer[] = [];
	for (const part of header.trim().split(/\s+/)) {
		if (out.length >= MAX_SIGNATURES) break;
		const comma = part.indexOf(",");
		if (comma < 0 || part.slice(0, comma) !== "v1a") continue;
		const sig = decodeStdBase64(part.slice(comma + 1));
		if (sig && sig.length === SIGNATURE_BYTES) out.push(sig);
	}
	return out;
}

/** The signed content: `${id}.${timestamp}.` followed by the raw body bytes. */
function signedContent(
	id: string,
	timestamp: string,
	body: Uint8Array,
): Buffer {
	return Buffer.concat([Buffer.from(`${id}.${timestamp}.`, "utf8"), body]);
}

/** True when `signature` is a valid Ed25519 signature by `key` over `id.timestamp.body`. */
export function verifySignature(
	key: KeyObject,
	id: string,
	timestamp: string,
	body: Uint8Array,
	signature: Uint8Array,
): boolean {
	try {
		return verify(null, signedContent(id, timestamp, body), key, signature);
	} catch {
		return false;
	}
}

/**
 * Signs a request for the `webhook-signature` header: `v1a,<standard base64>`.
 * For producers and tests; the SCDC itself only ever holds public keys.
 */
export function signPayload(input: {
	id: string;
	timestamp: string;
	body: string | Uint8Array;
	privateKey: KeyObject;
}): string {
	const body =
		typeof input.body === "string"
			? new TextEncoder().encode(input.body)
			: input.body;
	const sig = sign(
		null,
		signedContent(input.id, input.timestamp, body),
		input.privateKey,
	);
	return `v1a,${sig.toString("base64")}`;
}
