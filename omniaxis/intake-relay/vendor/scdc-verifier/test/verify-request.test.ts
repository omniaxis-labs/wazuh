import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	encodePublicKey,
	MAX_BODY_BYTES,
	type PublicKeyRecord,
	signPayload,
	TOLERANCE_SECONDS,
	verifyRequest,
} from "../src/index.ts";

const NOW_S = 1_794_028_600;
const NOW_MS = NOW_S * 1000;

function keyPair() {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	return { publicKey: encodePublicKey(publicKey), privateKey };
}

const mw = keyPair();
const ox = keyPair();
const wz = keyPair();

const KEYS: PublicKeyRecord[] = [
	{
		id: "k_mw",
		source: "musterward",
		environment: "production",
		publicKey: mw.publicKey,
	},
	{
		id: "k_ox",
		source: "omniaxis",
		environment: "production",
		publicKey: ox.publicKey,
	},
	{
		id: "k_wz",
		source: "wazuh",
		environment: "production",
		publicKey: wz.publicKey,
	},
];

function event(over: Record<string, unknown> = {}) {
	return {
		specversion: "scdc/1",
		id: "evt_01",
		source: "musterward",
		environment: "production",
		type: "auth.step_up_failed",
		time: "2026-11-07T05:12:49Z",
		severity: "sev3",
		dedupe_key: "auth.step_up_failed:staff_7",
		title: "Staff step-up failed",
		refs: {
			tenant_ref: "t_9f2c",
			actor_ref: "s_7",
			resource: "musterward-web",
		},
		counts: { attempts: 3 },
		reason: "no_permission",
		ocsf_class_uid: null,
		...over,
	};
}

function alert(over: Record<string, unknown> = {}) {
	return {
		specversion: "scdc-alert/1",
		id: "wz_1794028600.123",
		source: "wazuh",
		environment: "production",
		time: "2026-11-07T05:12:50Z",
		product: "musterward",
		product_environment: "production",
		type: "auth.step_up_failed",
		title: "Staff step-up failed",
		dedupe_key: "auth.step_up_failed:staff_7",
		severity: "sev2",
		rule: { id: "100210", level: 10, groups: ["scdc", "auth"] },
		...over,
	};
}

function request(
	body: unknown,
	opts: {
		key?: KeyObject;
		id?: string;
		ts?: number;
		raw?: string;
		sig?: string;
	} = {},
) {
	const raw = opts.raw ?? JSON.stringify(body);
	const id = opts.id ?? (body as { id: string }).id;
	const ts = String(opts.ts ?? NOW_S);
	const sig =
		opts.sig ??
		signPayload({
			id,
			timestamp: ts,
			body: raw,
			privateKey: opts.key ?? mw.privateKey,
		});
	const headers = new Headers({
		"webhook-id": id,
		"webhook-timestamp": ts,
		"webhook-signature": sig,
	});
	return { headers, rawBody: new TextEncoder().encode(raw) };
}

const verify = (
	r: ReturnType<typeof request>,
	kind: "event" | "alert" = "event",
	keys = KEYS,
) => verifyRequest({ ...r, keys, nowMs: NOW_MS, kind });

describe("verifyRequest: the section 4 contract", () => {
	it("accepts a correctly signed product event and names the key", () => {
		const res = verify(request(event()));
		expect(res.ok).toBe(true);
		if (!res.ok) return;
		expect(res.key.id).toBe("k_mw");
		expect(res.webhookId).toBe("evt_01");
		expect(res.body.title).toBe("Staff step-up failed");
	});

	it("refuses a tampered body", () => {
		const good = request(event());
		const tampered = new TextEncoder().encode(
			new TextDecoder().decode(good.rawBody).replace("sev3", "sev4"),
		);
		const res = verify({ ...good, rawBody: tampered });
		expect(res).toEqual({ ok: false, status: 401, reason: "bad_signature" });
	});

	it("refuses a tampered webhook-id even with the same body", () => {
		const r = request(event());
		r.headers.set("webhook-id", "evt_02");
		expect(verify(r)).toMatchObject({ ok: false, reason: "bad_signature" });
	});

	it("accepts a timestamp exactly 300 s old or ahead", () => {
		expect(TOLERANCE_SECONDS).toBe(300);
		expect(verify(request(event(), { ts: NOW_S - 300 })).ok).toBe(true);
		expect(verify(request(event(), { ts: NOW_S + 300 })).ok).toBe(true);
	});

	it("refuses a stale or future timestamp", () => {
		expect(verify(request(event(), { ts: NOW_S - 301 }))).toEqual({
			ok: false,
			status: 401,
			reason: "stale",
		});
		expect(verify(request(event(), { ts: NOW_S + 301 }))).toMatchObject({
			reason: "stale",
		});
	});

	it("refuses a non-numeric timestamp as malformed", () => {
		const r = request(event());
		r.headers.set("webhook-timestamp", "1e9");
		expect(verify(r)).toMatchObject({
			ok: false,
			status: 400,
			reason: "malformed",
		});
	});

	it("refuses a source that does not match the signing key", () => {
		// Signed with OmniAxis's real key, but claims to be Musterward.
		const res = verify(request(event(), { key: ox.privateKey }));
		expect(res).toEqual({ ok: false, status: 403, reason: "source_mismatch" });
	});

	it("refuses an environment that does not match the signing key", () => {
		const res = verify(request(event({ environment: "preview" })));
		expect(res).toEqual({
			ok: false,
			status: 403,
			reason: "environment_mismatch",
		});
	});

	it("refuses a signature from a key it does not hold", () => {
		const stranger = keyPair();
		expect(
			verify(request(event(), { key: stranger.privateKey })),
		).toMatchObject({
			reason: "bad_signature",
		});
	});

	it("refuses a body over 16 KB before reading it", () => {
		expect(MAX_BODY_BYTES).toBe(16_384);
		const big = event({ title: "x".repeat(MAX_BODY_BYTES) });
		expect(verify(request(big))).toEqual({
			ok: false,
			status: 413,
			reason: "too_large",
		});
	});

	it("accepts a body of exactly 16 KB as far as size goes", () => {
		const base = JSON.stringify(event({ reason: "" }));
		const raw = base.replace(
			'"reason":""',
			`"reason":"${"a".repeat(MAX_BODY_BYTES - base.length)}"`,
		);
		expect(new TextEncoder().encode(raw).byteLength).toBe(MAX_BODY_BYTES);
		const res = verify(request(null, { raw, id: "evt_01" }));
		// Too long a reason is a validation refusal, not a size refusal.
		expect(res).toMatchObject({ ok: false, reason: "invalid_body" });
	});

	it("accepts several signatures during key rotation", () => {
		const raw = JSON.stringify(event());
		const ts = String(NOW_S);
		const old = signPayload({
			id: "evt_01",
			timestamp: ts,
			body: raw,
			privateKey: keyPair().privateKey,
		});
		const current = signPayload({
			id: "evt_01",
			timestamp: ts,
			body: raw,
			privateKey: mw.privateKey,
		});
		expect(
			verify(request(null, { raw, id: "evt_01", sig: `${old} ${current}` })).ok,
		).toBe(true);
		expect(
			verify(request(null, { raw, id: "evt_01", sig: `v1,abc= ${current}` }))
				.ok,
		).toBe(true);
	});

	it("refuses an HMAC v1 signature on its own", () => {
		const r = request(event(), {
			sig: "v1,K5oZfzN95Z9UVu1EsfQmfVNQhnkZ2pj9o9NDN/H/pI4=",
		});
		expect(verify(r)).toMatchObject({ reason: "bad_signature" });
	});

	it("refuses a base64url signature: the contract is standard base64", () => {
		const r = request(event());
		const std = r.headers.get("webhook-signature") ?? "";
		const url = std.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
		if (url === std) return; // this signature happened to have no differing characters
		r.headers.set("webhook-signature", url);
		expect(verify(r)).toMatchObject({ reason: "bad_signature" });
	});

	it("refuses missing headers", () => {
		const r = request(event());
		r.headers.delete("webhook-signature");
		expect(verify(r)).toEqual({
			ok: false,
			status: 400,
			reason: "missing_headers",
		});
	});

	it("refuses a webhook-id that differs from the body id", () => {
		const raw = JSON.stringify(event({ id: "evt_other" }));
		const res = verify(request(null, { raw, id: "evt_01" }));
		expect(res).toEqual({ ok: false, status: 422, reason: "id_mismatch" });
	});

	it("refuses a body that is not JSON", () => {
		const res = verify(request(null, { raw: "not json", id: "evt_01" }));
		expect(res).toEqual({ ok: false, status: 400, reason: "invalid_json" });
	});

	it("drops fields that are not on the allowlist", () => {
		const res = verify(
			request(
				event({
					email: "someone@example.com",
					refs: { resource: "x", ip: "1.2.3.4" },
				}),
			),
		);
		expect(res.ok).toBe(true);
		if (!res.ok) return;
		expect(res.body).not.toHaveProperty("email");
		expect(res.body.refs).toEqual({ resource: "x" });
	});

	it("refuses a body that carries something shaped like a secret, even in a dropped field", () => {
		const res = verify(
			request(event({ notes: "ghp_0123456789abcdefghijABCDEFGHIJ012345" })),
		);
		expect(res).toEqual({ ok: false, status: 422, reason: "secret_detected" });
		const pem = verify(
			request(event({ title: "-----BEGIN PRIVATE KEY-----" })),
		);
		expect(pem).toMatchObject({ reason: "secret_detected" });
	});

	it("refuses an unknown source, severity or environment", () => {
		expect(verify(request(event({ severity: "sev9" })))).toMatchObject({
			reason: "invalid_body",
		});
		expect(verify(request(event({ environment: "staging" })))).toMatchObject({
			reason: "invalid_body",
		});
	});

	it("never trusts a key list that does not cover the claimed source", () => {
		const res = verify(
			request(event()),
			"event",
			KEYS.filter((k) => k.source !== "musterward"),
		);
		expect(res).toMatchObject({ ok: false, reason: "bad_signature" });
	});
});

describe("verifyRequest: Wazuh alerts", () => {
	it("accepts a signed alert from the Wazuh key", () => {
		const res = verify(request(alert(), { key: wz.privateKey }), "alert");
		expect(res.ok).toBe(true);
		if (!res.ok || res.body.specversion !== "scdc-alert/1")
			throw new Error("expected alert");
		expect(res.body.product).toBe("musterward");
		expect(res.body.severity).toBe("sev2");
	});

	it("refuses an alert signed with a product key", () => {
		const res = verify(request(alert(), { key: mw.privateKey }), "alert");
		expect(res).toEqual({ ok: false, status: 403, reason: "source_mismatch" });
	});

	it("derives severity from the rule level when absent, and refuses a mismatch", () => {
		const res = verify(
			request(alert({ severity: undefined, rule: { id: "1", level: 13 } }), {
				key: wz.privateKey,
			}),
			"alert",
		);
		expect(res.ok && res.body.severity).toBe("sev1");
		const bad = verify(
			request(alert({ severity: "sev4", rule: { id: "1", level: 13 } }), {
				key: wz.privateKey,
			}),
			"alert",
		);
		expect(bad).toMatchObject({ reason: "invalid_body" });
	});

	it("refuses a product event sent where an alert is expected", () => {
		const res = verify(request(event()), "alert");
		expect(res).toMatchObject({ ok: false, reason: "invalid_body" });
	});
});
