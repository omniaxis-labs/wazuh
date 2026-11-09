import { describe, expect, it } from "vitest";
import {
	decodePublicKey,
	findSecret,
	MemoryDedupeStore,
	parseSignatureHeader,
	severityForLevel,
	TEST_VECTOR,
	verifySignature,
} from "../src/index.ts";

describe("severityForLevel (design section 12)", () => {
	it.each([
		[16, "sev1"],
		[13, "sev1"],
		[12, "sev2"],
		[10, "sev2"],
		[9, "sev3"],
		[7, "sev3"],
		[6, "sev4"],
		[3, "sev4"],
	])("level %i is %s", (level, sev) => {
		expect(severityForLevel(level)).toBe(sev);
	});

	it("has no severity below level 3", () => {
		expect(severityForLevel(2)).toBeNull();
	});
});

describe("parseSignatureHeader", () => {
	it("keeps v1a entries in standard base64 and ignores other versions", () => {
		const sig = Buffer.alloc(64, 7).toString("base64");
		expect(
			parseSignatureHeader(`v1,abc v1a,${sig} v1a,not-base64!`),
		).toHaveLength(1);
	});

	it("caps the number of entries it will try", () => {
		const sig = Buffer.alloc(64, 7).toString("base64");
		expect(
			parseSignatureHeader(Array(20).fill(`v1a,${sig}`).join(" ")),
		).toHaveLength(8);
	});
});

describe("public keys", () => {
	it("accepts whpk_ and bare standard base64, refuses other lengths", () => {
		const raw = Buffer.alloc(32, 1).toString("base64");
		expect(decodePublicKey(`whpk_${raw}`)).not.toBeNull();
		expect(decodePublicKey(raw)).not.toBeNull();
		expect(decodePublicKey(Buffer.alloc(31, 1).toString("base64"))).toBeNull();
	});
});

describe("the published test vector", () => {
	it("verifies, so other languages can check their signer against it", () => {
		const key = decodePublicKey(TEST_VECTOR.publicKey);
		if (!key) throw new Error("bad vector key");
		const sig = parseSignatureHeader(TEST_VECTOR.signature)[0];
		if (!sig) throw new Error("bad vector signature");
		expect(
			verifySignature(
				key,
				TEST_VECTOR.id,
				TEST_VECTOR.timestamp,
				new TextEncoder().encode(TEST_VECTOR.body),
				sig,
			),
		).toBe(true);
	});
});

describe("findSecret", () => {
	it.each([
		["AKIAABCDEFGHIJKLMNOP", "aws-access-key"],
		["-----BEGIN OPENSSH PRIVATE KEY-----", "private-key-block"],
		["postgres://user:pw@host/db", "connection-string"],
		["sk_live_0123456789abcdefABCD", "stripe-live-key"],
		["whsk_0123456789abcdefABCDEFGH", "webhook-secret"],
	])("finds %s", (text, rule) => {
		expect(findSecret(text)).toBe(rule);
	});

	it("leaves ordinary event text alone", () => {
		expect(
			findSecret("Staff step-up failed: no_permission for s_7"),
		).toBeNull();
	});
});

describe("MemoryDedupeStore: dedupe on (source, id)", () => {
	it("reports a replay as seen and a different source as new", () => {
		const store = new MemoryDedupeStore({ ttlMs: 1000 });
		expect(store.remember("musterward", "evt_1", 0)).toBe(true);
		expect(store.remember("musterward", "evt_1", 10)).toBe(false);
		expect(store.remember("omniaxis", "evt_1", 10)).toBe(true);
	});

	it("forgets after the time to live", () => {
		const store = new MemoryDedupeStore({ ttlMs: 1000 });
		store.remember("musterward", "evt_1", 0);
		expect(store.remember("musterward", "evt_1", 1001)).toBe(true);
	});

	it("never grows past its cap", () => {
		const store = new MemoryDedupeStore({ ttlMs: 10_000, maxEntries: 3 });
		for (let i = 0; i < 10; i++) store.remember("musterward", `evt_${i}`, i);
		expect(store.size).toBeLessThanOrEqual(3);
	});
});
