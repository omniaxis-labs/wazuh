/**
 * A fixed, published test vector so a signer in another language (the
 * Python Wazuh integration, a product's producer) can check its output
 * byte for byte. The seed is public and must never sign anything real.
 *
 * Private key: Ed25519 seed = bytes 0x01..0x20, standard base64 below.
 */
export const TEST_VECTOR = {
	seed: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
	publicKey: "whpk_ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=",
	id: "evt_test_vector_1",
	timestamp: "1794028369",
	body: '{"specversion":"scdc/1","id":"evt_test_vector_1","source":"musterward","environment":"preview","type":"auth.step_up_failed","time":"2026-11-07T05:12:49Z","severity":"sev3","dedupe_key":"auth.step_up_failed:s_7","title":"Staff step-up failed","refs":{"resource":"musterward-web"},"counts":{"attempts":3},"reason":"no_permission","ocsf_class_uid":null}',
	signature:
		"v1a,jkkiuMR6kKocRiUtZUINBd+T6xGqQmEg5R4y8+eHAUnwh9YFxco3VM9MJ9+r5wqDIv925tFYcdtwm80fMRuzCQ==",
} as const;
