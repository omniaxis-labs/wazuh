import { cleanText } from "./text.ts";

/**
 * The scdc/1 product event and the scdc-alert/1 Wazuh alert (design
 * sections 4 and 12). Both are parsed through a field allowlist: anything
 * not named here is dropped, at every level, so a producer can never make
 * the SCDC store a field it did not plan for.
 */

export const PRODUCTS = [
	"musterward",
	"omniaxis",
	"rackhand",
	"crosswalk",
] as const;
export type Product = (typeof PRODUCTS)[number];
/** Alerts may also concern the company's shared accounts, not one product. */
export const ALERT_PRODUCTS = [...PRODUCTS, "company"] as const;
export type AlertProduct = (typeof ALERT_PRODUCTS)[number];
/** Who may sign: every product, and the Wazuh integration. */
export const SOURCES = [...PRODUCTS, "wazuh"] as const;
export type Source = (typeof SOURCES)[number];
export const ENVIRONMENTS = ["production", "preview"] as const;
export type Environment = (typeof ENVIRONMENTS)[number];
export const SEVERITIES = ["sev1", "sev2", "sev3", "sev4"] as const;
export type Severity = (typeof SEVERITIES)[number];

export type Refs = {
	tenant_ref?: string;
	actor_ref?: string;
	resource?: string;
};
export type Counts = Record<string, number>;

export type ScdcEvent = {
	specversion: "scdc/1";
	id: string;
	source: Product;
	environment: Environment;
	type: string;
	time: string;
	severity: Severity;
	dedupe_key: string;
	title: string;
	refs: Refs;
	counts: Counts;
	reason?: string;
	ocsf_class_uid: number | null;
};

export type ScdcAlert = {
	specversion: "scdc-alert/1";
	id: string;
	source: "wazuh";
	/** The Wazuh deployment's environment; must match the signing key. */
	environment: Environment;
	time: string;
	product: AlertProduct;
	/** The environment of the product the alert is about. */
	product_environment: Environment;
	type: string;
	title: string;
	dedupe_key: string;
	severity: Severity;
	rule: { id: string; level: number; groups: string[] };
	agent?: { name: string };
	/** The product event that raised the alert, when there was one. */
	event_id?: string;
	refs: Refs;
	counts: Counts;
	reason?: string;
};

/** Wazuh rule level to SCDC severity: 13+ SEV1, 10-12 SEV2, 7-9 SEV3, 3-6 SEV4. */
export function severityForLevel(level: number): Severity | null {
	if (level >= 13) return "sev1";
	if (level >= 10) return "sev2";
	if (level >= 7) return "sev3";
	if (level >= 3) return "sev4";
	return null;
}

export class InvalidBody extends Error {
	readonly field: string;
	constructor(field: string) {
		super(`invalid field: ${field}`);
		this.name = "InvalidBody";
		this.field = field;
	}
}

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const DOTTED = /^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+){0,7}$/;
const COUNT_KEY = /^[a-z][a-z0-9_]{0,39}$/;
const REF = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const RULE_ID = /^\d{1,9}$/;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/;

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

function oneOf<T extends string>(o: Obj, k: string, list: readonly T[]): T {
	const v = o[k];
	if (typeof v !== "string" || !(list as readonly string[]).includes(v))
		throw new InvalidBody(k);
	return v as T;
}

function matching(o: Obj, k: string, re: RegExp): string {
	const v = o[k];
	if (typeof v !== "string" || !re.test(v)) throw new InvalidBody(k);
	return v;
}

/** Plain text: cleaned of invisible and control characters, 1..max characters. */
function text(o: Obj, k: string, max: number): string {
	const v = o[k];
	if (typeof v !== "string") throw new InvalidBody(k);
	const t = cleanText(v).replace(/\s+/g, " ").trim();
	if (t.length === 0 || t.length > max) throw new InvalidBody(k);
	return t;
}

function optional<T>(
	o: Obj,
	k: string,
	read: (o: Obj, k: string) => T,
): T | undefined {
	return o[k] === undefined || o[k] === null ? undefined : read(o, k);
}

/** A dotted code such as `auth.step_up_failed`, at most 100 characters. */
function dotted(o: Obj, k: string): string {
	const v = matching(o, k, DOTTED);
	if (v.length > 100) throw new InvalidBody(k);
	return v;
}

function time(o: Obj, k: string): string {
	const v = matching(o, k, ISO_TIME);
	if (Number.isNaN(Date.parse(v))) throw new InvalidBody(k);
	return v;
}

function refs(o: Obj): Refs {
	const r = o.refs;
	if (r === undefined || r === null) return {};
	if (!isObj(r)) throw new InvalidBody("refs");
	const out: Refs = {};
	for (const k of ["tenant_ref", "actor_ref", "resource"] as const) {
		const v = optional(r, k, (x, key) => matching(x, key, REF));
		if (v !== undefined) out[k] = v;
	}
	return out;
}

function counts(o: Obj): Counts {
	const c = o.counts;
	if (c === undefined || c === null) return {};
	if (!isObj(c)) throw new InvalidBody("counts");
	const entries = Object.entries(c);
	if (entries.length > 16) throw new InvalidBody("counts");
	const out: Counts = {};
	for (const [k, v] of entries) {
		if (
			!COUNT_KEY.test(k) ||
			typeof v !== "number" ||
			!Number.isSafeInteger(v) ||
			v < 0
		)
			throw new InvalidBody(`counts.${k}`);
		out[k] = v;
	}
	return out;
}

function withOptional<T extends Obj>(base: T, extra: Obj): T {
	for (const [k, v] of Object.entries(extra))
		if (v !== undefined) (base as Obj)[k] = v;
	return base;
}

/** Parses a product event through the allowlist. Throws InvalidBody. */
export function parseEvent(v: unknown): ScdcEvent {
	if (!isObj(v)) throw new InvalidBody("body");
	if (v.specversion !== "scdc/1") throw new InvalidBody("specversion");
	const ocsf = v.ocsf_class_uid;
	if (
		ocsf !== undefined &&
		ocsf !== null &&
		!(Number.isSafeInteger(ocsf) && (ocsf as number) >= 0)
	)
		throw new InvalidBody("ocsf_class_uid");
	const base: ScdcEvent = {
		specversion: "scdc/1",
		id: matching(v, "id", ID),
		source: oneOf(v, "source", PRODUCTS),
		environment: oneOf(v, "environment", ENVIRONMENTS),
		type: dotted(v, "type"),
		time: time(v, "time"),
		severity: oneOf(v, "severity", SEVERITIES),
		dedupe_key: text(v, "dedupe_key", 200),
		title: text(v, "title", 140),
		refs: refs(v),
		counts: counts(v),
		ocsf_class_uid: (ocsf as number | null | undefined) ?? null,
	};
	return withOptional(base, { reason: optional(v, "reason", dotted) });
}

/** Parses a Wazuh alert through the allowlist. Throws InvalidBody. */
export function parseAlert(v: unknown): ScdcAlert {
	if (!isObj(v)) throw new InvalidBody("body");
	if (v.specversion !== "scdc-alert/1") throw new InvalidBody("specversion");
	if (v.source !== "wazuh") throw new InvalidBody("source");
	const r = v.rule;
	if (!isObj(r)) throw new InvalidBody("rule");
	const level = r.level;
	if (
		typeof level !== "number" ||
		!Number.isInteger(level) ||
		level < 0 ||
		level > 16
	)
		throw new InvalidBody("rule.level");
	const derived = severityForLevel(level);
	if (!derived) throw new InvalidBody("rule.level");
	const claimed = optional(v, "severity", (o, k) => oneOf(o, k, SEVERITIES));
	if (claimed !== undefined && claimed !== derived)
		throw new InvalidBody("severity");
	const groupsRaw = r.groups ?? [];
	if (!Array.isArray(groupsRaw) || groupsRaw.length > 16)
		throw new InvalidBody("rule.groups");
	const groups = groupsRaw.map((g) => {
		if (typeof g !== "string" || !/^[a-z0-9_-]{1,40}$/.test(g))
			throw new InvalidBody("rule.groups");
		return g;
	});
	let agent: { name: string } | undefined;
	if (v.agent !== undefined && v.agent !== null) {
		if (!isObj(v.agent)) throw new InvalidBody("agent");
		agent = { name: matching(v.agent, "name", REF) };
	}
	const base: ScdcAlert = {
		specversion: "scdc-alert/1",
		id: matching(v, "id", ID),
		source: "wazuh",
		environment: oneOf(v, "environment", ENVIRONMENTS),
		time: time(v, "time"),
		product: oneOf(v, "product", ALERT_PRODUCTS),
		product_environment: oneOf(v, "product_environment", ENVIRONMENTS),
		type: dotted(v, "type"),
		title: text(v, "title", 140),
		dedupe_key: text(v, "dedupe_key", 200),
		severity: derived,
		rule: { id: matching(r, "id", RULE_ID), level, groups },
		refs: refs(v),
		counts: counts(v),
	};
	return withOptional(base, {
		agent,
		event_id: optional(v, "event_id", (o, k) => matching(o, k, ID)),
		reason: optional(v, "reason", dotted),
	});
}
