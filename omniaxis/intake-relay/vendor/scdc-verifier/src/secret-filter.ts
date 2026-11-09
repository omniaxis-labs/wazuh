import { cleanText } from "./text.ts";

/**
 * Secret detection for intake bodies, adapted from Musterward's
 * `packages/intake/src/secret-filter.ts` (detection only: the SCDC refuses a
 * body that looks like it carries a key, it never stores a redacted copy).
 *
 * Each rule is anchored on a provider prefix so ordinary words do not match.
 * `findSecret` returns the rule's name, never the matched text, so a refusal
 * can be logged without repeating the secret.
 */
interface Rule {
	name: string;
	re: RegExp;
	/** Also run on the scan copy (marks and whitespace removed). */
	collapsed: boolean;
	/** Must match the cleaned text before scanRe runs on the scan copy. */
	scanGate?: RegExp;
	scanRe?: RegExp;
}

const RULES: readonly Rule[] = [
	{
		name: "aws-access-key",
		re: /(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}/,
		scanRe: /AKIA[A-Z0-9]{16}(?![A-Z0-9])/,
		collapsed: true,
	},
	{ name: "github-token", re: /gh[pousr]_[A-Za-z0-9]{36}/, collapsed: true },
	{ name: "github-pat", re: /github_pat_[A-Za-z0-9_]{22,}/, collapsed: true },
	{
		name: "stripe-live-key",
		re: /(?<![A-Za-z0-9])[sr]k_live_[A-Za-z0-9]{16,}/,
		scanGate: /(?<![A-Za-z0-9_])[sr]k_live_/,
		scanRe: /[sr]k_live_[A-Za-z0-9]{16,}/,
		collapsed: true,
	},
	{
		name: "stripe-test-key",
		re: /(?<![A-Za-z0-9])[sr]k_test_[A-Za-z0-9]{16,}/,
		scanGate: /(?<![A-Za-z0-9_])[sr]k_test_/,
		scanRe: /[sr]k_test_[A-Za-z0-9]{16,}/,
		collapsed: true,
	},
	{
		// Standard Webhooks secrets: HMAC (whsec_) and Ed25519 signing keys (whsk_).
		name: "webhook-secret",
		re: /(?<![A-Za-z0-9])wh(?:sec|sk)_[A-Za-z0-9+/=]{16,}/,
		scanGate: /(?<![A-Za-z0-9_])wh(?:sec|sk)_/,
		scanRe: /wh(?:sec|sk)_[A-Za-z0-9+/=]{16,}/,
		collapsed: true,
	},
	{ name: "slack-token", re: /xox[baprs]-[A-Za-z0-9-]{8,}/, collapsed: true },
	{ name: "private-key-block", re: /-----BEGIN/, collapsed: true },
	{ name: "openssh-private-key", re: /PRIVATE KEY-----/, collapsed: true },
	{
		name: "connection-string",
		re: /postgres(?:ql)?:\/\/[^\s:/@]+:[^\s@]+@/i,
		collapsed: false,
	},
	{
		name: "credential-url",
		re: /[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/@]+@/i,
		collapsed: false,
	},
	{
		name: "jwt",
		re: /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
		collapsed: true,
	},
	{
		name: "bearer-token",
		re: /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}/,
		collapsed: false,
	},
	{
		name: "aws-secret-key",
		re: /aws_?secret_?access_?key["'\s]*[=:]\s*["']?[A-Za-z0-9/+]{40}/i,
		collapsed: false,
	},
	{ name: "google-api-key", re: /AIza[0-9A-Za-z_-]{35}/, collapsed: true },
	{
		name: "anthropic-key",
		re: /(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,}/,
		scanGate: /(?<![A-Za-z0-9_])sk-ant-/,
		scanRe: /sk-ant-[A-Za-z0-9_-]{20,}/,
		collapsed: true,
	},
	{
		name: "openai-key",
		re: /(?<![A-Za-z0-9-])sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/,
		collapsed: false,
	},
	{
		name: "gitlab-token",
		re: /(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}/,
		scanGate: /(?<![A-Za-z0-9_])glpat-/,
		scanRe: /glpat-[A-Za-z0-9_-]{20,}/,
		collapsed: true,
	},
	{
		name: "node-package-token",
		re: /(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}/,
		scanGate: /(?<![A-Za-z0-9_])npm_/,
		scanRe: /npm_[A-Za-z0-9]{36}/,
		collapsed: true,
	},
	{
		name: "resend-key",
		re: /(?<![A-Za-z0-9])re_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/,
		collapsed: false,
	},
];

/**
 * The name of the first rule that matches, or null. Runs on the cleaned text
 * and on a scan copy with combining marks and all whitespace removed, so a
 * key split by spaces or invisible characters is still found.
 */
export function findSecret(s: string): string | null {
	const cleaned = cleanText(s);
	for (const r of RULES) if (r.re.test(cleaned)) return r.name;
	const scan = cleaned
		.normalize("NFD")
		.replace(/\p{M}/gu, "")
		.replace(/\s+/gu, "");
	for (const r of RULES)
		if (
			r.collapsed &&
			(!r.scanGate || r.scanGate.test(cleaned)) &&
			(r.scanRe ?? r.re).test(scan)
		)
			return r.name;
	return null;
}
