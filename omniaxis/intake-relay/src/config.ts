// Relay configuration: one JSON file plus environment overrides.
// The file holds public keys and paths only; the Wazuh API password is read
// from its own file (mode 0400) and never appears in the config or logs.

import { readFileSync } from "node:fs";
import { checkKey, PRODUCTS, type PublicKeyRecord } from "./verify.ts";

export interface RelayConfig {
  listen: { host: string; port: number };
  path: string;
  products: string[];
  keys: PublicKeyRecord[];
  sink: "api" | "file";
  api: { baseUrl: string; user: string; passwordFile: string; caFile?: string };
  intakeLog: string;
  relayLog: string;
  dedupeJournal?: string;
  trustProxy: boolean;
  ratePerMinute: number;
}

interface RawConfig {
  listen?: { host?: string; port?: number };
  path?: string;
  products?: string[];
  keys?: unknown[];
  sink?: "api" | "file";
  api?: { baseUrl?: string; user?: string; passwordFile?: string; caFile?: string };
  intakeLog?: string;
  relayLog?: string;
  dedupeJournal?: string;
  trustProxy?: boolean;
  ratePerMinute?: number;
}

export function loadConfig(file: string, env: NodeJS.ProcessEnv = process.env): RelayConfig {
  const raw = JSON.parse(readFileSync(file, "utf8")) as RawConfig;
  // The product list is the contract's (the shared verifier's); a config
  // may narrow it but never add to it.
  const products = raw.products ?? [...PRODUCTS];
  for (const p of products) {
    if (!(PRODUCTS as readonly string[]).includes(p)) throw new Error(`config: unknown product ${p}`);
  }
  const keys = (raw.keys ?? []).map(checkKey);
  const ids = new Set<string>();
  for (const k of keys) {
    if (!products.includes(k.source)) throw new Error(`config: key ${k.id} names unlisted product ${k.source}`);
    if (ids.has(k.id)) throw new Error(`config: duplicate key id ${k.id}`);
    ids.add(k.id);
  }
  const sink = (env.SCDC_SINK as RelayConfig["sink"]) ?? raw.sink ?? "api";
  if (sink !== "api" && sink !== "file") throw new Error("config: sink must be api or file");
  const host = env.SCDC_LISTEN_HOST ?? raw.listen?.host ?? "127.0.0.1";
  return {
    listen: { host, port: Number(env.SCDC_LISTEN_PORT ?? raw.listen?.port ?? 8787) },
    path: raw.path ?? "/api/intake/v1",
    products,
    keys,
    sink,
    api: {
      baseUrl: env.SCDC_API_URL ?? raw.api?.baseUrl ?? "https://127.0.0.1:55000",
      user: raw.api?.user ?? "scdc-intake",
      passwordFile: env.SCDC_API_PASSWORD_FILE ?? raw.api?.passwordFile ?? "/etc/omniaxis-intake/api-password",
      caFile: raw.api?.caFile,
    },
    intakeLog: env.SCDC_INTAKE_LOG ?? raw.intakeLog ?? "/var/log/omniaxis-scdc/intake.log",
    relayLog: env.SCDC_RELAY_LOG ?? raw.relayLog ?? "/var/log/omniaxis-scdc/relay.log",
    dedupeJournal: env.SCDC_DEDUPE_JOURNAL ?? raw.dedupeJournal,
    // Only trust X-Forwarded-For when the relay listens on loopback behind Caddy.
    trustProxy: raw.trustProxy ?? (host === "127.0.0.1" || host === "::1"),
    ratePerMinute: raw.ratePerMinute ?? 600,
  };
}
