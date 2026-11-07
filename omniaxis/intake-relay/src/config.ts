// Relay configuration: one JSON file plus environment overrides.
// The file holds public keys and paths only; the Wazuh API password is read
// from its own file (mode 0400) and never appears in the config or logs.

import { readFileSync } from "node:fs";
import { loadKey, type LoadedKey, type ProductKey } from "./verify.ts";

export interface RelayConfig {
  listen: { host: string; port: number };
  path: string;
  products: string[];
  keys: LoadedKey[];
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
  keys?: ProductKey[];
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
  const products = raw.products ?? [];
  if (products.length === 0) throw new Error("config: products is empty");
  const keys = (raw.keys ?? []).map(loadKey);
  for (const k of keys) {
    if (!products.includes(k.source)) throw new Error(`config: key ${k.keyId} names unknown product ${k.source}`);
  }
  const ids = new Set<string>();
  for (const k of keys) {
    if (ids.has(k.keyId)) throw new Error(`config: duplicate keyId ${k.keyId}`);
    ids.add(k.keyId);
  }
  const sink = (env.SCDC_SINK as RelayConfig["sink"]) ?? raw.sink ?? "api";
  if (sink !== "api" && sink !== "file") throw new Error("config: sink must be api or file");
  const host = env.SCDC_LISTEN_HOST ?? raw.listen?.host ?? "127.0.0.1";
  return {
    listen: { host, port: Number(env.SCDC_LISTEN_PORT ?? raw.listen?.port ?? 8787) },
    path: raw.path ?? "/v1/events",
    products,
    keys,
    sink,
    api: {
      baseUrl: env.SCDC_API_URL ?? raw.api?.baseUrl ?? "https://127.0.0.1:55000",
      user: raw.api?.user ?? "scdc-intake",
      passwordFile: env.SCDC_API_PASSWORD_FILE ?? raw.api?.passwordFile ?? "/etc/omniaxis-intake/api-password",
      caFile: raw.api?.caFile,
    },
    intakeLog: env.SCDC_INTAKE_LOG ?? raw.intakeLog ?? "/var/ossec/logs/omniaxis/intake.log",
    relayLog: env.SCDC_RELAY_LOG ?? raw.relayLog ?? "/var/ossec/logs/omniaxis/relay.log",
    dedupeJournal: env.SCDC_DEDUPE_JOURNAL ?? raw.dedupeJournal,
    // Only trust X-Forwarded-For when the relay listens on loopback behind Caddy.
    trustProxy: raw.trustProxy ?? (host === "127.0.0.1" || host === "::1"),
    ratePerMinute: raw.ratePerMinute ?? 600,
  };
}
