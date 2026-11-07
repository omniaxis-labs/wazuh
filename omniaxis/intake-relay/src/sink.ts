// Hand-off of verified events to Wazuh.
//
// ApiSink: POST /events on the local Wazuh server API (checked against 4.14.9
//   source: body {"events": [string, ...]}, at most 100 events per request,
//   at most 30 requests a minute (api/api/middlewares.py
//   MAX_REQUESTS_EVENTS_DEFAULT, not raisable by configuration), JWT from
//   POST /security/user/authenticate, RBAC action "event:ingest"). Events are
//   batched so the relay stays under the cap: 100 x 28/min = 2,800 events/min.
//   analysisd records them with location "API-Webhook".
// FileSink: appends to a file that Wazuh reads with <localfile> (syslog
//   format). Used on its own when configured, and as the durable fallback
//   whenever the API refuses or is down, so a verified event is never dropped.

import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { request as httpsRequest } from "node:https";
import { request as httpRequest, type IncomingMessage } from "node:http";
import { readFileSync } from "node:fs";
import type { ScdcEvent, PublicKeyRecord } from "./verify.ts";

export const LINE_PREFIX = "omniaxis-scdc: ";
export const API_MAX_BATCH = 100;
// 30/min is the hard cap; keep a margin for the token refresh and clock skew.
export const API_MIN_INTERVAL_MS = 2_200;

/** The single line Wazuh sees. Built only from fields the verifier allowlisted. */
export function toWazuhLine(ev: ScdcEvent, key: PublicKeyRecord, receivedAt: Date): string {
  const out: Record<string, unknown> = {
    specversion: ev.specversion,
    id: ev.id,
    source: ev.source,
    product: key.source,
    environment: ev.environment,
    type: ev.type,
    time: ev.time,
    severity: ev.severity,
    dedupe_key: ev.dedupe_key,
    title: ev.title,
  };
  if (Object.keys(ev.refs).length) out.refs = ev.refs;
  if (Object.keys(ev.counts).length) out.counts = ev.counts;
  if (ev.reason) out.reason = ev.reason;
  if (ev.ocsf_class_uid !== null) out.ocsf_class_uid = ev.ocsf_class_uid;
  out.key_id = key.id;
  out.received_at = receivedAt.toISOString();
  // JSON.stringify escapes every control character, so this is one line.
  return LINE_PREFIX + JSON.stringify(out);
}

export interface Sink {
  /** Queue lines. Resolves when they are durably handed off. */
  push(lines: string[]): Promise<void>;
  close(): Promise<void>;
  readonly name: string;
}

export class FileSink implements Sink {
  readonly name = "file";
  private chain: Promise<void> = Promise.resolve();
  private readonly path: string;
  constructor(path: string) {
    this.path = path;
  }
  push(lines: string[]): Promise<void> {
    if (lines.length === 0) return Promise.resolve();
    const data = lines.map((l) => l + "\n").join("");
    const next = this.chain.then(async () => {
      await mkdir(dirname(this.path), { recursive: true });
      await appendFile(this.path, data, { mode: 0o640 });
    });
    this.chain = next.catch(() => {});
    return next;
  }
  async close(): Promise<void> {
    await this.chain;
  }
}

export interface ApiSinkOptions {
  baseUrl: string; // e.g. https://127.0.0.1:55000
  user: string;
  passwordFile: string; // read at start; never logged
  caFile?: string; // the API's own certificate (self-signed by default)
  fallback: FileSink;
  onFailure?: (reason: string, count: number) => void;
  minIntervalMs?: number;
  /** Above this many waiting events, go straight to the file (about 7 s of API capacity). */
  maxQueue?: number;
}

type Waiter = { line: string; resolve: () => void; reject: (e: Error) => void };

export class ApiSink implements Sink {
  readonly name = "api";
  private queue: Waiter[] = [];
  private timer: NodeJS.Timeout | undefined;
  private lastSend = 0;
  private sending = false;
  private token: { value: string; expires: number } | undefined;
  private readonly password: string;
  private readonly ca: Buffer | undefined;
  private closed = false;
  private readonly o: ApiSinkOptions;

  constructor(o: ApiSinkOptions) {
    this.o = o;
    this.password = readFileSync(o.passwordFile, "utf8").trim();
    this.ca = o.caFile ? readFileSync(o.caFile) : undefined;
    const host = new URL(o.baseUrl).hostname;
    if (!["127.0.0.1", "localhost", "::1", "[::1]"].includes(host)) {
      throw new Error("the Wazuh API must be reached on localhost only");
    }
  }

  push(lines: string[]): Promise<void> {
    if (this.closed) return this.o.fallback.push(lines);
    if (this.queue.length + lines.length > (this.o.maxQueue ?? 300)) {
      // Back-pressure: straight to the durable file rather than grow memory.
      this.o.onFailure?.("queue_full", lines.length);
      return this.o.fallback.push(lines);
    }
    const ps = lines.map(
      (line) => new Promise<void>((resolve, reject) => this.queue.push({ line, resolve, reject })),
    );
    this.schedule();
    return Promise.all(ps).then(() => undefined);
  }

  private schedule(): void {
    if (this.timer || this.sending || this.queue.length === 0) return;
    const wait = Math.max(0, this.lastSend + (this.o.minIntervalMs ?? API_MIN_INTERVAL_MS) - Date.now());
    this.timer = setTimeout(() => {
      this.timer = undefined;
      void this.flush();
    }, wait);
  }

  async flush(): Promise<void> {
    if (this.sending || this.queue.length === 0) return;
    this.sending = true;
    const batch = this.queue.splice(0, API_MAX_BATCH);
    const lines = batch.map((w) => w.line);
    try {
      this.lastSend = Date.now();
      await this.send(lines);
      batch.forEach((w) => w.resolve());
    } catch (err) {
      const reason = err instanceof Error ? err.message : "unknown";
      this.o.onFailure?.(reason, lines.length);
      try {
        await this.o.fallback.push(lines);
        batch.forEach((w) => w.resolve());
      } catch (e) {
        batch.forEach((w) => w.reject(e as Error));
      }
    } finally {
      this.sending = false;
      this.schedule();
    }
  }

  private async send(lines: string[]): Promise<void> {
    const token = await this.getToken();
    const res = await this.call("POST", "/events", { Authorization: `Bearer ${token}` }, JSON.stringify({ events: lines }));
    if (res.status === 401) this.token = undefined;
    if (res.status !== 200) throw new Error(`api_status_${res.status}`);
    const body = JSON.parse(res.body) as { data?: { total_failed_items?: number } };
    if ((body.data?.total_failed_items ?? 0) > 0) throw new Error("api_partial_failure");
  }

  private async getToken(): Promise<string> {
    const now = Date.now();
    if (this.token && this.token.expires > now) return this.token.value;
    const basic = Buffer.from(`${this.o.user}:${this.password}`).toString("base64");
    const res = await this.call("POST", "/security/user/authenticate", { Authorization: `Basic ${basic}` });
    if (res.status !== 200) throw new Error(`api_auth_${res.status}`);
    const value = (JSON.parse(res.body) as { data: { token: string } }).data.token;
    // Default JWT lifetime is 900 s; refresh well before.
    this.token = { value, expires: now + 600_000 };
    return value;
  }

  private call(method: string, path: string, headers: Record<string, string>, body?: string): Promise<{ status: number; body: string }> {
    const url = new URL(path, this.o.baseUrl);
    const isHttps = url.protocol === "https:";
    const req = (isHttps ? httpsRequest : httpRequest)(url, {
      method,
      headers: { ...headers, ...(body ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } : {}) },
      timeout: 10_000,
      ...(isHttps
        ? {
            ca: this.ca,
            // The default Wazuh API certificate is self-signed for the host
            // name, not "127.0.0.1". Trust is pinned by `ca`; the connection
            // never leaves the loopback interface (checked in the constructor).
            checkServerIdentity: () => undefined,
            rejectUnauthorized: Boolean(this.ca),
          }
        : {}),
    });
    return new Promise((resolve, reject) => {
      req.on("timeout", () => req.destroy(new Error("api_timeout")));
      req.on("error", (e) => reject(new Error(e.message.startsWith("api_") ? e.message : "api_unreachable")));
      req.on("response", (res: IncomingMessage) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c: string) => (buf.length < 1_000_000 ? (buf += c) : undefined));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      });
      req.end(body);
    });
  }

  async close(): Promise<void> {
    this.closed = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    // Anything still queued goes to the durable file.
    const rest = this.queue.splice(0);
    if (rest.length) {
      await this.o.fallback.push(rest.map((w) => w.line));
      rest.forEach((w) => w.resolve());
    }
    await this.o.fallback.close();
  }
}
