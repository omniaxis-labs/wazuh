// The SCDC intake relay: the only public endpoint of the SCDC server.
// Caddy terminates TLS on 443 and proxies one path to this server on
// 127.0.0.1. Everything else on the host stays private.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { verifyEvent, MAX_BODY_BYTES, type PublicKeyRecord } from "./verify.ts";
import { Dedupe } from "./dedupe.ts";
import { toWazuhLine, type Sink } from "./sink.ts";

export const RELAY_PREFIX = "omniaxis-scdc-relay: ";


export interface RelayDeps {
  keys: PublicKeyRecord[];
  path: string;
  sink: Sink;
  dedupe: Dedupe;
  relayLog: (fields: Record<string, unknown>) => void;
  trustProxy: boolean;
  ratePerMinute: number;
  now?: () => number; // ms
}

/** Relay log writer: one prefixed JSON line per event, read by Wazuh. */
export function fileRelayLog(path: string): (fields: Record<string, unknown>) => void {
  mkdirSync(dirname(path), { recursive: true });
  return (fields) => {
    // The relay is company infrastructure: alerts about it go to "company".
    const line = RELAY_PREFIX + JSON.stringify({ product: "company", component: "scdc-intake", ...fields, at: new Date().toISOString() });
    try {
      appendFileSync(path, line + "\n", { mode: 0o640 });
    } catch {
      process.stderr.write(line + "\n");
    }
  };
}

class RateLimiter {
  private buckets = new Map<string, { tokens: number; at: number; warned: number }>();
  private readonly perMinute: number;
  constructor(perMinute: number) {
    this.perMinute = perMinute;
  }
  /** Returns "ok", "limited" or "limited_first" (first refusal this minute). */
  take(ip: string, now: number): "ok" | "limited" | "limited_first" {
    let b = this.buckets.get(ip);
    if (!b) {
      if (this.buckets.size > 50_000) this.buckets.clear();
      b = { tokens: this.perMinute, at: now, warned: 0 };
      this.buckets.set(ip, b);
    }
    b.tokens = Math.min(this.perMinute, b.tokens + ((now - b.at) / 60_000) * this.perMinute);
    b.at = now;
    if (b.tokens >= 1) {
      b.tokens -= 1;
      return "ok";
    }
    if (now - b.warned > 60_000) {
      b.warned = now;
      return "limited_first";
    }
    return "limited";
  }
}

function clientIp(req: IncomingMessage, trustProxy: boolean): string {
  const peer = req.socket.remoteAddress ?? "unknown";
  if (!trustProxy) return peer;
  const xff = req.headers["x-forwarded-for"];
  const raw = Array.isArray(xff) ? xff.join(",") : xff;
  if (!raw) return peer;
  // Caddy appends the real peer last; anything earlier is client-supplied.
  const last = raw.split(",").pop()?.trim();
  return last && /^[0-9a-fA-F:.]{2,45}$/.test(last) ? last : peer;
}

function send(res: ServerResponse, status: number, body: Record<string, unknown>): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(text),
    "Cache-Control": "no-store",
  });
  res.end(text);
}

function readBody(req: IncomingMessage, limit: number): Promise<Buffer | "too_large"> {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers["content-length"] ?? "0");
    if (declared > limit) {
      req.resume();
      resolve("too_large");
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    let over = false;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > limit) {
        over = true;
        chunks.length = 0;
        return;
      }
      if (!over) chunks.push(c);
    });
    req.on("end", () => resolve(over ? "too_large" : Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export function createRelay(d: RelayDeps): Server {
  const limiter = new RateLimiter(d.ratePerMinute);
  const maxBytes = MAX_BODY_BYTES;
  const now = d.now ?? Date.now;

  const handler = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = (req.url ?? "/").split("?")[0];
    if (url === "/healthz" && req.method === "GET") return send(res, 200, { status: "ok" });
    if (url !== d.path) return send(res, 404, { error: "not_found" });
    if (req.method !== "POST") {
      res.setHeader("Allow", "POST");
      return send(res, 405, { error: "method_not_allowed" });
    }
    const ip = clientIp(req, d.trustProxy);
    const rl = limiter.take(ip, now());
    if (rl !== "ok") {
      if (rl === "limited_first") d.relayLog({ event: "refused", reason: "rate_limited", srcip: ip });
      res.setHeader("Retry-After", "60");
      req.resume();
      return send(res, 429, { error: "rate_limited" });
    }
    const ctype = String(req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
    if (ctype !== "application/json") {
      req.resume();
      d.relayLog({ event: "refused", reason: "bad_content_type", srcip: ip });
      return send(res, 415, { error: "unsupported_media_type" });
    }
    const body = await readBody(req, maxBytes);
    if (body === "too_large") {
      d.relayLog({ event: "refused", reason: "too_large", srcip: ip });
      return send(res, 413, { error: "too_large" });
    }

    const result = verifyEvent(req.headers, body, d.keys, now());
    if (!result.ok) {
      const fields: Record<string, unknown> = { event: "refused", reason: result.reason, srcip: ip };
      if (result.field) fields.field = result.field;
      if (result.reason === "source_mismatch" || result.reason === "environment_mismatch") {
        // The signature verified, so the body is a real product's: name what it claimed.
        try {
          const claimed = JSON.parse(body.toString("utf8")) as { source?: unknown; environment?: unknown };
          if (typeof claimed.source === "string") fields.claimed_source = claimed.source.slice(0, 32);
          if (typeof claimed.environment === "string") fields.claimed_environment = claimed.environment.slice(0, 16);
        } catch {
          /* already verified as JSON by the verifier */
        }
      }
      d.relayLog(fields);
      return send(res, result.status, { error: result.reason });
    }

    const event = result.body;
    const key = result.key;
    if (!d.dedupe.firstSeen(event.source, event.id, now())) {
      return send(res, 200, { status: "duplicate", id: event.id });
    }
    try {
      await d.sink.push([toWazuhLine(event, key, new Date(now()))]);
    } catch (e) {
      d.dedupe.forget(event.source, event.id);
      d.relayLog({ event: "sink_failed", reason: "durable_write_failed", srcip: ip, key_id: key.id });
      return send(res, 503, { error: "unavailable" });
    }
    return send(res, 202, { status: "accepted", id: event.id });
  };

  const server = createServer((req, res) => {
    handler(req, res).catch(() => {
      if (!res.headersSent) send(res, 500, { error: "internal" });
      else res.destroy();
    });
  });
  // Slow-loris protection; Caddy also enforces its own timeouts.
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;
  return server;
}
