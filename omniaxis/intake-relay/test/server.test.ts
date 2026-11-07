import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { createRelay, RELAY_PREFIX } from "../src/server.ts";
import { Dedupe } from "../src/dedupe.ts";
import { ApiSink, FileSink, LINE_PREFIX, toWazuhLine, type Sink } from "../src/sink.ts";
import { loadConfig } from "../src/config.ts";
import { producer, event, signedHeaders } from "./helpers.ts";

const mw = producer("musterward");
const products = ["musterward", "omniaxis", "rackhand", "crosswalk"];

class MemorySink implements Sink {
  readonly name = "memory";
  lines: string[] = [];
  fail = false;
  async push(lines: string[]) {
    if (this.fail) throw new Error("boom");
    this.lines.push(...lines);
  }
  async close() {}
}

function startRelay(opts: { sink?: Sink; ratePerMinute?: number; trustProxy?: boolean } = {}) {
  const sink = (opts.sink ?? new MemorySink()) as MemorySink;
  const logs: Record<string, unknown>[] = [];
  const server = createRelay({
    keys: [mw.key],
    products,
    path: "/v1/events",
    sink,
    dedupe: new Dedupe(),
    relayLog: (f) => logs.push(f),
    trustProxy: opts.trustProxy ?? false,
    ratePerMinute: opts.ratePerMinute ?? 600,
  });
  return new Promise<{ url: string; sink: MemorySink; logs: typeof logs; server: Server }>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({ url: `http://127.0.0.1:${port}`, sink, logs, server });
    });
  });
}

async function post(url: string, body: string, headers: Record<string, string>) {
  const res = await fetch(`${url}/v1/events`, { method: "POST", body, headers });
  return { status: res.status, json: (await res.json()) as Record<string, unknown> };
}

test("accepts, hands one prefixed line to the sink, and dedupes retries", async () => {
  const r = await startRelay();
  const body = JSON.stringify(event({ email: "dropped@example.com" }));
  const h = signedHeaders(mw, body);
  const first = await post(r.url, body, h);
  assert.equal(first.status, 202);
  const again = await post(r.url, body, signedHeaders(mw, body));
  assert.equal(again.status, 200);
  assert.equal(again.json.status, "duplicate");
  assert.equal(r.sink.lines.length, 1);
  const line = r.sink.lines[0];
  assert.ok(line.startsWith(LINE_PREFIX));
  assert.equal(line.includes("\n"), false);
  const out = JSON.parse(line.slice(LINE_PREFIX.length));
  assert.equal(out.product, "musterward");
  assert.equal(out.key_id, "musterward-test");
  assert.equal("email" in out, false);
  assert.ok(out.received_at);
  r.server.close();
});

test("refusals return the right status and are logged for Wazuh", async () => {
  const r = await startRelay();
  const body = JSON.stringify(event({ source: "omniaxis" }));
  const res = await post(r.url, body, signedHeaders(mw, body));
  assert.equal(res.status, 403);
  assert.equal(res.json.error, "source_mismatch");
  const bad = await post(r.url, body, { ...signedHeaders(mw, body), "webhook-signature": `v1a,${Buffer.alloc(64).toString("base64")}` });
  assert.equal(bad.status, 401);
  assert.deepEqual(
    r.logs.map((l) => [l.event, l.reason, l.claimed_source]),
    [["refused", "source_mismatch", "omniaxis"], ["refused", "bad_signature", undefined]],
  );
  assert.equal(r.sink.lines.length, 0);
  r.server.close();
});

test("rejects oversize bodies with 413 without reading them all", async () => {
  const r = await startRelay();
  const body = "{" + " ".repeat(20_000) + "}";
  const res = await post(r.url, body, { "content-type": "application/json" });
  assert.equal(res.status, 413);
  r.server.close();
});

test("rejects wrong method, path and content type", async () => {
  const r = await startRelay();
  assert.equal((await fetch(`${r.url}/v1/events`)).status, 405);
  assert.equal((await fetch(`${r.url}/other`, { method: "POST" })).status, 404);
  const body = JSON.stringify(event());
  const res = await post(r.url, body, { ...signedHeaders(mw, body), "content-type": "text/plain" });
  assert.equal(res.status, 415);
  assert.equal((await fetch(`${r.url}/healthz`)).status, 200);
  r.server.close();
});

test("rate limits per client address and logs once", async () => {
  const r = await startRelay({ ratePerMinute: 2 });
  const body = JSON.stringify(event());
  const statuses = [];
  for (let i = 0; i < 4; i++) statuses.push((await post(r.url, body, signedHeaders(mw, body))).status);
  assert.deepEqual(statuses, [202, 200, 429, 429]);
  assert.equal(r.logs.filter((l) => l.reason === "rate_limited").length, 1);
  r.server.close();
});

test("uses the last X-Forwarded-For entry only behind the trusted proxy", async () => {
  const r = await startRelay({ trustProxy: true });
  const body = JSON.stringify(event({ source: "omniaxis" }));
  await post(r.url, body, { ...signedHeaders(mw, body), "x-forwarded-for": "1.2.3.4, 198.51.100.7" });
  assert.equal(r.logs[0].srcip, "198.51.100.7");
  r.server.close();
});

test("a sink failure returns 503 and forgets the id so the retry is accepted", async () => {
  const sink = new MemorySink();
  sink.fail = true;
  const r = await startRelay({ sink });
  const body = JSON.stringify(event());
  assert.equal((await post(r.url, body, signedHeaders(mw, body))).status, 503);
  sink.fail = false;
  assert.equal((await post(r.url, body, signedHeaders(mw, body))).status, 202);
  r.server.close();
});

test("dedupe journal survives a restart and expires after the window", () => {
  const dir = mkdtempSync(join(tmpdir(), "scdc-"));
  const journal = join(dir, "dedupe.journal");
  const t0 = 1_000_000;
  const a = new Dedupe({ journal, windowMs: 1000 });
  assert.equal(a.firstSeen("musterward", "evt_1", t0), true);
  assert.equal(a.firstSeen("musterward", "evt_1", t0 + 10), false);
  assert.equal(a.firstSeen("omniaxis", "evt_1", t0 + 10), true, "same id, other product");
  const b = new Dedupe({ journal, windowMs: 1000, now: t0 + 500 });
  assert.equal(b.firstSeen("musterward", "evt_1", t0 + 500), false);
  assert.equal(b.firstSeen("musterward", "evt_1", t0 + 1500), true);
});

// ---- ApiSink against a fake Wazuh API -------------------------------------

let fakeApi: Server;
let apiUrl: string;
const apiCalls: { path: string; auth: string; body: string }[] = [];
let apiFailEvents = false;

before(async () => {
  fakeApi = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      apiCalls.push({ path: req.url ?? "", auth: String(req.headers.authorization ?? ""), body });
      res.setHeader("content-type", "application/json");
      if (req.url === "/security/user/authenticate") {
        const ok = req.headers.authorization === `Basic ${Buffer.from("scdc-intake:pw-for-tests").toString("base64")}`;
        res.statusCode = ok ? 200 : 401;
        return res.end(JSON.stringify({ data: { token: "jwt-1" }, error: 0 }));
      }
      if (req.url === "/events") {
        if (apiFailEvents) {
          res.statusCode = 429;
          return res.end("{}");
        }
        const n = (JSON.parse(body) as { events: string[] }).events.length;
        return res.end(JSON.stringify({ data: { total_affected_items: n, total_failed_items: 0 }, error: 0 }));
      }
      res.statusCode = 404;
      res.end("{}");
    });
  });
  await new Promise<void>((r) => fakeApi.listen(0, "127.0.0.1", () => r()));
  apiUrl = `http://127.0.0.1:${(fakeApi.address() as AddressInfo).port}`;
});
after(() => fakeApi.close());

function apiSink(dir: string, failures: string[]) {
  const pw = join(dir, "pw");
  writeFileSync(pw, "pw-for-tests\n");
  return new ApiSink({
    baseUrl: apiUrl,
    user: "scdc-intake",
    passwordFile: pw,
    fallback: new FileSink(join(dir, "intake.log")),
    onFailure: (reason) => failures.push(reason),
    minIntervalMs: 50,
  });
}

test("ApiSink batches up to 100 events per POST /events with a bearer token", async () => {
  apiCalls.length = 0;
  apiFailEvents = false;
  const dir = mkdtempSync(join(tmpdir(), "scdc-"));
  const failures: string[] = [];
  const sink = apiSink(dir, failures);
  const lines = Array.from({ length: 150 }, (_, i) => `${LINE_PREFIX}{"n":${i}}`);
  await sink.push(lines);
  const events = apiCalls.filter((c) => c.path === "/events");
  assert.equal(apiCalls.filter((c) => c.path === "/security/user/authenticate").length, 1);
  assert.deepEqual(events.map((c) => (JSON.parse(c.body) as { events: string[] }).events.length), [100, 50]);
  assert.ok(events.every((c) => c.auth === "Bearer jwt-1"));
  assert.deepEqual(failures, []);
  assert.equal(existsSync(join(dir, "intake.log")), false);
  await sink.close();
});

test("ApiSink falls back to the durable file when the API refuses", async () => {
  apiFailEvents = true;
  const dir = mkdtempSync(join(tmpdir(), "scdc-"));
  const failures: string[] = [];
  const sink = apiSink(dir, failures);
  await sink.push([`${LINE_PREFIX}{"n":1}`]);
  assert.deepEqual(failures, ["api_status_429"]);
  assert.equal(readFileSync(join(dir, "intake.log"), "utf8"), `${LINE_PREFIX}{"n":1}\n`);
  apiFailEvents = false;
  await sink.close();
});

test("ApiSink refuses a non-loopback API address", () => {
  const dir = mkdtempSync(join(tmpdir(), "scdc-"));
  writeFileSync(join(dir, "pw"), "x");
  assert.throws(
    () => new ApiSink({ baseUrl: "https://203.0.113.5:55000", user: "u", passwordFile: join(dir, "pw"), fallback: new FileSink(join(dir, "f")) }),
    /localhost/,
  );
});

test("toWazuhLine never lets field text break the line", () => {
  const ev = { ...event(), title: "a\u2028b\u0000c" } as unknown as Parameters<typeof toWazuhLine>[0];
  const line = toWazuhLine(ev, mw.key, new Date(0));
  assert.equal(line.split("\n").length, 1);
});

test("config loads keys and refuses keys for unlisted products", () => {
  const dir = mkdtempSync(join(tmpdir(), "scdc-"));
  const raw = mw.key.keyObject.export({ format: "der", type: "spki" }).subarray(12).toString("base64");
  const file = join(dir, "c.json");
  writeFileSync(file, JSON.stringify({ products, keys: [{ source: "musterward", keyId: "k1", publicKey: raw }] }));
  const cfg = loadConfig(file, {});
  assert.equal(cfg.keys.length, 1);
  assert.equal(cfg.listen.host, "127.0.0.1");
  assert.equal(cfg.trustProxy, true);
  writeFileSync(file, JSON.stringify({ products, keys: [{ source: "acme", keyId: "k1", publicKey: raw }] }));
  assert.throws(() => loadConfig(file, {}), /unknown product/);
});

test("relay log lines carry the decoder prefix", () => {
  assert.equal(RELAY_PREFIX, "omniaxis-scdc-relay: ");
});
