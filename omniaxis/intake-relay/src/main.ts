// Entry point: node --disable-warning=ExperimentalWarning src/main.ts /etc/omniaxis-intake/config.json

import { loadConfig } from "./config.ts";
import { Dedupe } from "./dedupe.ts";
import { ApiSink, FileSink, type Sink } from "./sink.ts";
import { createRelay, fileRelayLog } from "./server.ts";

const configPath = process.argv[2] ?? process.env.SCDC_CONFIG ?? "/etc/omniaxis-intake/config.json";
const cfg = loadConfig(configPath);
const relayLog = fileRelayLog(cfg.relayLog);
const fileSink = new FileSink(cfg.intakeLog);

let sink: Sink = fileSink;
if (cfg.sink === "api") {
  sink = new ApiSink({
    ...cfg.api,
    fallback: fileSink,
    onFailure: (reason, count) => relayLog({ event: "sink_failed", reason, count, fallback: "file" }),
  });
}

const dedupe = new Dedupe({ journal: cfg.dedupeJournal });
setInterval(() => {
  dedupe.prune();
  dedupe.compact();
}, 24 * 3600 * 1000).unref();

const server = createRelay({
  keys: cfg.keys,
  path: cfg.path,
  sink,
  dedupe,
  relayLog,
  trustProxy: cfg.trustProxy,
  ratePerMinute: cfg.ratePerMinute,
});

server.listen(cfg.listen.port, cfg.listen.host, () => {
  relayLog({ event: "started", reason: `sink=${sink.name}`, keys: cfg.keys.length });
  process.stdout.write(`scdc intake relay listening on ${cfg.listen.host}:${cfg.listen.port}${cfg.path} (sink=${sink.name}, keys=${cfg.keys.length})\n`);
});

let stopping = false;
async function stop(): Promise<void> {
  if (stopping) return;
  stopping = true;
  server.close();
  await sink.close();
  dedupe.compact();
  process.exit(0);
}
process.on("SIGTERM", () => void stop());
process.on("SIGINT", () => void stop());
