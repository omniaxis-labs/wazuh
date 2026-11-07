// Repeats of (source, id) within 7 days are accepted but stored once
// (design section 4), so product retries are safe.
//
// In memory, with an append-only journal so a restart does not forget what it
// has seen. The journal is compacted on load and once a day.

import { appendFileSync, existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";

export const DEDUPE_WINDOW_MS = 7 * 24 * 3600 * 1000;

export class Dedupe {
  private seen = new Map<string, number>(); // key -> first seen (ms)
  private readonly journal: string | undefined;
  private readonly windowMs: number;
  private readonly maxEntries: number;

  constructor(opts: { journal?: string; windowMs?: number; maxEntries?: number; now?: number } = {}) {
    this.journal = opts.journal;
    this.windowMs = opts.windowMs ?? DEDUPE_WINDOW_MS;
    this.maxEntries = opts.maxEntries ?? 2_000_000;
    if (this.journal && existsSync(this.journal)) {
      const now = opts.now ?? Date.now();
      for (const line of readFileSync(this.journal, "utf8").split("\n")) {
        const tab = line.indexOf("\t");
        if (tab < 0) continue;
        const at = Number(line.slice(0, tab));
        if (Number.isFinite(at) && now - at < this.windowMs) this.seen.set(line.slice(tab + 1), at);
      }
      this.compact();
    }
  }

  static key(source: string, id: string): string {
    return `${source}\u0000${id}`;
  }

  /** True if this is the first time inside the window; records it. */
  firstSeen(source: string, id: string, now = Date.now()): boolean {
    const k = Dedupe.key(source, id);
    const at = this.seen.get(k);
    if (at !== undefined && now - at < this.windowMs) return false;
    if (this.seen.size >= this.maxEntries) this.prune(now);
    this.seen.set(k, now);
    if (this.journal) appendFileSync(this.journal, `${now}\t${k}\n`, { mode: 0o600 });
    return true;
  }

  /** Forget a key, used when the hand-off to Wazuh failed outright. */
  forget(source: string, id: string): void {
    this.seen.delete(Dedupe.key(source, id));
  }

  prune(now = Date.now()): void {
    for (const [k, at] of this.seen) if (now - at >= this.windowMs) this.seen.delete(k);
    // Still full: drop the oldest tenth (Map keeps insertion order).
    if (this.seen.size >= this.maxEntries) {
      let n = Math.ceil(this.maxEntries / 10);
      for (const k of this.seen.keys()) {
        if (n-- <= 0) break;
        this.seen.delete(k);
      }
    }
  }

  compact(): void {
    if (!this.journal) return;
    const tmp = `${this.journal}.tmp`;
    let out = "";
    for (const [k, at] of this.seen) out += `${at}\t${k}\n`;
    writeFileSync(tmp, out, { mode: 0o600 });
    renameSync(tmp, this.journal);
  }

  get size(): number {
    return this.seen.size;
  }
}
