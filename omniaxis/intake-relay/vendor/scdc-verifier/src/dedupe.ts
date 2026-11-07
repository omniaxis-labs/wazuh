/**
 * Dedupe on (source, id). The contract says repeats within 7 days are
 * accepted but stored once, so a producer's retries are always safe.
 *
 * The portal dedupes in the database (a unique index on the signals table).
 * The intake relay on the Wazuh server uses this in-memory store in front of
 * Wazuh, or any store with the same method backed by disk.
 */
export interface DedupeStore {
	/** True when (source, id) is new and is now remembered; false for a repeat. */
	remember(
		source: string,
		id: string,
		nowMs: number,
	): boolean | Promise<boolean>;
}

export const DEDUPE_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

export class MemoryDedupeStore implements DedupeStore {
	readonly #ttlMs: number;
	readonly #max: number;
	// Map keeps insertion order, so the first entry is always the oldest.
	readonly #seen = new Map<string, number>();

	constructor(opts: { ttlMs?: number; maxEntries?: number } = {}) {
		this.#ttlMs = opts.ttlMs ?? DEDUPE_WINDOW_MS;
		this.#max = opts.maxEntries ?? 200_000;
	}

	get size(): number {
		return this.#seen.size;
	}

	remember(source: string, id: string, nowMs: number): boolean {
		this.#evict(nowMs);
		// A NUL cannot appear in either part, so the key is unambiguous.
		const key = `${source}\u0000${id}`;
		const at = this.#seen.get(key);
		if (at !== undefined && nowMs - at <= this.#ttlMs) return false;
		this.#seen.delete(key);
		this.#seen.set(key, nowMs);
		while (this.#seen.size > this.#max) {
			const oldest = this.#seen.keys().next().value;
			if (oldest === undefined) break;
			this.#seen.delete(oldest);
		}
		return true;
	}

	#evict(nowMs: number): void {
		for (const [key, at] of this.#seen) {
			if (nowMs - at <= this.#ttlMs) break;
			this.#seen.delete(key);
		}
	}
}
