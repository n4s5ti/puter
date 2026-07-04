// -- AgentSec ProvenanceSink ------------------------------------------------
//
// Best-effort audit trail for lease lifecycle and writeback events.
// Provenance is always best-effort — a failed emit NEVER blocks the
// lifecycle operation (lease issuance, revocation, writeback).
//
// Three implementations:
//   1. NoOpProvenanceSink    — default for tests / backward-compat.
//   2. JSONLProvenanceSink   — appends one JSON line per event to a file.
//      Durable fallback when LBug is not reachable.
//   3. HttpProvenanceSink    — POSTs events to a configurable LBug endpoint.
//      Graceful degrade on network failure: log warning + drop.
//
// See: types.ts (ProvenanceEvent, ProvenanceEventType)

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

import type { ProvenanceEvent } from './types.js';

// -- Interface --------------------------------------------------------------

export interface ProvenanceSink {
    emit(event: ProvenanceEvent): Promise<void>;
}

// -- No-op (backward-compatible default) ------------------------------------

export class NoOpProvenanceSink implements ProvenanceSink {
    async emit(_event: ProvenanceEvent): Promise<void> {
        // no-op
    }
}

// -- JSONL file sink (durable fallback) -------------------------------------
//
// Appends one JSON line per event to ${AGENTSEC_PROVENANCE_FILE} or
// ~/.puter/data/agentsec/provenance.jsonl. Lazily creates the directory
// on first write. Atomic append via fs.promises.appendFile.

const DEFAULT_PROVENANCE_FILE = process.env.AGENTSEC_PROVENANCE_FILE
    ?? path.join(os.homedir(), '.puter/data/agentsec/provenance.jsonl');

export class JSONLProvenanceSink implements ProvenanceSink {
    #filePath: string;
    #initialized = false;

    constructor(filePath?: string) {
        this.#filePath = filePath ?? DEFAULT_PROVENANCE_FILE;
    }

    async #ensureDir(): Promise<void> {
        if (this.#initialized) return;
        await fs.promises.mkdir(path.dirname(this.#filePath), { recursive: true });
        this.#initialized = true;
    }

    async emit(event: ProvenanceEvent): Promise<void> {
        await this.#ensureDir();
        const line = JSON.stringify(event) + '\n';
        await fs.promises.appendFile(this.#filePath, line, 'utf-8');
    }
}

// -- HTTP sink (LBug forwarder) ---------------------------------------------
//
// POSTs each event as JSON to a configurable LBug endpoint.
// On fetch failure or missing URL, logs a warning and drops the event —
// provenance is best-effort audit, never enforcement.

export class HttpProvenanceSink implements ProvenanceSink {
    #url: string;
    #authHeader: string | null;

    constructor(url: string, authHeader?: string) {
        this.#url = url;
        this.#authHeader = authHeader ?? null;
    }

    async emit(event: ProvenanceEvent): Promise<void> {
        if (!this.#url) {
            console.warn(
                `[agentsec] HttpProvenanceSink: no URL configured, dropping event ${event.type}:${event.lease_id}`,
            );
            return;
        }

        try {
            const headers: Record<string, string> = {
                'Content-Type': 'application/json',
            };
            if (this.#authHeader) {
                headers['Authorization'] = this.#authHeader;
            }

            const res = await fetch(this.#url, {
                method: 'POST',
                headers,
                body: JSON.stringify(event),
            });

            if (!res.ok) {
                console.warn(
                    `[agentsec] HttpProvenanceSink: POST to ${this.#url} ` +
                    `returned ${res.status} for event ${event.type}:${event.lease_id}`,
                );
            }
        } catch (err) {
            console.warn(
                `[agentsec] HttpProvenanceSink: fetch failed for event ` +
                `${event.type}:${event.lease_id} — ${(err as Error).message}`,
            );
        }
    }
}
