// -- Lease persistence for AgentSec grant-issuer ---------------------------
//
// Three store implementations:
//   1. InMemoryLeaseStore — Map-backed, default (used by tests).
//   2. FileLeaseStore     — JSON files under a configurable directory.
//   3. PuterKVLeaseStore  — Puter SystemKVStore (when available).
//
// The grant-issuer prefers: PuterKV > File > InMemory. Tests use InMemory.

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

import type { LeaseRecord } from './types.js';

// -- Interface --------------------------------------------------------------

export interface LeaseStore {
    create(rec: LeaseRecord): Promise<void>;
    get(lease_id: string): Promise<LeaseRecord | undefined>;
    update(lease_id: string, patch: Partial<LeaseRecord>): Promise<void>;
    listActive(): Promise<LeaseRecord[]>;
    listAll(): Promise<LeaseRecord[]>;
    setRevoked(lease_id: string, status: 'revoked' | 'expired'): Promise<void>;
}

// -- In-memory store (default for tests / fallback) ------------------------

export class InMemoryLeaseStore implements LeaseStore {
    #leases = new Map<string, LeaseRecord>();

    async create(rec: LeaseRecord): Promise<void> {
        this.#leases.set(rec.lease_id, { ...rec });
    }

    async get(lease_id: string): Promise<LeaseRecord | undefined> {
        return this.#leases.get(lease_id);
    }

    async update(lease_id: string, patch: Partial<LeaseRecord>): Promise<void> {
        const existing = this.#leases.get(lease_id);
        if (!existing) return;
        Object.assign(existing, patch);
    }

    async listActive(): Promise<LeaseRecord[]> {
        const now = Math.floor(Date.now() / 1000);
        const result: LeaseRecord[] = [];
        for (const rec of this.#leases.values()) {
            if (rec.status === 'active' && rec.exp > now) {
                result.push({ ...rec });
            }
        }
        return result;
    }

    async listAll(): Promise<LeaseRecord[]> {
        return Array.from(this.#leases.values()).map((r) => ({ ...r }));
    }

    async setRevoked(lease_id: string, status: 'revoked' | 'expired'): Promise<void> {
        const rec = this.#leases.get(lease_id);
        if (rec) {
            rec.status = status;
        }
    }
}

// -- File-based store (durable fallback -- survives restart) ----------------
//
// Persists each LeaseRecord as <lease_id>.json under LEASE_DIR.
// Atomic writes via tmp + rename. Lazily creates the dir on first write.

const DEFAULT_LEASE_DIR = process.env.AGENTSEC_LEASE_DIR
    ?? path.join(os.homedir(), '.puter/data/agentsec/leases');

export class FileLeaseStore implements LeaseStore {
    #dir: string;
    #initialized = false;

    constructor(dir?: string) {
        this.#dir = dir ?? DEFAULT_LEASE_DIR;
    }

    async #ensureDir(): Promise<void> {
        if (this.#initialized) return;
        await fs.promises.mkdir(this.#dir, { recursive: true });
        this.#initialized = true;
    }

    #pathFor(lease_id: string): string {
        // Sanitize -- only uuid chars to prevent path traversal
        const safe = lease_id.replace(/[^a-fA-F0-9-]/g, '');
        return path.join(this.#dir, `${safe}.json`);
    }

    async create(rec: LeaseRecord): Promise<void> {
        await this.#ensureDir();
        const fp = this.#pathFor(rec.lease_id);
        const tmp = fp + '.tmp.' + process.pid;
        await fs.promises.writeFile(tmp, JSON.stringify(rec), 'utf-8');
        await fs.promises.rename(tmp, fp);
    }

    async get(lease_id: string): Promise<LeaseRecord | undefined> {
        const fp = this.#pathFor(lease_id);
        try {
            const raw = await fs.promises.readFile(fp, 'utf-8');
            return JSON.parse(raw) as LeaseRecord;
        } catch (err: unknown) {
            if ((err as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
            throw err;
        }
    }

    async update(lease_id: string, patch: Partial<LeaseRecord>): Promise<void> {
        const rec = await this.get(lease_id);
        if (!rec) return;
        Object.assign(rec, patch);
        await this.create(rec);
    }

    async listActive(): Promise<LeaseRecord[]> {
        await this.#ensureDir();
        const now = Math.floor(Date.now() / 1000);
        const result: LeaseRecord[] = [];
        let names: string[];
        try {
            names = await fs.promises.readdir(this.#dir);
        } catch {
            return result;
        }
        for (const name of names) {
            if (!name.endsWith('.json')) continue;
            try {
                const raw = await fs.promises.readFile(
                    path.join(this.#dir, name), 'utf-8',
                );
                const rec = JSON.parse(raw) as LeaseRecord;
                if (rec.status === 'active' && rec.exp > now) {
                    result.push(rec);
                }
            } catch {
                // skip corrupt files
            }
        }
        return result;
    }

    async listAll(): Promise<LeaseRecord[]> {
        await this.#ensureDir();
        const result: LeaseRecord[] = [];
        let names: string[];
        try {
            names = await fs.promises.readdir(this.#dir);
        } catch {
            return result;
        }
        for (const name of names) {
            if (!name.endsWith('.json')) continue;
            try {
                const raw = await fs.promises.readFile(
                    path.join(this.#dir, name), 'utf-8',
                );
                result.push(JSON.parse(raw) as LeaseRecord);
            } catch {
                // skip corrupt files
            }
        }
        return result;
    }

    async setRevoked(lease_id: string, status: 'revoked' | 'expired'): Promise<void> {
        const rec = await this.get(lease_id);
        if (!rec) return;
        rec.status = status;
        await this.create(rec);
    }
}

// -- Puter KV store (preferred when SystemKVStore is available) ------------
//
// Available when the extension has access to `stores.kv` via
// `extension.import('store')`. The SystemKVStore exposes get/set with
// scoped namespacing. Use this when running inside a full Puter backend;
// fall back to FileLeaseStore when a standalone extension test runs.

export interface PuterKVLike {
    get(opts: { key: string }): Promise<{ res: unknown }>;
    set(opts: { key: string; value: unknown }): Promise<{ res: boolean }>;
}

export class PuterKVLeaseStore implements LeaseStore {
    #kv: PuterKVLike;
    #prefix: string;

    constructor(kv: PuterKVLike, prefix?: string) {
        this.#kv = kv;
        this.#prefix = prefix ?? 'agentsec:lease:';
    }

    #key(lease_id: string): string {
        return this.#prefix + lease_id;
    }

    async create(rec: LeaseRecord): Promise<void> {
        await this.#kv.set({ key: this.#key(rec.lease_id), value: rec });
    }

    async get(lease_id: string): Promise<LeaseRecord | undefined> {
        const { res } = await this.#kv.get({ key: this.#key(lease_id) });
        return (res as LeaseRecord) ?? undefined;
    }

    async update(lease_id: string, patch: Partial<LeaseRecord>): Promise<void> {
        const rec = await this.get(lease_id);
        if (!rec) return;
        Object.assign(rec, patch);
        await this.create(rec);
    }

    async listActive(): Promise<LeaseRecord[]> {
        // SystemKVStore has no prefix-scan on the public API,
        // so listActive is a no-op via KV; implementers that need
        // sweep must use a separate index or FileLeaseStore.
        return [];
    }

    async listAll(): Promise<LeaseRecord[]> {
        // Same limitation as listActive — KV has no scan.
        return [];
    }

    async setRevoked(lease_id: string, status: 'revoked' | 'expired'): Promise<void> {
        const rec = await this.get(lease_id);
        if (!rec) return;
        rec.status = status;
        await this.create(rec);
    }
}
