// -- Tests for LeaseStore implementations and DI wiring --------------------

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Mock } from 'vitest';

import {
    InMemoryLeaseStore,
    FileLeaseStore,
    PuterKVLeaseStore,
} from './lease-store.js';
import type { LeaseStore } from './lease-store.js';
import type { LeaseRecord } from './types.js';

// -- Helpers ----------------------------------------------------------------

const makeRecord = (overrides: Partial<LeaseRecord> = {}): LeaseRecord => {
    const now = Math.floor(Date.now() / 1000);
    return {
        lease_id: crypto.randomUUID(),
        app_uid: 'app-test',
        target_uids: ['file-a-uid', 'file-b-uid'],
        anchor: 'file-root-uid',
        base_hashes: ['abc123'],
        exp: now + 3600,
        created_at: now,
        status: 'active',
        ...overrides,
    };
};

// Run a suite of tests against any LeaseStore implementation.
const testLeaseStore = (label: string, factory: () => LeaseStore): void => {
    describe(label, () => {
        let store: LeaseStore;

        beforeEach(() => {
            store = factory();
        });

        describe('create / get', () => {
            it('stores and retrieves a record', async () => {
                const rec = makeRecord();
                await store.create(rec);

                const got = await store.get(rec.lease_id);
                expect(got).toBeDefined();
                expect(got!.lease_id).toBe(rec.lease_id);
                expect(got!.app_uid).toBe('app-test');
                expect(got!.status).toBe('active');
            });

            it('returns undefined for unknown lease_id', async () => {
                const got = await store.get('nonexistent');
                expect(got).toBeUndefined();
            });
        });

        describe('update', () => {
            it('patches fields on an existing record', async () => {
                const rec = makeRecord();
                await store.create(rec);

                await store.update(rec.lease_id, { app_uid: 'app-updated' });

                const got = await store.get(rec.lease_id);
                expect(got!.app_uid).toBe('app-updated');
                // other fields unchanged
                expect(got!.anchor).toBe('file-root-uid');
            });

            it('silently skips unknown lease_id', async () => {
                await expect(
                    store.update('nonexistent', { status: 'revoked' }),
                ).resolves.toBeUndefined();
            });
        });

        describe('setRevoked', () => {
            it('marks an active record as revoked', async () => {
                const rec = makeRecord();
                await store.create(rec);

                await store.setRevoked(rec.lease_id, 'revoked');

                const got = await store.get(rec.lease_id);
                expect(got!.status).toBe('revoked');
            });

            it('marks an active record as expired', async () => {
                const rec = makeRecord();
                await store.create(rec);

                await store.setRevoked(rec.lease_id, 'expired');

                const got = await store.get(rec.lease_id);
                expect(got!.status).toBe('expired');
            });

            it('silently skips unknown lease_id', async () => {
                await expect(
                    store.setRevoked('nonexistent', 'revoked'),
                ).resolves.toBeUndefined();
            });
        });

        describe('listActive', () => {
            it('returns active unexpired records', async () => {
                const rec = makeRecord({ exp: Math.floor(Date.now() / 1000) + 86400 });
                await store.create(rec);

                const active = await store.listActive();
                expect(active).toHaveLength(1);
                expect(active[0].lease_id).toBe(rec.lease_id);
            });

            it('excludes expired records', async () => {
                const past = makeRecord({ exp: Math.floor(Date.now() / 1000) - 10 });
                await store.create(past);

                const active = await store.listActive();
                // The expired record may still be returned if the store
                // does not filter by exp (PuterKVLeaseStore), but for
                // InMemoryLeaseStore and FileLeaseStore it should not.
                // We assert it excludes the past-expiry record.
                expect(active.every((r) => r.exp > Math.floor(Date.now() / 1000)))
                    .toBe(true);
            });

            it('excludes revoked records', async () => {
                const rec = makeRecord({ status: 'revoked' });
                await store.create(rec);

                const active = await store.listActive();
                expect(active.every((r) => r.status === 'active')).toBe(true);
            });
        });

        describe('listAll', () => {
            it('returns all records regardless of status', async () => {
                const active = makeRecord();
                const revoked = makeRecord({ status: 'revoked' });
                await store.create(active);
                await store.create(revoked);

                const all = await store.listAll();
                expect(all.length).toBeGreaterThanOrEqual(2);
                const ids = all.map((r) => r.lease_id);
                expect(ids).toContain(active.lease_id);
                expect(ids).toContain(revoked.lease_id);
            });
        });
    });
};

// -- InMemoryLeaseStore -----------------------------------------------------

testLeaseStore('InMemoryLeaseStore', () => new InMemoryLeaseStore());

// -- FileLeaseStore ---------------------------------------------------------

describe('FileLeaseStore', () => {
    let tmpDir: string;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentsec-test-'));
    });

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('writes files to disk and reads them back', async () => {
        const store = new FileLeaseStore(tmpDir);
        const rec = makeRecord();
        await store.create(rec);

        // File exists on disk
        const safeId = rec.lease_id.replace(/[^a-fA-F0-9-]/g, '');
        const filePath = path.join(tmpDir, `${safeId}.json`);
        expect(fs.existsSync(filePath)).toBe(true);

        // Can read back
        const got = await store.get(rec.lease_id);
        expect(got).toBeDefined();
        expect(got!.lease_id).toBe(rec.lease_id);
    });

    it('survives across store instances (same dir)', async () => {
        const store1 = new FileLeaseStore(tmpDir);
        const rec = makeRecord();
        await store1.create(rec);

        // New instance, same dir reads same data
        const store2 = new FileLeaseStore(tmpDir);
        const got = await store2.get(rec.lease_id);
        expect(got).toBeDefined();
        expect(got!.lease_id).toBe(rec.lease_id);
    });

    it('performs atomic writes via tmp+rename', async () => {
        const store = new FileLeaseStore(tmpDir);
        const rec = makeRecord();
        await store.create(rec);

        // No .tmp files remain
        const files = fs.readdirSync(tmpDir);
        expect(files.every((f) => !f.includes('.tmp.'))).toBe(true);
    });

    it('creates the directory lazily on first write', async () => {
        const nested = path.join(tmpDir, 'nested', 'deep');
        // Dir does not exist yet
        expect(fs.existsSync(nested)).toBe(false);

        const store = new FileLeaseStore(nested);
        const rec = makeRecord();
        await store.create(rec);

        // Dir was created
        expect(fs.existsSync(nested)).toBe(true);
        const safeId = rec.lease_id.replace(/[^a-fA-F0-9-]/g, '');
        expect(fs.existsSync(path.join(nested, `${safeId}.json`))).toBe(true);
    });
});

// Shared tests for FileLeaseStore
testLeaseStore('FileLeaseStore (tmpdir)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentsec-test-'));
    return new FileLeaseStore(dir);
});

// -- PuterKVLeaseStore ------------------------------------------------------

describe('PuterKVLeaseStore', () => {
    let mockKv: {
        get: Mock;
        set: Mock;
    };

    beforeEach(() => {
        mockKv = {
            get: vi.fn().mockResolvedValue({ res: null }),
            set: vi.fn().mockResolvedValue({ res: true }),
        };
    });

    it('stores via kv.set with namespaced key', async () => {
        const store = new PuterKVLeaseStore(mockKv);
        const rec = makeRecord();
        await store.create(rec);

        expect(mockKv.set).toHaveBeenCalledTimes(1);
        expect(mockKv.set).toHaveBeenCalledWith({
            key: 'agentsec:lease:' + rec.lease_id,
            value: rec,
        });
    });

    it('retrieves via kv.get with namespaced key', async () => {
        const rec = makeRecord();
        mockKv.get.mockResolvedValue({ res: rec });

        const store = new PuterKVLeaseStore(mockKv);
        const got = await store.get(rec.lease_id);

        expect(mockKv.get).toHaveBeenCalledWith({
            key: 'agentsec:lease:' + rec.lease_id,
        });
        expect(got).toBeDefined();
        expect(got!.lease_id).toBe(rec.lease_id);
    });

    it('returns undefined when kv.get returns null', async () => {
        const store = new PuterKVLeaseStore(mockKv);
        const got = await store.get('unknown-lease');

        expect(got).toBeUndefined();
    });

    it('listActive and listAll return empty arrays (limitation)', async () => {
        const store = new PuterKVLeaseStore(mockKv);
        await expect(store.listActive()).resolves.toEqual([]);
        await expect(store.listAll()).resolves.toEqual([]);
    });

    it('setRevoked reads, patches, and re-writes', async () => {
        const rec = makeRecord();
        mockKv.get.mockResolvedValue({ res: rec });

        const store = new PuterKVLeaseStore(mockKv);
        await store.setRevoked(rec.lease_id, 'revoked');

        expect(mockKv.set).toHaveBeenCalledTimes(1);
        const setArg = mockKv.set.mock.calls[0][0] as { key: string; value: LeaseRecord };
        expect(setArg.value.status).toBe('revoked');
    });
});


