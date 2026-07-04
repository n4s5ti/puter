// -- Tests for AgentSec ProvenanceSink --------------------------------------
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

import {
    NoOpProvenanceSink,
    JSONLProvenanceSink,
    HttpProvenanceSink,
} from './provenance.js';
import type { ProvenanceEvent } from './types.js';

// -- Helpers ----------------------------------------------------------------

const makeEvent = (overrides: Partial<ProvenanceEvent> = {}): ProvenanceEvent => ({
    type: 'lease_issued',
    lease_id: crypto.randomUUID(),
    ts: Date.now(),
    app_uid: 'app-123',
    uids: ['file-a-uid', 'file-b-uid'],
    ...overrides,
});

// -- NoOpProvenanceSink -----------------------------------------------------

describe('NoOpProvenanceSink', () => {
    it('resolves without error on emit', async () => {
        const sink = new NoOpProvenanceSink();
        await expect(sink.emit(makeEvent())).resolves.toBeUndefined();
    });

    it('handles multiple emits', async () => {
        const sink = new NoOpProvenanceSink();
        await sink.emit(makeEvent());
        await sink.emit(makeEvent({ type: 'writeback_applied' }));
        await sink.emit(makeEvent({ type: 'lease_revoked' }));
        // no assertion — proving no throw
    });
});

// -- JSONLProvenanceSink ----------------------------------------------------

describe('JSONLProvenanceSink', () => {
    let tmpDir: string;
    let filePath: string;
    let sink: JSONLProvenanceSink;

    beforeEach(() => {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'provenance-test-'));
        filePath = path.join(tmpDir, 'provenance.jsonl');
        sink = new JSONLProvenanceSink(filePath);
    });

    afterEach(() => {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('appends one JSON line per emitted event', async () => {
        const e1 = makeEvent({ type: 'lease_issued', app_uid: 'app-1' });
        const e2 = makeEvent({ type: 'writeback_applied', app_uid: 'app-1' });

        await sink.emit(e1);
        await sink.emit(e2);

        const content = fs.readFileSync(filePath, 'utf-8').trimEnd();
        const lines = content.split('\n');
        expect(lines).toHaveLength(2);

        const parsed1 = JSON.parse(lines[0]);
        const parsed2 = JSON.parse(lines[1]);

        expect(parsed1.type).toBe('lease_issued');
        expect(parsed1.lease_id).toBe(e1.lease_id);
        expect(parsed1.app_uid).toBe('app-1');

        expect(parsed2.type).toBe('writeback_applied');
        expect(parsed2.lease_id).toBe(e2.lease_id);
    });

    it('creates parent directories lazily', async () => {
        const nestedPath = path.join(tmpDir, 'nested', 'sub', 'events.jsonl');
        const nestedSink = new JSONLProvenanceSink(nestedPath);

        const event = makeEvent();
        await nestedSink.emit(event);

        expect(fs.existsSync(nestedPath)).toBe(true);
        const content = fs.readFileSync(nestedPath, 'utf-8').trimEnd();
        const parsed = JSON.parse(content);
        expect(parsed.lease_id).toBe(event.lease_id);
    });

    it('handles events with all optional fields', async () => {
        const event: ProvenanceEvent = {
            type: 'writeback_rejected',
            lease_id: crypto.randomUUID(),
            ts: Date.now(),
            app_uid: 'app-rejected',
            uids: ['uid-rejected'],
            reason: 'stale_hash',
            base_hashes: { 'uid-rejected': 'abc123' },
            anchor: 'file-root-uid',
        };

        await sink.emit(event);

        const content = fs.readFileSync(filePath, 'utf-8').trimEnd();
        const parsed = JSON.parse(content);
        expect(parsed.reason).toBe('stale_hash');
        expect(parsed.base_hashes['uid-rejected']).toBe('abc123');
    });

    it('survives concurrent emits', async () => {
        const events = Array.from({ length: 10 }, (_, i) =>
            makeEvent({ lease_id: `concurrent-${i}`, uids: [`uid-${i}`] }),
        );

        await Promise.all(events.map((e) => sink.emit(e)));

        const content = fs.readFileSync(filePath, 'utf-8').trimEnd();
        const lines = content.split('\n');
        expect(lines).toHaveLength(10);
    });
});

// -- HttpProvenanceSink -----------------------------------------------------

describe('HttpProvenanceSink', () => {
    beforeEach(() => {
        vi.restoreAllMocks();
    });

    describe('graceful degrade', () => {
        it('resolves without throwing when fetch rejects', async () => {
            vi.spyOn(globalThis, 'fetch').mockRejectedValue(
                new Error('Network failure'),
            );

            const sink = new HttpProvenanceSink('https://lbug.example.com/ingest');
            const event = makeEvent();

            await expect(sink.emit(event)).resolves.toBeUndefined();
        });

        it('resolves without throwing when URL is empty', async () => {
            const consoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => {});
            const sink = new HttpProvenanceSink('');
            const event = makeEvent();

            await expect(sink.emit(event)).resolves.toBeUndefined();
            expect(consoleWarn).toHaveBeenCalled();
        });

        it('resolves without throwing when fetch returns non-ok status', async () => {
            vi.spyOn(globalThis, 'fetch').mockResolvedValue(
                new Response(null, { status: 500 }),
            );

            const sink = new HttpProvenanceSink('https://lbug.example.com/ingest');
            const event = makeEvent();

            await expect(sink.emit(event)).resolves.toBeUndefined();
        });
    });

    describe('correct request format', () => {
        it('POSTs event JSON with correct content type', async () => {
            const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
                new Response(null, { status: 200 }),
            );

            const sink = new HttpProvenanceSink('https://lbug.example.com/ingest');
            const event = makeEvent({ lease_id: 'lease-http-1' });

            await sink.emit(event);

            expect(fetchSpy).toHaveBeenCalledTimes(1);
            const [url, options] = fetchSpy.mock.calls[0];
            expect(url).toBe('https://lbug.example.com/ingest');
            expect(options.method).toBe('POST');
            expect(options.headers).toEqual({
                'Content-Type': 'application/json',
            });

            const body = JSON.parse(options.body as string);
            expect(body.lease_id).toBe('lease-http-1');
            expect(body.type).toBe('lease_issued');
        });

        it('includes Authorization header when provided', async () => {
            const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
                new Response(null, { status: 200 }),
            );

            const sink = new HttpProvenanceSink(
                'https://lbug.example.com/ingest',
                'Bearer lbug-token-abc',
            );
            const event = makeEvent();

            await sink.emit(event);

            const [, options] = fetchSpy.mock.calls[0];
            expect(options.headers['Authorization']).toBe('Bearer lbug-token-abc');
        });

        it('serializes all event fields in the POST body', async () => {
            const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
                new Response(null, { status: 200 }),
            );

            const sink = new HttpProvenanceSink('https://lbug.example.com/ingest');
            const event: ProvenanceEvent = {
                type: 'writeback_rejected',
                lease_id: 'lease-full-1',
                ts: 1700000000000,
                app_uid: 'app-full',
                uids: ['uid-full'],
                reason: 'stale_hash',
                base_hashes: { 'uid-full': 'def456' },
                anchor: 'anchor-uid',
            };

            await sink.emit(event);

            const [, options] = fetchSpy.mock.calls[0];
            const body = JSON.parse(options.body as string);
            expect(body).toEqual({
                type: 'writeback_rejected',
                lease_id: 'lease-full-1',
                ts: 1700000000000,
                app_uid: 'app-full',
                uids: ['uid-full'],
                reason: 'stale_hash',
                base_hashes: { 'uid-full': 'def456' },
                anchor: 'anchor-uid',
            });
        });
    });
});
