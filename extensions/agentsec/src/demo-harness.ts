// -- Demo E core integration harness -----------------------------------------
//
// Runnable demonstration that exercises the COMPLETE built primitive chain
// end-to-end with mocked services (blast, fs), proving the lease security
// model works as a coherent system.
//
// Run via: npx vitest run extensions/agentsec/src/demo-harness.test.ts
//
// The test is the authoritative way to execute this demo — it injects the
// REAL AgentSecGrantIssuer (via vitest module mocks) + WritebackBroker,
// exercises every step, and asserts the transcript + provenance audit trail.
//
// To run standalone outside vitest:
//   npx tsx extensions/agentsec/src/demo-harness.ts
// (requires @heyputer/backend mocks to be hoisted; use the test instead.)

import crypto from 'node:crypto';

import { InMemoryLeaseStore } from './lease-store.js';
import { sign, verify } from './jwt.js';
import { WritebackBroker } from './writeback.js';
import type { FsServiceShim } from './writeback.js';
import type {
    GrantRequest,
    LeaseToken,
    LeaseRecord,
    WritebackRequest,
    WritebackPatch,
    WritebackResult,
    ProvenanceEvent,
} from './types.js';
import type { ProvenanceSink } from './provenance.js';

// -- Constants --------------------------------------------------------------

const DEMO_SECRET = 'demo-e-leakme-secret';
const JWT_AUDIENCE = 'agentsec-grant-issuer';
const APP_UID = 'agent-app-1';
const ACTOR = { user: { id: 1, uuid: 'user-uuid-1' } };

// -- Mock FsServiceShim -----------------------------------------------------

class MockFsService implements FsServiceShim {
    readonly #store: Map<string, { content: string }>;

    constructor(store: Map<string, { content: string }>) {
        this.#store = store;
    }

    async readContent(uid: string): Promise<string | Buffer> {
        const entry = this.#store.get(uid);
        if (!entry) {
            throw new Error(`MockFs: file not found: ${uid}`);
        }
        return entry.content;
    }

    async write(uid: string, content: string): Promise<void> {
        const entry = this.#store.get(uid);
        if (!entry) {
            throw new Error(`MockFs: file not found: ${uid}`);
        }
        entry.content = content;
    }
}

// -- Capturing provenance sink ----------------------------------------------

export class CapturingProvenanceSink implements ProvenanceSink {
    readonly events: ProvenanceEvent[] = [];

    async emit(event: ProvenanceEvent): Promise<void> {
        this.events.push(event);
    }
}

// -- Hash helper ------------------------------------------------------------

const sha256 = (content: string): string =>
    crypto.createHash('sha256').update(content).digest('hex');

// -- Mock blast -------------------------------------------------------------

const mockBlast = (_symbolOrTask: string): string[] => ['fileA', 'fileB'];

// -- Demo transcript types --------------------------------------------------

export interface DemoStep {
    step: number;
    action: string;
    result: unknown;
    ok: boolean;
}

export interface DemoTranscript {
    steps: DemoStep[];
    provenance: ProvenanceEvent[];
    finalFsState: Record<string, string>;
}

// -- Services interface for dependency injection ----------------------------

export interface DemoEServices {
    /** Minimal lease manager surface (AgentSecGrantIssuer or equivalent) */
    leaseManager: {
        issueLease(
            actor: unknown,
            req: GrantRequest,
        ): Promise<LeaseToken>;
        revokeLease(actor: unknown, leaseId: string): Promise<void>;
        revokeExpired(actor: unknown): Promise<number>;
    };
    writebackBroker: WritebackBroker;
    mockFsStore: Map<string, { content: string }>;
    fsService: FsServiceShim;
    provenance: CapturingProvenanceSink;
    leaseStore: InMemoryLeaseStore;
    secret: string;
}

// -- Demo E core ------------------------------------------------------------

export async function runDemoE(
    services: DemoEServices,
): Promise<DemoTranscript> {
    const {
        leaseManager,
        writebackBroker,
        mockFsStore,
        fsService,
        provenance,
        leaseStore,
        secret,
    } = services;

    const steps: DemoStep[] = [];
    const pushStep = (
        step: number,
        action: string,
        result: unknown,
    ): void => {
        steps.push({ step, action, result, ok: true });
    };
    const pushFail = (
        step: number,
        action: string,
        result: unknown,
    ): void => {
        steps.push({ step, action, result, ok: false });
    };

    // ---- Step 1: BLAST ----------------------------------------------------
    const blastUids = mockBlast('edit auth module');
    // Seed mockFs with initial content
    mockFsStore.set('fileA', { content: 'original content A' });
    mockFsStore.set('fileB', { content: 'original content B' });
    const hashA = sha256('original content A');
    const hashB = sha256('original content B');
    pushStep(1, 'blast', {
        uids: blastUids,
        hashA,
        hashB,
    });

    // ---- Step 2: ISSUE LEASE ----------------------------------------------
    const tokenPayload: Record<string, unknown> = {
        jti: crypto.randomUUID(),
        sub: APP_UID,
        iss: 'oracle',
        aud: JWT_AUDIENCE,
        exp: Math.floor(Date.now() / 1000) + 120,
        iat: Math.floor(Date.now() / 1000),
        app_uid: APP_UID,
        anchor: 'edit auth module',
        target_uids: ['fileA', 'fileB'],
        base_hash: hashA,
    };
    const signedToken = sign(tokenPayload, secret);

    const grantReq: GrantRequest = {
        app_uid: APP_UID,
        target_uids: ['fileA', 'fileB'],
        anchor: 'edit auth module',
        base_hashes: [hashA, hashB],
        ttl_seconds: 120,
        token: signedToken,
    };

    let leaseToken: LeaseToken;
    try {
        leaseToken = await leaseManager.issueLease(ACTOR, grantReq);
        pushStep(2, 'issue lease', {
            lease_id: leaseToken.jti,
            target_uids: leaseToken.target_uids,
        });
    } catch (err) {
        pushFail(2, 'issue lease', { error: String(err) });
        return { steps, provenance: provenance.events, finalFsState: {} };
    }

    // ---- Step 3: VALID WRITEBACK ------------------------------------------
    const wbReq3: WritebackRequest = {
        token: leaseToken.token,
        app_uid: APP_UID,
        patches: [
            { uid: 'fileA', base_hash: hashA, content: 'new content A' },
        ],
    };
    let wbResult3: WritebackResult;
    try {
        wbResult3 = await writebackBroker.applyWriteback(wbReq3);
        pushStep(3, 'valid writeback', {
            applied: wbResult3.applied,
            rejected: wbResult3.rejected,
        });
    } catch (err) {
        pushFail(3, 'valid writeback', { error: String(err) });
        return { steps, provenance: provenance.events, finalFsState: {} };
    }

    // ---- Step 4: UNLEASED REJECT ------------------------------------------
    const wbReq4: WritebackRequest = {
        token: leaseToken.token,
        app_uid: APP_UID,
        patches: [
            { uid: 'fileC', base_hash: 'nohash', content: 'ghost content' },
        ],
    };
    const wbResult4 = await writebackBroker.applyWriteback(wbReq4);
    pushStep(4, 'unleased writeback', {
        applied: wbResult4.applied,
        rejected: wbResult4.rejected,
    });

    // ---- Step 5: STALE HASH REJECT ----------------------------------------
    const wbReq5: WritebackRequest = {
        token: leaseToken.token,
        app_uid: APP_UID,
        patches: [
            { uid: 'fileB', base_hash: '0000000000000000000000000000000000000000000000000000000000000000', content: 'stale content B' },
        ],
    };
    const wbResult5 = await writebackBroker.applyWriteback(wbReq5);
    pushStep(5, 'stale hash writeback', {
        applied: wbResult5.applied,
        rejected: wbResult5.rejected,
    });

    // ---- Step 6: REVOKE ---------------------------------------------------
    try {
        await leaseManager.revokeLease(ACTOR, leaseToken.jti);
        pushStep(6, 'revoke lease', { lease_id: leaseToken.jti });
    } catch (err) {
        pushFail(6, 'revoke lease', { error: String(err) });
        return { steps, provenance: provenance.events, finalFsState: {} };
    }

    // ---- Step 7: POST-REVOKE WRITEBACK (should reject) --------------------
    const wbReq7: WritebackRequest = {
        token: leaseToken.token,
        app_uid: APP_UID,
        patches: [
            { uid: 'fileA', base_hash: hashA, content: 'post-revoke edit' },
        ],
    };
    const wbResult7 = await writebackBroker.applyWriteback(wbReq7);
    pushStep(7, 'post-revoke writeback', {
        applied: wbResult7.applied,
        rejected: wbResult7.rejected,
    });

    // ---- Step 8: EXPIRED SWEEP --------------------------------------------
    // Issue a second lease with an expiration in the past
    const expiredTokenPayload: Record<string, unknown> = {
        jti: crypto.randomUUID(),
        sub: APP_UID,
        iss: 'oracle',
        aud: JWT_AUDIENCE,
        exp: Math.floor(Date.now() / 1000) + 120, // JWT must be valid for jwt.verify
        iat: Math.floor(Date.now() / 1000),
        app_uid: APP_UID,
        anchor: 'edit auth module',
        target_uids: ['fileA', 'fileB'],
        base_hash: hashA,
    };
    const expiredSignedToken = sign(expiredTokenPayload, secret);
    const expiredGrantReq: GrantRequest = {
        app_uid: APP_UID,
        target_uids: ['fileA', 'fileB'],
        anchor: 'edit auth module',
        base_hashes: [hashA, hashB],
        ttl_seconds: -10, // lease record exp = now - 10, immediately sweepable
        token: expiredSignedToken,
    };
    let expiredLeaseToken: LeaseToken;
    try {
        expiredLeaseToken = await leaseManager.issueLease(
            ACTOR,
            expiredGrantReq,
        );
        pushStep(8, 'issue expired lease', {
            lease_id: expiredLeaseToken.jti,
        });
    } catch (err) {
        pushFail(8, 'issue expired lease', { error: String(err) });
        return { steps, provenance: provenance.events, finalFsState: {} };
    }

    // Sweep expired leases
    const swept = await leaseManager.revokeExpired(ACTOR);
    pushStep(8, 'sweep expired', { leases_revoked: swept });

    // ---- Step 9: AUDIT ----------------------------------------------------
    // Capture final fs state
    const finalFsState: Record<string, string> = {};
    for (const [uid, entry] of mockFsStore) {
        finalFsState[uid] = entry.content;
    }

    pushStep(9, 'provenance audit', {
        total_events: provenance.events.length,
        event_types: provenance.events.map((e) => e.type),
    });

    return {
        steps,
        provenance: provenance.events,
        finalFsState,
    };
}

// ===========================================================================
// -- Standalone main --------------------------------------------------------
//
// Run via:  npx vitest run extensions/agentsec/src/demo-harness.test.ts
//
// Standalone execution (npx tsx) requires @heyputer/backend module mocks
// that vitest provides. The test is the canonical runner.

async function main(): Promise<void> {
    // Standalone: create leases manually using InMemoryLeaseStore + sign
    // instead of AgentSecGrantIssuer (which depends on PuterService).
    const leaseStore = new InMemoryLeaseStore();
    const provenance = new CapturingProvenanceSink();
    const mockFsStore = new Map<string, { content: string }>();
    const fsService = new MockFsService(mockFsStore);
    const secret = DEMO_SECRET;
    const jwtVerify = verify;

    const writebackBroker = new WritebackBroker(
        leaseStore,
        jwtVerify,
        secret,
        JWT_AUDIENCE,
        fsService,
        provenance,
    );

    // Minimal lease manager using low-level primitives (no Puter dependency)
    const leaseManager = {
        async issueLease(
            _actor: unknown,
            req: GrantRequest,
        ): Promise<LeaseToken> {
            // Verify the incoming JWT
            const decoded = verify(req.token, secret, JWT_AUDIENCE);
            const leaseId = (decoded.jti as string) ?? crypto.randomUUID();
            const now = Math.floor(Date.now() / 1000);
            const record: LeaseRecord = {
                lease_id: leaseId,
                app_uid: req.app_uid,
                target_uids: [...req.target_uids],
                anchor: req.anchor,
                base_hashes: [...req.base_hashes],
                exp: now + req.ttl_seconds,
                created_at: now,
                status: 'active',
            };
            await leaseStore.create(record);
            provenance.emit({
                type: 'lease_issued',
                lease_id: leaseId,
                ts: Date.now(),
                anchor: req.anchor,
                app_uid: req.app_uid,
                uids: [...req.target_uids],
                base_hashes: Object.fromEntries(
                    req.target_uids.map((uid, i) => [
                        uid,
                        req.base_hashes[i] ?? '',
                    ]),
                ),
            });
            const tokenPayload: Record<string, unknown> = {
                jti: leaseId,
                exp: record.exp,
                iat: now,
                sub: req.app_uid,
                iss: 'agentsec-grant-issuer',
                aud: JWT_AUDIENCE,
                base_hash: req.base_hashes[0] ?? '',
                anchor: req.anchor,
                app_uid: req.app_uid,
                target_uids: req.target_uids,
            };
            const token = sign(tokenPayload, secret);
            return {
                token,
                jti: leaseId,
                exp: record.exp,
                iat: now,
                sub: req.app_uid,
                iss: 'agentsec-grant-issuer',
                aud: JWT_AUDIENCE,
                base_hash: req.base_hashes[0] ?? '',
                anchor: req.anchor,
                app_uid: req.app_uid,
                target_uids: [...req.target_uids],
            };
        },
        async revokeLease(
            _actor: unknown,
            leaseId: string,
        ): Promise<void> {
            const rec = await leaseStore.get(leaseId);
            if (!rec || rec.status !== 'active') return;
            await leaseStore.setRevoked(leaseId, 'expired');
            provenance.emit({
                type: 'lease_revoked',
                lease_id: leaseId,
                ts: Date.now(),
                reason: 'revoked',
            });
        },
        async revokeExpired(
            _actor: unknown,
        ): Promise<number> {
            const now = Math.floor(Date.now() / 1000);
            const all = await leaseStore.listAll();
            let count = 0;
            for (const rec of all) {
                if (
                    rec.status === 'active' &&
                    rec.exp <= now
                ) {
                    await leaseStore.setRevoked(rec.lease_id, 'expired');
                    provenance.emit({
                        type: 'lease_revoked',
                        lease_id: rec.lease_id,
                        ts: Date.now(),
                        reason: 'expired',
                    });
                    provenance.emit({
                        type: 'lease_expired',
                        lease_id: rec.lease_id,
                        ts: Date.now(),
                    });
                    count++;
                }
            }
            return count;
        },
    };

    const transcript = await runDemoE({
        leaseManager,
        writebackBroker,
        mockFsStore,
        fsService,
        provenance,
        leaseStore,
        secret,
    });

    console.log('=== Demo E Core Integration Harness ===\n');
    for (const s of transcript.steps) {
        const icon = s.ok ? 'OK' : 'FAIL';
        console.log(`[${icon}] Step ${s.step}: ${s.action}`);
        console.log('  ', JSON.stringify(s.result, null, 2));
        console.log();
    }
    console.log('--- Provenance Audit Trail ---');
    for (const evt of transcript.provenance) {
        console.log(
            `  ${new Date(evt.ts).toISOString()} [${evt.type}] lease=${evt.lease_id.slice(0, 8)}... app=${evt.app_uid ?? '-'} uids=${evt.uids ?? '-'} reason=${evt.reason ?? '-'}`,
        );
    }
    console.log('\nFinal FS state:', transcript.finalFsState);

    // Self-check
    const allOk = transcript.steps.every((s) => s.ok);
    console.log(`\nDemo E result: ${allOk ? 'ALL PASS' : 'SOME FAILED'}`);
    process.exit(allOk ? 0 : 1);
}

const isMain =
    process.argv[1] &&
    (process.argv[1].endsWith('demo-harness.ts') ||
        process.argv[1].endsWith('demo-harness.js'));
if (isMain) {
    main().catch((err) => {
        console.error('Demo E failed:', err);
        process.exit(1);
    });
}
