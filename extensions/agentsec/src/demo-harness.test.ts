// -- Integration test for Demo E core ----------------------------------------
// Exercises the COMPLETE lease lifecycle chain end-to-end with mocked
// services, proving the lease security model works as a coherent system.

import { describe, expect, it, vi, beforeEach } from 'vitest';
import type { Mock } from 'vitest';
import crypto from 'node:crypto';

import { sign } from './jwt';

// Mocks for Puter core module imports — hoisted above static imports by
// vitest, so the class extension and module-scope registration fire
// through the mocks.
vi.mock('@heyputer/backend/src/extensions', () => ({
    extension: { registerService: vi.fn() },
}));
vi.mock('@heyputer/backend/src/services/types.js', () => ({
    PuterService: class PuterServiceMock {
        protected services: Record<string, unknown>;
        protected stores: Record<string, unknown>;

        constructor(
            _config: unknown,
            _clients: unknown,
            stores: unknown,
            services: unknown,
        ) {
            this.services = services as Record<string, unknown>;
            this.stores = stores as Record<string, unknown>;
        }
    },
}));

import { AgentSecGrantIssuer } from './index';
import { WritebackBroker } from './writeback';
import { InMemoryLeaseStore } from './lease-store';
import { verify as jwtVerify } from './jwt';
import { runDemoE, CapturingProvenanceSink } from './demo-harness';
import type { FsServiceShim } from './writeback';

// -- Constants --------------------------------------------------------------

const TEST_SECRET = 'demo-e-test-secret';
const JWT_AUDIENCE = 'agentsec-grant-issuer';
const APP_UID = 'agent-app-1';
const ACTOR = { user: { id: 1, uuid: 'user-uuid-1' } };

// -- Mock FsServiceShim -----------------------------------------------------

class MockFsService implements FsServiceShim {
    readonly store: Map<string, { content: string }>;

    constructor(store: Map<string, { content: string }>) {
        this.store = store;
    }

    async readContent(uid: string): Promise<string | Buffer> {
        const entry = this.store.get(uid);
        if (!entry) {
            throw new Error(`MockFs: file not found: ${uid}`);
        }
        return entry.content;
    }

    async write(uid: string, content: string): Promise<void> {
        const entry = this.store.get(uid);
        if (!entry) {
            throw new Error(`MockFs: file not found: ${uid}`);
        }
        entry.content = content;
    }
}

// -- Tests ------------------------------------------------------------------

describe('Demo E Core Integration Harness', () => {
    let grantIssuer: AgentSecGrantIssuer;
    let writebackBroker: WritebackBroker;
    let leaseStore: InMemoryLeaseStore;
    let provenance: CapturingProvenanceSink;
    let mockFsStore: Map<string, { content: string }>;
    let fsService: MockFsService;
    let mockPermSvc: {
        grantUserAppPermission: Mock;
        revokeUserAppPermission: Mock;
    };
    let mockTailscale: {
        provisionLeaseTag: Mock;
        revokeLeaseTag: Mock;
    };
    let mockFsEntryStore: {
        updateEntry: Mock;
    };

    beforeEach(() => {
        mockPermSvc = {
            grantUserAppPermission: vi.fn().mockResolvedValue(undefined),
            revokeUserAppPermission: vi.fn().mockResolvedValue(undefined),
        };
        mockTailscale = {
            provisionLeaseTag: vi.fn().mockResolvedValue(undefined),
            revokeLeaseTag: vi.fn().mockResolvedValue(undefined),
        };
        mockFsEntryStore = {
            updateEntry: vi.fn().mockResolvedValue(undefined),
        };
        provenance = new CapturingProvenanceSink();
        leaseStore = new InMemoryLeaseStore();
        mockFsStore = new Map<string, { content: string }>();
        fsService = new MockFsService(mockFsStore);

        grantIssuer = new AgentSecGrantIssuer(
            {},     // config
            {},     // clients
            { fsEntry: mockFsEntryStore }, // stores
            { permission: mockPermSvc },   // services
            mockTailscale,
            TEST_SECRET,
            leaseStore,
            provenance,
        );

        writebackBroker = new WritebackBroker(
            leaseStore,
            jwtVerify,
            TEST_SECRET,
            JWT_AUDIENCE,
            fsService,
            provenance,
        );
    });

    it('executes the complete lease lifecycle end-to-end', async () => {
        const transcript = await runDemoE({
            leaseManager: grantIssuer,
            writebackBroker,
            mockFsStore,
            fsService,
            provenance,
            leaseStore,
            secret: TEST_SECRET,
        });

        // -- Assert all steps completed successfully ------------------------
        const failedSteps = transcript.steps.filter((s) => !s.ok);
        expect(failedSteps).toHaveLength(0);
        expect(transcript.steps.length).toBeGreaterThanOrEqual(9);

        // -- Step 3: valid writeback applied --------------------------------
        const step3 = transcript.steps.find((s) => s.step === 3)!;
        expect(step3.ok).toBe(true);
        const step3Result = step3.result as { applied: { uid: string }[] };
        expect(step3Result.applied).toHaveLength(1);
        expect(step3Result.applied[0].uid).toBe('fileA');

        // mockFs should reflect the new content for fileA
        expect(transcript.finalFsState['fileA']).toBe('new content A');
        expect(transcript.finalFsState['fileB']).toBe('original content B');

        // -- Step 4: unleased writeback rejected ----------------------------
        const step4 = transcript.steps.find((s) => s.step === 4)!;
        expect(step4.ok).toBe(true);
        const step4Result = step4.result as { rejected: { uid: string; reason: string }[] };
        expect(step4Result.rejected).toHaveLength(1);
        expect(step4Result.rejected[0].reason).toBe('unleased');
        expect(step4Result.rejected[0].uid).toBe('fileC');

        // -- Step 5: stale hash writeback rejected --------------------------
        const step5 = transcript.steps.find((s) => s.step === 5)!;
        expect(step5.ok).toBe(true);
        const step5Result = step5.result as { rejected: { uid: string; reason: string }[] };
        expect(step5Result.rejected).toHaveLength(1);
        expect(step5Result.rejected[0].reason).toBe('stale_hash');

        // -- Step 6: revoke succeeded ---------------------------------------
        const step6 = transcript.steps.find((s) => s.step === 6)!;
        expect(step6.ok).toBe(true);

        // -- Step 7: post-revoke writeback rejected -------------------------
        const step7 = transcript.steps.find((s) => s.step === 7)!;
        expect(step7.ok).toBe(true);
        const step7Result = step7.result as { rejected: { uid: string; reason: string }[] };
        expect(step7Result.rejected).toHaveLength(1);
        expect(step7Result.rejected[0].reason).toBe('lease_inactive');

        // -- Step 8: expired lease swept ------------------------------------
        const step8a = transcript.steps.find(
            (s) => s.step === 8 && s.action === 'issue expired lease',
        )!;
        expect(step8a.ok).toBe(true);
        const step8b = transcript.steps.find(
            (s) => s.step === 8 && s.action === 'sweep expired',
        )!;
        expect(step8b.ok).toBe(true);
        const step8bResult = step8b.result as { leases_revoked: number };
        expect(step8bResult.leases_revoked).toBeGreaterThanOrEqual(1);

        // -- Step 9: provenance audit present --------------------------------
        const step9 = transcript.steps.find((s) => s.step === 9)!;
        expect(step9.ok).toBe(true);

        // -- Provenance event sequence in order -----------------------------
        const events = transcript.provenance;
        expect(events.length).toBeGreaterThanOrEqual(10);

        // Expected sequence:
        //   1. lease_issued        (step 2)
        //   2. writeback_applied   (step 3)
        //   3-4. writeback_rejected ×2 (step 4 unleased, step 5 stale_hash)
        //   5. lease_revoked       (step 6)
        //   6. immutable_set       (step 6)
        //   7. writeback_rejected  (step 7 lease_inactive)
        //   8. lease_issued        (step 8 expired lease)
        //   9. lease_revoked       (step 8 revokeExpired → revokeLease)
        //  10. immutable_set       (step 8 revokeExpired → revokeLease)
        //  11. lease_expired       (step 8 revokeExpired explicit emit)

        const [
            evt1, evt2, evt3, evt4,
            evt5, evt6, evt7, evt8,
            evt9, evt10, evt11,
        ] = events;

        expect(evt1.type).toBe('lease_issued');
        expect(evt1.lease_id).toBeTruthy();
        expect(evt1.app_uid).toBe(APP_UID);
        expect(evt1.uids).toEqual(['fileA', 'fileB']);

        expect(evt2.type).toBe('writeback_applied');
        expect(evt2.uids).toEqual(['fileA']);
        expect(evt2.app_uid).toBe(APP_UID);

        expect(evt3.type).toBe('writeback_rejected');
        expect(evt3.reason).toBe('unleased');
        expect(evt3.uids).toEqual(['fileC']);

        expect(evt4.type).toBe('writeback_rejected');
        expect(evt4.reason).toBe('stale_hash');
        expect(evt4.uids).toEqual(['fileB']);

        expect(evt5.type).toBe('lease_revoked');
        expect(evt5.reason).toBe('revoked');
        expect(evt5.lease_id).toBe(evt1.lease_id);

        expect(evt6.type).toBe('immutable_set');
        expect(evt6.lease_id).toBe(evt1.lease_id);

        expect(evt7.type).toBe('writeback_rejected');
        expect(evt7.reason).toBe('lease_inactive');

        expect(evt8.type).toBe('lease_issued');
        expect(evt8.lease_id).not.toBe(evt1.lease_id);

        expect(evt9.type).toBe('lease_revoked');
        expect(evt9.lease_id).toBe(evt8.lease_id);

        expect(evt10.type).toBe('immutable_set');
        expect(evt10.lease_id).toBe(evt8.lease_id);

        expect(evt11.type).toBe('lease_expired');
        expect(evt11.lease_id).toBe(evt8.lease_id);
    });

    it('confirms immutable_set events carry uids', async () => {
        const transcript = await runDemoE({
            leaseManager: grantIssuer,
            writebackBroker,
            mockFsStore,
            fsService,
            provenance,
            leaseStore,
            secret: TEST_SECRET,
        });

        const immEvts = transcript.provenance.filter(
            (e) => e.type === 'immutable_set',
        );
        // First from step 6 revoke, second from step 8 revokeExpired
        expect(immEvts).toHaveLength(2);
        for (const evt of immEvts) {
            expect(evt.uids).toBeDefined();
            expect(evt.uids!.length).toBeGreaterThan(0);
        }
    });
});
