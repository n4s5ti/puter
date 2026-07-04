// -- Tests for AgentSecGrantIssuer ------------------------------------------
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
import type { ProvenanceEvent } from './types.js';
import type { ProvenanceSink } from './provenance.js';

// -- Constants --------------------------------------------------------------

const TEST_SECRET = 'test-secret-for-grant-issuer-test';
const TEST_AUDIENCE = 'agentsec-grant-issuer';

// -- Helpers ----------------------------------------------------------------

const makeToken = (overrides: Record<string, unknown> = {}): string => {
    const payload: Record<string, unknown> = {
        jti: crypto.randomUUID(),
        sub: 'app-123',
        iss: 'oracle',
        aud: TEST_AUDIENCE,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        app_uid: 'app-123',
        anchor: 'file-root-uid',
        target_uids: ['file-a-uid', 'file-b-uid'],
        base_hash: 'abc123',
        ...overrides,
    };
    return sign(payload, TEST_SECRET);
};

/** Convenience: builds a GrantRequest with defaults + overrides.
  The `token` field must match the overridden claims if present. */
const makeDefaultRequest = (overrides: Record<string, unknown> = {}) => ({
    app_uid: 'app-123',
    target_uids: ['file-a-uid', 'file-b-uid'] as string[],
    anchor: 'file-root-uid',
    base_hashes: ['abc123'],
    ttl_seconds: 3600,
    token: makeToken(),
    ...overrides,
});

const TEST_ACTOR = { user: { id: 1, uuid: 'user-uuid-1' } };
// -- Capturing sink for provenance assertions ------------------------------

class CapturingProvenanceSink implements ProvenanceSink {
    readonly events: ProvenanceEvent[] = [];

    async emit(event: ProvenanceEvent): Promise<void> {
        this.events.push(event);
    }

    clear(): void {
        this.events.length = 0;
    }

    eventsByType(type: ProvenanceEvent['type']): ProvenanceEvent[] {
        return this.events.filter((e) => e.type === type);
    }
}

// -- Tests ------------------------------------------------------------------

describe('AgentSecGrantIssuer', () => {
    let grantIssuer: AgentSecGrantIssuer;
    let captured: CapturingProvenanceSink;
    let mockPermSvc: {
        grantUserAppPermission: Mock;
        revokeUserAppPermission: Mock;
    };
    let mockTailscale: {
        provisionLeaseTag: Mock;
        revokeLeaseTag: Mock;
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
        captured = new CapturingProvenanceSink();

        grantIssuer = new AgentSecGrantIssuer(
            {},     // config
            {},     // clients
            {},     // stores
            { permission: mockPermSvc }, // services
            mockTailscale,
            TEST_SECRET,
            undefined,  // leaseStore (default InMemory)
            captured,   // provenance
        );
    });

    describe('issueLease', () => {
        it('grants fs:<uid>:write for all target uids', async () => {
            const result = await grantIssuer.issueLease(
                TEST_ACTOR,
                makeDefaultRequest(),
            );

            expect(mockPermSvc.grantUserAppPermission).toHaveBeenCalledTimes(2);
            expect(mockPermSvc.grantUserAppPermission).toHaveBeenCalledWith(
                TEST_ACTOR,
                'app-123',
                'fs:file-a-uid:write',
                {},
                { reason: expect.stringContaining('agentsec lease ') },
            );
            expect(mockPermSvc.grantUserAppPermission).toHaveBeenCalledWith(
                TEST_ACTOR,
                'app-123',
                'fs:file-b-uid:write',
                {},
                { reason: expect.stringContaining('agentsec lease ') },
            );
        });

        it('records the lease and returns a signed JWT token', async () => {
            const result = await grantIssuer.issueLease(
                TEST_ACTOR,
                makeDefaultRequest(),
            );

            expect(result.jti).toBeTruthy();
            expect(typeof result.jti).toBe('string');
            expect(result.token).toBeTruthy();
            expect(typeof result.token).toBe('string');
            expect(result.token.split('.')).toHaveLength(3);
            expect(result).toMatchObject({
                sub: 'app-123',
                app_uid: 'app-123',
                anchor: 'file-root-uid',
                target_uids: ['file-a-uid', 'file-b-uid'],
                base_hash: 'abc123',
            });
            expect(result.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
        });

        it('calls tailscale provisioner with the lease id', async () => {
            const result = await grantIssuer.issueLease(
                TEST_ACTOR,
                makeDefaultRequest(),
            );

            expect(mockTailscale.provisionLeaseTag).toHaveBeenCalledTimes(1);
            expect(mockTailscale.provisionLeaseTag).toHaveBeenCalledWith(
                result.jti,
            );

            // Provenance: lease_issued emitted with correct fields
            const issued = captured.eventsByType('lease_issued');
            expect(issued).toHaveLength(1);
            expect(issued[0]).toMatchObject({
                type: 'lease_issued',
                lease_id: result.jti,
                app_uid: 'app-123',
                anchor: 'file-root-uid',
            });
            expect(issued[0].uids).toEqual(['file-a-uid', 'file-b-uid']);
            expect(issued[0].ts).toBeGreaterThan(0);
        });

        it('rejects token with wrong app_uid', async () => {
            const req = makeDefaultRequest({
                token: makeToken({ app_uid: 'wrong-app' }),
            });

            await expect(
                grantIssuer.issueLease(TEST_ACTOR, req),
            ).rejects.toThrow('JWT app_uid mismatch');
        });

        it('rejects expired token', async () => {
            const expiredToken = makeToken({
                exp: Math.floor(Date.now() / 1000) - 60,
            });

            await expect(
                grantIssuer.issueLease(
                    TEST_ACTOR,
                    makeDefaultRequest({ token: expiredToken }),
                ),
            ).rejects.toThrow();
        });

        it('rejects token with mismatched anchor', async () => {
            const req = makeDefaultRequest({
                token: makeToken({ anchor: 'file-wrong-uid' }),
            });

            await expect(
                grantIssuer.issueLease(TEST_ACTOR, req),
            ).rejects.toThrow('JWT anchor mismatch');
        });

        it('rejects token with mismatched target_uids', async () => {
            const req = makeDefaultRequest({
                token: makeToken({
                    target_uids: ['file-a-uid', 'file-c-uid'],
                }),
            });

            await expect(
                grantIssuer.issueLease(TEST_ACTOR, req),
            ).rejects.toThrow('JWT target_uids mismatch');
        });

        it('rejects token with subset of authorized target uids', async () => {
            // Token authorizes 1 uid, but req asks for 2 — lengths differ
            const req = makeDefaultRequest({
                token: makeToken({ target_uids: ['file-a-uid'] }),
                target_uids: ['file-a-uid', 'file-b-uid'],
            });

            await expect(
                grantIssuer.issueLease(TEST_ACTOR, req),
            ).rejects.toThrow('JWT target_uids mismatch');
        });
    });

    describe('revokeLease', () => {
        it('revokes all grants and marks record expired', async () => {
            const result = await grantIssuer.issueLease(
                TEST_ACTOR,
                makeDefaultRequest(),
            );

            mockPermSvc.grantUserAppPermission.mockClear();
            mockTailscale.provisionLeaseTag.mockClear();

            await grantIssuer.revokeLease(TEST_ACTOR, result.jti);

            expect(mockPermSvc.revokeUserAppPermission).toHaveBeenCalledTimes(
                2,
            );
            expect(mockPermSvc.revokeUserAppPermission).toHaveBeenCalledWith(
                TEST_ACTOR,
                'app-123',
                'fs:file-a-uid:write',
                { reason: 'lease expired' },
            );
            expect(mockPermSvc.revokeUserAppPermission).toHaveBeenCalledWith(
                TEST_ACTOR,
                'app-123',
                'fs:file-b-uid:write',
                { reason: 'lease expired' },
            );
            expect(mockTailscale.revokeLeaseTag).toHaveBeenCalledTimes(1);
            expect(mockTailscale.revokeLeaseTag).toHaveBeenCalledWith(
                result.jti,
            );

            // Provenance: lease_issued + lease_revoked emitted
            const revoked = captured.eventsByType('lease_revoked');
            expect(revoked).toHaveLength(1);
            expect(revoked[0]).toMatchObject({
                type: 'lease_revoked',
                lease_id: result.jti,
                app_uid: 'app-123',
                uids: ['file-a-uid', 'file-b-uid'],
                reason: 'revoked',
            });
            expect(revoked[0].ts).toBeGreaterThan(0);
        });

        it('is idempotent for already-revoked lease', async () => {
            const result = await grantIssuer.issueLease(
                TEST_ACTOR,
                makeDefaultRequest(),
            );

            await grantIssuer.revokeLease(TEST_ACTOR, result.jti);
            mockPermSvc.revokeUserAppPermission.mockClear();
            mockTailscale.revokeLeaseTag.mockClear();

            await grantIssuer.revokeLease(TEST_ACTOR, result.jti);

            expect(mockPermSvc.revokeUserAppPermission).not.toHaveBeenCalled();
            expect(mockTailscale.revokeLeaseTag).not.toHaveBeenCalled();
        });

        it('throws for unknown lease', async () => {
            await expect(
                grantIssuer.revokeLease(TEST_ACTOR, 'nonexistent-lease'),
            ).rejects.toThrow('lease not found');
        });

        it('emits immutable_set when fsEntry store sets immutable on uids', async () => {
            const mockFsEntryStore = {
                updateEntry: vi.fn().mockResolvedValue(undefined),
            };
            const captureSink = new CapturingProvenanceSink();
            const issuer = new AgentSecGrantIssuer(
                {},
                {},
                { fsEntry: mockFsEntryStore },
                { permission: mockPermSvc },
                mockTailscale,
                TEST_SECRET,
                undefined,
                captureSink,
            );

            const result = await issuer.issueLease(
                TEST_ACTOR,
                makeDefaultRequest(),
            );

            captureSink.clear();

            await issuer.revokeLease(TEST_ACTOR, result.jti);

            const immSet = captureSink.eventsByType('immutable_set');
            expect(immSet).toHaveLength(1);
            expect(immSet[0]).toMatchObject({
                type: 'immutable_set',
                lease_id: result.jti,
                uids: ['file-a-uid', 'file-b-uid'],
            });
            expect(immSet[0].ts).toBeGreaterThan(0);

            expect(mockFsEntryStore.updateEntry).toHaveBeenCalledTimes(2);
            expect(mockFsEntryStore.updateEntry).toHaveBeenCalledWith(
                'file-a-uid', { immutable: true },
            );
            expect(mockFsEntryStore.updateEntry).toHaveBeenCalledWith(
                'file-b-uid', { immutable: true },
            );
        });
    });

    describe('revokeExpired', () => {
        it('returns 0 when no leases exist', async () => {
            const count = await grantIssuer.revokeExpired(TEST_ACTOR);

            expect(count).toBe(0);
        });

        it('sweeps expired leases', async () => {
            // The JWT token must pass jwtVerify, so keep exp in the future.
            // The lease record's exp is computed as now + ttl_seconds.
            // Negative ttl_seconds produces a past exp in the record.
            const token = makeToken({
                exp: Math.floor(Date.now() / 1000) + 60,
                target_uids: ['file-expired-uid'],
            });
            await grantIssuer.issueLease(TEST_ACTOR, {
                app_uid: 'app-123',
                target_uids: ['file-expired-uid'],
                anchor: 'file-root-uid',
                base_hashes: ['hash'],
                ttl_seconds: -10,
                token,
            });

            const count = await grantIssuer.revokeExpired(TEST_ACTOR);

            expect(count).toBe(1);
            expect(mockPermSvc.revokeUserAppPermission).toHaveBeenCalled();

            // Provenance: lease_expired emitted
            const expired = captured.eventsByType('lease_expired');
            expect(expired).toHaveLength(1);
            expect(expired[0]).toMatchObject({
                type: 'lease_expired',
                uids: ['file-expired-uid'],
            });
            expect(expired[0].ts).toBeGreaterThan(0);
        });

        it('leaves active leases untouched', async () => {
            const token = makeToken({
                exp: Math.floor(Date.now() / 1000) + 86400,
                target_uids: ['file-future-uid'],
            });
            await grantIssuer.issueLease(TEST_ACTOR, {
                app_uid: 'app-123',
                target_uids: ['file-future-uid'],
                anchor: 'file-root-uid',
                base_hashes: ['hash'],
                ttl_seconds: 86400,
                token,
            });

            mockPermSvc.revokeUserAppPermission.mockClear();

            const count = await grantIssuer.revokeExpired(TEST_ACTOR);

            expect(count).toBe(0);
            expect(
                mockPermSvc.revokeUserAppPermission,
            ).not.toHaveBeenCalled();
        });

        it('sweeps only expired leases among mixed leases', async () => {
            // Expired lease — future JWT, negative ttl
            const expiredToken = makeToken({
                exp: Math.floor(Date.now() / 1000) + 60,
                target_uids: ['file-expired'],
            });
            await grantIssuer.issueLease(TEST_ACTOR, {
                app_uid: 'app-123',
                target_uids: ['file-expired'],
                anchor: 'file-root-uid',
                base_hashes: ['hash1'],
                ttl_seconds: -10,
                token: expiredToken,
            });

            // Active lease
            const activeToken = makeToken({
                exp: Math.floor(Date.now() / 1000) + 86400,
                target_uids: ['file-active'],
            });
            await grantIssuer.issueLease(TEST_ACTOR, {
                app_uid: 'app-123',
                target_uids: ['file-active'],
                anchor: 'file-root-uid',
                base_hashes: ['hash2'],
                ttl_seconds: 86400,
                token: activeToken,
            });

            mockPermSvc.revokeUserAppPermission.mockClear();

            const count = await grantIssuer.revokeExpired(TEST_ACTOR);

            expect(count).toBe(1);
            expect(mockPermSvc.revokeUserAppPermission).toHaveBeenCalledWith(
                TEST_ACTOR,
                'app-123',
                'fs:file-expired:write',
                { reason: 'lease expired' },
            );
        });
    });
});
