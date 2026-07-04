// -- Tests for AgentSec WritebackBroker -------------------------------------
import { describe, expect, it, vi, beforeEach } from 'vitest';
import type { Mock } from 'vitest';
import crypto from 'node:crypto';

import type { LeaseStore } from './lease-store.js';
import type { LeaseRecord, WritebackRequest } from './types.js';
import { WritebackBroker, normalizeHash } from './writeback.js';
import type { JwtVerifyFn, FsServiceShim } from './writeback.js';

// -- Constants --------------------------------------------------------------

const TEST_SECRET = 'test-writeback-secret';
const TEST_AUDIENCE = 'agentsec-grant-issuer';

const LEASE_ID = 'lease-uuid-001';
const APP_UID = 'app-123';
const UID_A = 'file-a-uid';
const UID_B = 'file-b-uid';

// Mock content that the mock FsServiceSim will return for each uid.
// MUST match what `makeHexHash(content)` produces for that content.
const CONTENT_A_ORIG = 'original content A';
const CONTENT_B_ORIG = 'original content B';
const CONTENT_A_CHANGED = 'changed content B';

const sha256hex = (data: string): string =>
    crypto.createHash('sha256').update(data).digest('hex');

const HASH_A = sha256hex(CONTENT_A_ORIG);
const HASH_B = sha256hex(CONTENT_B_ORIG);
const HASH_A_SHA256 = `sha256:${HASH_A}`;
const HASH_B_SHA256 = `sha256:${HASH_B}`;
const HASH_B_CHANGED = sha256hex(CONTENT_A_CHANGED);

// -- Helpers ----------------------------------------------------------------

const makeActiveLease = (): LeaseRecord => ({
    lease_id: LEASE_ID,
    app_uid: APP_UID,
    target_uids: [UID_A, UID_B],
    anchor: 'file-root-uid',
    base_hashes: [HASH_A, HASH_B],
    exp: Math.floor(Date.now() / 1000) + 3600,
    created_at: Math.floor(Date.now() / 1000) - 60,
    status: 'active',
});

const makeRevokedLease = (): LeaseRecord => ({
    ...makeActiveLease(),
    status: 'revoked',
});

const makeValidJwtDecoded = (overrides: Record<string, unknown> = {}) => ({
    jti: LEASE_ID,
    app_uid: APP_UID,
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    sub: APP_UID,
    iss: TEST_AUDIENCE,
    aud: TEST_AUDIENCE,
    target_uids: [UID_A, UID_B],
    ...overrides,
});

const makeHappyRequest = (
    overrides: Record<string, unknown> = {},
): WritebackRequest => ({
    token: 'valid.jwt.token',
    app_uid: APP_UID,
    patches: [
        { uid: UID_A, base_hash: HASH_A, content: 'new content for A' },
        { uid: UID_B, base_hash: HASH_B, content: 'new content for B' },
    ],
    ...(overrides as Record<string, unknown>),
});

// -- normalizeHash unit tests -----------------------------------------------

describe('normalizeHash', () => {
    it('strips sha256: prefix and lowercases hex', () => {
        expect(normalizeHash('sha256:ABCDEF')).toBe('abcdef');
    });

    it('passes through bare hex unchanged', () => {
        expect(normalizeHash('abcdef')).toBe('abcdef');
    });

    it('lowercases bare hex', () => {
        expect(normalizeHash('ABCDEF')).toBe('abcdef');
    });

    it('handles the empty prefix edge case', () => {
        expect(() => normalizeHash('sha256:')).toThrow('Invalid hash');
    });

    it('throws on invalid hex characters', () => {
        expect(() => normalizeHash('not-hex-string!')).toThrow('Invalid hash');
    });
});

// -- WritebackBroker tests --------------------------------------------------

describe('WritebackBroker', () => {
    let mockLeaseStore: LeaseStore;
    let mockJwtVerify: Mock<JwtVerifyFn>;
    let mockFsService: FsServiceShim;
    let broker: WritebackBroker;

    beforeEach(() => {
        mockLeaseStore = {
            create: vi.fn(),
            get: vi.fn(),
            update: vi.fn(),
            listActive: vi.fn(),
            listAll: vi.fn(),
            setRevoked: vi.fn(),
        };

        mockJwtVerify = vi.fn();

        mockFsService = {
            readContent: vi.fn(),
            write: vi.fn(),
        };

        broker = new WritebackBroker(
            mockLeaseStore,
            mockJwtVerify as unknown as JwtVerifyFn,
            TEST_SECRET,
            TEST_AUDIENCE,
            mockFsService,
        );
    });

    describe('happy path — valid token, active lease, all match', () => {
        it('applies all patches and rejects none', async () => {
            mockJwtVerify.mockReturnValue(makeValidJwtDecoded());
            mockLeaseStore.get = vi.fn().mockResolvedValue(makeActiveLease());
            mockFsService.readContent = vi.fn()
                .mockResolvedValueOnce(Buffer.from(CONTENT_A_ORIG))
                .mockResolvedValueOnce(Buffer.from(CONTENT_B_ORIG));
            mockFsService.write = vi.fn().mockResolvedValue(undefined);

            const result = await broker.applyWriteback(makeHappyRequest());

            expect(result.lease_id).toBe(LEASE_ID);
            expect(result.applied).toEqual([{ uid: UID_A }, { uid: UID_B }]);
            expect(result.rejected).toEqual([]);

            expect(mockFsService.write).toHaveBeenCalledTimes(2);
            expect(mockFsService.write).toHaveBeenCalledWith(
                UID_A,
                'new content for A',
            );
            expect(mockFsService.write).toHaveBeenCalledWith(
                UID_B,
                'new content for B',
            );
        });
    });

    describe('JWT validation failures — reject all patches', () => {
        it('rejects all with expired when JWT verify throws', async () => {
            mockJwtVerify.mockImplementation(() => {
                throw new Error('Token has expired');
            });
            mockLeaseStore.get = vi.fn();

            const result = await broker.applyWriteback(makeHappyRequest());

            expect(result.applied).toEqual([]);
            expect(result.rejected).toHaveLength(2);
            for (const r of result.rejected) {
                expect(r.reason).toBe('expired');
            }
            // Lease store should NEVER be consulted for expired tokens
            expect(mockLeaseStore.get).not.toHaveBeenCalled();
        });

        it('rejects all with expired when JWT missing jti claim', async () => {
            mockJwtVerify.mockReturnValue(
                makeValidJwtDecoded({ jti: undefined }),
            );

            const result = await broker.applyWriteback(makeHappyRequest());

            expect(result.applied).toEqual([]);
            expect(result.rejected).toHaveLength(2);
            expect(result.rejected[0].reason).toBe('expired');
            expect(result.rejected[0].detail).toContain('missing jti');
        });

        it('rejects all with expired when app_uid mismatches', async () => {
            mockJwtVerify.mockReturnValue(
                makeValidJwtDecoded({ app_uid: 'different-app' }),
            );

            const result = await broker.applyWriteback(makeHappyRequest());

            expect(result.applied).toEqual([]);
            expect(result.rejected).toHaveLength(2);
            expect(result.rejected[0].reason).toBe('expired');
            expect(result.rejected[0].detail).toContain('app_uid');
        });

        it('returns lease_id empty when JWT is invalid', async () => {
            mockJwtVerify.mockImplementation(() => {
                throw new Error('Invalid signature');
            });

            const result = await broker.applyWriteback(makeHappyRequest());

            expect(result.lease_id).toBe('');
        });
    });

    describe('lease validation failures — reject all patches', () => {
        it('rejects all with lease_inactive when lease not found', async () => {
            mockJwtVerify.mockReturnValue(makeValidJwtDecoded());
            mockLeaseStore.get = vi.fn().mockResolvedValue(undefined);

            const result = await broker.applyWriteback(makeHappyRequest());

            expect(result.applied).toEqual([]);
            expect(result.rejected).toHaveLength(2);
            for (const r of result.rejected) {
                expect(r.reason).toBe('lease_inactive');
                expect(r.detail).toContain('not found');
            }
        });

        it('rejects all with lease_inactive when lease status is revoked', async () => {
            mockJwtVerify.mockReturnValue(makeValidJwtDecoded());
            mockLeaseStore.get = vi.fn().mockResolvedValue(makeRevokedLease());

            const result = await broker.applyWriteback(makeHappyRequest());

            expect(result.applied).toEqual([]);
            expect(result.rejected).toHaveLength(2);
            for (const r of result.rejected) {
                expect(r.reason).toBe('lease_inactive');
                expect(r.detail).toContain('revoked');
            }
        });

        it('sets lease_id even when lease is inactive', async () => {
            mockJwtVerify.mockReturnValue(makeValidJwtDecoded());
            mockLeaseStore.get = vi.fn().mockResolvedValue(makeRevokedLease());

            const result = await broker.applyWriteback(makeHappyRequest());

            expect(result.lease_id).toBe(LEASE_ID);
        });
    });

    describe('per-patch isolation — unleased uid', () => {
        it('rejects unleased uid but applies other patches', async () => {
            mockJwtVerify.mockReturnValue(makeValidJwtDecoded());
            mockLeaseStore.get = vi.fn().mockResolvedValue(makeActiveLease());

            mockFsService.readContent = vi.fn()
                .mockResolvedValueOnce(Buffer.from(CONTENT_A_ORIG))
                .mockResolvedValueOnce(Buffer.from(CONTENT_B_ORIG));
            mockFsService.write = vi.fn().mockResolvedValue(undefined);

            const result = await broker.applyWriteback({
                token: 'valid.jwt.token',
                app_uid: APP_UID,
                patches: [
                    { uid: UID_A, base_hash: HASH_A, content: 'new A' },
                    {
                        uid: 'unleased-uid',
                        base_hash: 'aaaa',
                        content: 'should not apply',
                    },
                    { uid: UID_B, base_hash: HASH_B, content: 'new B' },
                ],
            });

            expect(result.applied).toEqual([{ uid: UID_A }, { uid: UID_B }]);
            expect(result.rejected).toHaveLength(1);
            expect(result.rejected[0]).toMatchObject({
                uid: 'unleased-uid',
                reason: 'unleased',
            });

            expect(mockFsService.write).toHaveBeenCalledTimes(2);
        });
    });

    describe('per-patch isolation — stale hash', () => {
        it('rejects patch with mismatched content hash but applies others', async () => {
            mockJwtVerify.mockReturnValue(makeValidJwtDecoded());
            mockLeaseStore.get = vi.fn().mockResolvedValue(makeActiveLease());

            // UID_A: current content matches lease hash — good.
            // UID_B: current content has changed since lease was issued — stale.
            mockFsService.readContent = vi.fn()
                .mockResolvedValueOnce(Buffer.from(CONTENT_A_ORIG))
                .mockResolvedValueOnce(Buffer.from(CONTENT_A_CHANGED));
            mockFsService.write = vi.fn().mockResolvedValue(undefined);

            const result = await broker.applyWriteback({
                token: 'valid.jwt.token',
                app_uid: APP_UID,
                patches: [
                    { uid: UID_A, base_hash: HASH_A, content: 'new A' },
                    {
                        uid: UID_B,
                        base_hash: HASH_B,
                        content: 'should not apply',
                    },
                ],
            });

            expect(result.applied).toEqual([{ uid: UID_A }]);
            expect(result.rejected).toHaveLength(1);
            expect(result.rejected[0]).toMatchObject({
                uid: UID_B,
                reason: 'stale_hash',
            });
            expect(result.rejected[0].detail).toContain('content hash');
            // detail should mention lease base_hash since current != HASH_B
            expect(result.rejected[0].detail).toContain('lease base_hash');

            expect(mockFsService.write).toHaveBeenCalledTimes(1);
            expect(mockFsService.write).toHaveBeenCalledWith(UID_A, 'new A');
        });

        it('rejects patch when patch base_hash does not match current content', async () => {
            mockJwtVerify.mockReturnValue(makeValidJwtDecoded());
            mockLeaseStore.get = vi.fn().mockResolvedValue(makeActiveLease());

            // Current content matches the lease's recorded HASH_A,
            // but the patch claims a different base hash.
            const wrongHash = sha256hex('wrong content');
            mockFsService.readContent = vi.fn()
                .mockResolvedValueOnce(Buffer.from(CONTENT_A_ORIG));
            mockFsService.write = vi.fn();

            const result = await broker.applyWriteback({
                token: 'valid.jwt.token',
                app_uid: APP_UID,
                patches: [
                    {
                        uid: UID_A,
                        base_hash: wrongHash,
                        content: 'new A',
                    },
                ],
            });

            expect(result.applied).toEqual([]);
            expect(result.rejected).toHaveLength(1);
            expect(result.rejected[0].reason).toBe('stale_hash');
            expect(result.rejected[0].detail).toContain('patch base_hash');
            expect(mockFsService.write).not.toHaveBeenCalled();
        });
    });

    describe('per-patch isolation — write failure', () => {
        it('rejects write_failed when fsService.write throws', async () => {
            mockJwtVerify.mockReturnValue(makeValidJwtDecoded());
            mockLeaseStore.get = vi.fn().mockResolvedValue(makeActiveLease());

            mockFsService.readContent = vi.fn()
                .mockResolvedValueOnce(Buffer.from(CONTENT_A_ORIG))
                .mockResolvedValueOnce(Buffer.from(CONTENT_B_ORIG));
            mockFsService.write = vi.fn()
                .mockResolvedValueOnce(undefined)
                .mockRejectedValueOnce(new Error('Disk full'));

            const result = await broker.applyWriteback(makeHappyRequest());

            expect(result.applied).toEqual([{ uid: UID_A }]);
            expect(result.rejected).toHaveLength(1);
            expect(result.rejected[0]).toMatchObject({
                uid: UID_B,
                reason: 'write_failed',
                detail: 'Disk full',
            });
        });
    });

    describe('hash normalization integration', () => {
        it('accepts sha256: prefixed hashes matching bare hex', async () => {
            mockJwtVerify.mockReturnValue(makeValidJwtDecoded());
            mockLeaseStore.get = vi.fn().mockResolvedValue(makeActiveLease());

            // Lease stores bare hex; patch uses sha256: prefix
            mockFsService.readContent = vi.fn()
                .mockResolvedValueOnce(Buffer.from(CONTENT_A_ORIG));
            mockFsService.write = vi.fn().mockResolvedValue(undefined);

            const result = await broker.applyWriteback({
                token: 'valid.jwt.token',
                app_uid: APP_UID,
                patches: [
                    {
                        uid: UID_A,
                        base_hash: HASH_A_SHA256,
                        content: 'new content A',
                    },
                ],
            });

            expect(result.applied).toEqual([{ uid: UID_A }]);
            expect(result.rejected).toEqual([]);
        });

        it('accepts bare hex when lease stores sha256: prefixed hashes', async () => {
            const leaseWithPrefixed: LeaseRecord = {
                ...makeActiveLease(),
                base_hashes: [HASH_A_SHA256, HASH_B_SHA256],
            };

            mockJwtVerify.mockReturnValue(makeValidJwtDecoded());
            mockLeaseStore.get = vi.fn().mockResolvedValue(leaseWithPrefixed);
            mockFsService.readContent = vi.fn()
                .mockResolvedValueOnce(Buffer.from(CONTENT_A_ORIG));
            mockFsService.write = vi.fn().mockResolvedValue(undefined);

            const result = await broker.applyWriteback({
                token: 'valid.jwt.token',
                app_uid: APP_UID,
                patches: [
                    { uid: UID_A, base_hash: HASH_A, content: 'new content A' },
                ],
            });

            expect(result.applied).toEqual([{ uid: UID_A }]);
            expect(result.rejected).toEqual([]);
        });
    });

    describe('edge cases', () => {
        it('handles empty patches list', async () => {
            mockJwtVerify.mockReturnValue(makeValidJwtDecoded());
            mockLeaseStore.get = vi.fn().mockResolvedValue(makeActiveLease());

            const result = await broker.applyWriteback({
                token: 'valid.jwt.token',
                app_uid: APP_UID,
                patches: [],
            });

            expect(result.applied).toEqual([]);
            expect(result.rejected).toEqual([]);
            expect(result.lease_id).toBe(LEASE_ID);
        });

        it('rejects all patches when fsService is null', async () => {
            const brokerNoFs = new WritebackBroker(
                mockLeaseStore,
                mockJwtVerify as unknown as JwtVerifyFn,
                TEST_SECRET,
                TEST_AUDIENCE,
                null,
            );

            mockJwtVerify.mockReturnValue(makeValidJwtDecoded());
            mockLeaseStore.get = vi.fn().mockResolvedValue(makeActiveLease());

            const result = await brokerNoFs.applyWriteback(makeHappyRequest());

            expect(result.applied).toEqual([]);
            expect(result.rejected).toHaveLength(2);
            for (const r of result.rejected) {
                expect(r.reason).toBe('stale_hash');
                expect(r.detail).toContain('no fsService configured');
            }
        });

        it('rejects patch when fsService.readContent throws', async () => {
            mockJwtVerify.mockReturnValue(makeValidJwtDecoded());
            mockLeaseStore.get = vi.fn().mockResolvedValue(makeActiveLease());

            mockFsService.readContent = vi.fn()
                .mockRejectedValue(new Error('File not found'));
            mockFsService.write = vi.fn();

            const result = await broker.applyWriteback({
                token: 'valid.jwt.token',
                app_uid: APP_UID,
                patches: [
                    { uid: UID_A, base_hash: HASH_A, content: 'new A' },
                ],
            });

            expect(result.applied).toEqual([]);
            expect(result.rejected).toHaveLength(1);
            expect(result.rejected[0].reason).toBe('stale_hash');
            expect(result.rejected[0].detail).toContain(
                'failed to read current content',
            );
        });
    });
});
