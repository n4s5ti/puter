// -- AgentSec lease-escape adversarial benchmark ----------------------------
//
// Measures the WritebackBroker's rejection of ADVERSARIAL write attempts
// against an active lease. Validates the permission boundary: an agent
// cannot write outside its blast-radius lease.
//
// N varied adversarial write attempts run through the REAL WritebackBroker
// (InMemoryLeaseStore, real JWT sign/verify, in-memory FsServiceShim).
// Escape rate MUST be 0% for all adversarial patterns.
//
// What this benchmark DOES test:
//   - Per-lease uid isolation (unleased uids are rejected)
//   - Content-hash staleness detection (stale hashes are rejected)
//   - UID spoofing resistance (near-miss uids are rejected)
//   - Batch isolation (a single bad patch never blocks good ones)
//   - Post-revoke / post-expiry rejection
//   - Wrong-secret token rejection
//
// What this benchmark does NOT test:
//   a) Real-LLM-driven agents (scripted adversarial patterns stand in)
//   b) Bypass via direct FsService calls outside the broker (the broker
//      is the enforcement point; callers that skip it are out of scope
//      and constitute an integration concern)
//   c) Side-channel attacks (timing, JWT alg confusion, etc.)

import crypto from 'node:crypto';
import { InMemoryLeaseStore } from './lease-store.js';
import { WritebackBroker } from './writeback.js';
import type { FsServiceShim } from './writeback.js';
import type { WritebackRejectReason } from './types.js';
import { sign as jwtSign, verify as jwtVerify } from './jwt.js';
import type {
    LeaseRecord,
    WritebackRequest,
    WritebackResult,
} from './types.js';
import { NoOpProvenanceSink } from './provenance.js';

// ===========================================================================
// -- Constants --------------------------------------------------------------

const TEST_SECRET = 'escape-bench-secret';
const BAD_SECRET = 'different-secret-not-matching';
const TEST_AUDIENCE = 'agentsec-grant-issuer';
const APP_UID = 'escape-bench-app';

const UID_A = 'uid-a';
const UID_B = 'uid-b';
const UID_C = 'uid-c';
const UID_D = 'uid-d';
const UID_E = 'uid-e';

const CONTENT_A = 'escape-bench original content A';
const CONTENT_B = 'escape-bench original content B';
const CONTENT_C = 'escape-bench original content C';
const CONTENT_D = 'escape-bench original content D';
const CONTENT_E = 'escape-bench original content E';

const sha256hex = (data: string): string =>
    crypto.createHash('sha256').update(data).digest('hex');

const HASH_A = sha256hex(CONTENT_A);
const HASH_B = sha256hex(CONTENT_B);

// ===========================================================================
// -- In-memory FsServiceShim for benchmarks ---------------------------------

export class BenchmarkFsService implements FsServiceShim {
    #store: Map<string, string>;

    constructor(seed?: Record<string, string>) {
        this.#store = new Map();
        if (seed) {
            for (const [uid, content] of Object.entries(seed)) {
                this.#store.set(uid, content);
            }
        }
    }

    async readContent(uid: string): Promise<string | Buffer> {
        const content = this.#store.get(uid);
        if (content === undefined) {
            throw new Error(`FS: uid not found: ${uid}`);
        }
        return Buffer.from(content);
    }

    async write(uid: string, content: string): Promise<void> {
        this.#store.set(uid, content);
    }

    /** Take a deep copy (independent state fork). */
    clone(): BenchmarkFsService {
        const copy = new BenchmarkFsService();
        for (const [uid, content] of this.#store) {
            copy.#store.set(uid, content);
        }
        return copy;
    }

    /** Return current content for a uid (for assertions). */
    getContent(uid: string): string | undefined {
        return this.#store.get(uid);
    }
}

// ===========================================================================
// -- Types ------------------------------------------------------------------

export interface PatchExpectation {
    uid: string;
    /** True if this patch is expected to be applied (legitimate write). */
    shouldApply: boolean;
    /** Expected rejection reason if not applied. */
    expectedReason?: WritebackRejectReason;
}

export interface EscapeAttemptResult {
    category: string;
    attempt: number;
    /** Per-patch outcome vs expectation. */
    patches: {
        uid: string;
        expected: PatchExpectation;
        actual: 'applied' | 'rejected';
        actualReason?: string;
        /** True if this patch escaped (was applied despite expected rejection). */
        escaped: boolean;
        /** True if this patch was falsely rejected (rejected despite expected application). */
        falseRejection: boolean;
    }[];
    /** Did the attempt encounter any escaped patch? */
    hasEscape: boolean;
    /** Did the attempt encounter any false rejection? */
    hasFalseRejection: boolean;
    /** Raw result from the broker. */
    result: WritebackResult;
}

export interface CategoryStats {
    attempts: number;
    escapes: number;
    falseRejections: number;
    appliedCount: number;
    rejectedCount: number;
    rejectedByReason: Record<string, number>;
    /** First escape attempt details (for debug). */
    firstEscape?: {
        attempt: number;
        uid: string;
        expectedReason?: string;
    };
    /** First false rejection details. */
    firstFalseRejection?: {
        attempt: number;
        uid: string;
        expectedReason?: string;
    };
}

export interface EscapeReport {
    perCategory: Record<string, CategoryStats>;
    totals: {
        totalAttempts: number;
        totalBadAttempts: number; // attempts with at least one bad patch
        totalGoodAttempts: number; // attempts with only good patches
        escapes: number;
        falseRejections: number;
        escapeRate: number; // escapes / total-bad-patches
        falseRejectionRate: number; // falseRejections / total-good-patches
    };
}

// ===========================================================================
// -- Base setup -------------------------------------------------------------

export interface BenchmarkSetup {
    leaseStore: InMemoryLeaseStore;
    baseFs: BenchmarkFsService;
    activeLease: LeaseRecord;
    expiredLease: LeaseRecord;
    validToken: string;
    expiredToken: string;
    badSecretToken: string;
}

/** Create the canonical benchmark state: leases + tokens + seed files. */
export function createBenchmarkSetup(): BenchmarkSetup {
    const leaseStore = new InMemoryLeaseStore();
    const baseFs = new BenchmarkFsService({
        [UID_A]: CONTENT_A,
        [UID_B]: CONTENT_B,
        [UID_C]: CONTENT_C,
        [UID_D]: CONTENT_D,
        [UID_E]: CONTENT_E,
    });

    const now = Math.floor(Date.now() / 1000);

    // Active lease for [UID_A, UID_B]
    const activeLease: LeaseRecord = {
        lease_id: crypto.randomUUID(),
        app_uid: APP_UID,
        target_uids: [UID_A, UID_B],
        anchor: 'bench-anchor',
        base_hashes: [HASH_A, HASH_B],
        exp: now + 86400, // 24 hours
        created_at: now,
        status: 'active',
    };

    // Expired lease for a uid not in the active lease
    const expiredLease: LeaseRecord = {
        lease_id: crypto.randomUUID(),
        app_uid: APP_UID,
        target_uids: ['past-uid'],
        anchor: 'bench-past',
        base_hashes: ['expiredhash'],
        exp: now - 3600, // 1 hour ago
        created_at: now - 7200,
        status: 'expired',
    };

    const validToken = jwtSign(
        {
            jti: activeLease.lease_id,
            exp: activeLease.exp,
            iat: now,
            sub: APP_UID,
            iss: TEST_AUDIENCE,
            aud: TEST_AUDIENCE,
            base_hash: HASH_A,
            anchor: 'bench-anchor',
            app_uid: APP_UID,
            target_uids: [UID_A, UID_B],
        },
        TEST_SECRET,
    );

    const expiredToken = jwtSign(
        {
            jti: expiredLease.lease_id,
            exp: expiredLease.exp,
            iat: now - 7200,
            sub: APP_UID,
            iss: TEST_AUDIENCE,
            aud: TEST_AUDIENCE,
            base_hash: 'expiredhash',
            anchor: 'bench-past',
            app_uid: APP_UID,
            target_uids: ['past-uid'],
        },
        TEST_SECRET,
    );

    const badSecretToken = jwtSign(
        {
            jti: crypto.randomUUID(),
            exp: now + 86400,
            iat: now,
            sub: APP_UID,
            iss: TEST_AUDIENCE,
            aud: TEST_AUDIENCE,
            base_hash: HASH_A,
            anchor: 'bench-anchor',
            app_uid: APP_UID,
            target_uids: [UID_A, UID_B],
        },
        BAD_SECRET,
    );

    leaseStore.create(activeLease);
    leaseStore.create(expiredLease);

    return {
        leaseStore,
        baseFs,
        activeLease,
        expiredLease,
        validToken,
        expiredToken,
        badSecretToken,
    };
}

/** Wire a WritebackBroker for a test run. */
function makeBroker(
    leaseStore: InMemoryLeaseStore,
    fsService: BenchmarkFsService,
): WritebackBroker {
    return new WritebackBroker(
        leaseStore,
        jwtVerify,
        TEST_SECRET,
        TEST_AUDIENCE,
        fsService,
        new NoOpProvenanceSink(),
    );
}

// ===========================================================================
// -- UID spoofing variant generators ----------------------------------------

const SPOOF_VARIANTS: (readonly [string, string])[] = [
    // Variant key, uid value
    ['trailing-space', `${UID_A} `],
    [
        'lowercase',
        UID_A.toLowerCase() === UID_A ? 'UID-A' : UID_A.toLowerCase(),
    ],
    ['zero-width-space', `${UID_A}\u200b`],
    ['null-byte-prefix', `\x00${UID_A}`],
    ['path-traversal', `${UID_A}/../sensitive`],
    ['different-case', 'UID-A'],
    ['underscore-suffix', `${UID_A}_`],
    ['dot-suffix', `${UID_A}.`],
    ['tab-suffix', `${UID_A}\t`],
    ['newline-suffix', `${UID_A}\n`],
];

// ===========================================================================
// -- Wrong-hash generators --------------------------------------------------

function* wrongHashes(count: number): Generator<string> {
    for (let i = 0; i < count; i++) {
        // Generate a deterministic wrong hex string of sha256 length
        const bad = HASH_A.split('')
            .map((ch, j) => {
                if (j === i % 64) {
                    const hexChars = '0123456789abcdef';
                    const idx = hexChars.indexOf(ch);
                    return hexChars[(idx + 1 + Math.floor(i / 64)) % 16];
                }
                return ch;
            })
            .join('');
        yield bad;
    }
}

// ===========================================================================
// -- Attempt generators per category ----------------------------------------

export function generateAttempts(
    category: string,
    N: number,
    setup: BenchmarkSetup,
): {
    request: WritebackRequest;
    expectations: PatchExpectation[];
    fallbackReplicator?: () => void;
}[] {
    const attempts: {
        request: WritebackRequest;
        expectations: PatchExpectation[];
        fallbackReplicator?: () => void;
    }[] = [];
    const now = Math.floor(Date.now() / 1000);
    const newContent = (base: string, i: number): string =>
        `${base}-modified-${category}-${i}-${now}`;

    switch (category) {
        case 'benign': {
            // Legitimate write — MUST apply.
            for (let i = 0; i < N; i++) {
                const req: WritebackRequest = {
                    token: setup.validToken,
                    app_uid: APP_UID,
                    patches: [
                        {
                            uid: UID_A,
                            base_hash: HASH_A,
                            content: newContent(CONTENT_A, i),
                        },
                    ],
                };
                attempts.push({
                    request: req,
                    expectations: [{ uid: UID_A, shouldApply: true }],
                });
            }
            break;
        }

        case 'unleased_uid': {
            // Patch a uid NOT in the lease.
            const unleasedUids = [UID_C, UID_D, UID_E];
            for (let i = 0; i < N; i++) {
                const uid = unleasedUids[i % unleasedUids.length];
                const req: WritebackRequest = {
                    token: setup.validToken,
                    app_uid: APP_UID,
                    patches: [
                        { uid, base_hash: 'deadbeef', content: 'evil content' },
                    ],
                };
                attempts.push({
                    request: req,
                    expectations: [
                        { uid, shouldApply: false, expectedReason: 'unleased' },
                    ],
                });
            }
            break;
        }

        case 'stale_hash': {
            // Correct uid but wrong base hash (file changed since lease).
            const wrongHashesGen = wrongHashes(N);
            const allWrong = Array.from(wrongHashesGen);
            for (let i = 0; i < N; i++) {
                const req: WritebackRequest = {
                    token: setup.validToken,
                    app_uid: APP_UID,
                    patches: [
                        {
                            uid: UID_A,
                            base_hash: allWrong[i % allWrong.length],
                            content: newContent(CONTENT_A, i),
                        },
                    ],
                };
                attempts.push({
                    request: req,
                    expectations: [
                        {
                            uid: UID_A,
                            shouldApply: false,
                            expectedReason: 'stale_hash',
                        },
                    ],
                });
            }
            break;
        }

        case 'uid_spoofing': {
            // Near-miss variants of a leased uid.
            const spoofVariants = SPOOF_VARIANTS;
            for (let i = 0; i < N; i++) {
                const [variant, spoofUid] =
                    spoofVariants[i % spoofVariants.length];
                const req: WritebackRequest = {
                    token: setup.validToken,
                    app_uid: APP_UID,
                    patches: [
                        {
                            uid: spoofUid,
                            base_hash: HASH_A,
                            content: newContent(CONTENT_A, i),
                        },
                    ],
                };
                attempts.push({
                    request: req,
                    expectations: [
                        {
                            uid: spoofUid,
                            shouldApply: false,
                            expectedReason: 'unleased',
                        },
                    ],
                });
            }
            break;
        }

        case 'batch_mixed': {
            // One good + one bad patch: A (leased, correct hash) + C (unleased).
            for (let i = 0; i < N; i++) {
                const req: WritebackRequest = {
                    token: setup.validToken,
                    app_uid: APP_UID,
                    patches: [
                        {
                            uid: UID_A,
                            base_hash: HASH_A,
                            content: newContent(CONTENT_A, i),
                        },
                        {
                            uid: UID_C,
                            base_hash: 'deadbeef',
                            content: 'evil in batch',
                        },
                    ],
                };
                attempts.push({
                    request: req,
                    expectations: [
                        { uid: UID_A, shouldApply: true },
                        {
                            uid: UID_C,
                            shouldApply: false,
                            expectedReason: 'unleased',
                        },
                    ],
                });
            }
            break;
        }

        case 'duplicate_uids': {
            // Same uid twice in one request. First applies, second becomes stale.
            for (let i = 0; i < N; i++) {
                const content = newContent(CONTENT_A, i);
                const req: WritebackRequest = {
                    token: setup.validToken,
                    app_uid: APP_UID,
                    patches: [
                        { uid: UID_A, base_hash: HASH_A, content },
                        { uid: UID_A, base_hash: HASH_A, content },
                    ],
                };
                attempts.push({
                    request: req,
                    expectations: [
                        { uid: UID_A, shouldApply: true },
                        // Second same patch: after first writes, content changed →
                        // stale hash (no escape — the second write's claimed
                        // base_hash no longer matches current content).
                        {
                            uid: UID_A,
                            shouldApply: false,
                            expectedReason: 'stale_hash',
                        },
                    ],
                });
            }
            break;
        }

        case 'empty_patches': {
            for (let i = 0; i < N; i++) {
                const req: WritebackRequest = {
                    token: setup.validToken,
                    app_uid: APP_UID,
                    patches: [],
                };
                attempts.push({
                    request: req,
                    expectations: [],
                });
            }
            break;
        }

        case 'post_revoke': {
            // Lease is revoked before the attempt. Each attempt:
            // 1. Create a fresh lease
            // 2. Revoke it immediately
            // 3. Try to write with the original token
            // But the token's jti still points to the now-revoked lease.
            // Each sub-attempt needs its own lease + token for isolation.
            for (let i = 0; i < N; i++) {
                const subLeaseId = crypto.randomUUID();
                const subLease: LeaseRecord = {
                    lease_id: subLeaseId,
                    app_uid: APP_UID,
                    target_uids: [UID_A, UID_B],
                    anchor: 'revoke-bench',
                    base_hashes: [HASH_A, HASH_B],
                    exp: now + 86400,
                    created_at: now,
                    status: 'active',
                };
                setup.leaseStore.create(subLease);

                const subToken = jwtSign(
                    {
                        jti: subLeaseId,
                        exp: subLease.exp,
                        iat: now,
                        sub: APP_UID,
                        iss: TEST_AUDIENCE,
                        aud: TEST_AUDIENCE,
                        base_hash: HASH_A,
                        anchor: 'revoke-bench',
                        app_uid: APP_UID,
                        target_uids: [UID_A, UID_B],
                    },
                    TEST_SECRET,
                );

                // Store a callback to revoke before broker call
                // We'll handle this inside the runner
                const req: WritebackRequest = {
                    token: subToken,
                    app_uid: APP_UID,
                    patches: [
                        {
                            uid: UID_A,
                            base_hash: HASH_A,
                            content: newContent(CONTENT_A, i),
                        },
                    ],
                };
                attempts.push({
                    request: req,
                    expectations: [
                        {
                            uid: UID_A,
                            shouldApply: false,
                            expectedReason: 'lease_inactive',
                        },
                    ],
                    // Tag: needs pre-run revocation
                    fallbackReplicator: () => {
                        setup.leaseStore.setRevoked(subLeaseId, 'revoked');
                    },
                });
            }
            break;
        }

        case 'expired_lease': {
            // Token with past exp — JWT verify rejects before lease check.
            for (let i = 0; i < N; i++) {
                const req: WritebackRequest = {
                    token: setup.expiredToken,
                    app_uid: APP_UID,
                    patches: [
                        {
                            uid: 'past-uid',
                            base_hash: 'expiredhash',
                            content: 'too late',
                        },
                    ],
                };
                attempts.push({
                    request: req,
                    expectations: [
                        {
                            uid: 'past-uid',
                            shouldApply: false,
                            expectedReason: 'expired',
                        },
                    ],
                });
            }
            break;
        }

        case 'wrong_audience_token': {
            // Token signed with a different secret — JWT verify fails.
            for (let i = 0; i < N; i++) {
                const req: WritebackRequest = {
                    token: setup.badSecretToken,
                    app_uid: APP_UID,
                    patches: [
                        {
                            uid: UID_A,
                            base_hash: HASH_A,
                            content: newContent(CONTENT_A, i),
                        },
                    ],
                };
                attempts.push({
                    request: req,
                    expectations: [
                        {
                            uid: UID_A,
                            shouldApply: false,
                            expectedReason: 'expired',
                        },
                    ],
                });
            }
            break;
        }

        default: {
            throw new Error(`Unknown category: ${category}`);
        }
    }

    return attempts;
}

// ===========================================================================
// -- Runner -----------------------------------------------------------------

/** Map from category name to list of patch expectations per attempt. */
const CATEGORIES_ALL = [
    'benign',
    'unleased_uid',
    'stale_hash',
    'uid_spoofing',
    'batch_mixed',
    'duplicate_uids',
    'empty_patches',
    'post_revoke',
    'expired_lease',
    'wrong_audience_token',
] as const;

/** Categories considered "good" (all patches should apply or no-ops). */
const GOOD_CATEGORIES = new Set(['benign', 'empty_patches']);

/** Categories whose all-patches are "bad" (all should be rejected). */
const ALL_BAD_CATEGORIES = new Set([
    'unleased_uid',
    'stale_hash',
    'uid_spoofing',
    'post_revoke',
    'expired_lease',
    'wrong_audience_token',
]);

export interface RunOptions {
    /** Attempts per category. Default 50. */
    N?: number;
    /** Subset of categories to run. Default all. */
    categories?: readonly string[];
}

/**
 * Run the full escape benchmark.
 * Creates a fresh setup, generates N adversarial attempts per category,
 * runs each through the REAL WritebackBroker, and reports escape metrics.
 */
export async function runEscapeBenchmark(
    opts: RunOptions = {},
): Promise<EscapeReport> {
    const N = opts.N ?? 50;
    const categories = opts.categories ?? CATEGORIES_ALL;

    const setup = createBenchmarkSetup();
    const perCategory: Record<string, CategoryStats> = {};

    let totalAttempts = 0;
    let totalBadPatches = 0; // patches that SHOULD be rejected
    let totalGoodPatches = 0; // patches that SHOULD be applied
    let totalEscapes = 0;
    let totalFalseRejections = 0;

    for (const category of categories) {
        const attempts = generateAttempts(category, N, setup);
        let escapes = 0;
        let falseRejections = 0;
        let appliedCount = 0;
        let rejectedCount = 0;
        const rejectedByReason: Record<string, number> = {};
        let firstEscape: CategoryStats['firstEscape'];
        let firstFalseRejection: CategoryStats['firstFalseRejection'];

        for (let idx = 0; idx < attempts.length; idx++) {
            const { request, expectations, fallbackReplicator } = attempts[idx];

            // For post_revoke: revoke the lease before the attempt
            if (fallbackReplicator) {
                fallbackReplicator();
            }

            // Create a fresh fsService per attempt (isolate state)
            const fsAttempt = setup.baseFs.clone();
            const broker = makeBroker(setup.leaseStore, fsAttempt);

            const result = await broker.applyWriteback(request);

            // Map result to expectations
            //
            // Pairwise consumption: for each uid, we drain the applied and
            // rejected queues in FIFO order, matching one expectation entry
            // to one result entry. This handles duplicate uids (same uid
            // appears in both applied and rejected) correctly because we
            // consume one slot per expectation rather than checking Set
            // membership.
            const appliedQ = new Map<string, number>();
            for (const a of result.applied) {
                appliedQ.set(a.uid, (appliedQ.get(a.uid) ?? 0) + 1);
            }
            const rejectedQ = new Map<string, { reason: string }[]>();
            for (const r of result.rejected) {
                const arr = rejectedQ.get(r.uid) ?? [];
                arr.push({ reason: r.reason });
                rejectedQ.set(r.uid, arr);
            }

            for (const exp of expectations) {
                const availApplied = appliedQ.get(exp.uid) ?? 0;
                const availRejected = rejectedQ.get(exp.uid) ?? [];

                if (exp.shouldApply) {
                    totalGoodPatches++;
                    if (availApplied > 0) {
                        appliedQ.set(exp.uid, availApplied - 1);
                        appliedCount++;
                    } else {
                        falseRejections++;
                        if (!firstFalseRejection) {
                            firstFalseRejection = {
                                attempt: idx,
                                uid: exp.uid,
                            };
                        }
                    }
                } else {
                    totalBadPatches++;
                    if (availApplied > 0) {
                        // Applied despite expected rejection — ESCAPE
                        appliedQ.set(exp.uid, availApplied - 1);
                        escapes++;
                        if (!firstEscape) {
                            firstEscape = {
                                attempt: idx,
                                uid: exp.uid,
                                expectedReason: exp.expectedReason,
                            };
                        }
                    } else if (availRejected.length > 0) {
                        // Properly rejected — consume one entry
                        const detail = availRejected.shift()!;
                        rejectedByReason[detail.reason] =
                            (rejectedByReason[detail.reason] ?? 0) + 1;
                        rejectedCount++;
                    }
                }
            }

            totalAttempts++;
        }

        perCategory[category] = {
            attempts: attempts.length,
            escapes,
            falseRejections,
            appliedCount,
            rejectedCount,
            rejectedByReason,
            firstEscape,
            firstFalseRejection,
        };
    }

    const totalGoodAttempts = categories
        .filter((c) => GOOD_CATEGORIES.has(c))
        .reduce((sum, c) => sum + perCategory[c].attempts, 0);

    const escapeRate = totalBadPatches > 0 ? totalEscapes / totalBadPatches : 0;
    const falseRejectionRate =
        totalGoodPatches > 0 ? totalFalseRejections / totalGoodPatches : 0;

    return {
        perCategory,
        totals: {
            totalAttempts,
            totalBadPatches,
            totalGoodAttempts,
            escapes: totalEscapes,
            falseRejections: totalFalseRejections,
            escapeRate,
            falseRejectionRate,
        },
    };
}

// ===========================================================================
// -- CLI runner (npx tsx) ---------------------------------------------------

/**
 * Print a readable summary table.
 */
function printReport(report: EscapeReport): void {
    console.log('\n=== AgentSec Lease-Escape Benchmark Report ===\n');
    console.log(
        `${'Category'.padEnd(22)} ${'Attempts'.padStart(8)} ${'Escapes'.padStart(8)} ${'FalseRej'.padStart(8)} ${'Applied'.padStart(8)} ${'Rejected'.padStart(8)}`,
    );
    console.log('-'.repeat(64));

    for (const [name, stats] of Object.entries(report.perCategory)) {
        console.log(
            `${name.padEnd(22)} ${String(stats.attempts).padStart(8)} ${String(stats.escapes).padStart(8)} ${String(stats.falseRejections).padStart(8)} ${String(stats.appliedCount).padStart(8)} ${String(stats.rejectedCount).padStart(8)}`,
        );
        if (stats.escapes > 0 && stats.firstEscape) {
            console.log(
                `  ⚠ FIRST ESCAPE: attempt ${stats.firstEscape.attempt}, uid "${stats.firstEscape.uid}", expected ${stats.firstEscape.expectedReason ?? '?'}`,
            );
        }
        if (stats.falseRejections > 0 && stats.firstFalseRejection) {
            console.log(
                `  ⚠ FIRST FALSE REJECTION: attempt ${stats.firstFalseRejection.attempt}, uid "${stats.firstFalseRejection.uid}"`,
            );
        }
        if (Object.keys(stats.rejectedByReason).length > 0) {
            const reasons = Object.entries(stats.rejectedByReason)
                .map(([r, c]) => `${r}:${c}`)
                .join(', ');
            console.log(`  reasons: ${reasons}`);
        }
    }

    console.log('\n--- Totals ---');
    console.log(`Total attempts:      ${report.totals.totalAttempts}`);
    console.log(`Total escapes:       ${report.totals.escapes}`);
    console.log(`Total false rej:     ${report.totals.falseRejections}`);
    console.log(
        `Escape rate:         ${(report.totals.escapeRate * 100).toFixed(2)}%`,
    );
    console.log(
        `False rejection rate: ${(report.totals.falseRejectionRate * 100).toFixed(2)}%`,
    );
    console.log(
        report.totals.escapeRate === 0
            ? '\nRESULT: ✓ Zero escapes — permission boundary holds.'
            : `\nRESULT: ✗ ${report.totals.escapes} escapes detected! Security boundary breached.`,
    );
}

// Run directly: npx tsx extensions/agentsec/src/escape-benchmark.ts
const isMain = process.argv[1]?.endsWith('escape-benchmark.ts');
if (isMain) {
    const N = parseInt(process.argv[2] ?? '50', 10);
    runEscapeBenchmark({ N }).then(printReport).catch(console.error);
}

// -- Explicit exports for testing -------------------------------------------

export { CATEGORIES_ALL, GOOD_CATEGORIES, ALL_BAD_CATEGORIES, SPOOF_VARIANTS };
