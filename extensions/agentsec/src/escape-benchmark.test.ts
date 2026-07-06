// -- Tests for AgentSec lease-escape adversarial benchmark -------------------
//
// These tests validate the WritebackBroker's permission boundary by running
// varied adversarial write attempts and measuring the escape rate.
//
// Target: escapeRate === 0 (no bad write escapes), falseRejectionRate === 0
// (no good write is falsely rejected). If either assertion fails, the runtime
// has a real security bug — do NOT relax assertions to force a pass.

import { describe, expect, it } from 'vitest';
import {
    runEscapeBenchmark,
    createBenchmarkSetup,
    generateAttempts,
} from './escape-benchmark.js';

// ===========================================================================
// -- Unit: setup integrity --------------------------------------------------

describe('createBenchmarkSetup', () => {
    it('produces valid leases and tokens', () => {
        const setup = createBenchmarkSetup();
        expect(setup.activeLease.status).toBe('active');
        expect(setup.activeLease.target_uids).toEqual(['uid-a', 'uid-b']);
        expect(setup.expiredLease.status).toBe('expired');
        expect(setup.validToken).toBeTruthy();
        expect(setup.validToken.split('.')).toHaveLength(3);
        expect(setup.expiredToken).toBeTruthy();
        expect(setup.badSecretToken).toBeTruthy();
    });

    it('seeds all five benchmark uids', async () => {
        const setup = createBenchmarkSetup();
        for (const uid of ['uid-a', 'uid-b', 'uid-c', 'uid-d', 'uid-e']) {
            const content = await setup.baseFs.readContent(uid);
            expect(content).toBeTruthy();
        }
    });
});

// ===========================================================================
// -- Unit: attempt generator produces correct expectations -------------------

describe('generateAttempts', () => {
    // Use small N for unit tests
    const N = 5;

    it('benign — patches expected to apply', () => {
        const setup = createBenchmarkSetup();
        const attempts = generateAttempts('benign', N, setup);
        expect(attempts).toHaveLength(N);
        for (const a of attempts) {
            expect(a.expectations).toHaveLength(1);
            expect(a.expectations[0].shouldApply).toBe(true);
        }
    });

    it('unleased_uid — patches expected rejected as unleased', () => {
        const setup = createBenchmarkSetup();
        const attempts = generateAttempts('unleased_uid', N, setup);
        expect(attempts).toHaveLength(N);
        for (const a of attempts) {
            expect(a.expectations[0].shouldApply).toBe(false);
            expect(a.expectations[0].expectedReason).toBe('unleased');
        }
    });

    it('stale_hash — patches expected rejected as stale_hash', () => {
        const setup = createBenchmarkSetup();
        const attempts = generateAttempts('stale_hash', N, setup);
        expect(attempts).toHaveLength(N);
        for (const a of attempts) {
            expect(a.expectations[0].shouldApply).toBe(false);
            expect(a.expectations[0].expectedReason).toBe('stale_hash');
        }
    });

    it('uid_spoofing — each uses a different spoof variant', () => {
        const setup = createBenchmarkSetup();
        const attempts = generateAttempts('uid_spoofing', N, setup);
        expect(attempts).toHaveLength(N);
        const uids = new Set(attempts.map((a) => a.request.patches[0].uid));
        // At least 2 unique spoof uids for N=5 (we have 10 variants)
        expect(uids.size).toBeGreaterThanOrEqual(2);
        for (const a of attempts) {
            // Check the spoof uid is NOT the real uid-a
            expect(a.request.patches[0].uid).not.toBe('uid-a');
            // Check the spoof uid is case-insensitively related (some variant)
            expect(a.request.patches[0].uid.toLowerCase()).toContain('uid-a');
            expect(a.expectations[0].shouldApply).toBe(false);
            expect(a.expectations[0].expectedReason).toBe('unleased');
        }
    });

    it('batch_mixed — one apply + one reject expectation', () => {
        const setup = createBenchmarkSetup();
        const attempts = generateAttempts('batch_mixed', N, setup);
        expect(attempts).toHaveLength(N);
        for (const a of attempts) {
            expect(a.expectations).toHaveLength(2);
            expect(a.expectations[0].shouldApply).toBe(true);
            expect(a.expectations[1].shouldApply).toBe(false);
            expect(a.expectations[1].expectedReason).toBe('unleased');
        }
    });

    it('empty_patches — zero expectations', () => {
        const setup = createBenchmarkSetup();
        const attempts = generateAttempts('empty_patches', N, setup);
        expect(attempts).toHaveLength(N);
        for (const a of attempts) {
            expect(a.request.patches).toHaveLength(0);
            expect(a.expectations).toHaveLength(0);
        }
    });

    it('post_revoke — has fallbackReplicator and expects lease_inactive', () => {
        const setup = createBenchmarkSetup();
        const attempts = generateAttempts('post_revoke', N, setup);
        expect(attempts).toHaveLength(N);
        for (const a of attempts) {
            expect(typeof a.fallbackReplicator).toBe('function');
            expect(a.expectations[0].shouldApply).toBe(false);
            expect(a.expectations[0].expectedReason).toBe('lease_inactive');
        }
    });
});

// ===========================================================================
// -- Integration: full benchmark run ----------------------------------------

describe('runEscapeBenchmark', () => {
    // Use N=10 for fast test runs (30 is used in the main security assertion)
    const N = 10;

    it('produces a valid EscapeReport with all categories', async () => {
        const report = await runEscapeBenchmark({ N });

        const expectedCategories = [
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
        ];

        for (const cat of expectedCategories) {
            expect(report.perCategory).toHaveProperty(cat);
            expect(report.perCategory[cat].attempts).toBe(N);
        }

        expect(report.totals.totalAttempts).toBe(N * expectedCategories.length);
        expect(typeof report.totals.escapeRate).toBe('number');
        expect(typeof report.totals.falseRejectionRate).toBe('number');
    });

    it('batch_mixed produces 1 applied + 1 rejected (isolation holds)', async () => {
        const report = await runEscapeBenchmark({
            N,
            categories: ['batch_mixed'],
        });

        const batch = report.perCategory['batch_mixed'];
        expect(batch.attempts).toBe(N);

        // Each attempt: 1 patch applied (A), 1 patch rejected (C)
        expect(batch.appliedCount).toBe(N);
        expect(batch.rejectedCount).toBe(N);

        // The rejection must be 'unleased'
        expect(batch.rejectedByReason['unleased']).toBe(N);

        // Zero escapes — C's patch must never be applied
        expect(batch.escapes).toBe(0);
    });

    it('uid_spoofing all rejected as unleased (no spoofed uid escapes)', async () => {
        const report = await runEscapeBenchmark({
            N: 30,
            categories: ['uid_spoofing'],
        });

        const spoof = report.perCategory['uid_spoofing'];
        expect(spoof.escapes).toBe(0);

        // All rejections must be 'unleased' (not 'expired' or 'stale_hash')
        expect(spoof.rejectedByReason['unleased']).toBe(30);
    });

    it('stale_hash all rejected (no wrong-hash write escapes)', async () => {
        const report = await runEscapeBenchmark({
            N: 30,
            categories: ['stale_hash'],
        });

        const stale = report.perCategory['stale_hash'];
        expect(stale.escapes).toBe(0);
        expect(stale.rejectedByReason['stale_hash']).toBe(30);
    });

    it('unleased_uid all rejected (no cross-uid write escapes)', async () => {
        const report = await runEscapeBenchmark({
            N: 30,
            categories: ['unleased_uid'],
        });

        const unleased = report.perCategory['unleased_uid'];
        expect(unleased.escapes).toBe(0);
        expect(unleased.rejectedByReason['unleased']).toBe(30);
    });

    it('post_revoke all rejected (revoked lease blocks writes)', async () => {
        const report = await runEscapeBenchmark({
            N: 30,
            categories: ['post_revoke'],
        });

        const revoked = report.perCategory['post_revoke'];
        expect(revoked.escapes).toBe(0);
        expect(revoked.rejectedByReason['lease_inactive']).toBe(30);
    });

    it('expired_lease all rejected (expired JWT blocks writes)', async () => {
        const report = await runEscapeBenchmark({
            N: 30,
            categories: ['expired_lease'],
        });

        const expired = report.perCategory['expired_lease'];
        expect(expired.escapes).toBe(0);
        expect(expired.rejectedByReason['expired']).toBe(30);
    });

    it('wrong_audience_token all rejected (bad JWT secret blocks writes)', async () => {
        const report = await runEscapeBenchmark({
            N: 30,
            categories: ['wrong_audience_token'],
        });

        const badToken = report.perCategory['wrong_audience_token'];
        expect(badToken.escapes).toBe(0);
        expect(badToken.rejectedByReason['expired']).toBe(30);
    });

    it('benign — all patches apply cleanly', async () => {
        const report = await runEscapeBenchmark({
            N: 30,
            categories: ['benign'],
        });

        const benign = report.perCategory['benign'];
        expect(benign.appliedCount).toBe(30);
        expect(benign.falseRejections).toBe(0);
    });
});

// ===========================================================================
// -- Security assertion: full benchmark with N=30 ---------------------------

describe('Security boundary: escapeRate === 0', () => {
    it('zero escapes across ALL adversarial categories', async () => {
        const report = await runEscapeBenchmark({ N: 30 });

        // Primary assertion: NO bad write escapes across any category
        const escapeCategories = Object.entries(report.perCategory).filter(
            ([, stats]) => stats.escapes > 0,
        );

        if (escapeCategories.length > 0) {
            // Surface full details so the test output is actionable
            const detail = escapeCategories
                .map(
                    ([name, stats]) =>
                        `${name}: ${stats.escapes} escapes` +
                        (stats.firstEscape
                            ? ` (first: attempt ${stats.firstEscape.attempt}, uid "${stats.firstEscape.uid}", expected ${stats.firstEscape.expectedReason ?? '?'})`
                            : ''),
                )
                .join('; ');
            expect(report.totals.escapes, `Escape breached: ${detail}`).toBe(0);
        }

        expect(report.totals.escapeRate).toBe(0);
    }, 30_000);

    it('zero false rejections (good writes are never rejected)', async () => {
        const report = await runEscapeBenchmark({ N: 30 });

        const falseRejectionCategories = Object.entries(
            report.perCategory,
        ).filter(([, stats]) => stats.falseRejections > 0);

        if (falseRejectionCategories.length > 0) {
            const detail = falseRejectionCategories
                .map(
                    ([name, stats]) =>
                        `${name}: ${stats.falseRejections} false rejections` +
                        (stats.firstFalseRejection
                            ? ` (first: attempt ${stats.firstFalseRejection.attempt}, uid "${stats.firstFalseRejection.uid}")`
                            : ''),
                )
                .join('; ');
            expect(
                report.totals.falseRejections,
                `False rejections: ${detail}`,
            ).toBe(0);
        }

        expect(report.totals.falseRejectionRate).toBe(0);
    }, 30_000);
});
