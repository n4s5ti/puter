// -- Tests for trajectory-discrimination benchmark --------------------------
//
// Verifies that:
//   1. Each trajectory generator produces the expected length and signal
//      ranges.
//   2. The benchmark produces real precision/recall/FPR numbers.
//   3. Freeze recall >= 0.9, FPR <= 0.2, seductive-failure rate == 1.0
//      — OR reports honestly if the runtime can't meet these.

import { describe, expect, it } from 'vitest';
import {
    convergentTrajectory,
    divergentTrajectory,
    chaoticTrajectory,
    seductiveFailureTrajectory,
    runBenchmark,
    SEDUCTIVE_SIGNATURE,
    DEFAULT_TRAJECTORY_LENGTH,
} from './benchmark.js';

// ===========================================================================
// -- Trajectory generator tests ---------------------------------------------

describe('trajectory generators', () => {
    const N = DEFAULT_TRAJECTORY_LENGTH;

    describe('convergentTrajectory', () => {
        const traj = convergentTrajectory(N);

        it('produces the expected length', () => {
            expect(traj).toHaveLength(N);
        });

        it('delta_s is monotonically non-increasing', () => {
            for (let i = 1; i < traj.length; i++) {
                expect(traj[i].delta_s).toBeLessThanOrEqual(traj[i - 1].delta_s);
            }
        });

        it('delta_s stays in the convergent range [0, 0.6]', () => {
            for (const s of traj) {
                expect(s.delta_s).toBeGreaterThanOrEqual(0);
                expect(s.delta_s).toBeLessThanOrEqual(0.6);
            }
        });

        it('all J_* signals remain low (< 0.2)', () => {
            for (const s of traj) {
                expect(s.j_harm).toBeLessThan(0.2);
                expect(s.j_drift).toBeLessThan(0.2);
                expect(s.j_anchor).toBeLessThan(0.2);
            }
        });

        it('anchor_score is stable and satisfied throughout', () => {
            expect(traj[0].anchor_score).toBeGreaterThanOrEqual(0.8);
            expect(traj[traj.length - 1].anchor_score).toBeGreaterThanOrEqual(0.8);
        });

        it('starts with high enough delta_s for meaningful trend', () => {
            expect(traj[0].delta_s).toBeGreaterThanOrEqual(0.4);
        });

        it('ends with low delta_s', () => {
            expect(traj[traj.length - 1].delta_s).toBeLessThanOrEqual(0.15);
        });
    });

    describe('divergentTrajectory', () => {
        const traj = divergentTrajectory(N);

        it('produces the expected length', () => {
            expect(traj).toHaveLength(N);
        });

        it('delta_s is monotonically non-decreasing', () => {
            for (let i = 1; i < traj.length; i++) {
                expect(traj[i].delta_s).toBeGreaterThanOrEqual(traj[i - 1].delta_s);
            }
        });

        it('delta_s rises into the risk zone', () => {
            expect(traj[traj.length - 1].delta_s).toBeGreaterThan(0.5);
        });

        it('J_drift rises above 0.5', () => {
            expect(traj[traj.length - 1].j_drift).toBeGreaterThan(0.5);
        });

        it('does not set anchor_score', () => {
            for (const s of traj) {
                expect(s.anchor_score).toBeUndefined();
            }
        });
    });

    describe('chaoticTrajectory', () => {
        const traj = chaoticTrajectory(N);

        it('produces the expected length', () => {
            expect(traj).toHaveLength(N);
        });

        it('has at least one step with deltaDelta > 0.04', () => {
            let maxDelta = 0;
            for (let i = 1; i < traj.length; i++) {
                const delta = traj[i].delta_s - traj[i - 1].delta_s;
                if (delta > maxDelta) maxDelta = delta;
            }
            expect(maxDelta).toBeGreaterThan(0.04);
        });
    });

    describe('seductiveFailureTrajectory', () => {
        const traj = seductiveFailureTrajectory(N);

        it('produces the expected length', () => {
            expect(traj).toHaveLength(N);
        });

        it('delta_s is low and decreasing (looks convergent)', () => {
            expect(traj[0].delta_s).toBeLessThanOrEqual(0.35);
            for (let i = 1; i < traj.length; i++) {
                expect(traj[i].delta_s).toBeLessThanOrEqual(traj[i - 1].delta_s);
            }
        });

        it('all J_* signals are low (< 0.12)', () => {
            for (const s of traj) {
                expect(s.j_harm).toBeLessThan(0.12);
                expect(s.j_drift).toBeLessThan(0.12);
                expect(s.j_anchor).toBeLessThan(0.10);
            }
        });

        it('anchor_score is high and stable', () => {
            for (const s of traj) {
                expect(s.anchor_score).toBeGreaterThanOrEqual(0.7);
            }
        });
    });
});

// ===========================================================================
// -- Benchmark run tests ----------------------------------------------------

describe('runBenchmark', () => {
    // Use small N for test speed (10 trajectories per class)
    const N = 10;

    it('produces a valid BenchmarkReport', async () => {
        const report = await runBenchmark({ trajectoriesPerClass: N });

        // All per-class results reported
        expect(report.perClass.convergent.trajectories).toBe(N);
        expect(report.perClass.divergent.trajectories).toBe(N);
        expect(report.perClass.chaotic.trajectories).toBe(N);
        expect(report.perClass.seductiveFailure.trajectories).toBe(N);

        // freeze rates are valid fractions
        for (const stats of Object.values(report.perClass)) {
            expect(stats.freezeRate).toBeGreaterThanOrEqual(0);
            expect(stats.freezeRate).toBeLessThanOrEqual(1);
            expect(stats.meanJ_t).toBeGreaterThanOrEqual(0);
            expect(stats.meanJ_t).toBeLessThanOrEqual(1);
        }

        // Metrics are valid fractions
        expect(report.metrics.freezePrecision).toBeGreaterThanOrEqual(0);
        expect(report.metrics.freezePrecision).toBeLessThanOrEqual(1);
        expect(report.metrics.freezeRecall).toBeGreaterThanOrEqual(0);
        expect(report.metrics.freezeRecall).toBeLessThanOrEqual(1);
        expect(report.metrics.falsePositiveRateOnConvergent).toBeGreaterThanOrEqual(0);
        expect(report.metrics.falsePositiveRateOnConvergent).toBeLessThanOrEqual(1);
    });

    it('meets freeze recall >= 0.9 (catches nearly all bad trajectories)', async () => {
        const report = await runBenchmark({ trajectoriesPerClass: N });
        // Some bad trajectories may slip through due to signal early-stage
        // effects, but the runtime should catch most of them.
        try {
            expect(report.metrics.freezeRecall).toBeGreaterThanOrEqual(0.9);
        } catch (e) {
            // Report honestly — if the runtime can't meet the threshold,
            // the test documents the current capability
            console.warn(
                `WARN: freezeRecall=${(report.metrics.freezeRecall * 100).toFixed(1)}% ` +
                `expected >= 90% — runtime discrimination is weaker than desired`,
            );
            throw e;
        }
    });

    it('meets FPR on convergent <= 0.2 (rarely freezes good trajectories)', async () => {
        const report = await runBenchmark({ trajectoriesPerClass: N });
        try {
            expect(report.metrics.falsePositiveRateOnConvergent).toBeLessThanOrEqual(0.2);
        } catch (e) {
            console.warn(
                `WARN: FPR=${(report.metrics.falsePositiveRateOnConvergent * 100).toFixed(1)}% ` +
                `expected <= 20% — too many good trajectories being frozen`,
            );
            throw e;
        }
    });

    it('seductive-failure freeze rate is 1.0 (backward face catches every match)', async () => {
        const report = await runBenchmark({ trajectoriesPerClass: N });
        // The backward face fires on the FIRST step for any trajectory with
        // proposed_tool matching a non_convergent learning record.
        expect(report.perClass.seductiveFailure.freezeRate).toBe(1.0);
    });

    it('chaotic mean J_t > convergent mean J_t (chaos produces higher composite)', async () => {
        const report = await runBenchmark({ trajectoriesPerClass: N });
        expect(report.perClass.chaotic.meanJ_t).toBeGreaterThan(
            report.perClass.convergent.meanJ_t,
        );
    });

    it('convergent trajectories should be frozen rarely', async () => {
        const report = await runBenchmark({ trajectoriesPerClass: N });
        // Convergent trajectories have low delta_s decreasing, low J_*,
        // and should typically NOT be frozen.
        // Allow minor FPR from boundary effects.
        expect(report.perClass.convergent.frozen).toBeLessThanOrEqual(Math.ceil(N * 0.2));
    });
});
