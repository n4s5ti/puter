// -- Tests for ATL4S Janus Control Kernel ------------------------------------
//
// Hand-traced trajectory tests asserting the harness produces sane control
// states across convergent, divergent, chaotic, and high-J_t scenarios.
// All inputs are fixed-seed deterministic (no randomness).

import { describe, expect, it } from 'vitest';
import { JanusHarness } from './janus-harness';
import type { SemanticSignals, ControlState, Action, Zone, LambdaObserve } from './janus-harness';

// -- Helpers ----------------------------------------------------------------

/** Assert a ControlState has the expected zone, λ, action, and numeric ranges. */
const expectSignals = (
    state: ControlState,
    expected: {
        zone: Zone;
        lambda: LambdaObserve;
        action: Action;
        delta_s: number;
    },
): void => {
    expect(state.zone).toBe(expected.zone);
    expect(state.lambda_observe).toBe(expected.lambda);
    expect(state.action).toBe(expected.action);
    expect(state.delta_s).toBeCloseTo(expected.delta_s, 10);
    expect(state.residual).toBeGreaterThanOrEqual(0);
    expect(state.residual).toBeLessThanOrEqual(1);
    expect(state.resonance).toBeGreaterThanOrEqual(0);
    expect(state.resonance).toBeLessThanOrEqual(1);
    expect(state.w_c).toBeGreaterThanOrEqual(-0.75);
    expect(state.w_c).toBeLessThanOrEqual(0.75);
    expect(state.j_t).toBeGreaterThanOrEqual(0);
    expect(state.j_t).toBeLessThanOrEqual(1);
};

/** Build a SemanticSignals with defaults for common fields. */
const sig = (overrides: Partial<SemanticSignals> & { delta_s: number }): SemanticSignals => ({
    j_harm: 0.1,
    j_drift: 0.1,
    j_anchor: 0.1,
    ...overrides,
});

// ===========================================================================
// -- Convergent trajectory --------------------------------------------------
//
// Δs dropping steadily: 0.50 → 0.35 → 0.22 → 0.12 → 0.05
// Each Δt ≤ -0.02 (convergent threshold). Low J_* signals.
// Expect: zone safe→transit→safe, λ convergent, action continue

describe('convergent trajectory', () => {
    it('drops steadily through zones toward continue', () => {
        const h = new JanusHarness();

        // Step 1 (t=1): Δs = 0.50 → transit, first step defaults to convergent
        const s1 = h.step(sig({ delta_s: 0.50 }));
        expectSignals(s1, { zone: 'transit', lambda: 'convergent', action: 'continue', delta_s: 0.50 });

        // Step 2: Δs = 0.35 → safe, Δt = -0.15 ≤ -0.02 → convergent
        const s2 = h.step(sig({ delta_s: 0.35 }));
        expectSignals(s2, { zone: 'safe', lambda: 'convergent', action: 'continue', delta_s: 0.35 });

        // Steps 3-5: continue dropping
        const s3 = h.step(sig({ delta_s: 0.22 }));
        expect(s3.lambda_observe).toBe('convergent');
        expect(s3.action).toBe('continue');

        const s4 = h.step(sig({ delta_s: 0.12 }));
        expect(s4.lambda_observe).toBe('convergent');
        expect(s4.action).toBe('continue');

        const s5 = h.step(sig({ delta_s: 0.05 }));
        expect(s5.lambda_observe).toBe('convergent');
        expect(s5.action).toBe('continue');
    });

    it('allows bridge on convergent trajectory', () => {
        const h = new JanusHarness();
        h.step(sig({ delta_s: 0.50 }));
        // Δs improves: 0.50 → 0.30
        const s2 = h.step(sig({ delta_s: 0.30 }));
        // W_c = clamp(Δs * P_t + 0.15*alt, -0.75, +0.75)
        // P_t = max(0.10, 0.50-0.30) = 0.20
        // W_c = 0.30*0.20 + 0.15 = 0.21 < 0.375 ✓
        expect(s2.w_c).toBeLessThan(0.375);
        expect(s2.can_bridge).toBe(true);
    });
});

// ===========================================================================
// -- Divergent trajectory ---------------------------------------------------
//
// Δs rising gradually with oscillation: each Δt < 0.04 (avoids chaotic),
// but E_bar rising and variance > 0.0004 for divergent detection.
// Trajectory: 0.10 → 0.13 → 0.16 → 0.19 → 0.22 → 0.25
// Each Δt = +0.03, clearly < 0.04, above absolute-recursive threshold (≥ 0.02)

describe('divergent trajectory', () => {
    it('classifies gradually rising Δs as divergent', () => {
        const h = new JanusHarness();

        h.step(sig({ delta_s: 0.10 }));
        h.step(sig({ delta_s: 0.13 }));
        h.step(sig({ delta_s: 0.16 }));
        // Step 4: Δs = 0.19, Δt = +0.03
        // Δt ∈ (-0.02, 0.04], E_bar rising, variance > 0.0004 → divergent
        const s4 = h.step(sig({ delta_s: 0.19 }));
        expect(s4.lambda_observe).toBe('divergent');
        expect(s4.zone).toBe('safe');
        expect(s4.action).toBe('slow'); // safe+divergent → slow
    });

    it('ramps through transit zone toward verify', () => {
        const h = new JanusHarness();

        for (const ds of [0.10, 0.13, 0.16, 0.19, 0.22, 0.25, 0.28, 0.31, 0.34, 0.37, 0.40]) {
            h.step(sig({ delta_s: ds }));
        }
        // Step 12: Δs = 0.43, transit zone, Δt = +0.03
        const s12 = h.step(sig({ delta_s: 0.43 }));
        expect(s12.zone).toBe('transit');
        expect(s12.lambda_observe).toBe('divergent');
        expect(s12.action).toBe('verify'); // divergent + not-safe → verify
    });
});

// ===========================================================================
// -- Recursive trajectory ---------------------------------------------------
//
// Δs oscillating in a narrow band: |Δt| < 0.02, E_bar flat.
// 0.30 → 0.31 → 0.29 → 0.31 → 0.30 → 0.31
// Need 4+ steps for E_bar slope to stabilize near zero.

describe('recursive trajectory', () => {
    it('classifies narrow-band oscillation as recursive', () => {
        const h = new JanusHarness();

        h.step(sig({ delta_s: 0.30 }));
        h.step(sig({ delta_s: 0.31 }));
        h.step(sig({ delta_s: 0.29 }));
        h.step(sig({ delta_s: 0.31 }));
        h.step(sig({ delta_s: 0.30 }));
        // Step 6: Δs = 0.31, |Δt| = 0.01 < 0.02, E_bar ~ flat → recursive
        const s6 = h.step(sig({ delta_s: 0.31 }));
        expect(s6.lambda_observe).toBe('recursive');
        expect(s6.zone).toBe('safe');
        expect(s6.action).toBe('continue');
    });

    it('triggers slow in transit+recursive', () => {
        const h = new JanusHarness();

        h.step(sig({ delta_s: 0.50 }));
        h.step(sig({ delta_s: 0.51 }));
        h.step(sig({ delta_s: 0.49 }));
        h.step(sig({ delta_s: 0.51 }));
        h.step(sig({ delta_s: 0.50 }));
        // Step 6: Δs = 0.51, transit+recursive → slow
        const s6 = h.step(sig({ delta_s: 0.51 }));
        expect(s6.zone).toBe('transit');
        expect(s6.lambda_observe).toBe('recursive');
        expect(s6.action).toBe('slow');
    });
});

// ===========================================================================
// -- Chaotic trajectory -----------------------------------------------------
//
// Δs jumping erratically: large Δt > 0.04 → chaotic.
// Per §6: chaotic only on Delta_t > +0.04 (positive jumps).

describe('chaotic trajectory', () => {
    it('detects positive jumps as chaotic and responds with pause', () => {
        const h = new JanusHarness();

        h.step(sig({ delta_s: 0.10 }));

        // Jump up: 0.10 → 0.50 (Δt = +0.40 > 0.04 → chaotic per §6)
        const s2 = h.step(sig({ delta_s: 0.50, j_harm: 0.3, j_drift: 0.3, j_anchor: 0.3 }));
        expect(s2.lambda_observe).toBe('chaotic');
        expect(s2.zone).toBe('transit');
        expect(s2.action).toBe('pause');

        // Another jump up: 0.50 → 0.80 (Δt = +0.30 > 0.04 → chaotic)
        const s3 = h.step(sig({ delta_s: 0.80 }));
        expect(s3.lambda_observe).toBe('chaotic');
        expect(s3.zone).toBe('risk');
        expect(s3.action).toBe('pause');
    });

    it('triggers rollback in danger+chaotic+high J_t', () => {
        const h = new JanusHarness();

        h.step(sig({ delta_s: 0.30 }));

        // Jump into danger zone with J_t = (0.80+0.70+0.70)/3 ≈ 0.733
        // J_t > 0.70 → pause (fires before chaotic check)
        const s2 = h.step(sig({
            delta_s: 0.90,
            j_harm: 0.8,
            j_drift: 0.7,
            j_anchor: 0.7,
        }));
        expect(s2.j_t).toBeCloseTo(0.733, 2);
        expect(s2.action).toBe('pause');
        expect(s2.zone).toBe('danger');
        expect(s2.lambda_observe).toBe('chaotic');

        // Push J_t over 0.85 → rollback
        const s3 = h.step(sig({
            delta_s: 0.95,
            j_harm: 0.95,
            j_drift: 0.90,
            j_anchor: 0.85,
        }));
        expect(s3.j_t).toBeCloseTo(0.9, 2);
        expect(s3.action).toBe('rollback');
        expect(s3.zone).toBe('danger');
        expect(s3.lambda_observe).toBe('chaotic');
    });
});

// ===========================================================================
// -- High J_t override ------------------------------------------------------
//
// Regardless of zone/λ, high J_t forces pause or rollback

describe('high J_t override', () => {
    it('forces rollback when J_t exceeds 0.85', () => {
        const h = new JanusHarness();
        const state = h.step(sig({
            delta_s: 0.05,
            j_harm: 0.9,
            j_drift: 0.9,
            j_anchor: 0.9,
        }));
        expect(state.j_t).toBeCloseTo(0.9, 2);
        expect(state.action).toBe('rollback');
    });

    it('forces pause when J_t exceeds 0.70', () => {
        const h = new JanusHarness();
        const state = h.step(sig({
            delta_s: 0.10,
            j_harm: 0.75,
            j_drift: 0.75,
            j_anchor: 0.75,
        }));
        expect(state.j_t).toBeCloseTo(0.75, 2);
        expect(state.action).toBe('pause');
    });

    it('does NOT override on moderate J_t (below 0.70)', () => {
        const h = new JanusHarness();
        const state = h.step(sig({
            delta_s: 0.10,
            j_harm: 0.3,
            j_drift: 0.3,
            j_anchor: 0.3,
        }));
        expect(state.j_t).toBeCloseTo(0.3, 2);
        expect(state.action).toBe('continue');
    });
});

// ===========================================================================
// -- Bridge condition -------------------------------------------------------
//
// can_bridge = (Δs improving) AND (W_c < 0.5 × θ_c = 0.375)

describe('bridge condition', () => {
    it('allows bridge when Δs improves and W_c is loose', () => {
        const h = new JanusHarness();
        h.step(sig({ delta_s: 0.50 }));
        const s2 = h.step(sig({ delta_s: 0.30 }));
        expect(s2.can_bridge).toBe(true);
    });

    it('denies bridge when Δs is worsening', () => {
        const h = new JanusHarness();
        h.step(sig({ delta_s: 0.30 }));
        const s2 = h.step(sig({ delta_s: 0.50 }));
        expect(s2.can_bridge).toBe(false);
    });

    it('denies when Δs unchanged', () => {
        const h = new JanusHarness();
        h.step(sig({ delta_s: 0.50 }));
        const s2 = h.step(sig({ delta_s: 0.50 }));
        expect(s2.can_bridge).toBe(false);
    });

    it('can_bridge is false on first step (no prior Δs)', () => {
        const h = new JanusHarness();
        const s = h.step(sig({ delta_s: 0.50 }));
        expect(s.can_bridge).toBe(false);
    });
});

// ===========================================================================
// -- Numeric invariants -----------------------------------------------------

describe('numeric invariants', () => {
    it('residual is correct at extreme Δs values', () => {
        const h1 = new JanusHarness();
        // Δs = 1.0 → E_t = clamp(1.0 - 0.01, 0, 1) = 0.99
        expect(h1.step(sig({ delta_s: 1.0 })).residual).toBe(0.99);

        const h2 = new JanusHarness();
        // Δs = 0 → E_t = clamp(0 - 0.01, 0, 1) = 0
        expect(h2.step(sig({ delta_s: 0 })).residual).toBe(0);

        const h3 = new JanusHarness();
        // Δs = 0.005 → E_t = clamp(0.005 - 0.01, 0, 1) = 0
        expect(h3.step(sig({ delta_s: 0.005 })).residual).toBe(0);
    });

    it('resonance converges to residual over constant-input steps', () => {
        const h = new JanusHarness();
        for (let i = 0; i < 10; i++) {
            h.step(sig({ delta_s: 0.30 }));
        }
        const state = h.step(sig({ delta_s: 0.30 }));
        expect(state.resonance).toBeCloseTo(state.residual, 2);
    });

    it('w_c never exceeds ±theta_c', () => {
        const h = new JanusHarness();
        for (let i = 0; i < 20; i++) {
            const state = h.step(sig({
                delta_s: i < 10 ? 0.90 : 0.05,
            }));
            expect(Math.abs(state.w_c)).toBeLessThanOrEqual(0.75 + 1e-10);
        }
    });
});

// ===========================================================================
// -- Idempotent reset -------------------------------------------------------

describe('reset', () => {
    it('clears all history and restores defaults', () => {
        const h = new JanusHarness();
        h.step(sig({ delta_s: 0.50 }));
        h.step(sig({ delta_s: 0.60 }));
        expect(h.stepCount).toBe(2);

        h.reset();

        expect(h.stepCount).toBe(0);
        expect(h.alternation).toBe(1);
        expect(h.deltaHistorySnapshot).toEqual([]);

        // After reset, first step should have t=1: default convergent
        const s1 = h.step(sig({ delta_s: 0.30 }));
        expect(s1.lambda_observe).toBe('convergent');
        expect(h.stepCount).toBe(1);
    });

    it('is idempotent', () => {
        const h = new JanusHarness();
        h.reset();
        h.reset();
        expect(h.stepCount).toBe(0);
        expect(h.alternation).toBe(1);
    });
});

// ===========================================================================
// -- Action mapping exhaustiveness ------------------------------------------

describe('action mapping', () => {
    it('safe+convergent → continue', () => {
        const h = new JanusHarness();
        const s = h.step(sig({ delta_s: 0.10 }));
        expect(s.zone).toBe('safe');
        expect(s.lambda_observe).toBe('convergent');
        expect(s.action).toBe('continue');
    });

    it('safe+recursive → continue', () => {
        const h = new JanusHarness();
        h.step(sig({ delta_s: 0.25 }));
        h.step(sig({ delta_s: 0.27 }));
        h.step(sig({ delta_s: 0.25 }));
        h.step(sig({ delta_s: 0.27 }));
        h.step(sig({ delta_s: 0.25 }));
        const s6 = h.step(sig({ delta_s: 0.26 }));
        expect(s6.zone).toBe('safe');
        expect(s6.lambda_observe).toBe('recursive');
        expect(s6.action).toBe('continue');
    });

    it('transit → continue (convergent first-step default)', () => {
        const h = new JanusHarness();
        const s = h.step(sig({ delta_s: 0.50 }));
        expect(s.zone).toBe('transit');
        expect(s.action).toBe('continue');
    });

    it('risk+convergent → slow', () => {
        const h = new JanusHarness();
        h.step(sig({ delta_s: 0.70 }));
        // Δs drops slightly: 0.70 → 0.68, Δt = -0.02 ≤ -0.02, convergent
        const s2 = h.step(sig({ delta_s: 0.68 }));
        expect(s2.zone).toBe('risk');
        expect(s2.lambda_observe).toBe('convergent');
        expect(s2.action).toBe('slow');
    });

    it('risk+recursive → slow', () => {
        const h = new JanusHarness();
        h.step(sig({ delta_s: 0.70 }));
        h.step(sig({ delta_s: 0.71 }));
        h.step(sig({ delta_s: 0.69 }));
        h.step(sig({ delta_s: 0.71 }));
        h.step(sig({ delta_s: 0.70 }));
        const s6 = h.step(sig({ delta_s: 0.70 }));
        expect(s6.zone).toBe('risk');
        expect(s6.lambda_observe).toBe('recursive');
        expect(s6.action).toBe('slow');
    });

    it('danger+convergent → verify', () => {
        const h = new JanusHarness();
        h.step(sig({ delta_s: 0.90 }));
        const s2 = h.step(sig({ delta_s: 0.87 }));
        expect(s2.zone).toBe('danger');
        expect(s2.lambda_observe).toBe('convergent');
        expect(s2.action).toBe('verify');
    });

    it('danger+divergent → pause', () => {
        const h = new JanusHarness();

        // Gradual rise: each Δt = 0.035 < 0.04 to avoid chaotic
        h.step(sig({ delta_s: 0.70 }));
        h.step(sig({ delta_s: 0.735 }));
        h.step(sig({ delta_s: 0.770 }));
        h.step(sig({ delta_s: 0.805 }));
        h.step(sig({ delta_s: 0.840 }));
        // Step 6: Δs = 0.875, Δt = 0.035 < 0.04, enters danger (≥ 0.85)
        const s6 = h.step(sig({ delta_s: 0.875 }));
        expect(s6.zone).toBe('danger');
        expect(s6.lambda_observe).toBe('divergent');
        expect(s6.action).toBe('pause');
    });

    it('safe+divergent → slow', () => {
        const h = new JanusHarness();

        // Gradually rising: each Δt = 0.03 < 0.04
        h.step(sig({ delta_s: 0.10 }));
        h.step(sig({ delta_s: 0.13 }));
        h.step(sig({ delta_s: 0.16 }));
        // Step 4: Δs = 0.19, Δt = +0.03, E_bar rising
        const s4 = h.step(sig({ delta_s: 0.19 }));
        expect(s4.zone).toBe('safe');
        expect(s4.lambda_observe).toBe('divergent');
        expect(s4.action).toBe('slow');
    });

    it('safe+convergent → continue (normal)', () => {
        const h = new JanusHarness();
        h.step(sig({ delta_s: 0.50 }));
        // Drop significantly: 0.50 → 0.10
        const s2 = h.step(sig({ delta_s: 0.10 }));
        expect(s2.zone).toBe('safe');
        expect(s2.lambda_observe).toBe('convergent');
        expect(s2.action).toBe('continue');
    });
});

// ===========================================================================
// -- Alternation flag -------------------------------------------------------

describe('alternation flag', () => {
    it('flips when anchor_score crosses the 0.5 boundary', () => {
        const h = new JanusHarness();

        h.step(sig({ delta_s: 0.30, anchor_score: 0.80 }));
        expect(h.alternation).toBe(1);

        // Score drops from 0.80 to 0.20: |Δ| = 0.60 ≥ 0.02, sign flips (+1→-1)
        h.step(sig({ delta_s: 0.30, anchor_score: 0.20 }));
        expect(h.alternation).toBe(-1);
    });

    it('does not flip on small changes below threshold', () => {
        const h = new JanusHarness();
        h.step(sig({ delta_s: 0.30, anchor_score: 0.60 }));
        expect(h.alternation).toBe(1);

        // Change of 0.01 < h = 0.02 → no flip
        h.step(sig({ delta_s: 0.30, anchor_score: 0.59 }));
        expect(h.alternation).toBe(1);
    });

    it('does not flip when sign stays the same', () => {
        const h = new JanusHarness();
        h.step(sig({ delta_s: 0.30, anchor_score: 0.90 }));
        expect(h.alternation).toBe(1);

        // Change of 0.35 ≥ 0.02, but both ≥ 0.5 (satisfied) → no sign change
        h.step(sig({ delta_s: 0.30, anchor_score: 0.55 }));
        expect(h.alternation).toBe(1);
    });
});

// ===========================================================================
// -- Edge cases -------------------------------------------------------------

describe('edge cases', () => {
    it('handles Δs at zone boundaries', () => {
        const h = new JanusHarness();

        expect(h.step(sig({ delta_s: 0.3999 })).zone).toBe('safe');
        expect(h.step(sig({ delta_s: 0.4000 })).zone).toBe('transit');
        expect(h.step(sig({ delta_s: 0.6000 })).zone).toBe('risk');
        expect(h.step(sig({ delta_s: 0.8500 })).zone).toBe('danger');
    });

    it('handles Δs = 0 and Δs = 1 extremes', () => {
        const h1 = new JanusHarness();
        const s1 = h1.step(sig({ delta_s: 0 }));
        expect(s1.zone).toBe('safe');
        expect(s1.residual).toBe(0);

        const h2 = new JanusHarness();
        const s2 = h2.step(sig({ delta_s: 1 }));
        expect(s2.zone).toBe('danger');
        expect(s2.residual).toBe(0.99);
    });

    it('clamps out-of-range inputs', () => {
        const h = new JanusHarness();
        const s = h.step({
            delta_s: 1.5,
            j_harm: -0.5,
            j_drift: 2.0,
            j_anchor: 0.5,
        });
        expect(s.delta_s).toBe(1);
        expect(s.j_t).toBeGreaterThanOrEqual(0);
        expect(s.j_t).toBeLessThanOrEqual(0.75);
    });

    it('computes cosine similarity in computeDeltaS', () => {
        const h = new JanusHarness();

        // Identical vectors → cos = 1 → Δs = 0
        expect(h.computeDeltaS([1, 0, 0], [1, 0, 0])).toBe(0);

        // Opposite vectors → cos = -1 → Δs = 1
        expect(h.computeDeltaS([1, 0, 0], [-1, 0, 0])).toBe(1);

        // Orthogonal vectors → cos = 0 → Δs = 1
        expect(h.computeDeltaS([1, 0, 0], [0, 1, 0])).toBe(1);

        // Partial overlap
        const ds = h.computeDeltaS([1, 1, 0], [1, 0, 0]);
        // cos = 1/√2 ≈ 0.707 → Δs ≈ 0.293
        expect(ds).toBeGreaterThan(0.2);
        expect(ds).toBeLessThan(0.4);
    });

    it('computeDeltaS handles empty anchor list', () => {
        const h = new JanusHarness();
        expect(h.computeDeltaS([1, 0, 0], [1, 0, 0], [])).toBe(0);
    });

    it('resonance equals residual on first step (window=1)', () => {
        const h = new JanusHarness();
        const s = h.step(sig({ delta_s: 0.50 }));
        expect(s.resonance).toBeCloseTo(s.residual, 5);
    });
});
