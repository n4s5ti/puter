// -- ATL4S Janus Control Kernel (Deterministic Half) ------------------------
//
// Pure-math, token-free control kernel implementing the ATL4S v2 spec.
// Takes the 4 semantic signals a model emits (Δs, J_harm, J_drift, J_anchor)
// and computes the full control state: zones, residual, resonance, coupler,
// lambda pattern classification, bridging permission, and action decision.
//
// Implements god_formulas.md (ATL4S Control Kernel — Unified v2 Spec).
// See: ai_docs/cannon/configs/atl5s/atl4s_math/god_formulas.md
//
// This is the DETERMINISTIC half of the semantic/deterministic governance
// split (§10). Zero tokens, no I/O, no Puter services.

// -- Types ------------------------------------------------------------------

export type Zone = 'safe' | 'transit' | 'risk' | 'danger';
export type LambdaObserve =
    | 'convergent'
    | 'recursive'
    | 'divergent'
    | 'chaotic';
export type Action = 'continue' | 'slow' | 'verify' | 'pause' | 'rollback';

/**
 * The 4 semantic signals the model emits at each reasoning step (§10.1).
 * These require model-level judgment — the harness never estimates them.
 */
export interface SemanticSignals {
    /** Semantic tension Δs_t ∈ [0,1]: how far current state is from goal */
    delta_s: number;
    /** Harm signal J_harm ∈ [0,1]: is this action causing or risking harm? */
    j_harm: number;
    /** Drift signal J_drift ∈ [0,1]: is the agent drifting from user intent? */
    j_drift: number;
    /** Anchor signal J_anchor ∈ [0,1]: are anchor constraints being violated? */
    j_anchor: number;
    /**
     * Optional anchor satisfaction score ∈ [0,1] summarizing how well key
     * anchor constraints are met. Used for alternation flag (§5.3).
     */
    anchor_score?: number;
}

/**
 * Full control state output from one step() call (§9 YAML header contract
 * plus diagnostic fields the spec says to track).
 */
export interface ControlState {
    /** Semantic tension Δs_t (passthrough from input) */
    delta_s: number;
    /** Zone classification from Δs (§3) */
    zone: Zone;
    /** Residual magnitude R_t = ||B_t|| scalar proxy (§4.1) */
    residual: number;
    /** Resonance E_resonance_t: rolling mean of residual over window min(t,5) (§4.2) */
    resonance: number;
    /** Coupler strength W_c_t ∈ [-θ_c, +θ_c] (§5.4) */
    w_c: number;
    /** Lambda pattern classification over trajectory (§6) */
    lambda_observe: LambdaObserve;
    /** Composite J_t = (J_harm + J_drift + J_anchor) / 3 (§9) */
    j_t: number;
    /** Whether a bridge (major plan change) is permitted (§7) */
    can_bridge: boolean;
    /** Recommended action from the control policy (§10.3 ¶5) */
    action: Action;
}

// -- Constants (from god_formulas.md spec) ----------------------------------

/** k_bias — small constant bias on residual (§4.1) */
const K_BIAS = 0.01;

/** lambda_C_bonus — structure degradation bonus weight (§4.1) */
const LAMBDA_C_BONUS = 0.10;

/** lambda_V_bonus — value degradation bonus weight (§4.1) */
const LAMBDA_V_BONUS = 0.10;

/** Zone threshold: safe/transit boundary (§3) */
const ZONE_SAFE_MAX = 0.40;

/** Zone threshold: transit/risk boundary (§3) */
const ZONE_TRANSIT_MAX = 0.60;

/** Zone threshold: risk/danger boundary (§3) */
const ZONE_RISK_MAX = 0.85;

/** B_c — coupler base (§5.1) — not directly used in W_c formula but is the
 *  nominal "correction vs explore" ratio the spec references */
// const B_c = 0.85;

/** gamma — unused in current W_c formula (§5.1) */
// const GAMMA = 0.618;

/** theta_c — coupler clamp bound (§5.1) */
const THETA_C = 0.75;

/** zeta_min — minimum progress floor (§5.1) */
const ZETA_MIN = 0.10;

/** omega — progress exponent (§5.1) — set to 1.0 (identity) */
const OMEGA = 1.0;

/** phi_delta — alternation phase amplitude (§5.1) */
const PHI_DELTA = 0.15;

/** epsilon — zero constant (§5.1) */
// const EPSILON = 0.0 — used only as additive identity, omitted

/**
 * h — alternation flip threshold: min |anchor_score change| to trigger
 *     sign-of-satisfaction check (§5.3)
 */
const ALT_FLIP_THRESHOLD = 0.02;

/**
 * Lambda classification thresholds (§6):
 *   convergent:  Delta_t ≤ CONVERGENT_DELTA_MAX
 *   recursive:   |Delta_t| < RECURSIVE_DELTA_MAX
 *   divergent:   Delta_t ∈ (RECURSIVE_DELTA_MAX, CHAOTIC_DELTA_MIN]
 *   chaotic:     Delta_t > CHAOTIC_DELTA_MIN
 */
const CONVERGENT_DELTA_MAX = -0.02;
const RECURSIVE_DELTA_ABS_MAX = 0.02;
const CHAOTIC_DELTA_MIN = 0.04;

/** Rolling mean window size for E_bar_t and E_resonance_t */
const ROLLING_WINDOW = 5;

/** Bridge condition: W_c must be looser than 0.5 × θ_c (§7) */
const BRIDGE_W_C_THRESHOLD = 0.5 * THETA_C; // 0.375

/**
 * Composite J_t weights (§9 default).
 * Spec says "mean of 3 components" (§10.2 table), so uniform.
 */
const J_HARM_WEIGHT = 1 / 3;
const J_DRIFT_WEIGHT = 1 / 3;
const J_ANCHOR_WEIGHT = 1 / 3;

// -- Helpers ----------------------------------------------------------------

/** Clamp value into [lo, hi]. */
const clamp = (x: number, lo: number, hi: number): number =>
    Math.max(lo, Math.min(hi, x));

/**
 * Rolling mean over the last `window` elements of `series`.
 * Returns mean of all elements if series length < window.
 * Returns 0 for empty series.
 */
const rollingMean = (series: number[], window: number): number => {
    if (series.length === 0) return 0;
    const slice = series.slice(-window);
    return slice.reduce((a, b) => a + b, 0) / slice.length;
};

/**
 * Compute the linear trend (slope) of the last `window` values in `series`.
 * Positive → rising, negative → falling, near-zero → flat.
 * Used for E_bar_t trend detection (§6).
 */
const linearTrend = (series: number[], window: number): number => {
    const slice = series.slice(-window);
    const n = slice.length;
    if (n < 2) return 0;
    const indices = Array.from({ length: n }, (_, i) => i);
    const meanX = (n - 1) / 2;
    const meanY = slice.reduce((a, b) => a + b, 0) / n;
    let num = 0;
    let den = 0;
    for (let i = 0; i < n; i++) {
        const dx = indices[i] - meanX;
        num += dx * (slice[i] - meanY);
        den += dx * dx;
    }
    return den === 0 ? 0 : num / den;
};

/**
 * Compute the variance of the last `window` values in `series`.
 * Used for oscillation detection (§6 divergent).
 */
const recentVariance = (series: number[], window: number): number => {
    const slice = series.slice(-window);
    const n = slice.length;
    if (n < 2) return 0;
    const mean = slice.reduce((a, b) => a + b, 0) / n;
    return slice.reduce((sum, v) => sum + (v - mean) ** 2, 0) / n;
};

// -- Zone classification (§3) -----------------------------------------------

const classifyZone = (delta_s: number): Zone => {
    if (delta_s < ZONE_SAFE_MAX) return 'safe';
    if (delta_s < ZONE_TRANSIT_MAX) return 'transit';
    if (delta_s < ZONE_RISK_MAX) return 'risk';
    return 'danger';
};

// -- Lambda pattern classification (§6) -------------------------------------
//
// Priority order (first match wins):
//   1. chaotic:   Δt > +0.04 OR erratic anchor flipping
//   2. convergent: Δt ≤ -0.02 AND E_bar slope ≤ 0
//   3. recursive:  |Δt| < 0.02 AND E_bar ~ flat (slope near zero)
//   4. divergent:  Δt ∈ (-0.02, +0.04] AND oscillation or rising Δs
//
// At t=1 (no history), defaults to 'convergent'.

const classifyLambda = (
    deltaDelta: number,
    eBarSlope: number,
    deltaVariance: number,
    anchorFlipping: boolean,
): LambdaObserve => {
    // Rule 1: Chaotic — large positive jump (> +0.04) or erratic anchor flipping
    // Per spec §6: chaotic only on Delta_t > +0.04 (not large drops, which
    // are convergent — tension is dropping fast, which is good)
    if (deltaDelta > CHAOTIC_DELTA_MIN || anchorFlipping) return 'chaotic';

    // Rule 2: Convergent — tension dropping steadily
    if (deltaDelta <= CONVERGENT_DELTA_MAX && eBarSlope <= 1e-6) return 'convergent';

    // Rule 3: Recursive — tension oscillating in a narrow band
    if (Math.abs(deltaDelta) < RECURSIVE_DELTA_ABS_MAX && Math.abs(eBarSlope) < 0.005) return 'recursive';

    // Rule 4: Divergent — tension rising or oscillating meaningfully
    if (deltaDelta > CONVERGENT_DELTA_MAX) {
        // Check for oscillation (variance indicates up/down movement)
        if (deltaVariance > 0.0004) return 'divergent';
        // Check for rising tension
        if (deltaDelta > 0) return 'divergent';
        // Delta in (-0.02, 0] but E_bar rising — divergent by slope
        if (eBarSlope > 0.005) return 'divergent';
    }

    // Fallback: convergent (conservative default)
    return 'convergent';
};

// -- Action decision --------------------------------------------------------
//
// Priority-ordered mapping (first match wins). Defines the control response
// based on (zone, λ_observe, J_t) per §10.3 ¶5 and spec policy:
//
//   J_t > 0.85                                   → rollback
//   J_t > 0.70                                   → pause
//   danger + chaotic                             → rollback
//   chaotic                                      → pause
//   danger + (divergent | recursive)             → pause
//   danger + convergent                          → verify
//   risk   + divergent                           → verify
//   divergent + not-safe                         → verify
//   risk                                         → slow
//   divergent                                    → slow
//   transit + recursive                          → slow
//   transit                                      → continue
//   safe   + recursive                           → continue
//   else (safe + convergent)                     → continue

const decideAction = (
    zone: Zone,
    lambda: LambdaObserve,
    j_t: number,
): Action => {
    // — Overrides (J_t high) — danger trumps all
    if (j_t > 0.85) return 'rollback';
    if (j_t > 0.70) return 'pause';

    // — Chaotic always triggers pause (or rollback if also in danger)
    if (zone === 'danger' && lambda === 'chaotic') return 'rollback';
    if (lambda === 'chaotic') return 'pause';

    // — Danger zone: requires at minimum verify
    if (zone === 'danger') {
        if (lambda === 'divergent' || lambda === 'recursive') return 'pause';
        if (lambda === 'convergent') return 'verify';
    }

    // — Divergent pattern in non-safe zones: needs verification
    if (zone === 'risk' && lambda === 'divergent') return 'verify';
    if (lambda === 'divergent' && zone !== 'safe') return 'verify';

    // — Risk zone: always triggers slow-down
    if (zone === 'risk') return 'slow';

    // — Divergent but safe: still needs attention
    if (lambda === 'divergent') return 'slow';

    // — Transit zone: mild concern
    if (zone === 'transit' && lambda === 'recursive') return 'slow';
    if (zone === 'transit') return 'continue';

    // — Safe zone
    if (zone === 'safe' && lambda === 'recursive') return 'continue';
    // zone === 'safe' && lambda === 'convergent'
    return 'continue';
};

// -- Pair for checking anchor satisfaction sign change (§5.3) ---------------

/**
 * Returns -1 if anchor_score is below 0.5 (dissatisfied),
 * +1 if above (satisfied), 0 if exactly 0.5.
 */
const anchorSign = (score: number): -1 | 0 | 1 => {
    if (score > 0.5) return 1;
    if (score < 0.5) return -1;
    return 0;
};

// ===========================================================================
// -- JanusHarness -----------------------------------------------------------

export class JanusHarness {
    // -- Trajectory history ------------------------------------------------

    /** History of Δs_t values for lambda classification and progress. */
    private readonly deltaHistory: number[] = [];

    /** History of residual R_t values for resonance tracking. */
    private readonly residualHistory: number[] = [];

    /** History of anchor_score values for alternation flag. */
    private readonly anchorHistory: number[] = [];

    /** Current alternation flag alt ∈ {+1, -1} (§5.3). */
    private alt: 1 | -1 = 1;

    /** Step counter t (1-indexed). */
    private t: number = 0;

    // -- Public API ---------------------------------------------------------

    /**
     * Step the harness with the model's semantic signals and compute the
     * full control state.
     *
     * @param input — the 4 semantic signals emitted by the model (§10.1)
     * @returns Full control state with zone, λ, W_c, J_t, bridge, action
     */
    step(input: SemanticSignals): ControlState {
        const { delta_s, j_harm, j_drift, j_anchor, anchor_score } = input;

        // Validate inputs are in [0,1]
        // (The model is expected to emit valid signals; clamp defensively)
        const ds = clamp(delta_s, 0, 1);
        const jh = clamp(j_harm, 0, 1);
        const jd = clamp(j_drift, 0, 1);
        const ja = clamp(j_anchor, 0, 1);
        const as = anchor_score !== undefined ? clamp(anchor_score, 0, 1) : undefined;

        this.t++;

        // -- Zone (§3) -------------------------------------------------------
        const zone = classifyZone(ds);

        // -- Residual (§4.1) --------------------------------------------------
        //
        // E_t = clamp(Δs - k_bias + 0.5*ΔC_est + 0.5*ΔV_est, 0, 1)
        //
        // Where ΔC_est, ΔV_est are optional structure/value degradation
        // estimates not provided in the current signal set, so default to 0.
        //
        // This operationalizes the vector B_t = I_t - G + k_bias as a scalar
        // using Δs_t = 1 - cos(I_t, G) as the tension proxy, yielding
        // R_t = |Δs_t - k_bias| as the 1D norm proxy.
        //
        // When ΔC_est/ΔV_est ARE available (future extension):
        //   R_t = |Δs_t - k_bias - lambda_C_bonus * ΔC_est - lambda_V_bonus * ΔV_est|
        //
        // Following the task assignment formula (the +0.5 convention is the
        // intended harness-mode adaptation; see god_formulas.md §4.1 for the
        // original vector form with lambda bonuses).

        const deltaC_est = 0; // not yet provided in SemanticSignals
        const deltaV_est = 0;

        const residualRaw =
            ds - K_BIAS + 0.5 * deltaC_est + 0.5 * deltaV_est;
        const residual = clamp(residualRaw, 0, 1);

        // -- Resonance (§4.2) ------------------------------------------------
        // E_resonance_t = rolling_mean(R_1, ..., R_t, window = min(t, 5))

        this.residualHistory.push(residual);
        const resonance = rollingMean(this.residualHistory, ROLLING_WINDOW);

        // -- Progress (§5.2) --------------------------------------------------
        // P_t = prog_t^omega where prog_t = max(zeta_min, Δs_{t-1} - Δs_t)
        // At t=1, prog_t = zeta_min

        let progress: number;
        if (this.t <= 1) {
            progress = ZETA_MIN;
        } else {
            const prevDs = this.deltaHistory[this.deltaHistory.length - 1];
            const rawProgress = prevDs - ds;
            progress = Math.max(ZETA_MIN, rawProgress);
        }

        // Track Δs for future steps
        this.deltaHistory.push(ds);

        const P_t = Math.pow(progress, OMEGA); // OMEGA=1, so identity

        // -- Alternation flag (§5.3) -----------------------------------------

        if (as !== undefined) {
            this.anchorHistory.push(as);

            if (this.anchorHistory.length >= 2) {
                const prevAs = this.anchorHistory[this.anchorHistory.length - 2];
                const absDiff = Math.abs(as - prevAs);

                if (absDiff >= ALT_FLIP_THRESHOLD) {
                    const prevSign = anchorSign(prevAs);
                    const curSign = anchorSign(as);
                    // "sign of satisfaction changed": one was satisfied (>0.5),
                    // the other dissatisfied (<0.5)
                    if (prevSign !== 0 && curSign !== 0 && prevSign !== curSign) {
                        this.alt = (this.alt === 1 ? -1 : 1) as 1 | -1;
                    }
                }
            }
        }

        // -- Coupler W_c (§5.4) ----------------------------------------------
        // W_c_t = clip(Δs_t * P_t + Φ_t, -θ_c, +θ_c)
        //   where Φ_t = φ_δ · alt_t + ε (ε = 0)

        const Phi_t = PHI_DELTA * this.alt;
        const w_c_raw = ds * P_t + Phi_t;
        const w_c = clamp(w_c_raw, -THETA_C, THETA_C);

        // -- Composite J_t (§9) ----------------------------------------------
        // J_t = mean of J_harm, J_drift, J_anchor
        // (see §10.2 table: "Composite signal (mean of 3 components)")

        const j_t = J_HARM_WEIGHT * jh + J_DRIFT_WEIGHT * jd + J_ANCHOR_WEIGHT * ja;

        // -- Lambda pattern classification (§6) -------------------------------

        // First step: no trajectory history yet, default to convergent
        const lambda: LambdaObserve = this.t === 1
            ? 'convergent'
            : (() => {
        let deltaDelta = 0;
        let eBarSlope = 0;
        let deltaVariance = 0;
        let anchorFlipping = false;

        if (this.t >= 2) {
            const prevDs = this.deltaHistory[this.deltaHistory.length - 2];
            deltaDelta = ds - prevDs;

            // E_bar_t = rolling_mean(Δs_1..Δs_t, window = min(t, 5))
            const eBarNow = rollingMean(this.deltaHistory, ROLLING_WINDOW);

            // Slope of E_bar over rolling window
            // For t < 3, we use what we have
            const trendWindow = Math.min(ROLLING_WINDOW, this.t);
            eBarSlope = linearTrend(this.deltaHistory, trendWindow);

            // Variance of Δs for oscillation detection
            deltaVariance = recentVariance(this.deltaHistory, Math.min(ROLLING_WINDOW, this.t));

            // Anchor flipping detection: if anchor_score changes by >0.10
            // total over the last 3 steps, it's erratic
            if (this.anchorHistory.length >= 3) {
                const recentAnchors = this.anchorHistory.slice(-3);
                const totalFlip = recentAnchors
                    .slice(1)
                    .reduce((sum, cur, i) => sum + Math.abs(cur - recentAnchors[i]), 0);
                anchorFlipping = totalFlip > 0.10;
            }
        }

        return classifyLambda(
            deltaDelta,
            eBarSlope,
            deltaVariance,
            anchorFlipping,
        );
    })();

        // -- Bridge condition (§7) -------------------------------------------
        // can_bridge = (Δs_t < Δs_{t-1}) AND (W_c_t < 0.5 × θ_c)

        let canBridge = false;
        if (this.t >= 2) {
            const prevDs = this.deltaHistory[this.deltaHistory.length - 2];
            if (ds < prevDs && w_c < BRIDGE_W_C_THRESHOLD) {
                canBridge = true;
            }
        }

        // -- Action decision -------------------------------------------------

        const action = decideAction(zone, lambda, j_t);

        return {
            delta_s: ds,
            zone,
            residual,
            resonance,
            w_c,
            lambda_observe: lambda,
            j_t,
            can_bridge: canBridge,
            action,
        };
    }

    /**
     * Reset the harness to its initial state, clearing all trajectory history.
     * Idempotent — safe to call at any time.
     */
    reset(): void {
        this.deltaHistory.length = 0;
        this.residualHistory.length = 0;
        this.anchorHistory.length = 0;
        this.alt = 1;
        this.t = 0;
    }

    /**
     * Optional helper: compute Δs as 1 - cosine similarity between an
     * embedding and a goal embedding.
     *
     * Base case (§2.2): Δs_base = 1 - cos(I_t, G), clamped to [0,1].
     * Anchor-aware (§2.3): computes structured similarity using the spec's
     * weights (w_e=0.50, w_r=0.30, w_c=0.20) against anchor feature vectors.
     *
     * NOTE: step() takes delta_s as a pre-computed input per the
     * semantic/deterministic split (§10.1). This helper exists for
     * symmetry with the spec's §2 formulas.
     */
    computeDeltaS(
        I_t_embedding: number[],
        G_embedding: number[],
        anchors?: { entities: number[]; relations: number[]; constraints: number[] }[],
    ): number {
        // Cosine similarity between two vectors
        const cosine = (a: number[], b: number[]): number => {
            if (a.length !== b.length || a.length === 0) return 0;
            let dot = 0, na = 0, nb = 0;
            for (let i = 0; i < a.length; i++) {
                dot += a[i] * b[i];
                na += a[i] * a[i];
                nb += b[i] * b[i];
            }
            const denom = Math.sqrt(na) * Math.sqrt(nb);
            return denom === 0 ? 0 : dot / denom;
        };

        if (anchors === undefined || anchors.length === 0) {
            // Base case (§2.2): Δs_base = 1 - cos(I_t, G)
            return clamp(1 - cosine(I_t_embedding, G_embedding), 0, 1);
        }

        // Anchor-aware (§2.3): structured similarity against the last anchor
        const lastAnchor = anchors[anchors.length - 1];
        const sim_e = cosine(I_t_embedding, lastAnchor.entities);
        const sim_r = cosine(I_t_embedding, lastAnchor.relations);
        const sim_c = cosine(I_t_embedding, lastAnchor.constraints);
        const sim_struct = 0.50 * sim_e + 0.30 * sim_r + 0.20 * sim_c;
        return clamp(1 - sim_struct, 0, 1);
    }

    // -- Diagnostic accessors for testing ------------------------------------

    /** Current step counter. */
    get stepCount(): number {
        return this.t;
    }

    /** Current alternation flag value. */
    get alternation(): 1 | -1 {
        return this.alt;
    }

    /** Current Δs history (internal copy). */
    get deltaHistorySnapshot(): number[] {
        return [...this.deltaHistory];
    }
}
