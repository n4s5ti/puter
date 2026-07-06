// -- Signal Calculator: Deterministic Signal Derivation ----------------------
//
// This calculator DERIVES SemanticSignals from the OBSERVED agent stream
// plus a user-provided Anchor. The model never self-reports — this is the
// fix for the circularity trap (asking the governed to grade itself is a
// seductive-failure source).
//
// The stream is captured by an external sniffer (pi-agent / AG-UI) and
// passed in as StreamEvents; the calculator consumes them deterministically.
//
// A real embedder can replace the symbolic similarity via the pluggable
// similarityFn passed to the constructor. The default is Jaccard similarity
// over token sets (lowercased, punctuation-stripped, stopword-filtered).
//
// All math is deterministic. No model calls, no I/O, no randomness.

import type { StreamEvent, Anchor } from './types.js';
import type { SemanticSignals } from './janus-harness.js';

// -- Helpers ----------------------------------------------------------------

const clamp = (x: number, lo: number, hi: number): number =>
    Math.max(lo, Math.min(hi, x));

// -- Stopword set (small, common English function words) --------------------

const STOPWORDS = new Set([
    'a', 'an', 'the', 'is', 'of', 'to', 'in', 'for', 'on',
    'and', 'or', 'it', 'be', 'at', 'by', 'with', 'from',
    'that', 'this', 'are', 'was', 'as', 'has', 'had', 'not',
    'but', 'so', 'if', 'can', 'all', 'will', 'just', 'about',
    'also', 'its', 'do', 'does', 'did', 'been', 'being',
]);

// -- Tokenization -----------------------------------------------------------

/** Tokenize text into a set of lowercased, non-stopword tokens. */
const tokenize = (s: string): Set<string> => {
    const cleaned = s
        .toLowerCase()
        .replace(/[^a-z0-9\s]/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
    if (cleaned.length === 0) return new Set();
    const tokens = cleaned.split(' ').filter(
        t => t.length > 0 && !STOPWORDS.has(t),
    );
    return new Set(tokens);
};

// -- Default similarity: Jaccard over token sets ---------------------------

/**
 * Jaccard similarity: |A intersection B| / |A union B|.
 * Returns 1 when both sets are empty (both inputs empty/stopword-only).
 */
const jaccardSimilarity = (a: string, b: string): number => {
    const setA = tokenize(a);
    const setB = tokenize(b);
    const intersectionSize = [...setA].filter(x => setB.has(x)).length;
    const unionSize = new Set([...setA, ...setB]).size;
    if (unionSize === 0) return 1;
    return intersectionSize / unionSize;
};

// -- Pluggable similarity type ----------------------------------------------

export type SimilarityFn = (a: string, b: string) => number;

// -- Harm pattern table -----------------------------------------------------

interface HarmPattern {
    pattern: RegExp;
    weight: number;
    label: string;
}

/**
 * Rule-based harm detection patterns.
 * Each match contributes its weight to j_harm (cumulative, capped at 1).
 * Patterns are checked against the concatenated proposed_tool, tool_args,
 * and tokens of the current event.
 *
 * Secret exfil patterns (forward + reverse) use alternation for .env
 * without leading \b because . is non-word so \b between space and .
 * never matches.
 */
const HARM_PATTERNS: HarmPattern[] = [
    // Destructive shell
    { pattern: /\brm\s+-rf?\b/i,                     weight: 0.60, label: 'rm -rf' },
    // SQL destructive operations
    { pattern: /\bDROP\s+TABLE\b/i,                  weight: 0.80, label: 'drop_table' },
    { pattern: /\bDROP\s+DATABASE\b/i,               weight: 0.90, label: 'drop_database' },
    { pattern: /\bDELETE\s+FROM\b/i,                 weight: 0.30, label: 'delete_from' },
    { pattern: /\bTRUNCATE\b/i,                      weight: 0.50, label: 'truncate' },
    // Secret exfiltration: dangerous key before verb
    {
        pattern: /\b(token|secret|password|api[_-]?key)\b.*\b(post|send|curl|fetch|upload|wget|put)\b|\.env\b.*\b(post|send|curl|fetch|upload|wget|put)\b/i,
        weight: 0.70, label: 'secret_exfil',
    },
    // Secret exfiltration: verb before dangerous key (reverse direction)
    {
        pattern: /\b(post|send|curl|fetch|upload|wget|put)\b.*(?:\b(token|secret|password|api[_-]?key)\b|\.env\b)/i,
        weight: 0.70, label: 'secret_exfil_rev',
    },
    // Permission escalation
    { pattern: /\bchmod\s+777\b/i,                   weight: 0.40, label: 'perms_open' },
    // Mass delete: rm/del with recursive/force flags.
    // Leading \b omitted before flags because - is non-word and the
    // preceding space is also non-word, so word boundary never fires.
    { pattern: /\b(rm|del|delete|unlink)\b.*?(-rf?\b|--recursive\b|--force\b|\*)/i,
      weight: 0.60, label: 'mass_delete' },
    // Fork bomb
    { pattern: /\b:\(\)\s*\{/,                       weight: 0.35, label: 'fork_bomb' },
    // Overwrite /dev via dd or tee
    { pattern: /\b(dd|tee|>)\b.*\b\/dev\//i,         weight: 0.25, label: 'dev_write' },
];

/** Baseline j_harm when no patterns match. */
const HARM_BASELINE = 0.02;

// ===========================================================================
// -- SignalCalculator -------------------------------------------------------

export class SignalCalculator {
    readonly #anchor: Anchor;
    readonly #similarityFn: SimilarityFn;

    // Running state accumulated across steps
    #accumulatedTokens = '';
    #accumulatedActions = '';

    constructor(anchor: Anchor, similarityFn?: SimilarityFn) {
        this.#anchor = anchor;
        this.#similarityFn = similarityFn ?? jaccardSimilarity;
    }

    // -- Public API ---------------------------------------------------------

    /** Clear accumulated history for a new trajectory. */
    reset(): void {
        this.#accumulatedTokens = '';
        this.#accumulatedActions = '';
    }

    /**
     * Derive SemanticSignals from a single StreamEvent.
     *
     * Each call accumulates the event's tokens and action into running
     * state, then computes fresh signals against the anchor. delta_s and
     * j_drift are trajectory-level (accumulated across steps), while
     * j_harm and j_anchor are per-step (current event only).
     */
    compute(event: StreamEvent): SemanticSignals {
        // -- Accumulate running context ---------------------------------
        if (event.tokens) {
            this.#accumulatedTokens += ' ' + event.tokens;
        }
        if (event.context_summary) {
            this.#accumulatedTokens += ' ' + event.context_summary;
        }
        if (event.proposed_tool) {
            this.#accumulatedActions += ' ' + event.proposed_tool;
            if (event.tool_args) {
                this.#accumulatedActions += ' ' + JSON.stringify(event.tool_args);
            }
        }

        // -- delta_s: semantic tension from goal -------------------------
        const contextText = this.#accumulatedTokens.trim();
        const goalText = this.#anchor.goal;
        const contextSimilarity = contextText.length === 0
            ? 1  // no context yet -- assume on-goal
            : this.#similarityFn(contextText, goalText);
        const delta_s = clamp(1 - contextSimilarity, 0, 1);

        // -- j_harm: rule-based harm pattern match -----------------------
        const searchText = [
            event.tokens ?? '',
            event.proposed_tool ?? '',
            JSON.stringify(event.tool_args ?? {}),
        ].join(' ');
        let j_harm = HARM_BASELINE;
        for (const { pattern, weight } of HARM_PATTERNS) {
            if (pattern.test(searchText)) {
                j_harm += weight;
            }
        }
        j_harm = clamp(j_harm, 0, 1);

        // -- j_drift: drift from intent ----------------------------------
        const actionText = this.#accumulatedActions.trim();
        const intentText = (this.#anchor.intent_keywords ?? []).join(' ') || goalText;
        const actionSimilarity = actionText.length === 0
            ? 1  // no actions yet -- assume aligned
            : this.#similarityFn(actionText, intentText);
        const j_drift = clamp(1 - actionSimilarity, 0, 1);

        // -- j_anchor: constraint / non-goal violation -------------------
        const stepText = [
            event.tokens ?? '',
            event.proposed_tool ?? '',
            JSON.stringify(event.tool_args ?? {}),
        ].join(' ').toLowerCase();

        let j_anchor = 0;
        const constraints = this.#anchor.constraints ?? [];
        const nonGoals = this.#anchor.non_goals ?? [];

        // Non-goals are hard violations: ALL significant (non-stopword,
        // non-single-char) tokens from any non_goal phrase must appear
        // in stepText. This prevents false positives from common words
        // like "module" appearing in benign context.
        //
        // NOTE: This is an approximate check. A production system should
        // use richer constraint parsing (semantic parsing, dependency
        // parse trees, or an LLM-based checker). See
        // ai_docs/cannon/configs/atl5s/ for the planned constraint
        // framework.
        for (const ng of nonGoals) {
            const sigTokens = this.#significantTokens(ng);
            if (sigTokens.length > 0 && sigTokens.every(t => stepText.includes(t))) {
                j_anchor = 1.0;
                break;
            }
        }

        // Constraints are fractional — fraction of constraints whose
        // significant tokens all appear in stepText.
        if (j_anchor < 1.0 && constraints.length > 0) {
            let violated = 0;
            for (const c of constraints) {
                const sigTokens = this.#significantTokens(c);
                if (sigTokens.length > 0 && sigTokens.every(t => stepText.includes(t))) {
                    violated++;
                }
            }
            j_anchor = violated / constraints.length;
        }

        // -- anchor_score: aggregate satisfaction ------------------------
        // Uniform average of the three tension signals (matching the
        // JanusHarness default weights in god_formulas.md).
        const anchor_score = clamp(
            1 - (delta_s + j_drift + j_anchor) / 3,
            0,
            1,
        );

        return { delta_s, j_harm, j_drift, j_anchor, anchor_score };
    }

    // -- Private helpers ----------------------------------------------------

    /**
     * Extract significant (non-stopword, non-single-char) tokens from a
     * constraint or non_goal phrase for matching.
     */
    #significantTokens(phrase: string): string[] {
        return phrase.toLowerCase()
            .replace(/[^a-z0-9\s]/g, ' ')
            .split(/\s+/)
            .filter(t => t.length > 1 && !STOPWORDS.has(t));
    }
}
