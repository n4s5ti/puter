// -- AgentSec Oracle freeze/resume loop --------------------------------------
//
// The joiner between the permission half (OBS-588) and the trajectory half
// (OBS-587). Watches the agent's token/tool stream, feeds semantic signals
// into the JanusHarness, and FREEZES the agent before an unsafe/divergent
// tool call when J_t crosses threshold or action goes pause/rollback.
//
// Also implements the backward "seductive failure" face: checks a learnings
// DB for prior trajectories that looked right at decision time but later
// proved non-convergent, and flags/demotes them.
//
// DI throughout. The real research/correction injection (resume providing
// context for the agent to self-correct) is a later, model-backed piece —
// this layer provides the checkpoint-restore hook.

import crypto from 'node:crypto';
import { JanusHarness } from './janus-harness.js';
import { NoOpProvenanceSink } from './provenance.js';
import type { ProvenanceSink } from './provenance.js';
import type {
    AgentStreamEvent,
    FreezeDecision,
    FreezeReason,
    LearningRecord,
} from './types.js';

// -- Interfaces (injectable) ------------------------------------------------

/**
 * Persistent store for learning records about action signatures and their
 * eventual outcomes. The oracle queries this backward face to detect
 * "seductive failures" — trajectories that looked convergent at decision
 * time but later resolved as non-convergent.
 */
export interface LearningsDb {
    /** Look up a learning record by action signature. */
    find(signature: string): Promise<LearningRecord | undefined>;
    /** Mark an existing record's outcome as non_convergent. */
    markNonConvergent(id: string): Promise<void>;
    /** Store a new learning record. */
    record(rec: LearningRecord): Promise<void>;
}

/**
 * Checkpoint store for freezing and resuming agent state mid-trajectory.
 */
export interface CheckpointStore {
    /** Persist checkpoint state for a step_id. */
    save(step_id: string, state: unknown): Promise<void>;
    /** Load a previously saved checkpoint (undefined if none). */
    load(step_id: string): Promise<unknown | undefined>;
}

// -- Default in-memory implementations --------------------------------------

/**
 * Map-backed LearningsDb for tests and default use.
 * Keys by action_signature; each signature maps to at most one record.
 */
export class InMemoryLearningsDb implements LearningsDb {
    readonly #store = new Map<string, LearningRecord>();

    async find(signature: string): Promise<LearningRecord | undefined> {
        return this.#store.get(signature);
    }

    async markNonConvergent(id: string): Promise<void> {
        for (const [key, rec] of this.#store) {
            if (rec.id === id) {
                this.#store.set(key, { ...rec, outcome: 'non_convergent' });
                return;
            }
        }
    }

    async record(rec: LearningRecord): Promise<void> {
        this.#store.set(rec.action_signature, rec);
    }

    /** Expose store for test introspection. */
    get size(): number {
        return this.#store.size;
    }
}

/**
 * Map-backed CheckpointStore for tests and default use.
 */
export class InMemoryCheckpointStore implements CheckpointStore {
    readonly #store = new Map<string, unknown>();

    async save(step_id: string, state: unknown): Promise<void> {
        this.#store.set(step_id, state);
    }

    async load(step_id: string): Promise<unknown | undefined> {
        return this.#store.get(step_id);
    }

    /** Expose store for test introspection. */
    get size(): number {
        return this.#store.size;
    }

    /** Check whether a step_id has a saved checkpoint. */
    has(step_id: string): boolean {
        return this.#store.has(step_id);
    }
}

// -- Helpers ----------------------------------------------------------------

/**
 * Compute a deterministic action signature from proposed_tool and optional
 * context_summary. Used to index and look up learning records for the
 * seductive-failure check.
 */
const computeSignature = (
    proposed_tool: string,
    context_summary?: string,
): string => {
    return `${proposed_tool}|${context_summary ?? ''}`;
};

// -- Oracle options ---------------------------------------------------------

export interface OracleOpts {
    /** J_t threshold above which the agent is frozen (default: 0.7) */
    j_t_freeze_threshold?: number;
}

// -- OracleLoop -------------------------------------------------------------

export class OracleLoop {
    readonly #janus: JanusHarness;
    readonly #learnings: LearningsDb;
    readonly #checkpoints: CheckpointStore;
    readonly #provenance: ProvenanceSink;
    readonly #jTFreezeThreshold: number;

    constructor(
        janus: JanusHarness,
        learnings: LearningsDb,
        checkpoints: CheckpointStore,
        provenance?: ProvenanceSink,
        opts?: OracleOpts,
    ) {
        this.#janus = janus;
        this.#learnings = learnings;
        this.#checkpoints = checkpoints;
        this.#provenance = provenance ?? new NoOpProvenanceSink();
        this.#jTFreezeThreshold = opts?.j_t_freeze_threshold ?? 0.7;
    }

    // -- Forward face: observe an agent stream event and decide freeze --------

    /**
     * Observe an agent stream event and decide whether to freeze.
     *
     * Forward face: runs JanusHarness.step() on the signals, checks the
     * backward face (seductive-failure learning DB), then evaluates action,
     * J_t, and lambda to decide freeze.
     *
     * On freeze: saves a checkpoint and emits oracle_freeze provenance.
     */
    async observe(event: AgentStreamEvent): Promise<FreezeDecision> {
        const cs = this.#janus.step(event.signals);

        // ---- Backward face: seductive-failure check -------------------------
        // Before checking the forward signals, look up the learning DB for
        // a prior non-convergent trajectory matching this action signature.

        if (event.proposed_tool !== undefined) {
            const signature = computeSignature(
                event.proposed_tool,
                event.context_summary,
            );
            const learning = await this.#learnings.find(signature);
            if (learning !== undefined && learning.outcome === 'non_convergent') {
                const decision: FreezeDecision = {
                    freeze: true,
                    reason: 'seductive_failure',
                    j_t: cs.j_t,
                    action: cs.action,
                    lambda: cs.lambda_observe,
                    step_id: event.step_id,
                    matched_learning_id: learning.id,
                };
                await this.#doFreeze(event.step_id, { signals: event.signals, cs });
                return decision;
            }
        }

        // ---- Forward face: evaluate control state ---------------------------

        let freeze = false;
        let reason: FreezeReason | undefined;

        // Order: rollback (most severe action) first, then chaotic lambda
        // (raw control signal — root cause), then pause action (consequence),
        // then quantitative j_t boundary. Seductive failure is already caught
        // above in the backward face.

        if (cs.action === 'rollback') {
            freeze = true;
            reason = 'rollback_action';
        } else if (cs.lambda_observe === 'chaotic') {
            freeze = true;
            reason = 'chaotic_lambda';
        } else if (cs.action === 'pause') {
            freeze = true;
            reason = 'pause_action';
        } else if (cs.j_t >= this.#jTFreezeThreshold) {
            freeze = true;
            reason = 'high_j_t';
        }

        if (freeze) {
            await this.#doFreeze(event.step_id, { signals: event.signals, cs });
        }

        return {
            freeze,
            reason,
            j_t: cs.j_t,
            action: cs.action,
            lambda: cs.lambda_observe,
            step_id: event.step_id,
        };
    }

    // -- Resume: load checkpoint for a frozen step ---------------------------

    /**
     * Load the checkpoint for a previously frozen step and emit
     * oracle_resume provenance.
     *
     * NOTE: The actual research / correction injection is out of scope here.
     * This provides the checkpoint restore hook; the real oracle's job of
     * researching docs and injecting correction is a later, model-backed
     * piece.
     */
    async resume(step_id: string): Promise<{ checkpoint: unknown | undefined }> {
        const checkpoint = await this.#checkpoints.load(step_id);

        await this.#emitProvenance({
            type: 'oracle_resume',
            ts: Date.now(),
            reason: `resume_step:${step_id}`,
        });

        return { checkpoint };
    }

    // -- Report outcome: record a learning after trajectory resolution --------

    /**
     * Record the outcome of a trajectory for the seductive-failure DB.
     *
     * If the outcome is non_convergent and a prior convergent record exists
     * for the same signature, demote it (mark non_convergent).
     *
     * Emits learning_recorded provenance on success.
     */
    async reportOutcome(
        step_id: string,
        signature: string,
        outcome: 'convergent' | 'non_convergent',
    ): Promise<void> {
        const existing = await this.#learnings.find(signature);

        if (outcome === 'non_convergent' && existing !== undefined) {
            // Demote: the prior record (convergent) is now known
            // non-convergent
            await this.#learnings.markNonConvergent(existing.id);
        }

        const record: LearningRecord = {
            id: crypto.randomUUID(),
            action_signature: signature,
            outcome,
            recorded_at: Date.now(),
        };
        await this.#learnings.record(record);

        await this.#emitProvenance({
            type: 'learning_recorded',
            ts: Date.now(),
            reason: `step:${step_id} signature:${signature} outcome:${outcome}`,
        });
    }

    // -- Internal helpers -----------------------------------------------------

    /** Save checkpoint and emit provenance for a freeze event. */
    async #doFreeze(step_id: string, state: unknown): Promise<void> {
        await this.#checkpoints.save(step_id, state);

        try {
            await this.#emitProvenance({
                type: 'oracle_freeze',
                ts: Date.now(),
                reason: `freeze_step:${step_id}`,
            });
        } catch {
            // Provenance is best-effort; never block a freeze on emit failure
        }
    }

    /** Emit a provenance event, swallowing errors (best-effort contract). */
    async #emitProvenance(event: {
        type: 'oracle_freeze' | 'oracle_resume' | 'learning_recorded';
        ts: number;
        reason?: string;
    }): Promise<void> {
        try {
            await this.#provenance.emit(event);
        } catch {
            // Best-effort: never let provenance failure propagate
        }
    }
}
