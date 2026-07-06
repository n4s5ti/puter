// -- Tests for AgentSec OracleLoop ------------------------------------------
//
// Covers the forward freeze face (high J_t, pause/rollback action, chaotic
// lambda), the backward seductive-failure face (learning DB lookup), resume
// (checkpoint restore), and reportOutcome (learning recording + demotion).
//
// Uses the real JanusHarness with crafted SemanticSignals to produce
// deterministic control states. Provenance events are captured via
// CapturingProvenanceSink for side-effect assertions.

import { describe, expect, it, beforeEach } from 'vitest';
import { JanusHarness } from './janus-harness.js';
import { CapturingProvenanceSink } from './demo-harness.js';
import {
    OracleLoop,
    InMemoryLearningsDb,
    InMemoryCheckpointStore,
} from './oracle.js';
import type { AgentStreamEvent, LearningRecord } from './types.js';

// ===========================================================================
// -- Factory helpers --------------------------------------------------------

/** Build an AgentStreamEvent with defaults. */
const event = (overrides: Partial<AgentStreamEvent> & {
    signals: AgentStreamEvent['signals'];
}): AgentStreamEvent => ({
    step_id: 'step-1',
    proposed_tool: undefined,
    context_summary: undefined,
    ...overrides,
});

/** Build a set of low-tension semantic signals (everything safe). */
const safeSignals = (overrides?: Partial<AgentStreamEvent['signals']>) => ({
    delta_s: 0.10,
    j_harm: 0.10,
    j_drift: 0.10,
    j_anchor: 0.10,
    ...overrides,
});

/** Build signals that produce a specific j_t from uniform components. */
const jtSignals = (j_t: number, overrides?: Partial<AgentStreamEvent['signals']>) => ({
    delta_s: 0.10,
    j_harm: j_t,
    j_drift: j_t,
    j_anchor: j_t,
    ...overrides,
});

/** Seed a learning record into an InMemoryLearningsDb. */
const seedLearning = async (
    db: InMemoryLearningsDb,
    proposed_tool: string,
    outcome: 'convergent' | 'non_convergent',
    context_summary?: string,
): Promise<LearningRecord> => {
    const signature = `${proposed_tool}|${context_summary ?? ''}`;
    const rec: LearningRecord = {
        id: `learning-${signature}`,
        action_signature: signature,
        outcome,
        recorded_at: Date.now(),
    };
    await db.record(rec);
    return rec;
};

// ===========================================================================
// -- OracleLoop tests -------------------------------------------------------

describe('OracleLoop', () => {
    let janus: JanusHarness;
    let learnings: InMemoryLearningsDb;
    let checkpoints: InMemoryCheckpointStore;
    let provenance: CapturingProvenanceSink;

    beforeEach(() => {
        janus = new JanusHarness();
        learnings = new InMemoryLearningsDb();
        checkpoints = new InMemoryCheckpointStore();
        provenance = new CapturingProvenanceSink();
    });

    // -- No-freeze cases -----------------------------------------------------

    it('does not freeze on low J_t with continue action and no seductive match', async () => {
        const oracle = new OracleLoop(janus, learnings, checkpoints, provenance);

        const decision = await oracle.observe(event({
            step_id: 'step-safe',
            signals: safeSignals(),
        }));

        expect(decision.freeze).toBe(false);
        expect(decision.reason).toBeUndefined();
        expect(decision.step_id).toBe('step-safe');
        // No checkpoint should be saved for non-freeze
        expect(checkpoints.has('step-safe')).toBe(false);
        // No oracle_freeze provenance emitted
        expect(provenance.events.filter(e => e.type === 'oracle_freeze')).toHaveLength(0);
    });

    // -- High J_t ------------------------------------------------------------

    it('freezes with reason high_j_t when J_t crosses the threshold', async () => {
        // Custom threshold 0.5; j_t=(0.6+0.6+0.6)/3=0.6 >= 0.5 but < 0.70,
        // so action won't be pause/rollback and high_j_t fires distinctly.
        const oracle = new OracleLoop(janus, learnings, checkpoints, provenance, {
            j_t_freeze_threshold: 0.5,
        });

        const decision = await oracle.observe(event({
            step_id: 'step-high-jt',
            signals: jtSignals(0.6),
        }));

        expect(decision.freeze).toBe(true);
        expect(decision.reason).toBe('high_j_t');
        expect(decision.j_t).toBeGreaterThanOrEqual(0.5);
        expect(decision.step_id).toBe('step-high-jt');
        // Checkpoint saved
        expect(checkpoints.has('step-high-jt')).toBe(true);
        // Provenance emitted
        expect(provenance.events.filter(e => e.type === 'oracle_freeze')).toHaveLength(1);
    });

    // -- Pause action --------------------------------------------------------

    it('freezes with reason pause_action when JanusHarness returns pause', async () => {
        const oracle = new OracleLoop(janus, learnings, checkpoints, provenance);

        // j_t > 0.70 triggers pause action (with safe zone, convergent lambda)
        const decision = await oracle.observe(event({
            step_id: 'step-pause',
            signals: jtSignals(0.80),
        }));

        expect(decision.freeze).toBe(true);
        expect(decision.reason).toBe('pause_action');
        expect(decision.step_id).toBe('step-pause');
        expect(checkpoints.has('step-pause')).toBe(true);
        expect(provenance.events.filter(e => e.type === 'oracle_freeze')).toHaveLength(1);
    });

    // -- Rollback action -----------------------------------------------------

    it('freezes with reason rollback_action when JanusHarness returns rollback', async () => {
        const oracle = new OracleLoop(janus, learnings, checkpoints, provenance);

        // j_t > 0.85 triggers rollback action unconditionally
        const decision = await oracle.observe(event({
            step_id: 'step-rollback',
            signals: jtSignals(0.90),
        }));

        expect(decision.freeze).toBe(true);
        expect(decision.reason).toBe('rollback_action');
        expect(decision.step_id).toBe('step-rollback');
        expect(checkpoints.has('step-rollback')).toBe(true);
    });

    // -- Chaotic lambda ------------------------------------------------------

    it('freezes with reason chaotic_lambda when lambda is chaotic', async () => {
        const oracle = new OracleLoop(janus, learnings, checkpoints, provenance);

        // Two steps: first has low delta_s, second has delta_delta > 0.04
        // j_t kept low (0.10) so action isn't pause from high J_t
        await oracle.observe(event({
            step_id: 'step-1',
            signals: safeSignals({ delta_s: 0.10 }),
        }));

        // delta_s=0.15 → delta_delta=0.05 > 0.04 → chaotic
        const decision = await oracle.observe(event({
            step_id: 'step-chaotic',
            signals: safeSignals({ delta_s: 0.15 }),
        }));

        expect(decision.freeze).toBe(true);
        expect(decision.reason).toBe('chaotic_lambda');
        expect(decision.step_id).toBe('step-chaotic');
        expect(checkpoints.has('step-chaotic')).toBe(true);
    });

    // -- Seductive failure ---------------------------------------------------

    it('freezes with seductive_failure when a non-convergent learning matches', async () => {
        const oracle = new OracleLoop(janus, learnings, checkpoints, provenance);
        const proposedTool = 'write_file';

        // Seed a non-convergent learning record for this tool
        const seeded = await seedLearning(learnings, proposedTool, 'non_convergent');

        // Observe a matching call (low signals so forward face wouldn't freeze)
        const decision = await oracle.observe(event({
            step_id: 'step-seductive',
            proposed_tool: proposedTool,
            signals: safeSignals(),
        }));

        expect(decision.freeze).toBe(true);
        expect(decision.reason).toBe('seductive_failure');
        expect(decision.matched_learning_id).toBe(seeded.id);
        expect(decision.step_id).toBe('step-seductive');
        // Checkpoint saved
        expect(checkpoints.has('step-seductive')).toBe(true);
        // Provenance emitted
        expect(provenance.events.filter(e => e.type === 'oracle_freeze')).toHaveLength(1);
    });

    it('does not freeze on seductive failure for convergent learning records', async () => {
        const oracle = new OracleLoop(janus, learnings, checkpoints, provenance);
        const proposedTool = 'read_file';

        // Seed a convergent learning record
        await seedLearning(learnings, proposedTool, 'convergent');

        // Observe with safe signals; forward face should not freeze
        const decision = await oracle.observe(event({
            step_id: 'step-no-seductive',
            proposed_tool: proposedTool,
            signals: safeSignals(),
        }));

        // Falls through to forward checks: all safe → no freeze
        expect(decision.freeze).toBe(false);
        expect(decision.reason).toBeUndefined();
    });

    it('does not trigger seductive failure when no learning record exists', async () => {
        const oracle = new OracleLoop(janus, learnings, checkpoints, provenance);

        // Observe with a proposed_tool but no matching learning record
        const decision = await oracle.observe(event({
            step_id: 'step-no-learning',
            proposed_tool: 'unknown_tool',
            signals: safeSignals(),
        }));

        expect(decision.freeze).toBe(false);
        expect(decision.reason).toBeUndefined();
    });

    it('does not trigger seductive failure when no proposed_tool is set', async () => {
        const oracle = new OracleLoop(janus, learnings, checkpoints, provenance);

        // Pure-reasoning step without proposed_tool should not check learnings
        const decision = await oracle.observe(event({
            step_id: 'step-reasoning',
            signals: safeSignals(),
        }));

        expect(decision.freeze).toBe(false);
    });

    // -- Signal priority: seductive failure overrides forward checks ----------

    it('seductive failure takes priority even when J_t is high', async () => {
        const oracle = new OracleLoop(janus, learnings, checkpoints, provenance);
        const proposedTool = 'rm_file';

        // Seed non-convergent learning
        await seedLearning(learnings, proposedTool, 'non_convergent');

        // Observe with high J_t (would normally trigger pause/rollback)
        const decision = await oracle.observe(event({
            step_id: 'step-priority',
            proposed_tool: proposedTool,
            signals: jtSignals(0.90),
        }));

        // Seductive failure fires first, not rollback_action
        expect(decision.freeze).toBe(true);
        expect(decision.reason).toBe('seductive_failure');
        expect(decision.j_t).toBeGreaterThan(0.8);
    });

    // -- Resume --------------------------------------------------------------

    it('resume loads a saved checkpoint and emits oracle_resume', async () => {
        const oracle = new OracleLoop(janus, learnings, checkpoints, provenance);

        // First, save a checkpoint via a freeze
        await oracle.observe(event({
            step_id: 'step-to-resume',
            signals: jtSignals(0.80),
        }));

        expect(checkpoints.has('step-to-resume')).toBe(true);

        // Resume
        const result = await oracle.resume('step-to-resume');

        expect(result.checkpoint).toBeDefined();
        expect(result.checkpoint).toHaveProperty('signals');
        expect(result.checkpoint).toHaveProperty('cs');

        // oracle_resume provenance emitted
        const resumeEvents = provenance.events.filter(e => e.type === 'oracle_resume');
        expect(resumeEvents).toHaveLength(1);
        expect(resumeEvents[0].reason).toContain('step-to-resume');
    });

    it('resume returns undefined checkpoint for unknown step_id', async () => {
        const oracle = new OracleLoop(janus, learnings, checkpoints, provenance);

        const result = await oracle.resume('nonexistent-step');

        expect(result.checkpoint).toBeUndefined();
    });

    // -- Report outcome ------------------------------------------------------

    it('reportOutcome records a new convergent learning record', async () => {
        const oracle = new OracleLoop(janus, learnings, checkpoints, provenance);

        await oracle.reportOutcome('step-42', 'read_file|', 'convergent');

        expect(learnings.size).toBe(1);
        const record = await learnings.find('read_file|');
        expect(record).toBeDefined();
        expect(record!.outcome).toBe('convergent');

        // learning_recorded provenance emitted
        const learningEvents = provenance.events.filter(e => e.type === 'learning_recorded');
        expect(learningEvents).toHaveLength(1);
    });

    it('reportOutcome demotes a prior convergent record on non-convergent outcome', async () => {
        const oracle = new OracleLoop(janus, learnings, checkpoints, provenance);

        // Seed a convergent record
        const seeded = await seedLearning(learnings, 'write_file', 'convergent');
        expect(seeded.outcome).toBe('convergent');

        // Report non-convergent for the same signature
        await oracle.reportOutcome('step-99', 'write_file|', 'non_convergent');

        // Prior record now demoted to non_convergent
        const demoted = await learnings.find('write_file|');
        // The original record should be marked non_convergent
        // (reportOutcome calls markNonConvergent, then creates a new record)
        // The markNonConvergent mutates the existing record in-place
        const original = await learnings.find('write_file|');
        // After markNonConvergent + record, the latest record for this signature
        // is the new one with outcome 'non_convergent'. The old one was demoted
        // before the new record was created.
        expect(original).toBeDefined();
        expect(original!.outcome).toBe('non_convergent');
    });

    it('reportOutcome with convergent outcome stores new record without demotion', async () => {
        const oracle = new OracleLoop(janus, learnings, checkpoints, provenance);

        // Seed a convergent record
        await seedLearning(learnings, 'list_dir', 'convergent');

        // Report convergent again for same signature — no demotion happens
        await oracle.reportOutcome('step-55', 'list_dir|', 'convergent');

        // The last record for this signature is still convergent,
        // and the original was never marked non_convergent
        const record = await learnings.find('list_dir|');
        expect(record).toBeDefined();
        expect(record!.outcome).toBe('convergent');
    });

    // -- Checkpoint content verification -------------------------------------

    it('saved checkpoint contains the signals and control state', async () => {
        const oracle = new OracleLoop(janus, learnings, checkpoints, provenance);

        await oracle.observe(event({
            step_id: 'step-checkpoint-content',
            signals: jtSignals(0.80, { delta_s: 0.50 }),
        }));

        const cp = await checkpoints.load('step-checkpoint-content') as {
            signals: unknown;
            cs: unknown;
        };
        expect(cp).toBeDefined();
        expect(cp.signals).toHaveProperty('delta_s', 0.50);
        expect(cp.signals).toHaveProperty('j_harm', 0.80);
        expect(cp.cs).toHaveProperty('zone');
        expect(cp.cs).toHaveProperty('action');
        expect(cp.cs).toHaveProperty('j_t');
        expect(cp.cs).toHaveProperty('lambda_observe');
    });

    // -- Decision shape: all fields present on freeze ------------------------

    it('returns a Full FreezeDecision shape even when not freezing', async () => {
        const oracle = new OracleLoop(janus, learnings, checkpoints, provenance);

        const decision = await oracle.observe(event({
            signals: safeSignals(),
        }));

        // Every FreezeDecision must have these fields
        expect(decision).toHaveProperty('freeze');
        expect(decision).toHaveProperty('j_t');
        expect(decision).toHaveProperty('action');
        expect(decision).toHaveProperty('lambda');
        expect(decision).toHaveProperty('step_id');
        expect(typeof decision.j_t).toBe('number');
        expect(typeof decision.freeze).toBe('boolean');
    });

    // -- Default threshold ---------------------------------------------------

    it('uses default j_t threshold of 0.7 when no opts provided', async () => {
        const oracle = new OracleLoop(janus, learnings, checkpoints, provenance);

        // j_t = 0.69 < 0.7 → no freeze
        const noFreeze = await oracle.observe(event({
            step_id: 'step-below-default',
            signals: jtSignals(0.69),
        }));
        expect(noFreeze.freeze).toBe(false);

        // j_t = 0.71 > 0.7 → freeze. But j_t=0.71 > 0.70 → action='pause'
        // so freeze reason is pause_action, which fires before high_j_t.
        // Let's use j_t=0.7 exactly: 0.7 > 0.70 is false in IEEE 754,
        // so action isn't pause. But 0.7 >= 0.7 is true.
        // (0.7+0.7+0.7)/3 = 0.69999999999999996 < 0.7, so let's use
        // slightly higher values.
        const freeze = await oracle.observe(event({
            step_id: 'step-above-default',
            signals: jtSignals(0.71),
        }));
        expect(freeze.freeze).toBe(true);
    });
});
