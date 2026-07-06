// -- Types for AgentSec grant-issuer ---------------------------------------

import type { SemanticSignals, ControlState } from './janus-harness.js';

/**
 * Claims carried by a JWT lease token.
 * The token authorizes the grant-issuer (a user-backed service) to issue
 * `fs:<uid>:write` capabilities to the requesting app for the listed
 * target file uids.
 */
export interface LeaseToken {
    /** JWT ID — unique lease identifier */
    jti: string;
    /** Expiration timestamp (Unix seconds) */
    exp: number;
    /** Issued-at timestamp (Unix seconds) */
    iat: number;
    /** Subject — the app uid that will receive the grants */
    sub: string;
    /** Issuer — the service that minted this token */
    iss: string;
    /** Audience — the grant-issuer service this token is intended for */
    aud: string;
    /**
     * Content hash of the base snapshot the lease was derived from.
     * Allows the issuer to detect whether the files changed between
     * lease issuance and grant application.
     */
    base_hash: string;
    /**
     * Anchor file uid — the file the agent pointed at to request
     * the lease (the semantic entry point).
     */
    anchor: string;
    /**
     * The app uid the grants will be issued to.
     */
    app_uid: string;
    /**
     * Target file uids this lease covers.
     */
    target_uids: string[];
    /** The signed JWT string for cross-service correlation */
    token: string;
}

/**
 * An issued lease, tracked server-side for expiry and revocation.
 */
export interface LeaseRecord {
    lease_id: string;
    app_uid: string;
    target_uids: string[];
    anchor: string;
    base_hashes: string[];
    exp: number;
    created_at: number;
    status: 'active' | 'revoked' | 'expired';
}

/**
 * Request from a service or agent to issue grants for a set of file uids.
 */
export interface GrantRequest {
    app_uid: string;
    target_uids: string[];
    anchor: string;
    base_hashes: string[];
    ttl_seconds: number;
    /**
     * Signed JWT from the requesting agent/application that authenticates
     * this grant request. Must be verifiable by the grant-issuer service.
     */
    token: string;
}

// -- Types for WritebackBroker --------------------------------------------

/**
 * A single file patch submitted as part of a writeback request.
 * The caller provides the uid, the base hash they patched against,
 * and the full new content.
 */
export interface WritebackPatch {
    /** Target FSEntry uid — must be in the lease's target_uids */
    uid: string;
    /**
     * SHA-256 hash of the content the caller patched against.
     * Normalized form: strips 'sha256:' prefix if present, lowercases hex.
     */
    base_hash: string;
    /** New full file content (diff application is a later refinement) */
    content: string;
}

/**
 * An incoming writeback request: a lease JWT + app identity + patches.
 */
export interface WritebackRequest {
    /** The lease JWT (Layer 3) */
    token: string;
    /** The agent app identity */
    app_uid: string;
    /** Patches to apply — each must be covered by the lease */
    patches: WritebackPatch[];
}

/**
 * Reason a single-uid writeback was rejected.
 */
export type WritebackRejectReason =
    | 'expired'
    | 'lease_inactive'
    | 'unleased'
    | 'stale_hash'
    | 'write_failed';

/**
 * Result of a writeback request: lists of applied and rejected patches.
 * Per-patch isolation: rejected patches never block other patches.
 */
export interface WritebackResult {
    lease_id: string;
    applied: { uid: string }[];
    rejected: {
        uid: string;
        reason: WritebackRejectReason;
        detail?: string;
    }[];
}

// -- Provenance event types ------------------------------------------------

export type ProvenanceEventType =
    | 'lease_issued'
    | 'writeback_applied'
    | 'writeback_rejected'
    | 'lease_revoked'
    | 'lease_expired'
    | 'immutable_set'
    | 'oracle_freeze'
    | 'oracle_resume'
    | 'learning_recorded';

export interface ProvenanceEvent {
    type: ProvenanceEventType;
    /** Lease identifier; optional for oracle events that don't track a lease */
    lease_id?: string;
    /** Epoch milliseconds */
    ts: number;
    anchor?: string;
    app_uid?: string;
    uids?: string[];
    /** Map from uid to base content hash at lease-issuance time */
    base_hashes?: Record<string, string>;
    /** Reason for rejection / expiration / freeze */
    reason?: string;
    actor?: string;
}

// -- Oracle loop types ------------------------------------------------------

export interface AgentStreamEvent {
    /** Unique identifier for this reasoning step */
    step_id: string;
    /** The tool call the agent is about to make (undefined for pure-reasoning steps) */
    proposed_tool?: string;
    /** The 4 semantic signals the model emits at this step */
    signals: SemanticSignals;
    /** Free-text summary of the agent's current context */
    context_summary?: string;
}

export type FreezeReason =
    | 'high_j_t'
    | 'pause_action'
    | 'rollback_action'
    | 'seductive_failure'
    | 'chaotic_lambda';

export interface FreezeDecision {
    /** Whether the agent should freeze before the proposed tool call */
    freeze: boolean;
    /** Why the freeze was triggered (undefined when freeze=false) */
    reason?: FreezeReason;
    /** Composite tension signal at decision time */
    j_t: number;
    /** Action the JanusHarness recommended */
    action: ControlState['action'];
    /** Lambda pattern classification at decision time */
    lambda: ControlState['lambda_observe'];
    /** The step_id this decision corresponds to */
    step_id: string;
    /** If seductive-failure match, the LearningRecord id that matched */
    matched_learning_id?: string;
}

export interface LearningRecord {
    /** Unique identifier */
    id: string;
    /** Normalized signature of the action/context */
    action_signature: string;
    /** Whether the trajectory resolved to a convergent or non-convergent outcome */
    outcome: 'convergent' | 'non_convergent';
    /** Epoch milliseconds when the record was created */
    recorded_at: number;
}
// -- Signal calculator types -----------------------------------------------

/**
 * Raw stream event captured by an external sniffer (pi-agent / AG-UI).
 * Richer than AgentStreamEvent — includes tokens, tool_args, and tool_result
 * that the SignalCalculator consumes to DERIVE SemanticSignals deterministically.
 */
export interface StreamEvent {
    /** Unique identifier for this reasoning step */
    step_id: string;
    /** Token delta / reasoning text produced this step */
    tokens?: string;
    /** Tool name the agent is about to call */
    proposed_tool?: string;
    /** Arguments for the proposed tool call */
    tool_args?: Record<string, unknown>;
    /** Result text returned by the tool */
    tool_result?: string;
    /** Free-text summary of the agent's current context */
    context_summary?: string;
}

/**
 * User-defined anchor: the goal, constraints, and non-goals that bound the
 * agent's trajectory. The SignalCalculator compares every StreamEvent against
 * this anchor to derive semantic signals.
 */
export interface Anchor {
    /** The user's goal text */
    goal: string;
    /** Stated constraints the agent must not violate */
    constraints?: string[];
    /** Explicit non-goals — actions the agent must avoid entirely */
    non_goals?: string[];
    /** Extracted intent terms (optional helper for j_drift computation) */
    intent_keywords?: string[];
}
