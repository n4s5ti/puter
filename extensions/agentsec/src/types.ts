// -- Types for AgentSec grant-issuer ---------------------------------------

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
