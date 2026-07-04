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
