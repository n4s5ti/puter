// -- AgentSec WritebackBroker -----------------------------------------------
//
// Symmetric counterpart to the grant-issuer: validates that a patch set
// matches an active lease (JWT valid, lease active, all target uids in
// the lease's target_uids, content hashes match the lease's base snapshot),
// then applies only the valid writes.
//
// Per-patch isolation: a single stale/unleased/failed patch never blocks
// other patches in the same request.
//
// DI pattern: LeaseStore + jwtVerify fn + fsService shim injected via
// constructor. Tests inject mocks; production wiring connects through
// the Puter extension service layer.

import crypto from 'node:crypto';
import type { LeaseStore } from './lease-store.js';
import type { WritebackRequest, WritebackPatch, WritebackResult, ProvenanceEvent } from './types.js';
import type { ProvenanceSink } from './provenance.js';
import { NoOpProvenanceSink } from './provenance.js';

// -- Types ------------------------------------------------------------------

/**
 * JWT verification function signature.
 * Takes (token, secret, expectedAudience) and returns decoded claims on
 * success, or throws on invalid/expired/mismatched-audience.
 */
export type JwtVerifyFn = (
    token: string,
    secret: string,
    expectedAud: string,
) => Record<string, unknown>;

/**
 * Narrow projection of the FSService surface this module needs (DI).
 *
 * Production wiring must provide a concrete adapter wrapping Puter's
 * FSService + FSEntry store. The WritebackBroker rejects ALL writes
 * with 'stale_hash' when no fsService is configured — it never silently
 * accepts without verification.
 *
 * Runtime gap: Puter's FSService (src/backend/services/fs/FSService.ts)
 * exposes `write(path, ...)` and the FSEntry store exposes `readContent`.
 * A concrete adapter wrapping `services.fs` + the fsEntry store is needed
 * before use in production. Tests inject a direct mock.
 */
export interface FsServiceShim {
    /** Read current content of an FSEntry by uid. Returns content as string or Buffer. */
    readContent(uid: string): Promise<string | Buffer>;
    /** Write new content to an FSEntry by uid. */
    write(uid: string, content: string): Promise<void>;
}

// -- Constants --------------------------------------------------------------

const JWT_ISSUER = 'agentsec-grant-issuer';
const JWT_AUDIENCE = 'agentsec-grant-issuer';

// -- Hash normalization -----------------------------------------------------

/**
 * Normalize a content hash string.
 * Accepts 'sha256:<hex>' or bare '<hex>'. Returns lowercase hex only.
 * Throws if the hex portion is not valid hex.
 */
export const normalizeHash = (hash: string): string => {
    let hex = hash;
    if (hex.startsWith('sha256:')) {
        hex = hex.slice(7);
    }
    hex = hex.toLowerCase();
    // Validate it's proper hex
    if (!/^[0-9a-f]+$/.test(hex)) {
        throw new Error(`Invalid hash: "${hash}" is not valid hex`);
    }
    return hex;
};

// -- WritebackBroker --------------------------------------------------------

export class WritebackBroker {
    readonly #leaseStore: LeaseStore;
    readonly #jwtVerify: JwtVerifyFn;
    readonly #jwtSecret: string;
    readonly #jwtAudience: string;
    readonly #fsService: FsServiceShim | null;
    readonly #provenance: ProvenanceSink;

    constructor(
        leaseStore: LeaseStore,
        jwtVerify: JwtVerifyFn,
        jwtSecret: string,
        jwtAudience: string = JWT_AUDIENCE,
        fsService: FsServiceShim | null = null,
        provenance?: ProvenanceSink,
    ) {
        this.#leaseStore = leaseStore;
        this.#jwtVerify = jwtVerify;
        this.#jwtSecret = jwtSecret;
        this.#jwtAudience = jwtAudience;
        this.#fsService = fsService;
        this.#provenance = provenance ?? new NoOpProvenanceSink();
    }

    /**
     * Apply a validated writeback: verify JWT -> check lease -> per-patch
     * uid-in-lease + hash-match -> write.
     *
     * Returns a WritebackResult with applied[] and rejected[] lists.
     * Lease-level failures (expired JWT, inactive lease) reject ALL patches.
     * Per-patch failures are isolated and never block other patches.
     */
    async applyWriteback(req: WritebackRequest): Promise<WritebackResult> {
        const applied: { uid: string }[] = [];
        const rejected: { uid: string; reason: WritebackResult['rejected'][number]['reason']; detail?: string }[] = [];

        // -- Step 1: Verify the JWT -----------------------------------------
        let decoded: Record<string, unknown>;
        try {
            decoded = this.#jwtVerify(req.token, this.#jwtSecret, this.#jwtAudience);
        } catch {
            // Token invalid or expired — reject all patches
            for (const patch of req.patches) {
                rejected.push({
                    uid: patch.uid,
                    reason: 'expired',
                    detail: 'JWT is invalid or expired',
                });
            }
            return { lease_id: '', applied, rejected };
        }

        const leaseId = (decoded.jti as string) ?? '';
        if (!leaseId) {
            for (const patch of req.patches) {
                rejected.push({
                    uid: patch.uid,
                    reason: 'expired',
                    detail: 'JWT missing jti (lease_id)',
                });
            }
            return { lease_id: '', applied, rejected };
        }

        // Validate app_uid matches
        const tokenAppUid = decoded.app_uid as string | undefined;
        if (tokenAppUid !== req.app_uid) {
            for (const patch of req.patches) {
                rejected.push({
                    uid: patch.uid,
                    reason: 'expired',
                    detail: `JWT app_uid "${tokenAppUid}" does not match request app_uid "${req.app_uid}"`,
                });
            }
            return { lease_id: '', applied, rejected };
        }

        // -- Step 2: Look up and validate the lease record ------------------
        const record = await this.#leaseStore.get(leaseId);
        if (!record || record.status !== 'active') {
            const reason: 'lease_inactive' = 'lease_inactive';
            const detail = !record
                ? `Lease "${leaseId}" not found`
                : `Lease "${leaseId}" has status "${record.status}" (must be "active")`;
            for (const patch of req.patches) {
                rejected.push({ uid: patch.uid, reason, detail });
            }
            return { lease_id: leaseId, applied, rejected };
        }

        // -- Step 3: Per-patch validation and application --------------------
        //
        // Build a quick lookup of the lease's base_hashes by uid.
        // LeaseRecord.base_hashes is indexed parallel to target_uids.
        const baseHashByUid = new Map<string, string>();
        for (let i = 0; i < record.target_uids.length; i++) {
            const uid = record.target_uids[i];
            const baseHash = record.base_hashes[i] ?? '';
            baseHashByUid.set(uid, normalizeHash(baseHash));
        }

        for (const patch of req.patches) {
            // -- Step 3a: uid must be in lease target_uids ------------------
            if (!baseHashByUid.has(patch.uid)) {
                rejected.push({
                    uid: patch.uid,
                    reason: 'unleased',
                    detail: `uid "${patch.uid}" is not in lease target_uids`,
                });
                continue;
            }

            // -- Step 3b: validate content hash -----------------------------
            const patchHash = normalizeHash(patch.base_hash);
            const leaseHash = baseHashByUid.get(patch.uid)!;
            let currentHash: string | null = null;

            if (this.#fsService) {
                try {
                    const currentContent = await this.#fsService.readContent(patch.uid);
                    currentHash = crypto
                        .createHash('sha256')
                        .update(Buffer.from(currentContent))
                        .digest()
                        .toString('hex');
                } catch (err) {
                    rejected.push({
                        uid: patch.uid,
                        reason: 'stale_hash',
                        detail: `failed to read current content: ${(err as Error).message}`,
                    });
                    continue;
                }
            } else {
                // No fsService configured — cannot verify content hashes.
                // Reject for safety: production must always provide a shim.
                rejected.push({
                    uid: patch.uid,
                    reason: 'stale_hash',
                    detail: 'no fsService configured — cannot read current content to verify hash',
                });
                continue;
            }

            // Dual hash check: current content must match BOTH the patch's
            // claimed base_hash AND the lease's recorded base_hash for this uid.
            //   - currentHash !== patchHash  → caller patched against wrong content
            //   - currentHash !== leaseHash   → file changed since lease was issued
            // If either mismatches, the write is rejected as stale.
            if (currentHash !== patchHash || currentHash !== leaseHash) {
                let detail: string;
                if (currentHash !== patchHash && currentHash !== leaseHash) {
                    detail = `content hash "${currentHash}" matches neither patch base_hash "${patchHash}" nor lease base_hash "${leaseHash}" for uid "${patch.uid}"`;
                } else if (currentHash !== patchHash) {
                    detail = `content hash "${currentHash}" does not match patch base_hash "${patchHash}" for uid "${patch.uid}"`;
                } else {
                    detail = `content hash "${currentHash}" does not match lease base_hash "${leaseHash}" for uid "${patch.uid}" — file changed since lease issuance`;
                }
                rejected.push({
                    uid: patch.uid,
                    reason: 'stale_hash',
                    detail,
                });
                continue;
            }

            // -- Step 3c: apply the write -----------------------------------
            if (this.#fsService) {
                try {
                    await this.#fsService.write(patch.uid, patch.content);
                    applied.push({ uid: patch.uid });
                } catch (err) {
                    rejected.push({
                        uid: patch.uid,
                        reason: 'write_failed',
                        detail: (err as Error).message,
                    });
                }
            } else {
                // Unreachable: the earlier fsService check rejects all patches
                // when no fsService is configured. This branch exists for
                // type-safety if the control flow changes.
                rejected.push({
                    uid: patch.uid,
                    reason: 'write_failed',
                    detail: 'no fsService configured',
                });
            }
        }

        // -- Best-effort provenance: writeback events ------------------------
        this.#emitProvenanceEvents(leaseId, req.app_uid, applied, rejected);

        return { lease_id: leaseId, applied, rejected };
    }

    /**
     * Emit provenance events for writeback results.
     * Best-effort: failures never block the writeback lifecycle.
     */
    #emitProvenanceEvents(
        leaseId: string,
        appUid: string,
        applied: { uid: string }[],
        rejected: { uid: string; reason: string; detail?: string }[],
    ): void {
        const ts = Date.now();

        for (const { uid } of applied) {
            this.#emitOne({
                type: 'writeback_applied',
                lease_id: leaseId,
                ts,
                app_uid: appUid,
                uids: [uid],
            });
        }

        for (const { uid, reason } of rejected) {
            this.#emitOne({
                type: 'writeback_rejected',
                lease_id: leaseId,
                ts,
                app_uid: appUid,
                uids: [uid],
                reason,
            });
        }
    }

    /**
     * Best-effort single provenance emission.
     * Never throws — provenance failure MUST NOT block lifecycle operations.
     */
    #emitOne(event: ProvenanceEvent): void {
        this.#provenance.emit(event).catch((err: Error) => {
            console.warn(
                `[agentsec] provenance emit failed for ${event.type}:${event.lease_id} — ${err.message}`,
            );
        });
    }
}
