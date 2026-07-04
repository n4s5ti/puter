// -- AgentSec grant-issuer service ------------------------------------------
//
// Three-layer lease design:
//   Layer 1 (Tailscale ACL) — host-level network tag. Stubbed as no-op;
//     real integration uses tailscale-mcp deploy-acl (YawLabs/tailscale-mcp).
//   Layer 2 (Puter ACL)     — fs:<uid>:write grants on Puter's PermissionService.
//   Layer 3 (JWT)           — signed lease token for cross-service correlation.
//
// See: AGENTS.md (ASCII `-` dividers, no ticket refs in code comments)

import crypto from 'node:crypto';

import { extension } from '@heyputer/backend/src/extensions';
import { PuterService } from '@heyputer/backend/src/services/types.js';
import { sign as jwtSign, verify as jwtVerify } from './jwt.js';
import { TailscaleAPIProvisioner } from './tailscale.js';
import type { GrantRequest, LeaseRecord, LeaseToken } from './types.js';
import type { LeaseStore } from './lease-store.js';
import { InMemoryLeaseStore } from './lease-store.js';
import { WritebackBroker } from './writeback.js';

// -- Constants --------------------------------------------------------------

const JWT_SECRET = process.env.AGENTSEC_JWT_SECRET ??
    'dev-secret-not-for-production';

const JWT_ISSUER = 'agentsec-grant-issuer';
const JWT_AUDIENCE = 'agentsec-grant-issuer';

// -- Layer-1: Tailscale ACL provisioner -------------------------------------

export interface TailscaleACLProvisioner {
    provisionLeaseTag(lease_id: string): Promise<void>;
    revokeLeaseTag(lease_id: string): Promise<void>;
}

/**
 * No-op default implementation for Layer 1.
 *
 * TODO: Replace with real tailscale-mcp deploy-acl integration
 * (YawLabs/tailscale-mcp) once the tailnet ACL pipeline is wired.
 */
class NoOpTailscaleACLProvisioner implements TailscaleACLProvisioner {
    async provisionLeaseTag(_lease_id: string): Promise<void> {
        // no-op
    }
    async revokeLeaseTag(_lease_id: string): Promise<void> {
        // no-op
    }
}

// -- Permission service interface (narrow projection) -----------------------
//
// IExtensionServiceInstances types services as [key: string]: unknown,
// so we project the permission service surface this module needs.
// The real PermissionService is always available at runtime.

interface PermissionSvc {
    grantUserAppPermission(
        actor: unknown,
        appUid: string,
        permission: string,
        extra: Record<string, unknown>,
        meta: { reason: string },
    ): Promise<void>;
    revokeUserAppPermission(
        actor: unknown,
        appUid: string,
        permission: string,
        meta: { reason: string },
    ): Promise<void>;
}

// -- Service implementation -------------------------------------------------

export class AgentSecGrantIssuer extends PuterService {
    #leaseStore: LeaseStore;
    #tailscale: TailscaleACLProvisioner | null;
    #jwtSecret: string;

    constructor(
        config?: unknown,
        clients?: unknown,
        stores?: unknown,
        services?: unknown,
        tailscale?: TailscaleACLProvisioner,
        jwtSecret?: string,
        leaseStore?: LeaseStore,
    ) {
        // Boundary: the PuterService parent expects specific config/store/
        // service types that extensions don't import. The runtime values
        // always satisfy the contract.
        super(
            config as never,
            clients as never,
            stores as never,
            services as never,
        );
        this.#tailscale = tailscale ?? null;
        this.#jwtSecret = jwtSecret ?? JWT_SECRET;
        this.#leaseStore = leaseStore ?? new InMemoryLeaseStore();
    }

    /**
     * Ensure the tailscale provisioner is initialized.
     * Deferred so that extension startup does not fail when the env file
     * is missing — the error surfaces only on first lease operation.
     */
    #ensureTailscale(lease_id: string): TailscaleACLProvisioner {
        if (!this.#tailscale) {
            try {
                this.#tailscale = new TailscaleAPIProvisioner();
            } catch (e) {
                throw new Error(
                    `AgentSec: cannot manage tailscale tag for lease ${lease_id} — ${(e as Error).message}`,
                );
            }
        }
        return this.#tailscale;
    }

    /**
     * Issue a three-layer lease for target file uids.
     *
     * The caller (a controller or internal service) provides the user
     * actor — the grant-issuer never derives the actor internally so it
     * remains a pure service without access to a request context.
     *
     * Steps:
     *   1. Validate the incoming JWT.
     *   2. Grant fs:<uid>:write for each target uid via PermissionService.
     *   3. Stub Layer-1 tailscale tag (provisionLeaseTag).
     *   4. Persist the lease via the configured LeaseStore.
     *   5. Sign and return a LeaseToken carrying the signed JWT.
     */
    async issueLease(
        actor: { user?: { id?: number; uuid?: string } },
        req: GrantRequest,
    ): Promise<LeaseToken> {
        // -- Validate incoming JWT ------------------------------------
        const decoded = jwtVerify(req.token, this.#jwtSecret, JWT_AUDIENCE);

        // Confirm the decoded claims match the request
        const decAppUid = decoded.app_uid as string | undefined;
        if (decAppUid !== req.app_uid) {
            throw new Error(
                `JWT app_uid mismatch: token says "${decAppUid}", request says "${req.app_uid}"`,
            );
        }
        const decAnchor = decoded.anchor as string | undefined;
        if (decAnchor !== req.anchor) {
            throw new Error(
                `JWT anchor mismatch: token says "${decAnchor}", request says "${req.anchor}"`,
            );
        }
        const decTargets = decoded.target_uids as string[] | undefined;
        if (
            !decTargets ||
            decTargets.length !== req.target_uids.length ||
            !decTargets.every((u) => req.target_uids.includes(u))
        ) {
            throw new Error(
                'JWT target_uids mismatch between token and request',
            );
        }

        // -- Generate lease id ----------------------------------------
        const lease_id = crypto.randomUUID();

        // -- Layer 2: grant fs:<uid>:write for each target -------------
        // Unchecked cast: extension services are typed as [key: string]:
        // unknown; the permission service is a core service always present.
        const permSvc = this.services.permission as unknown as PermissionSvc;

        for (const uid of req.target_uids) {
            await permSvc.grantUserAppPermission(
                actor,
                req.app_uid,
                `fs:${uid}:write`,
                {},
                { reason: `agentsec lease ${lease_id}` },
            );
        }

        // -- Layer 1: stub --------------------------------------------
        await this.#ensureTailscale(lease_id).provisionLeaseTag(lease_id);

        // -- Record the lease -----------------------------------------
        const now = Math.floor(Date.now() / 1000);
        const record: LeaseRecord = {
            lease_id,
            app_uid: req.app_uid,
            target_uids: [...req.target_uids],
            anchor: req.anchor,
            base_hashes: [...req.base_hashes],
            exp: now + req.ttl_seconds,
            created_at: now,
            status: 'active',
        };
        await this.#leaseStore.create(record);

        // -- Layer 3: sign the correlation token ----------------------
        const tokenPayload: Record<string, unknown> = {
            jti: lease_id,
            exp: record.exp,
            iat: now,
            sub: req.app_uid,
            iss: JWT_ISSUER,
            aud: JWT_AUDIENCE,
            base_hash: req.base_hashes[0] ?? '',
            anchor: req.anchor,
            app_uid: req.app_uid,
            target_uids: req.target_uids,
        };

        const signedToken = jwtSign(tokenPayload, this.#jwtSecret);

        return {
            token: signedToken,
            jti: lease_id,
            exp: record.exp,
            iat: now,
            sub: req.app_uid,
            iss: JWT_ISSUER,
            aud: JWT_AUDIENCE,
            base_hash: req.base_hashes[0] ?? '',
            anchor: req.anchor,
            app_uid: req.app_uid,
            target_uids: [...req.target_uids],
        };
    }

    /**
     * Revoke all grants for a lease and mark the record.
     *
     * After revoking the fs: grants, best-effort tries to set
     * FSEntry.immutable on each target uid as defense-in-depth.
     * The immutable flip is non-blocking — revocation completes
     * regardless of any error from the fsEntry store.
     */
    async revokeLease(
        actor: { user?: { id?: number; uuid?: string } },
        lease_id: string,
    ): Promise<void> {
        const record = await this.#leaseStore.get(lease_id);
        if (!record) {
            throw new Error(`lease not found: ${lease_id}`);
        }
        if (record.status !== 'active') {
            return; // already revoked or expired -- idempotent
        }

        // Unchecked cast: same rationale as issueLease.
        const permSvc = this.services.permission as unknown as PermissionSvc;

        for (const uid of record.target_uids) {
            await permSvc.revokeUserAppPermission(
                actor,
                record.app_uid,
                `fs:${uid}:write`,
                { reason: 'lease expired' },
            );
        }

        await this.#ensureTailscale(lease_id).revokeLeaseTag(lease_id);

        await this.#leaseStore.setRevoked(lease_id, 'expired');

        // -- Best-effort immutable defense-in-depth --------------------
        // FSEntry.immutable hardens the lease boundary by preventing
        // writes through any path once the lease is revoked.
        // The grant revocation is the primary enforcement; immutable is
        // a belt-and-suspenders measure. Errors never block revocation.
        try {
            const fsEntryStore = this.stores?.fsEntry as unknown as
                { updateEntry: (uid: string, patch: { immutable?: boolean }) => Promise<unknown> }
                | undefined;
            if (fsEntryStore?.updateEntry) {
                for (const uid of record.target_uids) {
                    await fsEntryStore.updateEntry(uid, { immutable: true });
                }
            } else {
                console.warn(
                    `[agentsec] immutable defense-in-depth skipped ` +
                    `for lease ${lease_id} — fsEntry store not reachable`,
                );
            }
        } catch (immErr) {
            console.warn(
                `[agentsec] immutable defense-in-depth failed ` +
                `for lease ${lease_id}: ${(immErr as Error).message}`,
            );
        }
    }

    /**
     * Sweep all active leases that have passed their expiration and
     * revoke them. Returns the number of leases revoked.
     */
    async revokeExpired(
        actor: { user?: { id?: number; uuid?: string } },
    ): Promise<number> {
        const now = Math.floor(Date.now() / 1000);
        const expired: string[] = [];
        const all = await this.#leaseStore.listAll();

        for (const record of all) {
            const lease_id = record.lease_id;
            if (record.status === 'active' && record.exp <= now) {
                expired.push(lease_id);
            }
        }

        for (const lease_id of expired) {
            await this.revokeLease(actor, lease_id);
        }

        return expired.length;
    }
}

// -- Registration -----------------------------------------------------------

extension.registerService('agentsec-grant-issuer', AgentSecGrantIssuer);

export { WritebackBroker };
