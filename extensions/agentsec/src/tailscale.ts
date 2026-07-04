// -- Tailscale ACL provisioner via HTTP API ---------------------------------
//
// Layer 1: manages tailnet ACL rules so tagged agent nodes can reach the
// writeback broker. Read-modify-write against the Tailscale HTTP API.
//
// Auth: reads TAILSCALE_API_KEY from ~/.config/agentsec/tailscale.env
// (or AGENTSEC_TAILSCALE_ENV override). File must be mode 0600.
//
// TODO: Add auth-key minting (POST /api/v2/tailnet/{tailnet}/keys) so
// provisionLeaseTag can also create an ephemeral auth key scoped to the
// newly provisioned tag. This is a follow-up; for now the caller must
// create auth keys out of band.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import type { TailscaleACLProvisioner } from './index.js';

// -- Types ------------------------------------------------------------------

/** The Tailscale policy shape returned by the API (grants format). */
interface TailscalePolicy {
    tagOwners: Record<string, string[]>;
    grants: TailscaleGrantRule[];
    [key: string]: unknown;
}

/** A single grants-format rule (no action/proto — uses ip instead). */
interface TailscaleGrantRule {
    src: string[];
    dst: string[];
    ip: string[];
}

// -- Helpers ----------------------------------------------------------------

/** Parse an env file (KEY=VALUE lines), returning a record. */
function parseEnvFile(envPath: string): Record<string, string> {
    if (!fs.existsSync(envPath)) return {};

    const stat = fs.statSync(envPath);
    if (stat.mode & 0o077) {
        console.warn(
            `AgentSec: env file ${envPath} has loose permissions ${stat.mode.toString(8)} — expected 0600`,
        );
    }

    const text = fs.readFileSync(envPath, 'utf-8');
    const result: Record<string, string> = {};
    for (const line of text.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx === -1) continue;
        const k = trimmed.slice(0, eqIdx).trim();
        const v = trimmed.slice(eqIdx + 1).trim();
        if (k) result[k] = v;
    }
    return result;
}

/** Strip trailing commas and trailing dashes from JSON (hujson tolerance). */
function stripHujson(text: string): string {
    // Strip hujson line-noise comments FIRST so trailing commas become visible
    let cleaned = text.replace(/\/\/[^\n]*/g, '');
    // Remove trailing commas before ] or }
    cleaned = cleaned.replace(/,(\s*[\]}])/g, '$1');
    return cleaned;
}

// -- Implementation ---------------------------------------------------------

export class TailscaleAPIProvisioner implements TailscaleACLProvisioner {
    readonly #apiKey: string;
    readonly #tailnet: string;
    readonly #brokerTag: string;
    readonly #brokerPorts: string[];

    constructor() {
        // Read env file
        const envPath = process.env.AGENTSEC_TAILSCALE_ENV
            || path.join(os.homedir(), '.config', 'agentsec', 'tailscale.env');
        const fileEnv = parseEnvFile(envPath);

        this.#apiKey = process.env.TAILSCALE_API_KEY || fileEnv.TAILSCALE_API_KEY || '';
        this.#tailnet = process.env.TAILSCALE_TAILNET
            || fileEnv.TAILSCALE_TAILNET
            || 'cyprus-ling.ts.net';
        this.#brokerTag = process.env.AGENTSEC_BROKER_TAG
            || fileEnv.AGENTSEC_BROKER_TAG
            || 'tag:writeback-broker';

        const brokerPortsRaw = process.env.AGENTSEC_BROKER_PORTS
            || fileEnv.AGENTSEC_BROKER_PORTS
            || '*';
        const ports = brokerPortsRaw.split(',').map(s => s.trim()).filter(Boolean);
        this.#brokerPorts = ports.length > 0 ? ports : ['*'];

        if (!this.#apiKey) {
            throw new Error(
                'AgentSec: TAILSCALE_API_KEY not set — ' +
                `create ${envPath} with TAILSCALE_API_KEY=tskey-...`,
            );
        }
    }

    #apiBase(): string {
        return `https://api.tailscale.com/api/v2/tailnet/${this.#tailnet}`;
    }

    async #fetchPolicy(): Promise<TailscalePolicy> {
        const url = `${this.#apiBase()}/acl`;
        const res = await fetch(url, {
            headers: { Authorization: `Bearer ${this.#apiKey}` },
        });

        if (!res.ok) {
            const body = await res.text().catch(() => '(no body)');
            throw new Error(
                `AgentSec: Tailscale GET /acl returned ${res.status}: ${body.slice(0, 500)}`,
            );
        }

        const raw = await res.text();
        const cleaned = stripHujson(raw);

        let parsed: unknown;
        try {
            parsed = JSON.parse(cleaned);
        } catch {
            throw new Error(
                `AgentSec: failed to parse Tailscale ACL JSON (body excerpt): ${raw.slice(0, 300)}`,
            );
        }

        if (typeof parsed !== 'object' || parsed === null) {
            throw new Error('AgentSec: Tailscale ACL response is not an object');
        }

        const policy = parsed as Record<string, unknown>;

        if (!Array.isArray(policy.grants)) {
            throw new Error('AgentSec: Tailscale ACL response has no "grants" array');
        }

        // Normalise missing tagOwners to empty object
        if (typeof policy.tagOwners !== 'object' || policy.tagOwners === null) {
            policy.tagOwners = {};
        }

        return {
            tagOwners: policy.tagOwners as Record<string, string[]>,
            grants: policy.grants as TailscaleGrantRule[],
            ...policy,
        };
    }

    async #applyPolicy(policy: TailscalePolicy): Promise<void> {
        const url = `${this.#apiBase()}/acl`;
        const res = await fetch(url, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${this.#apiKey}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(policy),
        });

        if (!res.ok) {
            const body = await res.text().catch(() => '(no body)');
            throw new Error(
                `AgentSec: Tailscale POST /acl returned ${res.status}: ${body.slice(0, 500)}`,
            );
        }
    }

    async provisionLeaseTag(lease_id: string): Promise<void> {
        const tag = `tag:agent-${lease_id}`;
        const policy = await this.#fetchPolicy();
        let changed = false;

        // 1. Ensure the broker tag exists in tagOwners so a node can carry it
        //    (persistent infrastructure shared across all leases)
        if (!(this.#brokerTag in policy.tagOwners)) {
            policy.tagOwners[this.#brokerTag] = ['autogroup:admin'];
            changed = true;
        }

        // 2. Ensure the lease tag exists in tagOwners (idempotent)
        if (!policy.tagOwners[tag]) {
            policy.tagOwners[tag] = ['autogroup:admin'];
            changed = true;
        }

        // 3. Append grants rule if not already present (idempotent)
        if (!policy.grants.some(r => r.src.some(s => s === tag))) {
            policy.grants.push({
                src: [tag],
                dst: [this.#brokerTag],
                ip: [...this.#brokerPorts],
            });
            changed = true;
        }

        if (changed) {
            await this.#applyPolicy(policy);
        }
    }

    async revokeLeaseTag(lease_id: string): Promise<void> {
        const tag = `tag:agent-${lease_id}`;
        const policy = await this.#fetchPolicy();

        let changed = false;

        // Remove lease tag from tagOwners
        if (tag in policy.tagOwners) {
            delete policy.tagOwners[tag];
            changed = true;
        }

        // Remove lease grant from grants
        const before = policy.grants.length;
        policy.grants = policy.grants.filter(r => !r.src.some(s => s === tag));
        if (policy.grants.length !== before) {
            changed = true;
        }

        // The broker tag is persistent infrastructure shared across all leases;
        // we never remove it from tagOwners here.

        if (changed) {
            await this.#applyPolicy(policy);
        }
    }
}
