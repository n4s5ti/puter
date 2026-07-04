// -- Tailscale ACL provisioner via HTTP API ---------------------------------
//
// Layer 1: manages tailnet ACL rules so tagged agent nodes can reach the
// writeback broker. Read-modify-write against the Tailscale HTTP API.
//
// Auth: reads TAILSCALE_API_KEY from ~/.config/agentsec/tailscale.env
// (or AGENTSEC_TAILSCALE_ENV override). File must be mode 0600.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import type { TailscaleACLProvisioner } from './index.js';

// -- Types ------------------------------------------------------------------

/** The ACL policy shape returned by the Tailscale API. */
interface TailscalePolicy {
    acls: TailscaleACLRule[];
    [key: string]: unknown;
}

interface TailscaleACLRule {
    action: string;
    src: string[];
    dst: string[];
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
    readonly #brokerHost: string;

    constructor() {
        // Read env file
        const envPath = process.env.AGENTSEC_TAILSCALE_ENV
            || path.join(os.homedir(), '.config', 'agentsec', 'tailscale.env');
        const fileEnv = parseEnvFile(envPath);

        this.#apiKey = process.env.TAILSCALE_API_KEY || fileEnv.TAILSCALE_API_KEY || '';
        this.#tailnet = process.env.TAILSCALE_TAILNET
            || fileEnv.TAILSCALE_TAILNET
            || 'cyprus-ling.ts.net';
        this.#brokerHost = process.env.AGENTSEC_BROKER_HOST
            || fileEnv.AGENTSEC_BROKER_HOST
            || 'writeback-broker';

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

    async #fetchACLs(): Promise<TailscalePolicy> {
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

        if (!Array.isArray(policy.acls)) {
            throw new Error('AgentSec: Tailscale ACL response has no "acls" array');
        }

        return { acls: policy.acls as TailscaleACLRule[], ...policy };
    }

    async #applyACLs(policy: TailscalePolicy): Promise<void> {
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
        const rule: TailscaleACLRule = {
            action: 'accept',
            src: [tag],
            dst: [`${this.#brokerHost}:443`],
        };

        const policy = await this.#fetchACLs();

        // Idempotent: skip if a rule for this exact src already exists
        if (policy.acls.some((r) => r.src.some((s) => s === tag))) {
            return;
        }

        policy.acls.push(rule);
        await this.#applyACLs(policy);
    }

    async revokeLeaseTag(lease_id: string): Promise<void> {
        const tag = `tag:agent-${lease_id}`;

        const policy = await this.#fetchACLs();

        const before = policy.acls.length;
        policy.acls = policy.acls.filter((r) => !r.src.some((s) => s === tag));

        // Idempotent: no-op if nothing removed
        if (policy.acls.length === before) {
            return;
        }

        await this.#applyACLs(policy);
    }
}
