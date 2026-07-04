// -- Tests for TailscaleAPIProvisioner ---------------------------------------
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import type { Mock } from 'vitest';

import { TailscaleAPIProvisioner } from './tailscale.js';

// -- Helpers ----------------------------------------------------------------

const TAILNET = 'cyprus-ling.ts.net';
const API_BASE = `https://api.tailscale.com/api/v2/tailnet/${TAILNET}/acl`;

/** Build a realistic Tailscale policy for test fixtures (grants format). */
function makePolicy(
    overrides: Partial<{
        tagOwners: Record<string, string[]>;
        grants: Array<{ src: string[]; dst: string[]; ip: string[] }>;
        ssh: unknown[];
        hosts: Record<string, string>;
    }> = {},
): Record<string, unknown> {
    return {
        tagOwners: { 'tag:existing': ['autogroup:admin'] },
        grants: [
            {
                src: ['tag:existing'],
                dst: ['tag:writeback-broker'],
                ip: ['tcp:443'],
            },
        ],
        ssh: [
            {
                action: 'accept',
                src: ['autogroup:admin'],
                dst: ['tag:existing'],
                users: ['root'],
            },
        ],
        ...overrides,
    };
}

/** Build a mock Response for the Tailscale API. */
function mockResponse(
    body: unknown,
    status = 200,
): Response {
    const json = typeof body === 'string' ? body : JSON.stringify(body);
    return new Response(json, {
        status,
        headers: { 'Content-Type': 'application/json' },
    });
}

// -- Tests ------------------------------------------------------------------

describe('TailscaleAPIProvisioner', () => {
    let provisioner: TailscaleAPIProvisioner;
    let mockFetch: Mock;

    beforeEach(() => {
        process.env.TAILSCALE_API_KEY = 'tskey-test-secret';
        mockFetch = vi.fn();
        vi.stubGlobal('fetch', mockFetch);
        provisioner = new TailscaleAPIProvisioner();
    });

    afterEach(() => {
        vi.unstubAllGlobals();
        delete process.env.TAILSCALE_API_KEY;
    });

    describe('provisionLeaseTag', () => {
        it('adds tagOwners entries and grants rule, POSTs updated policy', async () => {
            const policy = makePolicy();
            mockFetch
                .mockResolvedValueOnce(mockResponse(policy))
                .mockResolvedValueOnce(mockResponse({}));

            await provisioner.provisionLeaseTag('lease-abc');

            // First call: GET current policy
            expect(mockFetch).toHaveBeenNthCalledWith(
                1,
                API_BASE,
                expect.objectContaining({
                    headers: { Authorization: 'Bearer tskey-test-secret' },
                }),
            );

            // Second call: POST updated policy
            const postCall = mockFetch.mock.calls[1];
            expect(postCall[0]).toBe(API_BASE);
            expect(postCall[1]).toMatchObject({
                method: 'POST',
                headers: {
                    Authorization: 'Bearer tskey-test-secret',
                    'Content-Type': 'application/json',
                },
            });
            const postedBody = JSON.parse(postCall[1].body as string);

            // Verify tagOwners — broker tag + new lease tag alongside existing
            expect(postedBody.tagOwners).toEqual({
                'tag:existing': ['autogroup:admin'],
                'tag:writeback-broker': ['autogroup:admin'],
                'tag:agent-lease-abc': ['autogroup:admin'],
            });

            // Verify grants — new rule appended with broker tag as dst
            expect(postedBody.grants).toHaveLength(2);
            expect(postedBody.grants[1]).toEqual({
                src: ['tag:agent-lease-abc'],
                dst: ['tag:writeback-broker'],
                ip: ['*'],
            });

            // Verify existing ssh key preserved verbatim
            expect(postedBody.ssh).toEqual(policy.ssh);
        });

        it('does NOT duplicate broker tag when already present in tagOwners', async () => {
            const policy = makePolicy({
                tagOwners: {
                    'tag:existing': ['autogroup:admin'],
                    'tag:writeback-broker': ['autogroup:admin'],
                },
            });
            mockFetch
                .mockResolvedValueOnce(mockResponse(policy))
                .mockResolvedValueOnce(mockResponse({}));

            await provisioner.provisionLeaseTag('new-lease');

            const postBody = JSON.parse(mockFetch.mock.calls[1][1].body as string);

            // Broker tag appears exactly once
            expect(postBody.tagOwners).toEqual({
                'tag:existing': ['autogroup:admin'],
                'tag:writeback-broker': ['autogroup:admin'],
                'tag:agent-new-lease': ['autogroup:admin'],
            });
        });

        it('is idempotent when tagOwners entries and grants rule already exist', async () => {
            const policy = makePolicy({
                tagOwners: {
                    'tag:existing': ['autogroup:admin'],
                    'tag:agent-dup': ['autogroup:admin'],
                    'tag:writeback-broker': ['autogroup:admin'],
                },
                grants: [
                    {
                        src: ['tag:existing'],
                        dst: ['tag:writeback-broker'],
                        ip: ['tcp:443'],
                    },
                    {
                        src: ['tag:agent-dup'],
                        dst: ['tag:writeback-broker'],
                        ip: ['*'],
                    },
                ],
            });
            mockFetch.mockResolvedValueOnce(mockResponse(policy));

            await provisioner.provisionLeaseTag('dup');

            // Only GET — no POST since tag already fully provisioned
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it('POSTs strict JSON even when GET returned hujson', async () => {
            const hujsonBody = `{
                "tagOwners": {
                    "tag:existing": ["autogroup:admin"],
                },
                "grants": [
                    {
                        "src": ["tag:existing"],
                        "dst": ["tag:writeback-broker"],
                        "ip": ["tcp:443"],
                    },
                ],
                "ssh": [
                    {"action": "accept", "src": ["autogroup:admin"], "dst": ["tag:existing"], "users": ["root"]},
                ],
                // trailing comment
            }`;
            mockFetch
                .mockResolvedValueOnce(mockResponse(hujsonBody))
                .mockResolvedValueOnce(mockResponse({}));

            await provisioner.provisionLeaseTag('strict-json');

            const postCall = mockFetch.mock.calls[1];
            const bodyStr = postCall[1].body as string;

            // Must parse with standard JSON (no trailing commas, no comments)
            expect(() => JSON.parse(bodyStr)).not.toThrow();
            expect(bodyStr).not.toMatch(/,(\s*[}\]])/);
            expect(bodyStr).not.toContain('//');

            const postedBody = JSON.parse(bodyStr);
            expect(postedBody.tagOwners['tag:agent-strict-json']).toEqual([
                'autogroup:admin',
            ]);
        });
    });

    describe('revokeLeaseTag', () => {
        it('removes the matching tagOwners entry and grants rule, preserves broker tag, POSTs update', async () => {
            const policy = makePolicy({
                tagOwners: {
                    'tag:existing': ['autogroup:admin'],
                    'tag:agent-to-revoke': ['autogroup:admin'],
                    'tag:writeback-broker': ['autogroup:admin'],
                },
                grants: [
                    {
                        src: ['tag:existing'],
                        dst: ['tag:writeback-broker'],
                        ip: ['tcp:443'],
                    },
                    {
                        src: ['tag:agent-to-revoke'],
                        dst: ['tag:writeback-broker'],
                        ip: ['*'],
                    },
                ],
            });
            mockFetch
                .mockResolvedValueOnce(mockResponse(policy))
                .mockResolvedValueOnce(mockResponse({}));

            await provisioner.revokeLeaseTag('to-revoke');

            const postBody = JSON.parse(mockFetch.mock.calls[1][1].body as string);

            // tagOwners: revoked tag removed, broker tag preserved
            expect(postBody.tagOwners).toEqual({
                'tag:existing': ['autogroup:admin'],
                'tag:writeback-broker': ['autogroup:admin'],
            });

            // grants: revoked rule removed, existing rule preserved
            expect(postBody.grants).toHaveLength(1);
            expect(postBody.grants[0].src).toEqual(['tag:existing']);

            // ssh preserved
            expect(postBody.ssh).toEqual(policy.ssh);
        });

        it('is idempotent when the tag does not exist', async () => {
            const policy = makePolicy();
            mockFetch.mockResolvedValueOnce(mockResponse(policy));

            await provisioner.revokeLeaseTag('nonexistent');

            // Only GET — no POST
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });
    });

    describe('auth readiness', () => {
        it('throws a clear error when TAILSCALE_API_KEY is missing', () => {
            delete process.env.TAILSCALE_API_KEY;
            process.env.AGENTSEC_TAILSCALE_ENV = '/nonexistent/env/file';

            expect(() => new TailscaleAPIProvisioner()).toThrow(
                'TAILSCALE_API_KEY not set',
            );

            delete process.env.AGENTSEC_TAILSCALE_ENV;
        });
    });

    describe('hujson tolerance', () => {
        it('parses a GET response with trailing commas and comments', async () => {
            const hujsonBody = `{
                "tagOwners": {
                    "tag:existing": ["autogroup:admin"],
                },
                "grants": [
                    {
                        "src": ["tag:existing"],
                        "dst": ["tag:writeback-broker"],
                        "ip": ["tcp:443"],
                    },
                ],
                // trailing comment
            }`;
            mockFetch
                .mockResolvedValueOnce(mockResponse(hujsonBody))
                .mockResolvedValueOnce(mockResponse({}));

            await provisioner.provisionLeaseTag('hujson-lease');

            const postBody = JSON.parse(mockFetch.mock.calls[1][1].body as string);
            expect(postBody.tagOwners['tag:agent-hujson-lease']).toEqual([
                'autogroup:admin',
            ]);
            expect(postBody.grants).toHaveLength(2);
            expect(postBody.grants[1].src).toEqual(['tag:agent-hujson-lease']);
        });
    });

    describe('error handling', () => {
        it('throws a clear error when grants array is missing from response', async () => {
            const badPolicy = { tagOwners: {}, ssh: [] };
            mockFetch.mockResolvedValueOnce(mockResponse(badPolicy));

            await expect(
                provisioner.provisionLeaseTag('no-grants'),
            ).rejects.toThrow('no "grants" array');
        });

        it('preserves additional top-level keys through read-modify-write', async () => {
            const policy = makePolicy({
                hosts: { 'my-node': '100.64.0.1' },
                nodeAttrs: [{ target: ['tag:existing'], attr: ['some-attr'] }],
            });
            mockFetch
                .mockResolvedValueOnce(mockResponse(policy))
                .mockResolvedValueOnce(mockResponse({}));

            await provisioner.provisionLeaseTag('extras-lease');

            const postBody = JSON.parse(mockFetch.mock.calls[1][1].body as string);
            expect(postBody.hosts).toEqual({ 'my-node': '100.64.0.1' });
            expect(postBody.nodeAttrs).toEqual([
                { target: ['tag:existing'], attr: ['some-attr'] },
            ]);
        });
    });
});
