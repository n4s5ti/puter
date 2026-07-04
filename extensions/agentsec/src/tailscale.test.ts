// -- Tests for TailscaleAPIProvisioner ---------------------------------------
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import type { Mock } from 'vitest';

import { TailscaleAPIProvisioner } from './tailscale.js';

// -- Helpers ----------------------------------------------------------------

const TAILNET = 'cyprus-ling.ts.net';
const API_BASE = `https://api.tailscale.com/api/v2/tailnet/${TAILNET}/acl`;

/** Build a minimal ACL policy for test fixtures. */
function makePolicy(
    overrides: Partial<{ acls: unknown[] }> = {},
): Record<string, unknown> {
    return {
        acls: [
            { action: 'accept', src: ['tag:existing'], dst: ['existing:443'] },
        ],
        tagOwners: { 'tag:existing': ['autogroup:admin'] },
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
        it('appends a new tag rule and POSTs the updated policy', async () => {
            const policy = makePolicy();
            mockFetch
                .mockResolvedValueOnce(mockResponse(policy))
                .mockResolvedValueOnce(mockResponse({}));

            await provisioner.provisionLeaseTag('lease-abc');

            // First call: GET current ACL
            expect(mockFetch).toHaveBeenNthCalledWith(
                1,
                API_BASE,
                expect.objectContaining({
                    headers: { Authorization: 'Bearer tskey-test-secret' },
                }),
            );

            // Second call: POST updated ACL with new rule appended
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
            expect(postedBody.acls).toHaveLength(2);
            expect(postedBody.acls[1]).toEqual({
                action: 'accept',
                src: ['tag:agent-lease-abc'],
                dst: ['writeback-broker:443'],
            });
            // Original rule and tagOwners preserved
            expect(postedBody.tagOwners).toEqual(policy.tagOwners);
        });

        it('is idempotent when the tag rule already exists', async () => {
            const policy = makePolicy({
                acls: [
                    { action: 'accept', src: ['tag:existing'], dst: ['existing:443'] },
                    { action: 'accept', src: ['tag:agent-dup'], dst: ['writeback-broker:443'] },
                ],
            });
            mockFetch.mockResolvedValueOnce(mockResponse(policy));

            await provisioner.provisionLeaseTag('dup');

            // Only one fetch call (GET) — no POST since rule already exists
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });
    });

    describe('revokeLeaseTag', () => {
        it('removes the matching tag rule and POSTs the updated policy', async () => {
            const policy = makePolicy({
                acls: [
                    { action: 'accept', src: ['tag:existing'], dst: ['existing:443'] },
                    {
                        action: 'accept',
                        src: ['tag:agent-to-revoke'],
                        dst: ['writeback-broker:443'],
                    },
                ],
            });
            mockFetch
                .mockResolvedValueOnce(mockResponse(policy))
                .mockResolvedValueOnce(mockResponse({}));

            await provisioner.revokeLeaseTag('to-revoke');

            const postBody = JSON.parse(mockFetch.mock.calls[1][1].body as string);
            expect(postBody.acls).toHaveLength(1);
            expect(postBody.acls[0].src).toEqual(['tag:existing']);
        });

        it('is idempotent when the tag rule does not exist', async () => {
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

            expect(() => new TailscaleAPIProvisioner()).toThrow(
                'TAILSCALE_API_KEY not set',
            );
        });
    });

    describe('hujson tolerance', () => {
        it('parses a GET response with trailing commas and dashes', async () => {
            const hujsonBody = `{
                "acls": [
                    {"action": "accept", "src": ["tag:existing"], "dst": ["existing:443"]},
                ],
                "tagOwners": {
                    "tag:existing": ["autogroup:admin"],
                },
                // trailing comment
            }`;
            mockFetch
                .mockResolvedValueOnce(mockResponse(hujsonBody))
                .mockResolvedValueOnce(mockResponse({}));

            await provisioner.provisionLeaseTag('hujson-lease');

            const postBody = JSON.parse(mockFetch.mock.calls[1][1].body as string);
            expect(postBody.acls).toHaveLength(2);
            expect(postBody.acls[1].src).toEqual(['tag:agent-hujson-lease']);
        });
    });
});
