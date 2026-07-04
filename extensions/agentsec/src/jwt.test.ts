// -- Tests for AgentSec JWT module -----------------------------------------
import { describe, expect, it } from 'vitest';
import { sign, verify } from './jwt';

const SECRET = 'test-secret-key-not-for-production';
const AUDIENCE = 'agentsec-grant-issuer';

describe('jwt', () => {
    describe('sign / verify round-trip', () => {
        it('signs and verifies a valid token', () => {
            const payload = {
                jti: 'lease-001',
                sub: 'app-abc-123',
                iss: 'agent-oracle',
                aud: AUDIENCE,
                app_uid: 'app-abc-123',
                anchor: 'file-root-uid',
                target_uids: ['file-a-uid', 'file-b-uid'],
                base_hash: 'abc123def456',
                exp: Math.floor(Date.now() / 1000) + 3600,
            };

            const token = sign(payload, SECRET);
            expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

            const decoded = verify(token, SECRET, AUDIENCE);
            expect(decoded.jti).toBe('lease-001');
            expect(decoded.sub).toBe('app-abc-123');
            expect(decoded.iss).toBe('agent-oracle');
            expect(decoded.aud).toBe(AUDIENCE);
            expect(decoded.app_uid).toBe('app-abc-123');
            expect(decoded.anchor).toBe('file-root-uid');
            expect(decoded.target_uids).toEqual(['file-a-uid', 'file-b-uid']);
            expect(decoded.base_hash).toBe('abc123def456');
        });

        it('auto-sets iat when absent', () => {
            const payload = {
                jti: 'lease-002',
                sub: 'app-xyz',
                iss: 'agent-oracle',
                aud: AUDIENCE,
                app_uid: 'app-xyz',
                anchor: 'file-uid',
                target_uids: [],
                base_hash: 'hash',
                exp: Math.floor(Date.now() / 1000) + 3600,
            };

            const token = sign(payload, SECRET);
            const decoded = verify(token, SECRET, AUDIENCE);
            expect(decoded.iat).toBeTypeOf('number');
            expect(Number(decoded.iat)).toBeLessThanOrEqual(Math.floor(Date.now() / 1000));
        });

        it('preserves iat when provided', () => {
            const iat = Math.floor(Date.now() / 1000) - 100;
            const payload = {
                jti: 'lease-003',
                sub: 'app-xyz',
                iss: 'agent-oracle',
                aud: AUDIENCE,
                app_uid: 'app-xyz',
                anchor: 'file-uid',
                target_uids: [],
                base_hash: 'hash',
                exp: Math.floor(Date.now() / 1000) + 3600,
                iat,
            };

            const token = sign(payload, SECRET);
            const decoded = verify(token, SECRET, AUDIENCE);
            expect(Number(decoded.iat)).toBe(iat);
        });
    });

    describe('expired token rejection', () => {
        it('rejects a token with past exp', () => {
            const payload = {
                jti: 'lease-expired',
                sub: 'app-exp',
                iss: 'agent-oracle',
                aud: AUDIENCE,
                app_uid: 'app-exp',
                anchor: 'file-uid',
                target_uids: [],
                base_hash: 'hash',
                exp: Math.floor(Date.now() / 1000) - 10,
            };

            const token = sign(payload, SECRET);
            expect(() => verify(token, SECRET, AUDIENCE)).toThrow('Token has expired');
        });
    });

    describe('wrong audience rejection', () => {
        it('rejects a token with mismatched aud', () => {
            const payload = {
                jti: 'lease-wrong-aud',
                sub: 'app-aud',
                iss: 'agent-oracle',
                aud: 'some-other-service',
                app_uid: 'app-aud',
                anchor: 'file-uid',
                target_uids: [],
                base_hash: 'hash',
                exp: Math.floor(Date.now() / 1000) + 3600,
            };

            const token = sign(payload, SECRET);
            expect(() => verify(token, SECRET, AUDIENCE)).toThrow('Token audience mismatch');
        });
    });

    describe('tamper detection', () => {
        it('rejects a token with modified payload', () => {
            const payload = {
                jti: 'lease-tamper',
                sub: 'app-tamper',
                iss: 'agent-oracle',
                aud: AUDIENCE,
                app_uid: 'app-tamper',
                anchor: 'file-uid',
                target_uids: [],
                base_hash: 'hash',
                exp: Math.floor(Date.now() / 1000) + 3600,
            };

            // Decode payload, mutate a claim, re-encode with original signature
            const token = sign(payload, SECRET);
            const parts = token.split('.');
            const fromBase64url = (str: string): Buffer => {
                const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
                return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
            };
            const toBase64url = (buf: Buffer): string =>
                buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
            const decoded = JSON.parse(fromBase64url(parts[1]).toString('utf-8'));
            decoded.anchor = 'tampered-anchor-uid';
            const modifiedBody = toBase64url(Buffer.from(JSON.stringify(decoded), 'utf-8'));
            const tampered = [parts[0], modifiedBody, parts[2]].join('.');
            expect(() => verify(tampered, SECRET, AUDIENCE)).toThrow('Invalid signature');
        });

        it('rejects a token with wrong secret', () => {
            const payload = {
                jti: 'lease-wrong-secret',
                sub: 'app-wrong',
                iss: 'agent-oracle',
                aud: AUDIENCE,
                app_uid: 'app-wrong',
                anchor: 'file-uid',
                target_uids: [],
                base_hash: 'hash',
                exp: Math.floor(Date.now() / 1000) + 3600,
            };

            const token = sign(payload, SECRET);
            expect(() => verify(token, 'different-secret', AUDIENCE)).toThrow('Invalid signature');
        });

        it('rejects malformed token (not 3 parts)', () => {
            expect(() => verify('not-a-jwt', SECRET, AUDIENCE)).toThrow('JWT must have 3 parts');
        });

        it('rejects token with garbage payload encoding', () => {
            const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
                .toString('base64')
                .replace(/=/g, '')
                .replace(/\+/g, '-')
                .replace(/\//g, '_');
            const token = `${header}.not-base64url.signature`;
            // Signature check happens before payload validation
            expect(() => verify(token, SECRET, AUDIENCE)).toThrow('Invalid signature');
        });
    });

    describe('missing exp claim', () => {
        it('rejects a token without exp', () => {
            const payload = {
                jti: 'lease-no-exp',
                sub: 'app-noexp',
                iss: 'agent-oracle',
                aud: AUDIENCE,
                app_uid: 'app-noexp',
                anchor: 'file-uid',
                target_uids: [],
                base_hash: 'hash',
            };

            const token = sign(payload, SECRET);
            expect(() => verify(token, SECRET, AUDIENCE)).toThrow('Token missing valid exp claim');
        });
    });
});
