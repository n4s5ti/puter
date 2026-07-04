// -- JWT sign/verify for AgentSec lease tokens -----------------------------
//
// Uses HMAC-SHA256 (node:crypto). No external dependencies.
// Claims are standard JWT claims + AgentSec-specific ones defined in types.ts.

import { createHmac, timingSafeEqual } from 'node:crypto';

// -- Constants --------------------------------------------------------------

const ALGORITHM = 'HS256';
const ALGORITHM_IDENT = { alg: ALGORITHM, typ: 'JWT' };

// -- Helpers ----------------------------------------------------------------

const base64url = (buf: Buffer): string =>
    buf
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');

const fromBase64url = (str: string): Buffer => {
    const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
    return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
};

const hmacRaw = (data: string, secret: string): Buffer => {
    return createHmac('sha256', secret).update(data).digest();
};

const hmacSign = (data: string, secret: string): string => {
    return base64url(hmacRaw(data, secret));
};

// -- Public API -------------------------------------------------------------

/**
 * Sign a payload into a JWT using HMAC-SHA256.
 *
 * @param payload  - The claims object. `iat` is auto-set if absent.
 * @param secret   - HMAC secret key.
 * @returns The compact JWT string.
 */
export const sign = (payload: Record<string, unknown>, secret: string): string => {
    const header = base64url(Buffer.from(JSON.stringify(ALGORITHM_IDENT), 'utf-8'));
    const body = base64url(
        Buffer.from(
            JSON.stringify({ ...payload, iat: payload.iat ?? Math.floor(Date.now() / 1000) }),
            'utf-8',
        ),
    );
    const data = `${header}.${body}`;
    const signature = hmacSign(data, secret);
    return `${data}.${signature}`;
};

/**
 * Verify and decode a JWT token.
 *
 * @param token       - The compact JWT string.
 * @param secret      - HMAC secret key.
 * @param expectedAud - Expected audience value. Rejects tokens with a
 *                      mismatched `aud` claim.
 * @returns The decoded payload if valid, or throws with a descriptive message.
 */
export const verify = (
    token: string,
    secret: string,
    expectedAud: string,
): Record<string, unknown> => {
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('JWT must have 3 parts');
    }

    const [headerB64, bodyB64, sigB64] = parts;

    // -- Verify signature ---------------------------------------------------
    const data = `${headerB64}.${bodyB64}`;
    const sigBuf = fromBase64url(sigB64);
    const expectedBuf = hmacRaw(data, secret);

    if (sigBuf.length !== expectedBuf.length) {
        throw new Error('Invalid signature');
    }

    if (!timingSafeEqual(sigBuf, expectedBuf)) {
        throw new Error('Invalid signature');
    }

    // -- Decode & validate claims -------------------------------------------
    let payload: Record<string, unknown>;
    try {
        payload = JSON.parse(fromBase64url(bodyB64).toString('utf-8'));
    } catch {
        throw new Error('Invalid payload encoding');
    }

    if (typeof payload !== 'object' || payload === null) {
        throw new Error('Payload must be a JSON object');
    }

    // -- Expiry check -------------------------------------------------------
    const now = Math.floor(Date.now() / 1000);
    const exp = Number(payload.exp);
    if (!Number.isFinite(exp)) {
        throw new Error('Token missing valid exp claim');
    }
    if (now > exp) {
        throw new Error('Token has expired');
    }

    // -- Audience check -----------------------------------------------------
    if (payload.aud !== expectedAud) {
        throw new Error('Token audience mismatch');
    }

    return payload;
};
