// -- Tests for agentsec-grant-issuer extension entry ------------------------
import { describe, expect, it, vi, beforeEach } from 'vitest';

// Mock the Puter extension API before importing the module under test.
// The module-scope `extension.registerService(...)` call runs on import,
// so mocks must be in place first. This is a test boundary exception —
// we need dynamic import to verify module-scope side-effects fire.
const mockRegisterService = vi.fn();
let PuterServiceMock: new () => object;

vi.mock('@heyputer/backend/src/extensions', () => ({
    extension: {
        registerService: mockRegisterService,
    },
}));

vi.mock('@heyputer/backend/src/services/types.js', () => {
    PuterServiceMock = class {
        // Minimal mock for instanceof compatibility
    };
    return { PuterService: PuterServiceMock };
});

describe('agentsec extension entry', () => {
    beforeEach(() => {
        mockRegisterService.mockClear();
    });

    it('registers the agentsec-grant-issuer service on import', async () => {
        // Dynamic import triggers module-scope registration.
        // Exception: test exercising module loading boundary.
        await import('./index');

        expect(mockRegisterService).toHaveBeenCalledTimes(1);
        expect(mockRegisterService).toHaveBeenCalledWith(
            'agentsec-grant-issuer',
            expect.anything(),
        );

        // Verify the registered value is a constructable class
        const registrationCall = mockRegisterService.mock.calls[0];
        const ServiceClass = registrationCall[1] as new () => object;
        expect(typeof ServiceClass).toBe('function');
        expect(new ServiceClass()).toBeInstanceOf(Object);
    });
});
