// packages/core/src/totp/__tests__/qr.test.ts
//
// TOTP-03: pixel-buffer decode wrapper, fail-closed (D-10). Uses SYNTHETIC
// pixel-buffer fixtures (not real image files) -- mocks jsqr's default export
// to control the decode outcome deterministically.

import { describe, it, expect, vi } from 'vitest';

const mockJsQR = vi.fn();
vi.mock('jsqr', () => ({
  default: (...args: unknown[]) => mockJsQR(...args),
}));

const { decodeQrToOtpauthUri } = await import('../qr');

function fixturePixels() {
  return { data: new Uint8ClampedArray(16), width: 2, height: 2 };
}

describe('decodeQrToOtpauthUri', () => {
  it('passes the decoded string through unchanged on a mocked hit', () => {
    mockJsQR.mockReturnValueOnce({ data: 'otpauth://totp/Acme:alice?secret=GEZDGNBV&issuer=Acme' });
    const result = decodeQrToOtpauthUri(fixturePixels());
    expect(result).toBe('otpauth://totp/Acme:alice?secret=GEZDGNBV&issuer=Acme');
  });

  it('maps a mocked no-QR miss (null) to null -- D-10 fail-closed, never a throw', () => {
    mockJsQR.mockReturnValue(null);
    const pixels = fixturePixels();
    let result: string | null = 'sentinel';
    expect(() => {
      result = decodeQrToOtpauthUri(pixels);
    }).not.toThrow();
    expect(result).toBeNull();
  });

  it('passes through a non-otpauth payload string unchanged -- this wrapper does no payload validation (that is parsePastedTotp\'s job)', () => {
    mockJsQR.mockReturnValueOnce({ data: 'https://example.com/not-a-totp-thing' });
    const result = decodeQrToOtpauthUri(fixturePixels());
    expect(result).toBe('https://example.com/not-a-totp-thing');
  });

  it('calls jsQR with the pixel buffer\'s data/width/height', () => {
    mockJsQR.mockReturnValueOnce(null);
    const pixels = fixturePixels();
    decodeQrToOtpauthUri(pixels);
    expect(mockJsQR).toHaveBeenCalledWith(pixels.data, pixels.width, pixels.height);
  });
});
