// packages/core/src/totp/qr.ts
//
// Pixel-buffer -> otpauth URI decode wrapper (D-09/D-10, TOTP-03).
//
// This module contains ONLY a pure function — no IO, no imports of @tauri-apps,
// svelte, node:fs, node:path, or DOM (`<canvas>` pixel extraction stays
// desktop-side; this module receives an already-extracted pixel buffer).
//
// D-10 fail-closed contract: returns `null` on decode failure (no QR found) —
// does NOT throw. A missing/garbled QR is an expected, common outcome, not an
// exceptional one, mirroring `import/detect.ts`'s `| null`-on-no-match idiom
// rather than parse.ts's throw-based idiom.
//
// This wrapper does NO otpauth/TOTP validation itself — it returns the raw
// decoded string (or null) verbatim. Validity (single otpauth://totp URI,
// D-09) is enforced downstream by `parsePastedTotp`, keeping that gate in one
// place.

import jsQR from 'jsqr';

export interface PixelBuffer {
  /** RGBA pixel data, length === width * height * 4. */
  data: Uint8ClampedArray;
  width: number;
  height: number;
}

/**
 * Decode a QR code from a pixel buffer into its embedded string. Returns
 * `null` when no QR code is found (D-10 fail-closed signal) — never throws.
 */
export function decodeQrToOtpauthUri(pixels: PixelBuffer): string | null {
  // Self-enforce the "never throws" contract: a malformed pixel buffer (e.g. a
  // data length that doesn't match width*height*4) can make jsQR throw. Treat
  // any decode failure as "no QR found" (null) rather than relying on the
  // caller to wrap this — the contract lives with the function, not its callers.
  try {
    const code = jsQR(pixels.data, pixels.width, pixels.height);
    if (code === null) return null;
    return code.data;
  } catch {
    return null;
  }
}
