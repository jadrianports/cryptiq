// apps/desktop/src/lib/bridge/__tests__/bridgeFingerprint.test.ts
//
// Wave-0 node test: BRIDGE-05 fingerprint formatter.
// Pins the exact grouped-hex output for a known key so the approval modal's
// display string is deterministic and testable without Tauri/Svelte.
//
// Environment: node (vitest.config.ts — no browser provider invoked).

import { describe, it, expect } from 'vitest';
import { formatFingerprint } from '../bridgeFingerprint';

describe('bridgeFingerprint — BRIDGE-05 fingerprint formatter', () => {
  it('formats the first 8 bytes as grouped uppercase hex joined by middle dots', () => {
    // First 8 bytes: 0x4f, 0x2a, 0x8c, 0x11, 0xb0, 0x71, 0xd9, 0xf3
    const key = new Uint8Array([
      0x4f, 0x2a, 0x8c, 0x11, 0xb0, 0x71, 0xd9, 0xf3,
      // Remaining 24 bytes of a 32-byte Curve25519 key — ignored by the formatter.
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    expect(formatFingerprint(key)).toBe('4F2A·8C11·B071·D9F3');
  });

  it('uses the U+00B7 MIDDLE DOT separator (not a regular period or hyphen)', () => {
    const key = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]);
    const result = formatFingerprint(key);
    expect(result).toContain('·');
    expect(result).not.toContain('.');
    expect(result).not.toContain('-');
  });

  it('groups into 4-char chunks separated by exactly 3 dots for an 8-byte (16 hex char) input', () => {
    const key = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const result = formatFingerprint(key);
    const groups = result.split('·');
    expect(groups).toHaveLength(4);
    for (const group of groups) {
      expect(group).toHaveLength(4);
    }
  });

  it('pads single-hex-digit bytes with a leading zero (e.g. 0x01 -> "01" not "1")', () => {
    const key = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    expect(formatFingerprint(key)).toBe('0102·0304·0506·0708');
  });

  it('only uses the first 8 bytes even when given a full 32-byte key', () => {
    const first8 = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22];
    const rest = new Array(24).fill(0xff); // deliberately different tail bytes
    const key = new Uint8Array([...first8, ...rest]);
    expect(formatFingerprint(key)).toBe('AABB·CCDD·EEFF·1122');
  });
});
