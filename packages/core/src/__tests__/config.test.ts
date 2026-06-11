// packages/core/src/__tests__/config.test.ts
//
// D-03 regression-lock assertions for the listenerEnabled field in CryptiqConfig.
// Purpose: pin the parse/serialize contract for the device-local listener kill-switch
// so any accidental removal or type change breaks these tests immediately.
//
// Conventions (CLAUDE.md):
//   - No Math.random; no getSodium() — pure config construction.
//   - No console.* calls.
//   - Import only from '../config/config', '../config/types', and 'vitest'.

import { describe, it, expect } from 'vitest';
import { parseConfig, serializeConfig, ConfigCorruptError } from '../config/config';
import { DEFAULT_CONFIG } from '../config/types';

describe('CryptiqConfig listenerEnabled field (D-03)', () => {
  describe('DEFAULT_CONFIG', () => {
    it('DEFAULT_CONFIG.listenerEnabled is true', () => {
      expect(DEFAULT_CONFIG.listenerEnabled).toBe(true);
    });

    it('DEFAULT_CONFIG.schemaVersion is still 1 (no schema bump)', () => {
      expect(DEFAULT_CONFIG.schemaVersion).toBe(1);
    });
  });

  describe('parseConfig — listenerEnabled absence defaults to true', () => {
    it('parses a config with no listenerEnabled key as true', () => {
      const bytes = new TextEncoder().encode(
        JSON.stringify({ vaultPath: null, schemaVersion: 1 }, null, 2) + '\n',
      );
      const parsed = parseConfig(bytes);
      expect(parsed.listenerEnabled).toBe(true);
    });

    it('parses a config with listenerEnabled: true as true', () => {
      const bytes = serializeConfig({ vaultPath: null, schemaVersion: 1, listenerEnabled: true });
      const parsed = parseConfig(bytes);
      expect(parsed.listenerEnabled).toBe(true);
    });

    it('parses a config with listenerEnabled: false as false', () => {
      const bytes = serializeConfig({ vaultPath: null, schemaVersion: 1, listenerEnabled: false });
      const parsed = parseConfig(bytes);
      expect(parsed.listenerEnabled).toBe(false);
    });
  });

  describe('parseConfig — listenerEnabled type validation', () => {
    it('throws ConfigCorruptError when listenerEnabled is a string', () => {
      const bytes = new TextEncoder().encode(
        JSON.stringify({ vaultPath: null, schemaVersion: 1, listenerEnabled: 'yes' }, null, 2) +
          '\n',
      );
      expect(() => parseConfig(bytes)).toThrowError(ConfigCorruptError);
    });

    it('throws ConfigCorruptError when listenerEnabled is a number', () => {
      const bytes = new TextEncoder().encode(
        JSON.stringify({ vaultPath: null, schemaVersion: 1, listenerEnabled: 1 }, null, 2) + '\n',
      );
      expect(() => parseConfig(bytes)).toThrowError(ConfigCorruptError);
    });

    it('throws ConfigCorruptError when listenerEnabled is null', () => {
      const bytes = new TextEncoder().encode(
        JSON.stringify({ vaultPath: null, schemaVersion: 1, listenerEnabled: null }, null, 2) +
          '\n',
      );
      expect(() => parseConfig(bytes)).toThrowError(ConfigCorruptError);
    });

    it('ConfigCorruptError message mentions listenerEnabled', () => {
      const bytes = new TextEncoder().encode(
        JSON.stringify({ vaultPath: null, schemaVersion: 1, listenerEnabled: 'yes' }, null, 2) +
          '\n',
      );
      expect(() => parseConfig(bytes)).toThrowError(/listenerEnabled/);
    });
  });

  describe('serializeConfig + parseConfig round-trip', () => {
    it('round-trips listenerEnabled: false (false persists)', () => {
      const original = { vaultPath: null, schemaVersion: 1 as const, listenerEnabled: false };
      const bytes = serializeConfig(original);
      const parsed = parseConfig(bytes);
      expect(parsed.listenerEnabled).toBe(false);
    });

    it('round-trips listenerEnabled: true (true persists)', () => {
      const original = { vaultPath: null, schemaVersion: 1 as const, listenerEnabled: true };
      const bytes = serializeConfig(original);
      const parsed = parseConfig(bytes);
      expect(parsed.listenerEnabled).toBe(true);
    });

    it('full round-trip: parseConfig(serializeConfig(cfg)) preserves false', () => {
      const cfg = { vaultPath: '/some/path', schemaVersion: 1 as const, listenerEnabled: false };
      const result = parseConfig(serializeConfig(cfg));
      expect(result.listenerEnabled).toBe(false);
      expect(result.vaultPath).toBe('/some/path');
      expect(result.schemaVersion).toBe(1);
    });

    it('absent listenerEnabled in serialized JSON defaults to true after parse', () => {
      // Simulates an old config.json written before the field existed
      const oldConfigBytes = new TextEncoder().encode(
        JSON.stringify({ vaultPath: null, schemaVersion: 1 }, null, 2) + '\n',
      );
      const parsed = parseConfig(oldConfigBytes);
      expect(parsed.listenerEnabled).toBe(true);
    });
  });
});
