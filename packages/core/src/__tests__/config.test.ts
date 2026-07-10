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

// UX-05 / D-04 regression-lock for the extensionBridgeEnabled field (Phase 20-01).
// The device-local browser-extension kill-switch. The 20-01 fix extended parseConfig to
// round-trip this flag (the plan's tolerant-passthrough premise was wrong — parseConfig
// reconstructs the object explicitly and silently DROPPED the flag on load). Without the
// round-trip, a persisted OFF (false) would parse back as true (?? true), desyncing the
// Settings toggle from the reality the Rust boot-gate enforces. These tests fail if that
// round-trip regresses.
describe('CryptiqConfig extensionBridgeEnabled field (UX-05 / D-04)', () => {
  describe('DEFAULT_CONFIG', () => {
    it('DEFAULT_CONFIG.extensionBridgeEnabled is true', () => {
      expect(DEFAULT_CONFIG.extensionBridgeEnabled).toBe(true);
    });
  });

  describe('parseConfig — extensionBridgeEnabled absence defaults to true', () => {
    it('parses a config with no extensionBridgeEnabled key as true (upgrade safety)', () => {
      // Simulates a pre-Phase-20 config.json written before the field existed.
      const bytes = new TextEncoder().encode(
        JSON.stringify({ vaultPath: null, schemaVersion: 1 }, null, 2) + '\n',
      );
      const parsed = parseConfig(bytes);
      expect(parsed.extensionBridgeEnabled).toBe(true);
    });

    it('parses a config with extensionBridgeEnabled: false as false', () => {
      const bytes = new TextEncoder().encode(
        JSON.stringify(
          { vaultPath: null, schemaVersion: 1, extensionBridgeEnabled: false },
          null,
          2,
        ) + '\n',
      );
      const parsed = parseConfig(bytes);
      expect(parsed.extensionBridgeEnabled).toBe(false);
    });
  });

  describe('parseConfig — extensionBridgeEnabled type validation', () => {
    it('throws ConfigCorruptError when extensionBridgeEnabled is a string', () => {
      const bytes = new TextEncoder().encode(
        JSON.stringify(
          { vaultPath: null, schemaVersion: 1, extensionBridgeEnabled: 'off' },
          null,
          2,
        ) + '\n',
      );
      expect(() => parseConfig(bytes)).toThrowError(ConfigCorruptError);
    });

    it('ConfigCorruptError message mentions extensionBridgeEnabled', () => {
      const bytes = new TextEncoder().encode(
        JSON.stringify({ vaultPath: null, schemaVersion: 1, extensionBridgeEnabled: 1 }, null, 2) +
          '\n',
      );
      expect(() => parseConfig(bytes)).toThrowError(/extensionBridgeEnabled/);
    });

    it('throws ConfigCorruptError when extensionBridgeEnabled is null', () => {
      const bytes = new TextEncoder().encode(
        JSON.stringify(
          { vaultPath: null, schemaVersion: 1, extensionBridgeEnabled: null },
          null,
          2,
        ) + '\n',
      );
      expect(() => parseConfig(bytes)).toThrowError(ConfigCorruptError);
    });
  });

  describe('serializeConfig + parseConfig round-trip (the 20-01 regression)', () => {
    it('round-trips extensionBridgeEnabled: false — persisted OFF survives a load', () => {
      // THE regression the 20-01 fix locks: before the parseConfig round-trip, a persisted
      // false parsed back as true (?? true), so the reloaded Settings toggle showed ON while
      // the Rust boot-gate kept the bridge OFF — a UI-vs-reality desync (D-04).
      const original = {
        vaultPath: null,
        schemaVersion: 1 as const,
        extensionBridgeEnabled: false,
      };
      const result = parseConfig(serializeConfig(original));
      expect(result.extensionBridgeEnabled).toBe(false);
    });

    it('round-trips extensionBridgeEnabled: true — ON persists', () => {
      const original = {
        vaultPath: '/some/path',
        schemaVersion: 1 as const,
        extensionBridgeEnabled: true,
      };
      const result = parseConfig(serializeConfig(original));
      expect(result.extensionBridgeEnabled).toBe(true);
      expect(result.vaultPath).toBe('/some/path');
    });

    it('round-trip preserves extensionBridgeEnabled and listenerEnabled independently', () => {
      // Guards against the two device-local flags being conflated during parse.
      const original = {
        vaultPath: null,
        schemaVersion: 1 as const,
        listenerEnabled: true,
        extensionBridgeEnabled: false,
      };
      const result = parseConfig(serializeConfig(original));
      expect(result.listenerEnabled).toBe(true);
      expect(result.extensionBridgeEnabled).toBe(false);
    });
  });
});

// HIBP-01 / HIBP-06 / D-02 / D-16 regression-lock for the two consent flags (Phase 31-01).
// UNLIKE listenerEnabled/extensionBridgeEnabled (default true), these flags MUST default to
// false on absence — a naive `?? true` copy-paste would silently authorize this app's
// first-ever network egress for every pre-Phase-31 config.json (RESEARCH Pitfall 2). The
// "both keys absent -> both false" fixture below is the regression lock for that failure mode.
describe('CryptiqConfig HIBP consent flags (D-02/D-16)', () => {
  describe('DEFAULT_CONFIG', () => {
    it('DEFAULT_CONFIG.hibpEntryScanEnabled is false', () => {
      expect(DEFAULT_CONFIG.hibpEntryScanEnabled).toBe(false);
    });

    it('DEFAULT_CONFIG.hibpMasterCheckEnabled is false', () => {
      expect(DEFAULT_CONFIG.hibpMasterCheckEnabled).toBe(false);
    });

    it('DEFAULT_CONFIG.schemaVersion is still 1 (no schema bump)', () => {
      expect(DEFAULT_CONFIG.schemaVersion).toBe(1);
    });
  });

  describe('parseConfig — both HIBP keys absent defaults to false (the pre-Phase-31 upgrade fixture)', () => {
    it('parses a config with neither hibpEntryScanEnabled nor hibpMasterCheckEnabled as both false', () => {
      // Simulates every existing install's config.json prior to Phase 31 — neither key exists.
      const bytes = new TextEncoder().encode(
        JSON.stringify({ vaultPath: null, schemaVersion: 1 }, null, 2) + '\n',
      );
      const parsed = parseConfig(bytes);
      expect(parsed.hibpEntryScanEnabled).toBe(false);
      expect(parsed.hibpMasterCheckEnabled).toBe(false);
    });
  });

  describe('parseConfig — hibpEntryScanEnabled explicit values', () => {
    it('parses hibpEntryScanEnabled: true as true', () => {
      const bytes = new TextEncoder().encode(
        JSON.stringify(
          { vaultPath: null, schemaVersion: 1, hibpEntryScanEnabled: true },
          null,
          2,
        ) + '\n',
      );
      const parsed = parseConfig(bytes);
      expect(parsed.hibpEntryScanEnabled).toBe(true);
    });

    it('parses hibpEntryScanEnabled: false as false', () => {
      const bytes = new TextEncoder().encode(
        JSON.stringify(
          { vaultPath: null, schemaVersion: 1, hibpEntryScanEnabled: false },
          null,
          2,
        ) + '\n',
      );
      const parsed = parseConfig(bytes);
      expect(parsed.hibpEntryScanEnabled).toBe(false);
    });
  });

  describe('parseConfig — hibpMasterCheckEnabled explicit values', () => {
    it('parses hibpMasterCheckEnabled: true as true', () => {
      const bytes = new TextEncoder().encode(
        JSON.stringify(
          { vaultPath: null, schemaVersion: 1, hibpMasterCheckEnabled: true },
          null,
          2,
        ) + '\n',
      );
      const parsed = parseConfig(bytes);
      expect(parsed.hibpMasterCheckEnabled).toBe(true);
    });

    it('parses hibpMasterCheckEnabled: false as false', () => {
      const bytes = new TextEncoder().encode(
        JSON.stringify(
          { vaultPath: null, schemaVersion: 1, hibpMasterCheckEnabled: false },
          null,
          2,
        ) + '\n',
      );
      const parsed = parseConfig(bytes);
      expect(parsed.hibpMasterCheckEnabled).toBe(false);
    });
  });

  describe('parseConfig — HIBP flag type validation (fail-closed on non-boolean)', () => {
    it('throws ConfigCorruptError when hibpEntryScanEnabled is a string', () => {
      const bytes = new TextEncoder().encode(
        JSON.stringify(
          { vaultPath: null, schemaVersion: 1, hibpEntryScanEnabled: 'yes' },
          null,
          2,
        ) + '\n',
      );
      expect(() => parseConfig(bytes)).toThrowError(ConfigCorruptError);
      expect(() => parseConfig(bytes)).toThrowError(/hibpEntryScanEnabled/);
    });

    it('throws ConfigCorruptError when hibpEntryScanEnabled is a number', () => {
      const bytes = new TextEncoder().encode(
        JSON.stringify({ vaultPath: null, schemaVersion: 1, hibpEntryScanEnabled: 1 }, null, 2) +
          '\n',
      );
      expect(() => parseConfig(bytes)).toThrowError(ConfigCorruptError);
    });

    it('throws ConfigCorruptError when hibpMasterCheckEnabled is a string', () => {
      const bytes = new TextEncoder().encode(
        JSON.stringify(
          { vaultPath: null, schemaVersion: 1, hibpMasterCheckEnabled: 'no' },
          null,
          2,
        ) + '\n',
      );
      expect(() => parseConfig(bytes)).toThrowError(ConfigCorruptError);
      expect(() => parseConfig(bytes)).toThrowError(/hibpMasterCheckEnabled/);
    });

    it('throws ConfigCorruptError when hibpMasterCheckEnabled is a number', () => {
      const bytes = new TextEncoder().encode(
        JSON.stringify(
          { vaultPath: null, schemaVersion: 1, hibpMasterCheckEnabled: 0 },
          null,
          2,
        ) + '\n',
      );
      expect(() => parseConfig(bytes)).toThrowError(ConfigCorruptError);
    });
  });

  describe('serializeConfig + parseConfig round-trip', () => {
    it('round-trips hibpEntryScanEnabled: true — explicit ON persists', () => {
      const original = {
        vaultPath: null,
        schemaVersion: 1 as const,
        hibpEntryScanEnabled: true,
      };
      const result = parseConfig(serializeConfig(original));
      expect(result.hibpEntryScanEnabled).toBe(true);
    });

    it('round-trips hibpMasterCheckEnabled: true — explicit ON persists', () => {
      const original = {
        vaultPath: null,
        schemaVersion: 1 as const,
        hibpMasterCheckEnabled: true,
      };
      const result = parseConfig(serializeConfig(original));
      expect(result.hibpMasterCheckEnabled).toBe(true);
    });

    it('round-trip preserves hibpEntryScanEnabled and hibpMasterCheckEnabled independently', () => {
      const original = {
        vaultPath: null,
        schemaVersion: 1 as const,
        hibpEntryScanEnabled: true,
        hibpMasterCheckEnabled: false,
      };
      const result = parseConfig(serializeConfig(original));
      expect(result.hibpEntryScanEnabled).toBe(true);
      expect(result.hibpMasterCheckEnabled).toBe(false);
    });

    it('round-trip does not disturb listenerEnabled/extensionBridgeEnabled defaults', () => {
      const original = {
        vaultPath: null,
        schemaVersion: 1 as const,
        hibpEntryScanEnabled: true,
        hibpMasterCheckEnabled: true,
      };
      const result = parseConfig(serializeConfig(original));
      expect(result.listenerEnabled).toBe(true);
      expect(result.extensionBridgeEnabled).toBe(true);
    });
  });
});
