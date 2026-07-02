// apps/desktop/src/lib/bridge/__tests__/ExtensionPeerStore.test.ts
//
// Wave-0 node test: BRIDGE-09 $state.raw association store.
//
// Test environment: node (same idiom as sync/__tests__/syncOrchestration.test.ts).
// Tauri: vi.mock('@tauri-apps/api/core') — no live Tauri backend needed.
//
// Covers:
//   - init() fail-open: a rejected extensionPeersList() invoke yields an empty list,
//     never throws into the caller (T-15-10 / D-04 UI must not crash on a corrupt sidecar).
//   - init() happy path: populates #associations from the resolved list.
//   - revoke() filters the target association out AND calls the revoke invoke first.
//   - renameLabel() persists via invoke AND updates the local label (unlike sync's
//     local-only rename — 15-PATTERNS.md ExtensionPeerStore adaptation note).
//   - reset() empties the list (vault-lock path, T-15-10).

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

import { invoke } from '@tauri-apps/api/core';
import { extensionPeerStore } from '../ExtensionPeerStore.svelte';
import type { ExtensionAssociation } from '../bridgeCommands';

const mockInvoke = vi.mocked(invoke);

const CONFIG_DIR = '/fake/config';

function makeAssociation(overrides: Partial<ExtensionAssociation> = {}): ExtensionAssociation {
  return {
    clientId: 'client-a',
    clientPublicKey: 'aabbccdd',
    label: 'Chrome',
    pairedAt: '2026-07-01T00:00:00.000Z',
    lastUsedAt: null,
    pairingTokenHash: 'deadbeef',
    ...overrides,
  };
}

beforeEach(() => {
  mockInvoke.mockReset();
  extensionPeerStore.reset();
});

describe('ExtensionPeerStore — BRIDGE-09 $state.raw association store', () => {
  describe('init', () => {
    it('populates associations from extension_peers_list on the happy path', async () => {
      const seeded = [makeAssociation()];
      mockInvoke.mockResolvedValueOnce(seeded);

      await extensionPeerStore.init(CONFIG_DIR);

      expect(mockInvoke).toHaveBeenCalledWith('extension_peers_list', { configDir: CONFIG_DIR });
      expect(extensionPeerStore.associations).toHaveLength(1);
      expect(extensionPeerStore.associations[0]?.clientId).toBe('client-a');
    });

    it('fails open to an empty list on a read error (never throws into the UI)', async () => {
      mockInvoke.mockRejectedValueOnce(new Error('extension-peers.json corrupt'));

      await expect(extensionPeerStore.init(CONFIG_DIR)).resolves.toBeUndefined();
      expect(extensionPeerStore.associations).toEqual([]);
    });
  });

  describe('revoke', () => {
    it('calls revoke_extension_association_cmd then filters the target out', async () => {
      mockInvoke.mockResolvedValueOnce([
        makeAssociation({ clientId: 'client-a' }),
        makeAssociation({ clientId: 'client-b', label: 'Edge' }),
      ]);
      await extensionPeerStore.init(CONFIG_DIR);

      mockInvoke.mockResolvedValueOnce(undefined); // revoke_extension_association_cmd
      await extensionPeerStore.revoke(CONFIG_DIR, 'client-a');

      expect(mockInvoke).toHaveBeenCalledWith('revoke_extension_association_cmd', {
        configDir: CONFIG_DIR,
        clientId: 'client-a',
      });
      expect(extensionPeerStore.associations).toHaveLength(1);
      expect(extensionPeerStore.associations[0]?.clientId).toBe('client-b');
    });
  });

  describe('renameLabel', () => {
    it('persists via rename_extension_association AND updates the local label', async () => {
      mockInvoke.mockResolvedValueOnce([makeAssociation({ clientId: 'client-a', label: 'Chrome' })]);
      await extensionPeerStore.init(CONFIG_DIR);

      mockInvoke.mockResolvedValueOnce(undefined); // rename_extension_association
      await extensionPeerStore.renameLabel(CONFIG_DIR, 'client-a', 'Chrome (work)');

      expect(mockInvoke).toHaveBeenCalledWith('rename_extension_association', {
        configDir: CONFIG_DIR,
        clientId: 'client-a',
        label: 'Chrome (work)',
      });
      expect(extensionPeerStore.associations[0]?.label).toBe('Chrome (work)');
    });
  });

  describe('reset', () => {
    it('empties the association list (vault-lock path)', async () => {
      mockInvoke.mockResolvedValueOnce([makeAssociation()]);
      await extensionPeerStore.init(CONFIG_DIR);
      expect(extensionPeerStore.associations).toHaveLength(1);

      extensionPeerStore.reset();

      expect(extensionPeerStore.associations).toEqual([]);
    });
  });
});
