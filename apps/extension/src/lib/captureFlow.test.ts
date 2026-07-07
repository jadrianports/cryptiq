// apps/extension/src/lib/captureFlow.test.ts
//
// Covers Plan 19-02 Task 2's behaviors: decideCaptureFlow's 0/1/many decision
// (CAP-01, D-05/D-06), shouldNudgeGenerate's threshold (HEALTH-01), and
// buildSaveParams's generated-value threading (GEN-02). Mirrors popupFill
// .test.ts's describe-block structure.

import { describe, expect, it } from 'vitest';
import type { EntryMatchMetadata } from './contentScriptMessages';
import { buildSaveParams, decideCaptureFlow, shouldNudgeGenerate } from './captureFlow';

function makeCandidate(overrides: Partial<EntryMatchMetadata> = {}): EntryMatchMetadata {
  return {
    id: 'entry-1',
    title: 'Example',
    username: 'me@example.com',
    domainHint: 'example.com',
    type: 'login',
    ...overrides,
  };
}

describe('captureFlow', () => {
  describe('decideCaptureFlow (CAP-01, D-05/D-06)', () => {
    it('returns new for a captured username with zero matching candidates (brand-new domain)', () => {
      const result = decideCaptureFlow([], 'me@example.com');
      expect(result).toEqual({ kind: 'new' });
    });

    it('returns new when the domain has candidates but none match the captured username (known-domain-no-match)', () => {
      const candidates = [makeCandidate({ id: 'a', username: 'someone-else@example.com' })];
      const result = decideCaptureFlow(candidates, 'me@example.com');
      expect(result).toEqual({ kind: 'new' });
    });

    it('returns update with the matching entryId for exactly one username match', () => {
      const candidates = [
        makeCandidate({ id: 'a', username: 'someone-else@example.com' }),
        makeCandidate({ id: 'b', username: 'me@example.com' }),
      ];
      const result = decideCaptureFlow(candidates, 'me@example.com');
      expect(result).toEqual({ kind: 'update', entryId: 'b' });
    });

    it('returns picker with only the matching candidates for more than one username match', () => {
      const candidates = [
        makeCandidate({ id: 'a', username: 'me@example.com' }),
        makeCandidate({ id: 'b', username: 'someone-else@example.com' }),
        makeCandidate({ id: 'c', username: 'me@example.com' }),
      ];
      const result = decideCaptureFlow(candidates, 'me@example.com');
      expect(result.kind).toBe('picker');
      if (result.kind === 'picker') {
        expect(result.candidates.map((c) => c.id)).toEqual(['a', 'c']);
      }
    });
  });

  describe('shouldNudgeGenerate (HEALTH-01)', () => {
    it('returns true for scores below the threshold', () => {
      expect(shouldNudgeGenerate(0)).toBe(true);
      expect(shouldNudgeGenerate(1)).toBe(true);
      expect(shouldNudgeGenerate(2)).toBe(true);
    });

    it('returns false for scores at or above the threshold', () => {
      expect(shouldNudgeGenerate(3)).toBe(false);
      expect(shouldNudgeGenerate(4)).toBe(false);
    });
  });

  describe('buildSaveParams (GEN-02)', () => {
    it('carries a generated password through into the returned params unchanged', () => {
      const generatedPassword = 'Xk9!qT2#vLp8@mN4';
      const params = buildSaveParams({
        mode: 'new',
        title: 'Example',
        username: 'me@example.com',
        password: generatedPassword,
        url: 'https://example.com',
      });

      expect(params.password).toBe(generatedPassword);
      expect(params).toEqual({
        mode: 'new',
        title: 'Example',
        username: 'me@example.com',
        password: generatedPassword,
        url: 'https://example.com',
      });
    });

    it('includes entryId only for update mode', () => {
      const params = buildSaveParams({
        mode: 'update',
        entryId: 'entry-42',
        title: 'Example',
        username: 'me@example.com',
        password: 'typed-password',
        url: 'https://example.com',
      });

      expect(params.entryId).toBe('entry-42');
      expect(params.mode).toBe('update');
    });

    it('omits entryId for new mode', () => {
      const params = buildSaveParams({
        mode: 'new',
        title: 'Example',
        username: 'me@example.com',
        password: 'typed-password',
        url: 'https://example.com',
      });

      expect(Object.prototype.hasOwnProperty.call(params, 'entryId')).toBe(false);
    });
  });
});
