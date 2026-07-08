// apps/extension/src/lib/icons.test.ts
//
// Phase 27 (XUI-02, D-02/D-03/D-04/D-05): unit tests for the pure
// `iconForType` icon selector. Lives under `src/lib/`, NEVER
// `entrypoints/` -- a test file there breaks `wxt build` (CLAUDE.md).

import { describe, expect, it } from 'vitest';
import { iconForType } from './icons';

describe('iconForType', () => {
  it('returns a non-empty key glyph for login', () => {
    const svg = iconForType('login');
    expect(svg).toBeTruthy();
    expect(svg).toContain('<svg');
  });

  it('returns a non-empty credit-card glyph for card', () => {
    const svg = iconForType('card');
    expect(svg).toBeTruthy();
    expect(svg).toContain('<svg');
  });

  it('returns a non-empty ID-badge glyph for identity', () => {
    const svg = iconForType('identity');
    expect(svg).toBeTruthy();
    expect(svg).toContain('<svg');
  });

  it('returns undefined for secure-note (D-04 -- not a fillable type, no bespoke glyph)', () => {
    expect(iconForType('secure-note')).toBeUndefined();
  });

  it('renders login/card/identity as distinct glyphs', () => {
    const login = iconForType('login');
    const card = iconForType('card');
    const identity = iconForType('identity');
    expect(login).not.toEqual(card);
    expect(card).not.toEqual(identity);
    expect(login).not.toEqual(identity);
  });

  for (const type of ['login', 'card', 'identity'] as const) {
    it(`${type} glyph is line-style (stroke=currentColor, fill=none) -- D-02`, () => {
      const svg = iconForType(type) ?? '';
      expect(svg).toContain('stroke="currentColor"');
      expect(svg).toContain('fill="none"');
    });

    it(`${type} glyph has no hardcoded hex color and never references the accent (D-05)`, () => {
      const svg = iconForType(type) ?? '';
      expect(svg).not.toMatch(/#[0-9a-fA-F]{3,6}/);
      expect(svg.toLowerCase()).not.toContain('accent');
    });
  }
});
