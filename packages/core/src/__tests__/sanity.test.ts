import { describe, it, expect } from 'vitest';
import { parseConfig, serializeConfig, DEFAULT_CONFIG } from '../config/config';

describe('vitest harness wired correctly', () => {
  it('runs at all', () => {
    expect(1 + 1).toBe(2);
  });

  it('parseConfig round-trips DEFAULT_CONFIG', () => {
    // First real piece of testable core logic — proves the harness handles
    // imports of @cryptiq/core types and that the config helper works.
    const bytes = serializeConfig(DEFAULT_CONFIG);
    const parsed = parseConfig(bytes);
    expect(parsed).toEqual(DEFAULT_CONFIG);
  });
});
