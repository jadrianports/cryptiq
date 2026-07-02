// packages/core/src/entries/originMatch.test.ts
//
// FILL-03 KAT table for `registrableHost` — D-14: one `it` per required case
// (subdomain, www, IDN/punycode, IP, localhost, empty, malformed, file://).
// Mirrors the table-driven describe/it shape of crypto/__tests__/padding.test.ts.

import { describe, it, expect } from 'vitest';
import { registrableHost } from './originMatch';

describe('entries/originMatch — eTLD+1 registrable-host extraction (FILL-03)', () => {
  it('reduces a subdomain to its eTLD+1 base domain (D-01 subdomain-agnostic match)', () => {
    expect(registrableHost('accounts.google.com')).toBe('google.com');
  });

  it('reduces a www. subdomain to its bare eTLD+1 (D-01 www <-> bare)', () => {
    expect(registrableHost('www.example.com')).toBe('example.com');
  });

  it('extracts the eTLD+1 from a punycode-encoded IDN host (D-04 ASCII/punycode form)', () => {
    expect(registrableHost('xn--e1afmkfd.xn--p1ai')).toBe('xn--e1afmkfd.xn--p1ai');
  });

  it('extracts the eTLD+1 from a full URL with an IDN host (D-04)', () => {
    expect(registrableHost('https://почта.рф/login')).toBe('почта.рф');
  });

  it('returns null for a raw IP address (D-03 fail closed)', () => {
    expect(registrableHost('192.168.1.1')).toBeNull();
  });

  it('returns null for localhost (D-03 fail closed — no known TLD)', () => {
    expect(registrableHost('localhost')).toBeNull();
  });

  it('returns null for an empty string (D-02 empty url skipped)', () => {
    expect(registrableHost('')).toBeNull();
  });

  it('returns null for whitespace-only input (D-02 empty url skipped)', () => {
    expect(registrableHost('   ')).toBeNull();
  });

  it('returns null for malformed, non-URL input (D-02 unparseable -> skipped, fail closed)', () => {
    expect(registrableHost('not a url at all')).toBeNull();
  });

  it('returns null for a file:// URL (D-03 fail closed — non-HTTP scheme, no registrable domain)', () => {
    expect(registrableHost('file:///C:/foo/bar.html')).toBeNull();
  });

  it('leniently accepts a bare host with no scheme and a trailing port/path (D-02)', () => {
    expect(registrableHost('example.com:8080/path')).toBe('example.com');
  });
});
