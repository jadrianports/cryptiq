// packages/core/src/import/mappers.ts
//
// Concrete header→field mappers for the three known CSV export formats (IMPORT-02).
//
// Detection is by HEADER NAME (lowercase + trim normalized), NOT by column index —
// browser export format column order can vary (PITFALL 15 / RESEARCH Pattern 3).
//
// The three mappers are ordered in ALL_MAPPERS in specificity order: Bitwarden
// (most specific headers) → Firefox (httpRealm is a strong discriminator) →
// Chrome/Edge (broadest — url+username+password+name).
//
// Core purity: no @tauri-apps/*, svelte, node:fs, node:path imports.
// No console.*, no Math.random.

/**
 * Case-insensitive row field accessor.
 *
 * Tries the exact key first, then walks all row keys looking for a
 * case-insensitive match. Returns `undefined` when no key matches.
 *
 * This gives all mappers parity with the detection step, which normalises
 * headers via `s.toLowerCase().trim()` — a CSV whose headers happen to be
 * uppercase/mixed-case still DETECTS (detect() lowercases) and now also MAPS
 * correctly (FIX 2 / IMPORT-02 carry-forward).
 */
function get(row: Record<string, string>, key: string): string | undefined {
  if (Object.prototype.hasOwnProperty.call(row, key)) {
    return row[key];
  }
  const lower = key.toLowerCase();
  for (const k of Object.keys(row)) {
    if (k.toLowerCase() === lower) {
      return row[k];
    }
  }
  return undefined;
}

/**
 * A format mapper: detects a CSV header set and maps raw row data to the
 * Cryptiq field set (title, url, username, password, notes).
 *
 * The `detect` function MUST use lowercase+trim normalized header names
 * (Pitfall 15 — never match by column index).
 */
export interface ImportMapper {
  /** Unique format identifier. */
  name: string;
  /**
   * Returns true if the given headers (raw, un-normalized strings from the CSV)
   * match this format's required header set. The implementation normalizes
   * headers internally via `s.toLowerCase().trim()`.
   */
  detect(headers: string[]): boolean;
  /**
   * Map a raw CSV row (keyed by original header strings) to a partial field set.
   * The returned object may omit any field; `mapRow()` in map.ts fills the defaults.
   *
   * All returned field values MUST be the raw string value from the CSV — never
   * mutate or prefix values (IMPORT-08 / Pitfall 4 verbatim inerting).
   */
  map(row: Record<string, string>): Partial<{
    title: string;
    url: string;
    username: string;
    password: string;
    notes: string;
  }>;
}

// ---------------------------------------------------------------------------
// Chrome / Edge
// ---------------------------------------------------------------------------

/**
 * Mapper for Chrome/Edge CSV exports.
 *
 * Required headers: `name`, `url`, `username`, `password` (case-insensitive).
 * Optional: `note` or `notes`.
 *
 * The Chrome export format is:
 *   `name,url,username,password,note`
 *
 * [VERIFIED: Chrome Password Manager export behavior, 2026-06-02]
 */
export const CHROME_EDGE_MAPPER: ImportMapper = {
  name: 'chrome-edge',
  detect(headers: string[]): boolean {
    const h = new Set(headers.map((s) => s.toLowerCase().trim()));
    return (
      h.has('name') &&
      h.has('url') &&
      h.has('username') &&
      h.has('password')
    );
  },
  map(row: Record<string, string>): Partial<{ title: string; url: string; username: string; password: string; notes: string }> {
    // Use case-insensitive `get` so uppercase/mixed-case headers map correctly (FIX 2).
    return {
      title:    get(row, 'name')     ?? '',
      url:      get(row, 'url')      ?? '',
      username: get(row, 'username') ?? '',
      password: get(row, 'password') ?? '',
      // `note` (Chrome) or `notes` — try both.
      notes:    get(row, 'note')     ?? get(row, 'notes') ?? '',
    };
  },
};

// ---------------------------------------------------------------------------
// Firefox
// ---------------------------------------------------------------------------

/**
 * Mapper for Firefox CSV exports.
 *
 * Required headers: `url`, `username`, `password`, `httpRealm`
 * (case-insensitive).
 *
 * The Firefox export format is:
 *   `url,username,password,httpRealm,formActionOrigin,guid,timeCreated,...`
 *
 * Firefox has no "name" column — we derive the entry title from the URL.
 *
 * [VERIFIED: Firefox Password Manager export behavior, 2026-06-02]
 */
export const FIREFOX_MAPPER: ImportMapper = {
  name: 'firefox',
  detect(headers: string[]): boolean {
    const h = new Set(headers.map((s) => s.toLowerCase().trim()));
    return (
      h.has('url') &&
      h.has('username') &&
      h.has('password') &&
      h.has('httprealm') // distinguishes Firefox from Chrome (which has 'name' but not 'httpRealm')
    );
  },
  map(row: Record<string, string>): Partial<{ title: string; url: string; username: string; password: string; notes: string }> {
    // Firefox has no name column; derive title from URL (as documented in RESEARCH Pattern 3).
    // Use case-insensitive `get` for parity with detect() (FIX 2).
    const url = get(row, 'url') ?? '';
    return {
      title:    url,
      url:      url,
      username: get(row, 'username') ?? '',
      password: get(row, 'password') ?? '',
      notes:    '',
    };
  },
};

// ---------------------------------------------------------------------------
// Bitwarden
// ---------------------------------------------------------------------------

/**
 * Mapper for Bitwarden CSV exports.
 *
 * Required headers: `login_uri`, `login_username`, `login_password`
 * (case-insensitive).
 *
 * The Bitwarden export format is:
 *   `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp`
 *
 * [VERIFIED: Bitwarden CSV export format, 2026-06-02]
 */
export const BITWARDEN_MAPPER: ImportMapper = {
  name: 'bitwarden',
  detect(headers: string[]): boolean {
    const h = new Set(headers.map((s) => s.toLowerCase().trim()));
    return (
      h.has('login_uri') &&
      h.has('login_username') &&
      h.has('login_password')
    );
  },
  map(row: Record<string, string>): Partial<{ title: string; url: string; username: string; password: string; notes: string }> {
    // Use case-insensitive `get` for parity with detect() (FIX 2).
    return {
      title:    get(row, 'name')           ?? '',
      url:      get(row, 'login_uri')      ?? '',
      username: get(row, 'login_username') ?? '',
      password: get(row, 'login_password') ?? '',
      notes:    get(row, 'notes')          ?? '',
    };
  },
};

// ---------------------------------------------------------------------------
// ALL_MAPPERS — ordered array for detectFormat() to iterate
// ---------------------------------------------------------------------------

/**
 * All known format mappers in detection-priority order.
 *
 * `detectFormat()` iterates this array and returns the first mapper whose
 * `detect()` returns true. Order matters:
 *   1. Bitwarden — most specific (`login_uri` / `login_username`)
 *   2. Firefox   — strong discriminator: `httpRealm`
 *   3. Chrome/Edge — broadest: requires `name`+`url`+`username`+`password`
 */
export const ALL_MAPPERS: ImportMapper[] = [
  BITWARDEN_MAPPER,
  FIREFOX_MAPPER,
  CHROME_EDGE_MAPPER,
];
