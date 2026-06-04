// packages/core/src/sync/duplicate.ts
//
// Advisory duplicate-detection helper for Phase 8 (D-19).
//
// Contract:
//   - Advisory only — no auto-merge; keep-both (MERGE-03) remains the merge rule.
//   - Groups active entries sharing a normalized (lowercased, trimmed) title + url.
//   - Returns an empty array when no duplicates are found — never throws.
//   - Zero IO: no Tauri, no Svelte, no node:fs, no node:path, no libsodium imports.
//
// Phase 12 renders the duplicate hint; the engine never coalesces duplicates.
//
// Source: CONTEXT.md D-19; PATTERNS.md duplicate.ts section

import type { InnerDoc, Entry } from '../entries/types';
import type { PossibleDuplicate } from './types';

/**
 * Find groups of active entries that share a normalized (lowercased, trimmed)
 * `title` + `url`.
 *
 * Advisory only — the caller decides what to do with the hints (D-19). Never throws;
 * returns an empty array when no duplicates are present.
 *
 * @param doc - The merged or local `InnerDoc` to inspect.
 * @returns Array of groups with 2+ entries sharing the same normalized title + url.
 *          Sorted deterministically by normalized key.
 */
export function findPossibleDuplicates(doc: InnerDoc): PossibleDuplicate[] {
  // D-19: only ACTIVE entries (deletedAt === null); tombstones are never duplicate-flagged.
  const activeEntries = doc.entries.filter((e: Entry) => e.deletedAt === null);

  // Group by normalized (trimmed, lowercased) title + url. Use a JSON-encoded tuple
  // as the key so it is collision-free for ALL inputs — a raw separator (e.g. '\x00')
  // is spoofable: title 'a\x00b'+url 'c' would collide with title 'a'+url 'b\x00c'.
  const groups = new Map<string, Entry[]>();

  for (const entry of activeEntries) {
    const normalizedTitle = entry.title.trim().toLowerCase();
    const normalizedUrl = entry.url.trim().toLowerCase();
    const key = JSON.stringify([normalizedTitle, normalizedUrl]);

    const group = groups.get(key);
    if (group !== undefined) {
      group.push(entry);
    } else {
      groups.set(key, [entry]);
    }
  }

  // Collect groups of size > 1 and sort result deterministically by normalized key.
  const result: PossibleDuplicate[] = [];

  const sortedKeys = [...groups.keys()].sort();

  for (const key of sortedKeys) {
    const group = groups.get(key)!;
    if (group.length > 1) {
      // title/url from first entry (original casing, as documented in D-19)
      const first = group[0]!;
      result.push({
        title: first.title,
        url: first.url,
        entries: group,
      });
    }
  }

  return result;
}
