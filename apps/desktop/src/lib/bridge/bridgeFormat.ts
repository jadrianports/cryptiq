// apps/desktop/src/lib/bridge/bridgeFormat.ts
//
// Pure formatting helpers for the "Browser Extensions" settings section (D-03).
//
// ExtensionSettingsSection shows a "paired date" AND a "last-used" relative time —
// DeviceList only has "last synced". Rather than hardcode the "Last synced" verb
// baked into sync's formatRelativeLastSynced, this sibling takes an injectable verb
// so the identical relative-time logic serves both the "Paired" and "Last used" rows
// (15-PATTERNS.md: "reuse it or copy its shape into a bridgeFormat.ts sibling").
//
// Core purity note: pure TS, no Svelte/Tauri/node:fs import.

/**
 * Format a relative time label from an ISO 8601 timestamp, prefixed with a
 * caller-supplied verb phrase (e.g. "Paired", "Last used").
 *
 * Returns:
 *  - "{neverLabel}"              when ts is null
 *  - "{verb} just now"           when the timestamp is within the last 60 seconds
 *  - "{verb} {N} minutes ago"    for 1-59 minutes
 *  - "{verb} {N} hours ago"      for 1-23 hours
 *  - "{verb} {N} days ago"       for 24 h+
 *
 * The `now` parameter is injectable for deterministic tests — defaults to Date.now().
 *
 * @param ts          ISO 8601 timestamp string, or null.
 * @param verb        The verb phrase prefixing the relative time (e.g. "Paired").
 * @param neverLabel  The label shown when ts is null (e.g. "Never used").
 * @param now         Current epoch ms (injectable — defaults to Date.now()).
 * @returns           A user-facing relative time string.
 */
export function formatRelativeBridgeTime(
  ts: string | null,
  verb: string,
  neverLabel: string,
  now?: number,
): string {
  if (ts === null || ts === undefined || ts === '') {
    return neverLabel;
  }

  const nowMs = now !== undefined ? now : Date.now();
  const thenMs = new Date(ts).getTime();
  const diffMs = nowMs - thenMs;

  if (diffMs < 0) {
    // Future timestamp (clock skew) — treat as just now.
    return `${verb} just now`;
  }

  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 60) {
    return `${verb} just now`;
  }

  const diffMin = Math.floor(diffMs / (60 * 1000));
  if (diffMin < 60) {
    return `${verb} ${String(diffMin)} minute${diffMin === 1 ? '' : 's'} ago`;
  }

  const diffHour = Math.floor(diffMs / (60 * 60 * 1000));
  if (diffHour < 24) {
    return `${verb} ${String(diffHour)} hour${diffHour === 1 ? '' : 's'} ago`;
  }

  const diffDay = Math.floor(diffMs / (24 * 60 * 60 * 1000));
  return `${verb} ${String(diffDay)} day${diffDay === 1 ? '' : 's'} ago`;
}

/** Format the "paired date" row — pairedAt is always present (set at approval time). */
export function formatPairedAt(ts: string, now?: number): string {
  return formatRelativeBridgeTime(ts, 'Paired', 'Paired', now);
}

/** Format the "last-used" row — lastUsedAt is null until the first authenticated RPC. */
export function formatLastUsedAt(ts: string | null, now?: number): string {
  return formatRelativeBridgeTime(ts, 'Last used', 'Never used', now);
}
