// apps/desktop/src/lib/sync/syncFormat.ts
//
// Pure formatting helpers for sync status strings (UI-18 / D-14 / D-16).
//
// SECURITY (UI-18 counts-only fence):
//   These helpers interpolate ONLY integer MergeCounts fields + static labels.
//   NO entry title, username, password, URL, or tags ever appear in sync strings.
//   The syncCountsFence.test.ts node test pins the exact output and asserts the fence.
//
// Core purity note: MergeCounts is imported type-only from @cryptiq/core.
//   This file imports no Svelte, no Tauri, no node:fs — pure TS.

import type { MergeCounts } from '@cryptiq/core';

/**
 * Format a sync summary string from merge counts (D-14 / UI-18 fence).
 *
 * Returns "Synced — {added} added, {updated} updated, {deleted} deleted, {unchanged} unchanged"
 * or "Already up to date." when all mutation counts are zero.
 *
 * SECURITY: interpolates ONLY integer count fields. No entry data. The output
 * matches /^Synced — \d+ added, \d+ updated, \d+ deleted, \d+ unchanged$/ for
 * non-zero-change syncs — asserted by syncCountsFence.test.ts (UI-18 node gate).
 *
 * @param counts The MergeCounts object from the last successful sync.
 * @returns A user-facing summary string.
 */
export function formatSyncSummary(counts: MergeCounts): string {
  const { added, updated, deleted, unchanged } = counts;
  if (added === 0 && updated === 0 && deleted === 0) {
    return 'Already up to date.';
  }
  return `Synced — ${String(added)} added, ${String(updated)} updated, ${String(deleted)} deleted, ${String(unchanged)} unchanged`;
}

/**
 * Format a relative "last synced" label from an ISO 8601 timestamp (D-16).
 *
 * Returns:
 *  - "Never synced"         when ts is null
 *  - "Last synced just now" when the timestamp is within the last 60 seconds
 *  - "Last synced {N} minutes ago" for 1–59 minutes
 *  - "Last synced {N} hours ago"   for 1–23 hours
 *  - "Last synced {N} days ago"    for 24 h+
 *
 * The `now` parameter is injectable for deterministic tests — defaults to Date.now().
 *
 * @param ts  ISO 8601 timestamp string, or null for a never-synced device.
 * @param now Current epoch ms (injectable — defaults to Date.now()).
 * @returns A user-facing relative time string.
 */
export function formatRelativeLastSynced(ts: string | null, now?: number): string {
  if (ts === null || ts === undefined || ts === '') {
    return 'Never synced';
  }

  const nowMs = now !== undefined ? now : Date.now();
  const thenMs = new Date(ts).getTime();
  const diffMs = nowMs - thenMs;

  if (diffMs < 0) {
    // Future timestamp (clock skew) — treat as just now.
    return 'Last synced just now';
  }

  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 60) {
    return 'Last synced just now';
  }

  const diffMin = Math.floor(diffMs / (60 * 1000));
  if (diffMin < 60) {
    return `Last synced ${String(diffMin)} minute${diffMin === 1 ? '' : 's'} ago`;
  }

  const diffHour = Math.floor(diffMs / (60 * 60 * 1000));
  if (diffHour < 24) {
    return `Last synced ${String(diffHour)} hour${diffHour === 1 ? '' : 's'} ago`;
  }

  const diffDay = Math.floor(diffMs / (24 * 60 * 60 * 1000));
  return `Last synced ${String(diffDay)} day${diffDay === 1 ? '' : 's'} ago`;
}
