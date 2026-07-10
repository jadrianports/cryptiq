<!--
  HealthView.svelte — Password health dashboard (P6-06 / AUDIT-01..06).

  Responsibilities:
    1. Score every active entry's password locally with zxcvbn-ts (AUDIT-01 — no network).
       Score cache + audit orchestration live in healthAudit.svelte.ts (session store).
    2. Read staleThresholdDays from getVaultSettings() (AUDIT-04 / P6-08) — delegated to
       the store's ensureAuditFresh call.
    3. Call ensureAuditFresh(vault, scoreEntry) via $effect.pre — runs BEFORE paint so
       small-miss results (incl. the fix-return case) are ready before the frame renders.
    4. Render four count cards; clicking a card reveals the flagged entries below
       (drill-down pattern, P6-06).
    5. Jump-to-fix (AUDIT-06 / P6-07):
         Weak/Reused/Stale → set ui.selectedEntryId + ui.openGeneratorFor + go('main')
         Needs-update      → set ui.selectedEntryId + ui.openNeedsSiteUpdateFor + go('main')
    6. All-clear empty state when all four buckets are empty (P6-06).

  Security invariants:
    T-06-12: entries held in healthAudit.result ($state.raw) — NEVER copied into $state
             (Pitfall 7). Cache key is id+modifiedAt, NEVER the plaintext password.
    T-06-13: zxcvbn-ts is fully local (bundled dictionaries); no fetch/http (AUDIT-01).
    T-06-14: staleThresholdDays via getVaultSettings() only; default 365 when absent.
    No console.* of passwords or any secret data.

  $effect.pre semantics: runs BEFORE the DOM is updated for the current reactive frame.
  For the small-miss synchronous path (SYNC_THRESHOLD ≤ 8, including the critical 1-miss
  fix-return), ensureAuditFresh completes synchronously inside the $effect.pre callback,
  writing the new result to healthAudit.result before the frame paints. This guarantees
  zero stale-flag flash on fix-return.

  For the large-miss (cold/bulk) path, ensureAuditFresh sets status='scanning'
  synchronously (captured in $effect.pre before paint), so the skeleton frame shows
  instead of stale data, and the async chunks fill in without blocking the main thread.

  zxcvbn-ts setup: delegates to apps/desktop/src/lib/zxcvbnSetup.ts's shared
  lazy-singleton (Phase 17 Plan 02 extraction) — same module StrengthMeter.svelte
  and rpcDispatch.ts use. Does NOT duplicate option init locally.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import type { Entry } from '@cryptiq/core';
  import { vaultSession } from '../state/vault.svelte';
  import { ui } from '../state/ui.svelte';
  import { go } from '../state/view.svelte';
  import { healthAudit, ensureAuditFresh } from '../state/healthAudit.svelte';
  import { breachAudit, ensureBreachAuditFresh, retryUnknown } from '../state/breachAudit.svelte';
  import { hibpInvoke } from '../adapters/hibpInvoke';
  import { loadConfig } from '../config/config-adapter';
  import { scorePassword } from '../zxcvbnSetup';
  import VisualIdentity from '../components/VisualIdentity.svelte';
  import Sidebar from '../components/Sidebar.svelte';

  // ── Score injector (T-06-12 / T-06-13) ──────────────────────────────────────
  // The scorer is defined here (desktop layer owns zxcvbn); injected into the store
  // so the store module does NOT import zxcvbn directly → stays unit-testable.
  // Delegates to the shared zxcvbnSetup.ts singleton (Phase 17 Plan 02 extraction) —
  // no more local zxcvbn-ts configuration in this file.
  function scoreEntry(e: Entry): number {
    return scorePassword(e.password);
  }

  // ── $effect.pre: trigger audit before paint ──────────────────────────────────
  // $effect.pre runs BEFORE the DOM is updated for the current reactive frame.
  // Tracking dep: vaultSession.vault — reassigned on every CRUD mutation.
  //
  // Small-miss path (≤ 8 misses, including the critical 1-miss fix-return case):
  //   ensureAuditFresh() runs synchronously inside $effect.pre, writing the new
  //   result before paint → ZERO stale-flag flash on fix-return. Flash-free guaranteed.
  //
  // Large-miss path (cold open / bulk import):
  //   ensureAuditFresh() sets status='scanning' synchronously (captured before paint),
  //   so the skeleton shows instead of stale data. Async chunks fill in without blocking.
  $effect.pre(() => {
    const vault = vaultSession.vault; // tracked dep
    // void the returned Promise — $effect.pre is synchronous; async work is internal
    void ensureAuditFresh(vault, scoreEntry);
  });

  // ── Drill-down state ─────────────────────────────────────────────────────────
  // Plain $state (category label is not secret). null = no card expanded.
  type AuditCategory = 'reused' | 'weak' | 'stale' | 'needsUpdate';
  let selectedCategory = $state<AuditCategory | null>(null);

  function toggleCategory(cat: AuditCategory): void {
    selectedCategory = selectedCategory === cat ? null : cat;
  }

  // ── Jump-to-fix (AUDIT-06 / P6-07) ──────────────────────────────────────────
  // Weak/Reused/Stale: auto-open generator popover on the selected entry.
  // Needs-update: focus the needsSiteUpdate toggle instead.
  // Widened to accept 'breached' (D-12) — it only branches on === 'needsUpdate',
  // so a breached entry takes the same `else`/openGeneratorFor path as weak/reused/stale.
  function jumpToFix(entry: Entry, category: AuditCategory | 'breached'): void {
    // Reset listFilter FIRST — must be 'all' so MainView's recently-deleted branch
    // does not short-circuit before the selectedEntryId branch (Fix 1 / routing bug).
    // Flagged/audited entries are always active (deletedAt === null), so 'all' is correct.
    ui.listFilter = 'all';
    ui.selectedEntryId = entry.id;
    if (category === 'needsUpdate') {
      ui.openNeedsSiteUpdateFor = entry.id;
    } else {
      ui.openGeneratorFor = entry.id;
    }
    go('main');
  }

  // ── Breach dimension (HIBP-02/HIBP-04/HIBP-05, 31-04-PLAN.md) ───────────────
  // Bespoke overlay on top of the 4-bucket healthAudit machinery — 'breached' is
  // deliberately kept OUT of AuditCategory/CARDS/countFor/entriesFor (those index
  // healthAudit.result[key], which has no breached bucket — routing 'breached'
  // through the generic CARDS.find(...)! drill-down below would throw at runtime).

  /** Consent flag (D-01/D-02), read from config.json on mount. Default OFF. */
  let entryScanConsent = $state(false);

  /** Own toggle for the breach drill-down — independent of `selectedCategory`. */
  let showBreachDrillDown = $state(false);

  onMount(() => {
    void (async () => {
      const cfg = await loadConfig();
      entryScanConsent = cfg.hibpEntryScanEnabled ?? false;
      // Session-once trigger (D-04): rely on breachAudit.hasSwept, NOT the
      // vaultSession.vault-tracking $effect.pre above (that re-fires on every
      // CRUD save). A revisit within the same unlocked session after the first
      // sweep renders instantly from cache — no re-sweep, no scanning flash.
      if (entryScanConsent && !breachAudit.hasSwept) {
        await ensureBreachAuditFresh(vaultSession.vault, hibpInvoke);
      }
    })();
  });

  const breachedCount = $derived(breachAudit.result?.breached.length ?? 0);
  const unknownCount = $derived(breachAudit.result?.unknown.length ?? 0);

  /** Card variant: 'disabled' (consent OFF) | 'scanning' (first sweep in flight,
   *  digits withheld) | 'resolved' (cache hit or sweep settled, two-tone counts). */
  const breachCardVariant = $derived(
    !entryScanConsent ? 'disabled' : breachAudit.status === 'scanning' && !breachAudit.hasSwept ? 'scanning' : 'resolved',
  );

  /** Copywriting Contract: "{N} breached" (unknown===0) or "{N} breached · {M} unknown"
   *  (never omit the unknown clause when unknown>0 — the SC-4/HIBP-05 rendering). */
  const breachCountLabel = $derived(
    unknownCount === 0 ? `${breachedCount} breached` : `${breachedCount} breached · ${unknownCount} unknown`,
  );

  function handleRecheck(): void {
    // Forces a full fresh sweep, bypassing the session-once hasSwept guard.
    void ensureBreachAuditFresh(vaultSession.vault, hibpInvoke);
  }

  function handleRetryUnknown(): void {
    void retryUnknown(vaultSession.vault, hibpInvoke);
  }

  function toggleBreachDrillDown(): void {
    if (breachCardVariant === 'resolved' && breachedCount + unknownCount > 0) {
      showBreachDrillDown = !showBreachDrillDown;
    }
  }

  type BreachRow = { entry: Entry; kind: 'breached' | 'unknown' };

  /** Breached entries first, then unknown — reads directly from breachAudit.result,
   *  never countFor/entriesFor (those are healthAudit-keyed only). */
  const breachRows = $derived<BreachRow[]>(
    breachAudit.result === null
      ? []
      : [
          ...breachAudit.result.breached.map((entry): BreachRow => ({ entry, kind: 'breached' })),
          ...breachAudit.result.unknown.map((entry): BreachRow => ({ entry, kind: 'unknown' })),
        ],
  );

  // ── All-clear helper ─────────────────────────────────────────────────────────
  // Widened (load-bearing, D-10/HIBP-05): when breach-scan consent is ON, a
  // genuine "All clear" claim additionally requires the sweep to have SETTLED
  // (hasSwept && status !== 'scanning') AND breached===0 && unknown===0 — the
  // all-zero INITIAL breach state must not make this true during the in-flight
  // window (healthAudit resolves synchronously, breachAudit does not), which
  // would render a false "All clear" hero and hide the 5th card's scanning
  // state. When consent is OFF, the existing 4-bucket check is unaffected.
  const isAllClear = $derived(
    healthAudit.result !== null &&
      healthAudit.result.reused.length === 0 &&
      healthAudit.result.weak.length === 0 &&
      healthAudit.result.stale.length === 0 &&
      healthAudit.result.needsUpdate.length === 0 &&
      (!entryScanConsent ||
        (breachAudit.hasSwept && breachAudit.status !== 'scanning' && breachedCount === 0 && unknownCount === 0)),
  );

  // ── Card metadata ────────────────────────────────────────────────────────────
  type CardDef = {
    key: AuditCategory;
    label: string;
    description: string;
    colorClass: string; // Tailwind token for the count badge
    iconPath: string;   // SVG path data
  };

  const CARDS: CardDef[] = [
    {
      key: 'reused',
      label: 'Reused',
      description: 'Same password used across multiple entries.',
      colorClass: 'text-cryptiq-danger',
      iconPath: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zm7-4h6m-3-3v6',
    },
    {
      key: 'weak',
      label: 'Weak',
      description: 'Password strength is too low (zxcvbn score ≤ 2).',
      colorClass: 'text-cryptiq-attention',
      iconPath: 'M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z',
    },
    {
      key: 'stale',
      label: 'Stale',
      description: 'Password not changed within the stale threshold.',
      colorClass: 'text-cryptiq-fg-muted',
      iconPath: 'M12 8v4l3 3M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z',
    },
    {
      key: 'needsUpdate',
      label: 'Needs update',
      description: 'Flagged to revisit and rotate.',
      colorClass: 'text-cryptiq-accent',
      iconPath: 'M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4m0 4h.01',
    },
  ];

  function countFor(key: AuditCategory): number {
    if (healthAudit.result === null) return 0;
    return healthAudit.result[key].length;
  }

  function entriesFor(key: AuditCategory): Entry[] {
    if (healthAudit.result === null) return [];
    return healthAudit.result[key];
  }
</script>

<div class="flex h-screen overflow-hidden bg-cryptiq-bg">
  <!-- Sidebar (persistent rail — same as MainView, enables sidebar nav) -->
  <Sidebar />

  <!-- Main content area -->
  <div class="flex flex-1 flex-col overflow-y-auto">
  <!-- Header -->
  <header class="border-b border-cryptiq-border bg-cryptiq-surface px-6 py-5">
    <div class="flex items-center gap-3">
      <!-- Shield icon -->
      <svg
        class="size-6 text-cryptiq-fg-subtle"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="1.75"
        stroke-linecap="round"
        stroke-linejoin="round"
        aria-hidden="true"
      >
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
      <div>
        <h1 class="text-title font-semibold text-cryptiq-fg">Password Health</h1>
        <p class="text-meta text-cryptiq-fg-muted">All checks run locally — no network access.</p>
      </div>
    </div>
  </header>

  <div class="flex-1 px-6 py-5">
    {#if healthAudit.status === 'scanning' && healthAudit.result === null}
      <!-- Cold open / bulk import: skeleton while first scan completes.
           UI is fully clickable; scoring runs in async chunks off the main thread. -->
      <div class="flex flex-col items-center justify-center gap-2 py-12 text-center">
        <p class="text-body text-cryptiq-fg-muted">Analyzing password health…</p>
      </div>
    {:else if healthAudit.result === null}
      <!-- Vault not unlocked -->
      <div class="flex flex-col items-center justify-center gap-2 py-12 text-center">
        <p class="text-body text-cryptiq-fg-muted">Vault is not unlocked.</p>
      </div>
    {:else if isAllClear}
      <!-- All clear empty state (P6-06) -->
      <div class="flex flex-col items-center justify-center gap-4 py-16 text-center">
        <svg
          class="size-12 text-cryptiq-success"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
          stroke-linecap="round"
          stroke-linejoin="round"
          aria-hidden="true"
        >
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <path d="m9 12 2 2 4-4" />
        </svg>
        <div>
          <p class="text-title font-semibold text-cryptiq-fg">All clear</p>
          <p class="mt-1 text-body text-cryptiq-fg-muted">No issues found. Your passwords look great.</p>
        </div>
      </div>
    {:else}
      <!-- Four count cards.
           When status='scanning' and result is present (background refresh), the existing
           result remains visible — non-blocking. A subtle "refreshing" affordance could be
           added here in the future; for now the instant-cache-hit case makes this rare. -->
      <div class="mb-6 grid grid-cols-2 gap-3">
        {#each CARDS as card (card.key)}
          {@const count = countFor(card.key)}
          <button
            type="button"
            onclick={() => { if (count > 0) toggleCategory(card.key); }}
            aria-expanded={selectedCategory === card.key}
            aria-label="{card.label}: {count} {count === 1 ? 'entry' : 'entries'}"
            class="flex flex-col gap-2 rounded-cryptiq border bg-cryptiq-surface p-4 text-left transition-colors
                   {count === 0
                     ? 'cursor-default border-cryptiq-border opacity-50'
                     : selectedCategory === card.key
                       ? 'border-cryptiq-accent bg-cryptiq-surface-2 shadow-cryptiq-panel'
                       : 'cursor-pointer border-cryptiq-border hover:border-cryptiq-accent hover:bg-cryptiq-surface-2'}"
          >
            <div class="flex items-center justify-between gap-2">
              <svg
                class="size-5 text-cryptiq-fg-subtle"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="1.75"
                stroke-linecap="round"
                stroke-linejoin="round"
                aria-hidden="true"
              >
                <path d={card.iconPath} />
              </svg>
              <span class="text-2xl font-bold tabular-nums {count > 0 ? card.colorClass : 'text-cryptiq-fg-subtle'}">
                {count}
              </span>
            </div>
            <div>
              <p class="text-body font-semibold text-cryptiq-fg">{card.label}</p>
              <p class="text-meta text-cryptiq-fg-muted leading-snug">{card.description}</p>
            </div>
          </button>
        {/each}

        <!-- 5th card: breach dimension (HIBP-02/HIBP-05) — bespoke block, NOT part of
             the CARDS loop (CardDef has only one count slot; this card needs two). -->
        <div class="col-span-2 flex flex-col gap-2 rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface p-4 text-left">
          {#if breachCardVariant === 'disabled'}
            <div class="flex items-center justify-between gap-2">
              <svg
                class="size-5 text-cryptiq-fg-subtle"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="1.75"
                stroke-linecap="round"
                stroke-linejoin="round"
                aria-hidden="true"
              >
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <path d="M12 8v4m0 4h.01" />
              </svg>
            </div>
            <div>
              <p class="text-body font-semibold text-cryptiq-fg">Breach checking is off</p>
              <p class="text-meta text-cryptiq-fg-muted leading-snug">
                Turn it on to check your stored passwords against known data breaches.
              </p>
            </div>
            <button
              type="button"
              onclick={() => go('settings')}
              class="self-start text-meta font-medium text-cryptiq-accent"
            >
              Turn on breach checking →
            </button>
          {:else if breachCardVariant === 'scanning'}
            <div class="flex items-center justify-between gap-2">
              <svg
                class="size-5 text-cryptiq-fg-subtle"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="1.75"
                stroke-linecap="round"
                stroke-linejoin="round"
                aria-hidden="true"
              >
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <path d="M12 8v4m0 4h.01" />
              </svg>
              <span class="text-meta text-cryptiq-fg-muted">Checking passwords…</span>
            </div>
            <div>
              <p class="text-body font-semibold text-cryptiq-fg">Breached</p>
              <p class="text-meta text-cryptiq-fg-muted leading-snug">Passwords found in known data breaches.</p>
            </div>
          {:else}
            <div class="flex items-center justify-between gap-2">
              <button
                type="button"
                onclick={toggleBreachDrillDown}
                aria-expanded={showBreachDrillDown}
                aria-label={breachCountLabel}
                class="flex flex-1 items-center gap-2 text-left
                       {breachedCount + unknownCount > 0 ? 'cursor-pointer' : 'cursor-default'}"
              >
                <svg
                  class="size-5 {breachedCount > 0 ? 'text-cryptiq-danger' : 'text-cryptiq-fg-subtle'}"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="1.75"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  aria-hidden="true"
                >
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                  <path d="M12 8v4m0 4h.01" />
                </svg>
                <span class="flex items-baseline gap-1.5">
                  <span class="text-2xl font-bold tabular-nums {breachedCount > 0 ? 'text-cryptiq-danger' : 'text-cryptiq-fg-subtle'}">
                    {breachedCount}
                  </span>
                  {#if unknownCount > 0}
                    <span class="text-cryptiq-fg-muted" aria-hidden="true">·</span>
                    <span class="size-1.5 rounded-full bg-cryptiq-attention" aria-hidden="true"></span>
                    <span class="text-2xl font-bold tabular-nums text-cryptiq-fg">{unknownCount}</span>
                  {/if}
                </span>
              </button>
              <button type="button" onclick={handleRecheck} class="shrink-0 text-meta text-cryptiq-accent">
                Re-check
              </button>
            </div>
            <div>
              <p class="text-body font-semibold text-cryptiq-fg">Breached</p>
              <p class="text-meta text-cryptiq-fg-muted leading-snug">Passwords found in known data breaches.</p>
            </div>
            {#if unknownCount > 0}
              <button
                type="button"
                onclick={handleRetryUnknown}
                class="self-start text-meta text-cryptiq-accent"
              >
                Retry {unknownCount} unknown
              </button>
            {/if}
          {/if}
        </div>
      </div>

      <!-- Breach drill-down (bespoke, SEPARATE from the generic selectedCategory block
           below — 'breached' never reaches CARDS.find(...)!/countFor/entriesFor). -->
      {#if showBreachDrillDown && breachCardVariant === 'resolved'}
        <section aria-label="Breached entries">
          <h2 class="mb-3 text-body font-semibold text-cryptiq-fg">
            Breached
            <span class="ml-1.5 text-meta text-cryptiq-fg-muted">({breachRows.length})</span>
          </h2>
          <ul class="space-y-1.5" role="list">
            {#each breachRows as row (row.entry.id)}
              <li>
                {#if row.kind === 'breached'}
                  <button
                    type="button"
                    onclick={() => jumpToFix(row.entry, 'breached')}
                    class="flex w-full items-center gap-3 rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface px-3 py-2.5
                           text-left transition-colors hover:border-cryptiq-accent hover:bg-cryptiq-surface-2"
                    aria-label="Fix {row.entry.title}"
                  >
                    <VisualIdentity label={row.entry.title} size={36} />
                    <span class="inline-flex shrink-0 items-center gap-1 rounded-full bg-cryptiq-danger px-2 py-0.5 text-meta font-medium text-cryptiq-danger-fg">
                      Breached
                    </span>
                    <div class="min-w-0 flex-1">
                      <p class="truncate text-body font-medium text-cryptiq-fg">{row.entry.title}</p>
                      {#if row.entry.username}
                        <p class="truncate text-meta text-cryptiq-fg-muted">{row.entry.username}</p>
                      {/if}
                    </div>
                    <div class="flex shrink-0 items-center gap-1.5 text-meta text-cryptiq-accent">
                      <span class="hidden sm:inline">Fix</span>
                      <svg
                        class="size-4"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="1.75"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        aria-hidden="true"
                      >
                        <path d="m9 18 6-6-6-6" />
                      </svg>
                    </div>
                  </button>
                {:else}
                  <div
                    class="flex w-full items-center gap-3 rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface px-3 py-2.5"
                  >
                    <VisualIdentity label={row.entry.title} size={36} />
                    <span
                      class="inline-flex shrink-0 items-center gap-1 rounded-full bg-cryptiq-attention px-2 py-0.5 text-meta font-medium text-cryptiq-fg dark:text-cryptiq-bg"
                      aria-label="Could not be checked — network error, offline, or rate-limited"
                    >
                      Unknown
                    </span>
                    <div class="min-w-0 flex-1">
                      <p class="truncate text-body font-medium text-cryptiq-fg">{row.entry.title}</p>
                      {#if row.entry.username}
                        <p class="truncate text-meta text-cryptiq-fg-muted">{row.entry.username}</p>
                      {/if}
                    </div>
                  </div>
                {/if}
              </li>
            {/each}
          </ul>
        </section>
      {/if}

      <!-- Drill-down list for selected category -->
      {#if selectedCategory !== null}
        {@const entries = entriesFor(selectedCategory)}
        {@const cardDef = CARDS.find((c) => c.key === selectedCategory)!}
        <section aria-label="{cardDef.label} entries">
          <h2 class="mb-3 text-body font-semibold text-cryptiq-fg">
            {cardDef.label}
            <span class="ml-1.5 text-meta text-cryptiq-fg-muted">({entries.length})</span>
          </h2>
          <ul class="space-y-1.5" role="list">
            {#each entries as entry (entry.id)}
              <li>
                <button
                  type="button"
                  onclick={() => jumpToFix(entry, selectedCategory!)}
                  class="flex w-full items-center gap-3 rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface px-3 py-2.5
                         text-left transition-colors hover:border-cryptiq-accent hover:bg-cryptiq-surface-2"
                  aria-label="Fix {entry.title}"
                >
                  <VisualIdentity label={entry.title} size={36} />
                  <div class="min-w-0 flex-1">
                    <p class="truncate text-body font-medium text-cryptiq-fg">{entry.title}</p>
                    {#if entry.username}
                      <p class="truncate text-meta text-cryptiq-fg-muted">{entry.username}</p>
                    {/if}
                  </div>
                  <!-- Jump-to-fix affordance -->
                  <div class="flex shrink-0 items-center gap-1.5 text-meta text-cryptiq-accent">
                    <span class="hidden sm:inline">Fix</span>
                    <svg
                      class="size-4"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      stroke-width="1.75"
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      aria-hidden="true"
                    >
                      <path d="m9 18 6-6-6-6" />
                    </svg>
                  </div>
                </button>
              </li>
            {/each}
          </ul>
        </section>
      {/if}
    {/if}
  </div>
  </div>
</div>
