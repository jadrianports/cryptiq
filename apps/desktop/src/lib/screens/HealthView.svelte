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

  zxcvbn-ts setup: reuses the same lazy-singleton pattern as StrengthMeter.svelte
  (module-level ensureZxcvbnConfigured, called once). Does NOT duplicate option init.
-->
<script lang="ts" module>
  // zxcvbn-ts lazy singleton — mirrors StrengthMeter.svelte to ensure options are
  // set exactly once across the module boundary (language packs are heavy).
  import { zxcvbn, zxcvbnOptions } from '@zxcvbn-ts/core';
  import * as zxcvbnCommon from '@zxcvbn-ts/language-common';
  import * as zxcvbnEn from '@zxcvbn-ts/language-en';

  let _zxcvbnConfigured = false;

  function ensureZxcvbnConfigured(): void {
    if (_zxcvbnConfigured) return;
    zxcvbnOptions.setOptions({
      translations: zxcvbnEn.translations,
      graphs: zxcvbnCommon.adjacencyGraphs,
      dictionary: {
        ...zxcvbnCommon.dictionary,
        ...zxcvbnEn.dictionary,
      },
    });
    _zxcvbnConfigured = true;
  }
</script>

<script lang="ts">
  import type { Entry } from '@cryptiq/core';
  import { vaultSession } from '../state/vault.svelte';
  import { ui } from '../state/ui.svelte';
  import { go } from '../state/view.svelte';
  import { healthAudit, ensureAuditFresh } from '../state/healthAudit.svelte';
  import VisualIdentity from '../components/VisualIdentity.svelte';
  import Sidebar from '../components/Sidebar.svelte';

  // ── Score injector (T-06-12 / T-06-13) ──────────────────────────────────────
  // The scorer is defined here (desktop layer owns zxcvbn); injected into the store
  // so the store module does NOT import zxcvbn directly → stays unit-testable.
  // ensureZxcvbnConfigured() is idempotent — safe to call on every score request.
  function scoreEntry(e: Entry): number {
    ensureZxcvbnConfigured();
    return zxcvbn(e.password).score;
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
  function jumpToFix(entry: Entry, category: AuditCategory): void {
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

  // ── All-clear helper ─────────────────────────────────────────────────────────
  const isAllClear = $derived(
    healthAudit.result !== null &&
      healthAudit.result.reused.length === 0 &&
      healthAudit.result.weak.length === 0 &&
      healthAudit.result.stale.length === 0 &&
      healthAudit.result.needsUpdate.length === 0,
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
      </div>

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
