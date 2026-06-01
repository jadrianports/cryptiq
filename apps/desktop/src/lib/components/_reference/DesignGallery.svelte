<!--
  DesignGallery.svelte — preview harness for the Phase 4 canonical components.

  NOT a shipped screen. It exists so the design source-of-truth components can be
  reviewed (light + dark, real layout) before the planner wires them to the
  VaultSession. To preview: temporarily render <DesignGallery /> from App.svelte
  (behind the sodium gate) and run `pnpm --filter @cryptiq/desktop dev`. The
  planner does NOT build on this file — it builds on the four components it shows.

  Mock data only; no @cryptiq/core, no VaultSession, no IPC.
-->
<script lang="ts">
  import EntryListRow from '../EntryListRow.svelte';
  import FirstRunStep from '../FirstRunStep.svelte';
  import GeneratorSurface from '../GeneratorSurface.svelte';

  type MockEntry = {
    id: string;
    title: string;
    username: string;
    favorite: boolean;
    needsUpdate: boolean;
    password: string;
    url: string;
    notes: string;
  };

  const entries: MockEntry[] = [
    { id: '1', title: 'GitHub', username: 'ada@hey.com', favorite: true, needsUpdate: false, password: 'Tq7$mK9pL2vR4nW8xZ', url: 'https://github.com', notes: 'Personal account. 2FA via authenticator.' },
    { id: '2', title: 'Proton Mail', username: 'ada.lovelace', favorite: true, needsUpdate: false, password: 'cinder-velvet-quartz-meadow-41', url: 'https://proton.me', notes: '' },
    { id: '3', title: 'Bank of Analytical Engines', username: 'a.lovelace', favorite: false, needsUpdate: true, password: 'H8!pQ2mZ6kL9wX4tB', url: 'https://example-bank.test', notes: 'Forces password reset every 90 days.' },
    { id: '4', title: 'Figma', username: 'ada@hey.com', favorite: false, needsUpdate: false, password: 'willow-ember-plume-cobalt', url: 'https://figma.com', notes: '' },
    { id: '5', title: 'Vercel', username: 'ada', favorite: false, needsUpdate: false, password: 'R3#vN7mP1kQ8sJ5dF', url: 'https://vercel.com', notes: '' },
  ];

  const sidebar = [
    { label: 'All items', count: 128, active: true },
    { label: 'Favorites', count: 12, active: false },
    { label: 'Needs update', count: 3, active: false },
    { label: 'Recently Deleted', count: 0, active: false },
    { label: 'Generator', count: null, active: false },
    { label: 'Settings', count: null, active: false },
  ];

  let selectedId = $state('1');
</script>

<div class="min-h-screen space-y-12 bg-cryptiq-bg px-8 py-10">
  <header>
    <h1 class="text-display font-semibold text-cryptiq-fg">Cryptiq — Design Reference</h1>
    <p class="mt-1 text-body text-cryptiq-fg-muted">
      Phase 4 canonical components. Calm, serious, slightly-premium · light + dark (system).
    </p>
  </header>

  <!-- 1 · App shell silhouette (P4-04) -->
  <section class="space-y-3">
    <h2 class="text-meta font-semibold tracking-wide text-cryptiq-fg-subtle uppercase">App shell — sidebar · list · detail</h2>
    <div class="flex h-[560px] overflow-hidden rounded-cryptiq-lg border border-cryptiq-border shadow-cryptiq-panel">
      <!-- Sidebar -->
      <nav class="flex w-56 shrink-0 flex-col gap-0.5 border-r border-cryptiq-border bg-cryptiq-bg p-3">
        <p class="px-2 pb-2 text-emphasis font-semibold tracking-tight text-cryptiq-fg">Cryptiq</p>
        {#each sidebar as item (item.label)}
          <button
            type="button"
            class="flex items-center justify-between rounded-cryptiq px-2.5 py-2 text-body transition-colors
                   {item.active ? 'bg-cryptiq-selected font-medium text-cryptiq-accent' : 'text-cryptiq-fg-muted hover:bg-cryptiq-hover hover:text-cryptiq-fg'}"
          >
            <span>{item.label}</span>
            {#if item.count !== null && item.count > 0}
              <span class="text-meta text-cryptiq-fg-subtle">{item.count}</span>
            {/if}
          </button>
        {/each}
      </nav>

      <!-- List -->
      <div class="flex w-80 shrink-0 flex-col border-r border-cryptiq-border bg-cryptiq-surface">
        <div class="border-b border-cryptiq-border p-3">
          <div class="flex items-center gap-2 rounded-cryptiq bg-cryptiq-surface-2 px-2.5 py-1.5">
            <svg class="size-4 text-cryptiq-fg-subtle" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3" /></svg>
            <span class="text-body text-cryptiq-fg-subtle">Search… <kbd class="text-meta">Ctrl F</kbd></span>
          </div>
        </div>
        <div class="flex-1 space-y-0.5 overflow-y-auto p-2">
          {#each entries as entry (entry.id)}
            <EntryListRow
              title={entry.title}
              username={entry.username}
              favorite={entry.favorite}
              needsUpdate={entry.needsUpdate}
              selected={entry.id === selectedId}
              onSelect={() => (selectedId = entry.id)}
            />
          {/each}
        </div>
      </div>

      <!-- Detail -->
      <div class="min-w-0 flex-1">
        {#key selectedId}
          <!--
            EntryDetail is now VaultSession-wired (04-05) and requires entryId.
            The gallery uses a placeholder since no vault is loaded in the preview harness.
          -->
          <div class="flex h-full items-center justify-center rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface p-6">
            <p class="text-body text-cryptiq-fg-muted">
              EntryDetail requires a live VaultSession — run the app to preview.
            </p>
          </div>
        {/key}
      </div>
    </div>
  </section>

  <!-- 2 · First-run — unrecoverable warning (P4-08) -->
  <section class="space-y-3">
    <h2 class="text-meta font-semibold tracking-wide text-cryptiq-fg-subtle uppercase">First-run — unrecoverable-password warning</h2>
    <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border">
      <FirstRunStep
        step={2}
        total={6}
        eyebrow="Before you continue"
        title="Your master password can't be recovered"
        tone="danger"
        ackLabel="I understand that if I forget my master password and have no recovery key, my vault is gone for good."
        continueLabel="I understand — continue"
        onBack={() => {}}
        onContinue={() => {}}
      >
        <p>
          Cryptiq never sees your master password and stores no copy of it — anywhere.
          That's what keeps your vault private even from us.
        </p>
        <p class="mt-2">
          The trade-off: <strong class="font-semibold">there is no reset and no "forgot password" email.</strong>
          If you forget it and haven't saved a recovery key, the encrypted vault can never be opened again. By design.
        </p>
      </FirstRunStep>
    </div>
  </section>

  <!-- 3 · First-run — master password + strength meter (AUTH-02) -->
  <section class="space-y-3">
    <h2 class="text-meta font-semibold tracking-wide text-cryptiq-fg-subtle uppercase">First-run — master password</h2>
    <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border">
      <FirstRunStep
        step={4}
        total={6}
        eyebrow="Create your key"
        title="Choose a master password"
        onBack={() => {}}
        onContinue={() => {}}
      >
        <p class="mb-4">Pick something long and memorable. A weak password is allowed — but we'll warn you.</p>
        <div class="space-y-3">
          <input type="password" value="correct-horse-battery" aria-label="Master password" class="w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-2 font-mono text-body text-cryptiq-fg outline-none focus:ring-2 focus:ring-cryptiq-ring" />
          <input type="password" value="correct-horse-battery" aria-label="Confirm master password" class="w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-2 font-mono text-body text-cryptiq-fg outline-none focus:ring-2 focus:ring-cryptiq-ring" />
          <!-- zxcvbn-ts strength meter (AUTH-02) -->
          <div class="flex items-center gap-2">
            <span class="flex flex-1 gap-1" aria-hidden="true">
              <span class="h-1 flex-1 rounded-full bg-cryptiq-success"></span>
              <span class="h-1 flex-1 rounded-full bg-cryptiq-success"></span>
              <span class="h-1 flex-1 rounded-full bg-cryptiq-success"></span>
              <span class="h-1 flex-1 rounded-full bg-cryptiq-border"></span>
            </span>
            <span class="text-meta font-medium text-cryptiq-success">Strong</span>
          </div>
        </div>
      </FirstRunStep>
    </div>
  </section>

  <!-- 4 · Generator (standalone) -->
  <section class="space-y-3">
    <h2 class="text-meta font-semibold tracking-wide text-cryptiq-fg-subtle uppercase">Generator — standalone screen</h2>
    <div class="grid place-items-center rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-bg p-10">
      <GeneratorSurface
        variant="standalone"
        generate={async (o) => { void o; return '— run app for live generation —'; }}
        estimateBits={(_o) => 0}
        onSaveDefault={() => {}}
        onSaveAsEntry={() => {}}
      />
    </div>
  </section>

  <!-- 5 · List states (UI-04 / UI-11) -->
  <section class="space-y-3">
    <h2 class="text-meta font-semibold tracking-wide text-cryptiq-fg-subtle uppercase">Empty &amp; no-results states</h2>
    <div class="grid grid-cols-2 gap-4">
      <div class="grid h-64 place-items-center rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface p-6 text-center">
        <div>
          <div class="mx-auto grid size-12 place-items-center rounded-cryptiq-lg bg-cryptiq-surface-2 text-cryptiq-fg-subtle">
            <svg class="size-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
          </div>
          <p class="mt-3 text-emphasis font-medium text-cryptiq-fg">Your vault is empty</p>
          <p class="mt-1 text-body text-cryptiq-fg-muted">Add your first login to get started.</p>
          <button type="button" class="mt-4 rounded-cryptiq bg-cryptiq-accent px-4 py-2 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover">+ New item</button>
        </div>
      </div>
      <div class="grid h-64 place-items-center rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface p-6 text-center">
        <div>
          <div class="mx-auto grid size-12 place-items-center rounded-cryptiq-lg bg-cryptiq-surface-2 text-cryptiq-fg-subtle">
            <svg class="size-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3" /></svg>
          </div>
          <p class="mt-3 text-emphasis font-medium text-cryptiq-fg">No matches</p>
          <p class="mt-1 text-body text-cryptiq-fg-muted">Nothing matches " analyticl". Check the spelling or clear the search.</p>
        </div>
      </div>
    </div>
  </section>
</div>
