<!--
  TotpSection.svelte — Two-factor (TOTP) orchestrator (D-01/D-02/D-03/D-04/D-05/
  D-06/D-07/D-08/D-11/D-12, TOTP-01/02/03/04/06).

  29-04 BUILT: empty state (smart-paste + Add-from-image), the parse preview,
  the prominent one-basket disclosure, fail-closed inline errors, and
  Save/Discard.

  29-05 (THIS PLAN) BUILDS: the filled/view-mode state — renders TotpCodeRing,
  editable label/issuer (persisted on blur, wholesale-replace, D-12: secret/
  algorithm/digits/period NEVER hand-editable), the seed reveal hold-to-peek
  control (own secretHeld/secretToggled state, read-only `<span>`, never an
  `<input>` — D-12), a Remove control gated behind an inline confirm modal
  mirroring PurgeConfirm.svelte's shape (D-11), and the persistent inline
  one-basket disclosure (D-07/D-08, exact CVV class match).

  Callback-through-parent CRUD (D-01, mirrors persistCard/persistIdentity):
  this component NEVER touches vaultSession directly. `onSave` persists via
  the parent's vaultSession.updateEntry(entryId, { totp }) + scheduleSave();
  `onRemove` does the equivalent removal (vaultSession.updateEntry(entryId,
  { totp: null }) — the null-sentinel remove path).

  Fail-closed (D-10): a bad paste or an undecodable/non-totp QR shows a typed
  inline error and adds NOTHING — preview is only ever set from a fully valid
  parsePastedTotp() result, never a partial value.
-->
<script lang="ts">
  import { parsePastedTotp, decodeQrToOtpauthUri } from '@cryptiq/core';
  import { TotpParseError } from '@cryptiq/core';
  import type { EntryTotp } from '@cryptiq/core';
  import { setNativeDialogOpen, clearNativeDialogOpen } from '../state/dialogGuard.svelte';
  import TotpCodeRing from './TotpCodeRing.svelte';

  const GENERIC_PARSE_ERROR_MESSAGE =
    "That doesn't look like an otpauth:// link or a Base32 setup key.";
  const GENERIC_PARSE_ERROR_HINT = 'Copy the code again from the service’s 2FA setup screen.';
  const QR_FAIL_MESSAGE = "Couldn't find a TOTP QR code in that image.";
  const QR_FAIL_HINT = 'Try a different image, or paste the setup key instead.';
  // D-07/D-08 — same text in both placements (add-flow prominent panel + the
  // persistent inline note here). No legalese, states the trade-off once.
  const ONE_BASKET_DISCLOSURE =
    "Keeping your 2FA seed next to its password puts both factors in one vault — " +
    "if this vault is ever compromised, they fall together. That's the trade-off of " +
    'an all-in-one manager.';

  type Props = {
    entryId: string | null;
    totp: EntryTotp | undefined;
    onSave: (totp: EntryTotp) => void;
    onRemove: () => void;
  };
  // entryId is part of the locked prop contract (EntryDetail uses it to guard
  // the blank-form case before ever mounting a totp) but is not read inside
  // this component itself — `_`-prefixed per project convention.
  let { entryId: _entryId, totp, onSave, onRemove }: Props = $props();

  let pastedValue = $state('');
  // $state.raw (not deep $state): `preview` holds the raw parsed secret pre-save;
  // a deep-reactive proxy would expose it via the DevTools proxy — the same
  // locked no-secret-in-proxy invariant the vault key/state follow (CLAUDE.md).
  // Always wholesale-reassigned (never mutated in place), so .raw is a drop-in.
  let preview = $state.raw<EntryTotp | null>(null);
  let error = $state<{ source: 'paste' | 'qr'; message: string; hint: string } | null>(null);
  let fileInputEl: HTMLInputElement | undefined = $state();

  function attemptParsePaste(raw: string): void {
    if (raw.trim() === '') return;
    try {
      preview = parsePastedTotp(raw);
      error = null;
      pastedValue = '';
    } catch (e) {
      preview = null;
      if (e instanceof TotpParseError) {
        error = { source: 'paste', message: e.message, hint: GENERIC_PARSE_ERROR_HINT };
      } else {
        error = { source: 'paste', message: GENERIC_PARSE_ERROR_MESSAGE, hint: GENERIC_PARSE_ERROR_HINT };
      }
    }
  }

  function handlePasteFieldBlur(): void {
    attemptParsePaste(pastedValue);
  }

  function handlePasteFieldPaste(event: ClipboardEvent): void {
    const text = event.clipboardData?.getData('text') ?? '';
    if (text === '') return;
    event.preventDefault();
    pastedValue = text;
    attemptParsePaste(text);
  }

  function handleAddFromImageClick(): void {
    // Mirrors ImportView.svelte's native-file-dialog auto-lock guard — the OS
    // file picker steals webview focus, which would otherwise false-positive
    // the idle/blur auto-lock while the user is actively picking a QR image.
    setNativeDialogOpen();
    fileInputEl?.click();
  }

  async function handleImagePicked(event: Event): Promise<void> {
    clearNativeDialogOpen();
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    // Allow re-selecting the same file after a failed attempt.
    input.value = '';
    if (file === undefined) return;

    error = null;
    try {
      const bitmap = await createImageBitmap(file);
      const canvas = document.createElement('canvas');
      canvas.width = bitmap.width;
      canvas.height = bitmap.height;
      const ctx = canvas.getContext('2d');
      if (ctx === null) {
        preview = null;
        error = { source: 'qr', message: QR_FAIL_MESSAGE, hint: QR_FAIL_HINT };
        return;
      }
      ctx.drawImage(bitmap, 0, 0);
      const imageData = ctx.getImageData(0, 0, bitmap.width, bitmap.height);
      const decodedUri = decodeQrToOtpauthUri({
        data: imageData.data,
        width: imageData.width,
        height: imageData.height,
      });
      if (decodedUri === null) {
        // D-10: no QR found — fail closed, add nothing.
        preview = null;
        error = { source: 'qr', message: QR_FAIL_MESSAGE, hint: QR_FAIL_HINT };
        return;
      }
      // Reuses the URI branch of parsePastedTotp — enforces D-09's
      // "single otpauth://totp only" via its own instanceof OTPAuth.TOTP gate.
      preview = parsePastedTotp(decodedUri);
      pastedValue = '';
      error = null;
    } catch {
      // D-10: a decode/parse failure on the QR path shows the SAME fail-closed
      // QR error as a missing QR — never a partial/best-effort seed.
      preview = null;
      error = { source: 'qr', message: QR_FAIL_MESSAGE, hint: QR_FAIL_HINT };
    }
  }

  function handleSave(): void {
    if (preview === null) return;
    onSave(preview);
    preview = null;
    pastedValue = '';
    error = null;
  }

  function handleDiscard(): void {
    preview = null;
    pastedValue = '';
    error = null;
  }

  // ── Filled/view-mode state (D-04/D-05/D-06/D-11/D-12, TOTP-04/06) ────────

  // label/issuer editable-field mirrors (D-12) — seeded from the current totp
  // whenever it changes (entry swap, or after a save round-trips a new object).
  let labelDraft = $state('');
  let issuerDraft = $state('');

  $effect(() => {
    labelDraft = totp?.label ?? '';
    issuerDraft = totp?.issuer ?? '';
  });

  // Seed reveal (D-11/D-12) — its OWN independent hold-to-peek + toggle state,
  // never shared with EntryDetail's password/CVV reveal pairs. Read-only when
  // revealed (a <span>, never an <input> — the secret is not hand-editable).
  let secretToggled = $state(false);
  let secretHeld = $state(false);
  const secretRevealed = $derived(secretToggled || secretHeld);

  // Remove-confirm modal (D-06/D-11) — mirrors PurgeConfirm.svelte's exact
  // shape, mounted from here rather than as a new standalone component.
  let showRemoveConfirm = $state(false);

  function persistLabelIssuer(): void {
    if (totp === undefined) return;
    // Wholesale-replace (D-12): secret/algorithm/digits/period pass through
    // UNCHANGED — only label/issuer are ever hand-edited. Conditional spread
    // omits a blanked-out label/issuer entirely (exactOptionalPropertyTypes).
    onSave({
      secret: totp.secret,
      algorithm: totp.algorithm,
      digits: totp.digits,
      period: totp.period,
      ...(labelDraft.trim() !== '' ? { label: labelDraft.trim() } : {}),
      ...(issuerDraft.trim() !== '' ? { issuer: issuerDraft.trim() } : {}),
    });
  }

  function handleRemoveConfirm(): void {
    showRemoveConfirm = false;
    onRemove();
  }

  function handleRemoveCancel(): void {
    showRemoveConfirm = false;
  }

  function handleRemoveModalKeydown(e: KeyboardEvent): void {
    if (!showRemoveConfirm) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      handleRemoveCancel();
    }
  }
</script>

<svelte:window onkeydown={handleRemoveModalKeydown} />

<div class="rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface-2 px-3 py-2.5">
  <span class="mb-2 block text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">
    Two-Factor (TOTP)
  </span>

  {#if totp === undefined}
    {#if preview === null}
      <!-- Empty state (D-02) -->
      <p class="text-body font-medium text-cryptiq-fg">No 2FA code yet</p>
      <p class="mt-1 text-meta text-cryptiq-fg-subtle">
        Paste a setup key or otpauth:// link from the service's 2FA screen, or add a QR code image.
      </p>

      <div class="mt-3">
        <input
          type="text"
          bind:value={pastedValue}
          onblur={handlePasteFieldBlur}
          onpaste={handlePasteFieldPaste}
          placeholder="Paste otpauth:// link or setup key"
          aria-label="Paste otpauth:// link or setup key"
          class="w-full min-w-0 rounded-cryptiq bg-cryptiq-surface px-2 py-1.5 text-body text-cryptiq-fg
                 outline-none placeholder:text-cryptiq-fg-subtle focus:ring-2 focus:ring-cryptiq-ring"
        />
        {#if error?.source === 'paste'}
          <span class="mt-1 block text-meta text-cryptiq-danger">{error.message}</span>
          <span class="block text-meta text-cryptiq-fg-subtle">{error.hint}</span>
        {/if}
      </div>

      <div class="mt-2.5">
        <input
          bind:this={fileInputEl}
          type="file"
          accept="image/*"
          class="hidden"
          aria-hidden="true"
          tabindex="-1"
          onchange={handleImagePicked}
        />
        <button
          type="button"
          onclick={handleAddFromImageClick}
          title="Add from image"
          aria-label="Add from image"
          class="flex items-center gap-1.5 rounded-cryptiq border border-cryptiq-border-strong px-3 py-1.5 text-meta font-medium text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
        >
          <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" /><circle cx="8.5" cy="8.5" r="1.5" /><path d="m21 15-5-5L5 21" /></svg>
          Add from image
        </button>
        {#if error?.source === 'qr'}
          <span class="mt-1 block text-meta text-cryptiq-danger">{error.message}</span>
          <span class="block text-meta text-cryptiq-fg-subtle">{error.hint}</span>
        {/if}
      </div>
    {:else}
      <!-- Parse-preview state (D-03) -->
      <div class="space-y-2">
        <div class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5">
          <span class="text-meta uppercase text-cryptiq-fg-subtle">Issuer</span>
          <span class="text-body text-cryptiq-fg">{preview.issuer ?? '—'}</span>
          <span class="text-meta uppercase text-cryptiq-fg-subtle">Account</span>
          <span class="text-body text-cryptiq-fg">{preview.label ?? '—'}</span>
          <span class="text-meta uppercase text-cryptiq-fg-subtle">Algorithm</span>
          <span class="text-body text-cryptiq-fg">{preview.algorithm}</span>
          <span class="text-meta uppercase text-cryptiq-fg-subtle">Digits</span>
          <span class="text-body text-cryptiq-fg">{preview.digits}</span>
          <span class="text-meta uppercase text-cryptiq-fg-subtle">Refreshes</span>
          <span class="text-body text-cryptiq-fg">every {preview.period}s</span>
        </div>

        <!-- One-basket disclosure (D-07/D-08), prominent placement before Save (TOTP-06) -->
        <div class="rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface p-3 text-body text-cryptiq-fg-muted">
          {ONE_BASKET_DISCLOSURE}
        </div>

        <div class="flex items-center gap-2">
          <button
            type="button"
            onclick={handleSave}
            class="rounded-cryptiq bg-cryptiq-accent px-3 py-1.5 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover focus:outline-none focus:ring-2 focus:ring-cryptiq-ring"
          >
            Save code
          </button>
          <button
            type="button"
            onclick={handleDiscard}
            class="rounded-cryptiq px-3 py-1.5 text-body font-medium text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
          >
            Discard preview
          </button>
        </div>
      </div>
    {/if}
  {:else}
    <!-- Filled/view-mode state (D-04/D-05/D-06, TOTP-04) -->
    <TotpCodeRing {totp} />

    <div class="mt-3 space-y-3">
      <!-- Issuer (editable, D-12) -->
      <div>
        <span class="mb-1 block text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">Issuer</span>
        <input
          type="text"
          bind:value={issuerDraft}
          onblur={persistLabelIssuer}
          placeholder="—"
          aria-label="TOTP issuer"
          class="w-full min-w-0 rounded-cryptiq bg-transparent px-2 py-1.5 text-body text-cryptiq-fg
                 outline-none placeholder:text-cryptiq-fg-subtle focus:bg-cryptiq-surface focus:ring-2 focus:ring-cryptiq-ring"
        />
      </div>

      <!-- Account/label (editable, D-12) -->
      <div>
        <span class="mb-1 block text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">Account</span>
        <input
          type="text"
          bind:value={labelDraft}
          onblur={persistLabelIssuer}
          placeholder="—"
          aria-label="TOTP account label"
          class="w-full min-w-0 rounded-cryptiq bg-transparent px-2 py-1.5 text-body text-cryptiq-fg
                 outline-none placeholder:text-cryptiq-fg-subtle focus:bg-cryptiq-surface focus:ring-2 focus:ring-cryptiq-ring"
        />
      </div>

      <!-- Seed management: reveal (hold-to-peek + toggle, own state, read-only
           span — D-11/D-12) and Remove (gated behind a confirm modal). -->
      <div>
        <span class="mb-1 block text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">Setup key</span>
        <div class="flex items-center gap-1">
          <div
            class="flex min-w-0 flex-1 items-center rounded-cryptiq bg-cryptiq-surface px-2 py-1.5"
            onpointerdown={() => (secretHeld = true)}
            onpointerup={() => (secretHeld = false)}
            onpointerleave={() => (secretHeld = false)}
            onpointercancel={() => (secretHeld = false)}
            role="presentation"
          >
            {#if secretRevealed}
              <span class="min-w-0 flex-1 truncate font-mono text-body text-cryptiq-fg select-all">{totp.secret}</span>
            {:else}
              <span class="min-w-0 flex-1 truncate font-mono text-body text-cryptiq-fg select-none">
                {'•'.repeat(Math.min(24, totp.secret.length || 16))}
              </span>
              <span class="ml-2 text-meta text-cryptiq-fg-subtle select-none">hold to peek</span>
            {/if}
          </div>

          <!-- Click toggle (accessibility fallback for press-and-hold). -->
          <button
            type="button"
            onclick={() => (secretToggled = !secretToggled)}
            aria-pressed={secretToggled}
            title={secretToggled ? 'Hide setup key' : 'Show setup key'}
            class="grid size-8 shrink-0 place-items-center rounded-cryptiq text-cryptiq-fg-subtle transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
          >
            {#if secretRevealed}
              <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M9.9 4.24A9.1 9.1 0 0 1 12 4c7 0 10 8 10 8a18 18 0 0 1-2.16 3.19M6.6 6.6A18 18 0 0 0 2 12s3 8 10 8a9.3 9.3 0 0 0 5.4-1.6" /><path d="m2 2 20 20" /><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" /></svg>
            {:else}
              <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3-8 10-8 10 8 10 8-3 8-10 8-10-8-10-8Z" /><circle cx="12" cy="12" r="3" /></svg>
            {/if}
          </button>

          <!-- Remove (D-11), gated behind a confirm modal. -->
          <button
            type="button"
            onclick={() => (showRemoveConfirm = true)}
            title="Remove 2FA code"
            aria-label="Remove 2FA code"
            class="grid size-8 shrink-0 place-items-center rounded-cryptiq text-cryptiq-fg-subtle transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-danger"
          >
            <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
              <path d="M3 6h18" /><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" /><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
              <path d="M10 11v6" /><path d="M14 11v6" />
            </svg>
          </button>
        </div>
      </div>
    </div>

    <!-- Persistent inline one-basket disclosure (D-07/D-08, TOTP-06) — exact
         class match to the CVV precedent (EntryDetail.svelte:952-954). -->
    <p class="mt-1.5 text-meta text-cryptiq-fg-subtle">
      {ONE_BASKET_DISCLOSURE}
    </p>

    {#if showRemoveConfirm}
      <!-- "Remove 2FA code?" confirm modal — mirrors PurgeConfirm.svelte's exact
           icon/heading/body/danger-button shape (D-11), mounted here rather
           than as a new standalone component. -->
      <div
        class="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
        role="presentation"
        onclick={(e) => { if (e.target === e.currentTarget) handleRemoveCancel(); }}
      >
        <div
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="totp-remove-title"
          aria-describedby="totp-remove-desc"
          class="w-full max-w-sm rounded-cryptiq-lg border border-cryptiq-danger-border bg-cryptiq-surface p-6 shadow-cryptiq-popover"
        >
          <div class="mb-4 flex items-start gap-3">
            <div class="mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-cryptiq bg-cryptiq-danger-surface">
              <svg class="size-5 text-cryptiq-danger" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M3 6h18" />
                <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
              </svg>
            </div>
            <div>
              <h2 id="totp-remove-title" class="text-emphasis font-semibold text-cryptiq-fg">
                Remove 2FA code?
              </h2>
              <p id="totp-remove-desc" class="mt-1 text-body text-cryptiq-fg-muted">
                <strong class="font-medium text-cryptiq-fg">{totp.issuer || totp.label || 'This entry'}</strong>
                will no longer generate codes here. You can add it again later by re-scanning the
                QR or re-entering the setup key.
              </p>
            </div>
          </div>

          <div class="flex justify-end gap-2">
            <button
              type="button"
              onclick={handleRemoveCancel}
              class="rounded-cryptiq border border-cryptiq-border px-4 py-2 text-body font-medium text-cryptiq-fg-muted
                     transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg focus:outline-none focus:ring-2 focus:ring-cryptiq-ring"
            >
              Cancel
            </button>
            <button
              type="button"
              onclick={handleRemoveConfirm}
              class="rounded-cryptiq bg-cryptiq-danger px-4 py-2 text-body font-semibold text-cryptiq-danger-fg
                     transition-colors hover:opacity-90 focus:outline-none focus:ring-2 focus:ring-cryptiq-ring"
            >
              Remove 2FA code
            </button>
          </div>
        </div>
      </div>
    {/if}
  {/if}
</div>
