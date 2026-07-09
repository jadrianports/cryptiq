<!--
  TotpSection.svelte — Two-factor (TOTP) ingestion orchestrator (D-01/D-02/D-03,
  TOTP-01/02/03/06).

  THIS PLAN (29-04) BUILDS: empty state (smart-paste + Add-from-image), the
  parse preview, the prominent one-basket disclosure, fail-closed inline
  errors, and Save/Discard.

  NOT THIS PLAN (29-05 extends this file, does not duplicate it): the filled
  view-mode state (TotpCodeRing mount + issuer/label caption + persistent
  disclosure), the seed reveal hold-to-peek control, and the remove-confirm
  modal (D-11/D-12). When `totp` is already defined, this plan renders nothing
  extra — 29-05 fills that branch in.

  Callback-through-parent CRUD (D-01, mirrors persistCard/persistIdentity):
  this component NEVER touches vaultSession directly. `onSave` persists via
  the parent's vaultSession.updateEntry(entryId, { totp }) + scheduleSave();
  `onRemove` (wired by 29-05) will do the equivalent removal.

  Fail-closed (D-10): a bad paste or an undecodable/non-totp QR shows a typed
  inline error and adds NOTHING — preview is only ever set from a fully valid
  parsePastedTotp() result, never a partial value.
-->
<script lang="ts">
  import { parsePastedTotp, decodeQrToOtpauthUri } from '@cryptiq/core';
  import { TotpParseError } from '@cryptiq/core';
  import type { EntryTotp } from '@cryptiq/core';
  import { setNativeDialogOpen, clearNativeDialogOpen } from '../state/dialogGuard.svelte';

  const GENERIC_PARSE_ERROR_MESSAGE =
    "That doesn't look like an otpauth:// link or a Base32 setup key.";
  const GENERIC_PARSE_ERROR_HINT = 'Copy the code again from the service’s 2FA setup screen.';
  const QR_FAIL_MESSAGE = "Couldn't find a TOTP QR code in that image.";
  const QR_FAIL_HINT = 'Try a different image, or paste the setup key instead.';

  type Props = {
    entryId: string | null;
    totp: EntryTotp | undefined;
    onSave: (totp: EntryTotp) => void;
    onRemove: () => void;
  };
  // entryId/onRemove are part of the locked prop contract (29-05 extends this
  // component with the filled/remove-modal state) but are not read by this
  // plan's empty/preview/error states — `_`-prefixed per project convention.
  let { entryId: _entryId, totp, onSave, onRemove: _onRemove }: Props = $props();

  let pastedValue = $state('');
  let preview = $state<EntryTotp | null>(null);
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
</script>

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
          Keeping your 2FA seed next to its password puts both factors in one vault — if this
          vault is ever compromised, they fall together. That's the trade-off of an all-in-one
          manager.
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
  {/if}
</div>
