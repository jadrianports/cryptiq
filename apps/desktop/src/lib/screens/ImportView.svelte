<!--
  ImportView.svelte — Phase 6 CSV import wizard (P6-02 / IMPORT-01..08).

  Step sequence:
    1  pick-file   — user selects a CSV file; BOM check; UTF-16 rejection (IMPORT-04)
    2  column-map  — shown only when detectFormat() returns null (IMPORT-03 generic fallback)
    3  preview     — per-row Skip/Import toggle with duplicate flags + malformed-row report
    4  commit      — iterates rows with action==='import', calls addEntry×N, then save()
    5  reminder    — "securely delete your CSV file" (IMPORT-07)

  Security:
    - previewRows and malformedRows use $state.raw (NOT $state) — these hold decrypted
      passwords and must NOT be wrapped in Svelte's deep reactive proxy (Pitfall 7 /
      T-06-05 mitigation). CLAUDE.md §Crypto rules — locked decision.
    - No console.* of any row/field value anywhere in this file (SEC rule).
    - papaparse runs in a Vite Web Worker (csvWorker.ts?worker) with worker:false inside,
      avoiding the SCRIPT_PATH bundle-detection failure (RESEARCH Pitfall 1 / IMPORT-01).
    - The CSV file is read via the browser File API — no plugin-fs capability needed.
    - detectBom() runs BEFORE the file content is passed to the worker (IMPORT-04).

  Dependencies (all consumed via @cryptiq/core — no duplicate logic in the UI):
    - detectFormat()     — auto-detect Chrome/Edge/Firefox/Bitwarden headers (IMPORT-02)
    - mapRow()           — field mapping + malformed-row collection (IMPORT-08 / P6-04)
    - deduplicateRows()  — flag duplicates by (url+username) against live vault (IMPORT-05)
    - normalizeRow()     — produce EntryInput from MappedRow (IMPORT-06; addEntry assigns UUID)
    - vaultSession.addEntry() / save()  — commit through the session (P3-02)

  Token rules: cryptiq-* tokens only (P4-03). Reuses FirstRunStep progress container.
-->
<script lang="ts">
  import type { Entry } from '@cryptiq/core';
  import {
    detectFormat,
    mapRow,
    deduplicateRows,
    normalizeRow,
    tokenize,
    type ImportMapper,
    type MappedRow,
    type DedupResult,
    type SniffCandidate,
    type SniffFormat,
  } from '@cryptiq/core';
  import FirstRunStep from '../components/FirstRunStep.svelte';
  import { vaultSession } from '../state/vault.svelte';
  import { pushToast } from '../state/ui.svelte';
  import { go } from '../state/view.svelte';
  // Fix-forward (import-auto-lock regression): guard the file-picker OS dialog
  // open/close so App.svelte blur-lock and idle-lock don't fire spuriously.
  import { setNativeDialogOpen, clearNativeDialogOpen } from '../state/dialogGuard.svelte';
  import { detectBom } from '../import/detectEncoding';
  // .txt front door (IMPORT-09/10/11, Phase 32): Svelte-free BOM-gate/sniff/tokenize
  // orchestration. See the `.txt` branch of handleFileSelect below.
  import { readTxtFile } from '../import/txtImport';
  // Vite Web Worker import — Vite compiles csvWorker.ts as a separate bundle.
  // The ?worker suffix is the Vite convention for manual Web Worker creation.
  import CsvWorker from '../import/csvWorker?worker';

  // ── Step machine ───────────────────────────────────────────────────────────
  // Mirrors the FirstRunWizard step-machine pattern (P4-07).
  type WizardStep = 'pick-file' | 'column-map' | 'preview' | 'commit' | 'reminder';

  let step = $state<WizardStep>('pick-file');

  const totalSteps = 5;

  function stepNumber(s: WizardStep): number {
    const map: Record<WizardStep, number> = {
      'pick-file':  1,
      'column-map': 2,
      'preview':    3,
      'commit':     4,
      'reminder':   5,
    };
    return map[s] ?? 1;
  }

  // ── State: NOT $state.raw vs $state (Pitfall 7 / T-06-05) ─────────────────
  //
  // previewRows and malformedRows hold decrypted passwords and must NOT be wrapped
  // in Svelte's deep reactive proxy (which would expose them in DevTools). Use
  // $state.raw and reassign the whole array on change.
  //
  // Other fields (step, error, parsing, etc.) are non-secret UI state: plain $state.

  // $state.raw — holds decrypted password data (Pitfall 7 / T-06-05 mitigation).
  let previewRows = $state.raw<DedupResult[]>([]);
  let malformedRows = $state.raw<Array<{ rowIndex: number; reason: string }>>([]);

  // Plain $state — non-secret UI / control-flow state.
  let error = $state<string | null>(null);
  let parsingProgress = $state(false);
  let committing = $state(false);

  // ── Column-mapping state (IMPORT-03 generic fallback) ─────────────────────
  // Used when detectFormat() returns null (unknown header set).

  /** The raw header strings from the first CSV row. */
  let csvHeaders = $state<string[]>([]);
  /** All data rows collected from the worker, before mapping. */
  let rawDataRows = $state<string[][]>([]);

  // Generic column-map selections: index in csvHeaders for each Cryptiq field.
  // -1 = "not mapped" (field stays empty).
  let colTitle    = $state(-1);
  let colUrl      = $state(-1);
  let colUsername = $state(-1);
  let colPassword = $state(-1);
  let colNotes    = $state(-1);

  // ── .txt source state (IMPORT-09/10/11, D-03/D-04) ────────────────────────
  // Set true only by the .txt branch of handleFileSelect; reset false on the
  // CSV branch. Gates the detected-format pill row (only meaningful for a
  // sniffed .txt source — CSV imports that land on column-map via a null
  // detectFormat() never sniffed anything).
  let sourceIsTxt = $state(false);
  // Stashed split lines from the selected .txt file, so a pill click can
  // re-tokenize without re-reading the file.
  let txtLines = $state<string[]>([]);
  // All 5 scored candidates from sniffFormat() (D-03 — always show every
  // candidate, not just the winner).
  let txtCandidates = $state<SniffCandidate[]>([]);
  // The currently-selected candidate format (pill highlight + label).
  let txtSelectedFormat = $state<SniffFormat | null>(null);
  // Ragged rows from the current tokenize() call, merged into malformedRows
  // AFTER buildPreviewFromMapper() runs (D-04) — see applyGenericMappingWithRagged.
  let pendingRaggedRows = $state<Array<{ rowIndex: number; reason: string }>>([]);

  // ── Helpers ────────────────────────────────────────────────────────────────

  /**
   * Helper to extract the typed Entry array from the vault's opaque `entries` field.
   * Mirrors the pattern from MainView.svelte (same safe-cast strategy).
   */
  function getEntries(vault: { entries: object } | null): Entry[] {
    if (vault === null) return [];
    const inner = vault.entries as { entries?: Entry[] };
    return Array.isArray(inner.entries) ? inner.entries : [];
  }

  // ── pick-file step ────────────────────────────────────────────────────────

  /**
   * Handle a user-selected CSV file.
   *
   * Flow:
   *   1. Read first 3 bytes → detectBom() — reject UTF-16 (IMPORT-04).
   *   2. Read whole file as text.
   *   3. Post text to csvWorker — papaparse step() sends one row per message.
   *   4. First row = headers → detectFormat() → mapper or generic fallback.
   *   5. Remaining rows → mapRow() per row, collecting mapped + malformed rows.
   *   6. deduplicateRows() against active vault entries → previewRows.
   *   7. Advance to preview (or column-map if format unknown).
   */
  async function handleFileSelect(event: Event): Promise<void> {
    // Fix-forward (import-auto-lock regression / SECURITY_INVARIANT 4):
    // Clear the dialog guard immediately on file-select (onchange). This covers
    // the normal path — the hard-timeout and focus-return listener also clear it
    // if the dialog is cancelled without selecting a file.
    clearNativeDialogOpen();

    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (file === null || file === undefined) return;

    error = null;
    parsingProgress = true;

    // ── .txt branch (IMPORT-09/10/11) ────────────────────────────────────────
    // Always lands on column-map, NEVER the CSV path's header-based auto-detect
    // helper — this IS the mechanism that satisfies IMPORT-11's "no fast path"
    // requirement (32-RESEARCH.md Assumption A4). Reuses buildPreviewFromMapper /
    // applyGenericMapping completely unchanged (IMPORT-10) via the SAME
    // csvHeaders/rawDataRows state the CSV branch below already populates.
    if (file.name.toLowerCase().endsWith('.txt')) {
      try {
        const result = await readTxtFile(file);
        csvHeaders = result.headers;
        rawDataRows = result.dataRows;
        // Pitfall 5: reset stale column-map selections on every new .txt file.
        colTitle = colUrl = colUsername = colPassword = colNotes = -1;
        txtLines = result.lines;
        txtCandidates = result.candidates;
        txtSelectedFormat = result.bestFormat;
        pendingRaggedRows = result.raggedRows;
        sourceIsTxt = true;
        step = 'column-map';
      } catch (e) {
        if (e instanceof Error && e.message === 'utf16-rejected') {
          error =
            'This file looks like UTF-16. Please re-export it as UTF-8 from your browser or password manager and try again.';
        } else if (e instanceof Error && e.message === 'empty-file') {
          error = 'The file appears to be empty.';
        } else {
          error = 'Failed to read the file.';
        }
      } finally {
        parsingProgress = false;
      }
      return;
    }

    // CSV branch (unchanged) — reset the .txt-source flag so a previous .txt
    // import's pill row / ragged-merge wiring doesn't leak into this import.
    sourceIsTxt = false;

    try {
      // Step 1: BOM check — read first 3 bytes only (IMPORT-04 / T-06-06).
      const headerBuf = await file.slice(0, 3).arrayBuffer();
      const headerBytes = new Uint8Array(headerBuf);
      const bomResult = detectBom(headerBytes);

      if (bomResult.encoding === 'utf-16-le' || bomResult.encoding === 'utf-16-be') {
        error =
          'This file looks like UTF-16. Please re-export it as UTF-8 from your browser or password manager and try again.';
        parsingProgress = false;
        return;
      }

      // Step 2: Read whole file as text.
      const csvText = await file.text();

      // Step 3: Parse via Web Worker (IMPORT-01 / T-06-07 non-blocking).
      const allRows = await parseWithWorker(csvText);
      if (allRows.length === 0) {
        error = 'The CSV file appears to be empty.';
        parsingProgress = false;
        return;
      }

      // Step 4: First row is the header.
      const firstRow = allRows[0];
      if (firstRow === undefined) {
        error = 'The CSV file appears to be empty.';
        parsingProgress = false;
        return;
      }
      const headers: string[] = firstRow;
      const dataRows: string[][] = allRows.slice(1);
      csvHeaders = headers;
      rawDataRows = dataRows;

      // Try auto-detection.
      const mapper = detectFormat(headers);

      if (mapper === null) {
        // Unknown format — show column-map step (IMPORT-03).
        parsingProgress = false;
        step = 'column-map';
        return;
      }

      // Step 5: Map rows and collect malformed.
      buildPreviewFromMapper(mapper, headers, dataRows);
    } catch (e) {
      error = e instanceof Error ? e.message : 'Failed to read the CSV file.';
    } finally {
      parsingProgress = false;
    }
  }

  /**
   * Parse CSV text in the Web Worker, returning all rows (including headers).
   * Each row is a string[].
   */
  function parseWithWorker(csvText: string): Promise<string[][]> {
    return new Promise((resolve, reject) => {
      const worker = new CsvWorker();
      const rows: string[][] = [];

      worker.onmessage = (e: MessageEvent<
        | { type: 'row'; data: string[]; errors: { message: string }[] }
        | { type: 'complete' }
        | { type: 'error'; message: string }
      >) => {
        const msg = e.data;
        if (msg.type === 'row') {
          rows.push(msg.data);
        } else if (msg.type === 'complete') {
          worker.terminate();
          resolve(rows);
        } else if (msg.type === 'error') {
          worker.terminate();
          reject(new Error(msg.message));
        }
      };

      worker.onerror = (e: ErrorEvent) => {
        worker.terminate();
        reject(new Error(e.message));
      };

      worker.postMessage({ csvText });
    });
  }

  /**
   * Map data rows using the given mapper and build previewRows + malformedRows.
   * Runs deduplicateRows() against active vault entries (IMPORT-05).
   * Assigns to $state.raw fields by full reassignment (Pitfall 7).
   */
  function buildPreviewFromMapper(
    mapper: ImportMapper,
    headers: string[],
    dataRows: string[][],
  ): void {
    const mapped: MappedRow[] = [];
    const malformed: Array<{ rowIndex: number; reason: string }> = [];

    for (let i = 0; i < dataRows.length; i++) {
      const rawRow: string[] = dataRows[i] ?? [];
      // Build a Record<header, value> from the row array.
      const rowObj: Record<string, string> = {};
      for (let j = 0; j < headers.length; j++) {
        const colVal: string = rawRow[j] ?? '';
        rowObj[headers[j] ?? ''] = colVal;
      }

      // sourceRowIndex is 1-based (header is row 0, data starts at row 1).
      const result = mapRow(rowObj, mapper, i + 1);
      if ('malformed' in result && result.malformed === true) {
        malformed.push({ rowIndex: i + 1, reason: result.reason });
      } else {
        mapped.push(result as MappedRow);
      }
    }

    // deduplicateRows() against active vault entries (IMPORT-05).
    const existingEntries = getEntries(vaultSession.vault);
    const deduped = deduplicateRows(mapped, existingEntries);

    // Assign to $state.raw by full reassignment (Pitfall 7 — no deep proxy on passwords).
    previewRows = deduped;
    malformedRows = malformed;

    step = 'preview';
  }

  // ── column-map step (IMPORT-03 generic fallback) ──────────────────────────

  function applyGenericMapping(): void {
    // Synthesize an ImportMapper from the user's column selections.
    // Capture column indices at synthesis time (avoid closure over reactive state).
    const titleIdx    = colTitle;
    const urlIdx      = colUrl;
    const usernameIdx = colUsername;
    const passwordIdx = colPassword;
    const notesIdx    = colNotes;
    const headersCopy = [...csvHeaders];

    const genericMapper: ImportMapper = {
      name: 'generic',
      detect: () => true,
      map(row: Record<string, string>): Partial<{ title: string; url: string; username: string; password: string; notes: string }> {
        return {
          title:    titleIdx    >= 0 ? (row[headersCopy[titleIdx] ?? ''] ?? '') : '',
          url:      urlIdx      >= 0 ? (row[headersCopy[urlIdx] ?? ''] ?? '') : '',
          username: usernameIdx >= 0 ? (row[headersCopy[usernameIdx] ?? ''] ?? '') : '',
          password: passwordIdx >= 0 ? (row[headersCopy[passwordIdx] ?? ''] ?? '') : '',
          notes:    notesIdx    >= 0 ? (row[headersCopy[notesIdx] ?? ''] ?? '') : '',
        };
      },
    };

    buildPreviewFromMapper(genericMapper, csvHeaders, rawDataRows);
  }

  // ── .txt detected-format pill row (D-03/D-04) ─────────────────────────────

  /**
   * Re-tokenize the stashed .txt lines under a newly-selected candidate format
   * and reassign csvHeaders/rawDataRows/pendingRaggedRows. Stays on column-map —
   * never re-invokes readTxtFile (no re-read of the file needed).
   */
  function selectTxtFormat(format: SniffFormat): void {
    const result = tokenize(txtLines, format);
    csvHeaders = result.headers;
    rawDataRows = result.dataRows;
    pendingRaggedRows = result.raggedRows;
    txtSelectedFormat = format;
    // Pitfall 5: reset stale column-map selections — the new header set may
    // have a different column count/order than the previous one.
    colTitle = colUrl = colUsername = colPassword = colNotes = -1;
  }

  /** UI-SPEC Copywriting Contract: "Detected: {delimiter description}, {N} columns/fields". */
  function txtFormatDescription(format: SniffFormat): string {
    switch (format) {
      case 'comma':
        return 'comma-separated';
      case 'tab':
        return 'tab-separated';
      case 'whitespace':
        return 'whitespace-separated';
      case 'kv-colon':
        return 'key: value pairs';
      case 'kv-equals':
        return 'key=value pairs';
    }
  }

  /** Positional candidates count "columns"; kv candidates count "fields" (UI-SPEC example). */
  function txtFieldUnit(format: SniffFormat): string {
    return format === 'kv-colon' || format === 'kv-equals' ? 'fields' : 'columns';
  }

  /**
   * Merge any pending ragged rows into malformedRows AFTER buildPreviewFromMapper()
   * runs (D-04) — that function does a full $state.raw reassignment of malformedRows,
   * which would otherwise wipe any pre-merged ragged entries.
   */
  function applyGenericMappingWithRagged(): void {
    applyGenericMapping(); // UNCHANGED — sets previewRows/malformedRows/step
    if (pendingRaggedRows.length > 0) {
      // Full-array reassignment (Pitfall 7 / $state.raw invariant) — never .push.
      malformedRows = [...malformedRows, ...pendingRaggedRows];
      pendingRaggedRows = [];
    }
  }

  // ── preview step ───────────────────────────────────────────────────────────

  /** Toggle a row's action between 'skip' and 'import'. */
  function toggleRowAction(index: number): void {
    // Full-array reassignment required for $state.raw reactivity (Pitfall 7).
    const updated = previewRows.map((r, i) => {
      if (i !== index) return r;
      return { ...r, action: r.action === 'import' ? 'skip' as const : 'import' as const };
    });
    previewRows = updated;
  }

  const rowsToImport = $derived(previewRows.filter((r) => r.action === 'import').length);
  const rowsToSkip   = $derived(previewRows.filter((r) => r.action === 'skip').length);

  // ── commit step ───────────────────────────────────────────────────────────

  /**
   * Commit all rows with action === 'import' to the vault.
   *
   * Per plan: for each row, call normalizeRow() then vaultSession.addEntry().
   * After the loop, call vaultSession.save() exactly ONCE (P3-02 save pattern).
   * No console.* of any row/field value (SEC rule / T-06-05).
   */
  async function handleCommit(): Promise<void> {
    if (committing) return;
    committing = true;
    error = null;

    try {
      // Fix-forward (import-auto-lock regression / SECURITY_INVARIANT 5):
      // Wrap the ENTIRE commit burst — normalizeRow + addEntry × N + save() —
      // in runCriticalOp so the idle controller defers its lock check for the
      // whole import (LOCK-04). runCriticalOp is internally try/finally-safe:
      // the critical-op counter can NEVER leak even if this function throws.
      // No console.* of any row/field value (SEC rule / T-06-05).
      let importedCount = 0;

      await vaultSession.runCriticalOp(async () => {
        const toImport = previewRows.filter((r) => r.action === 'import');

        for (const result of toImport) {
          // normalizeRow is the final core pipeline step — it returns EntryInput.
          // addEntry() in VaultSession assigns the CSPRNG UUID + timestamps (IMPORT-06).
          const input = await normalizeRow(result.row);
          await vaultSession.addEntry(input);
          importedCount++;
        }

        // Save exactly once after the loop (P3-02 / IMPORT-06).
        await vaultSession.save();
      });

      pushToast(`Imported ${importedCount} ${importedCount === 1 ? 'entry' : 'entries'}.`);
      step = 'reminder';
    } catch (e) {
      error = e instanceof Error ? e.message : 'Import failed. Please try again.';
    } finally {
      committing = false;
    }
  }
</script>

<!-- ── Step: pick-file ──────────────────────────────────────────────────── -->
{#if step === 'pick-file'}
  <FirstRunStep
    step={stepNumber('pick-file')}
    total={totalSteps}
    eyebrow="Import"
    title="Import passwords from a CSV file."
    showContinue={false}
  >
    <p>
      Export your passwords as a CSV, or point Cryptiq at a plain-text <code>passwords.txt</code>
      file — either way, Cryptiq auto-detects the format and lets you review before committing.
    </p>
    <p class="mt-3 text-meta text-cryptiq-fg-subtle">
      Supported: Chrome / Edge, Firefox, Bitwarden CSV exports, and plaintext <code>.txt</code>
      (<code>key: value</code>, <code>key=value</code>, comma-, tab-, or whitespace-separated).
    </p>

    {#if error}
      <div
        class="mt-4 rounded-cryptiq border border-cryptiq-danger-border bg-cryptiq-danger-surface px-3 py-2"
        role="alert"
      >
        <p class="text-body text-cryptiq-danger">{error}</p>
      </div>
    {/if}

    <div class="mt-5">
      {#if parsingProgress}
        <div class="flex items-center gap-3 text-body text-cryptiq-fg-muted">
          <span
            class="inline-block size-4 animate-spin rounded-full border-2 border-cryptiq-border border-t-cryptiq-accent"
            aria-hidden="true"
          ></span>
          Reading file…
        </div>
      {:else}
        <label class="block">
          <span class="mb-1.5 block text-meta font-medium text-cryptiq-fg-muted">
            Choose a file to import
          </span>
          <input
            type="file"
            accept=".csv,text/csv,.txt,text/plain"
            onclick={setNativeDialogOpen}
            onchange={handleFileSelect}
            class="block w-full cursor-pointer rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface-2 px-3 py-2 text-body text-cryptiq-fg
                   file:mr-3 file:cursor-pointer file:rounded file:border-0 file:bg-cryptiq-accent file:px-3 file:py-1 file:text-meta file:font-medium file:text-cryptiq-accent-fg
                   hover:border-cryptiq-border-strong focus:outline-none focus:ring-1 focus:ring-cryptiq-ring"
          />
        </label>
      {/if}
    </div>

    <div class="mt-8 flex items-center justify-between gap-3">
      <button
        type="button"
        onclick={() => go('main')}
        class="rounded-cryptiq px-3 py-2 text-body font-medium text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
      >
        Cancel
      </button>
      <span></span>
    </div>
  </FirstRunStep>

<!-- ── Step: column-map (IMPORT-03 generic fallback) ─────────────────────── -->
{:else if step === 'column-map'}
  <FirstRunStep
    step={stepNumber('column-map')}
    total={totalSteps}
    eyebrow="Column mapping"
    title="Map your columns to Cryptiq fields."
    continueLabel="Preview import"
    canContinue={colPassword >= 0 && colTitle >= 0}
    onBack={() => { step = 'pick-file'; }}
    onContinue={sourceIsTxt ? applyGenericMappingWithRagged : applyGenericMapping}
  >
    <p>
      Cryptiq couldn't auto-detect this CSV format. Select which column maps to each field.
      <strong>Title</strong> and <strong>Password</strong> are required; other fields are optional.
    </p>

    {#if sourceIsTxt && txtSelectedFormat}
      {@const selectedCandidate = txtCandidates.find((c) => c.format === txtSelectedFormat)}
      <div class="mt-4 flex flex-wrap items-center gap-1.5">
        <span class="text-meta font-medium text-cryptiq-fg-muted">
          Detected: {txtFormatDescription(txtSelectedFormat)}, {selectedCandidate?.fieldCount ?? 0} {txtFieldUnit(txtSelectedFormat)}
        </span>
        {#each txtCandidates as candidate (candidate.format)}
          <button
            type="button"
            disabled={!candidate.eligible}
            onclick={() => selectTxtFormat(candidate.format)}
            class="rounded px-2 py-0.5 text-meta font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-40
                   {candidate.format === txtSelectedFormat
                     ? 'bg-cryptiq-accent text-cryptiq-accent-fg'
                     : 'bg-cryptiq-surface-2 text-cryptiq-fg-muted hover:bg-cryptiq-hover'}"
          >
            {candidate.label}
          </button>
        {/each}
      </div>
    {/if}

    <div class="mt-4 space-y-3">
      {#each [
        { label: 'Title *', bind: 'title' },
        { label: 'URL', bind: 'url' },
        { label: 'Username', bind: 'username' },
        { label: 'Password *', bind: 'password' },
        { label: 'Notes', bind: 'notes' },
      ] as field (field.bind)}
        <div class="flex items-center gap-3">
          <label class="w-24 shrink-0 text-meta font-medium text-cryptiq-fg-muted" for="col-{field.bind}">
            {field.label}
          </label>
          <select
            id="col-{field.bind}"
            value={
              field.bind === 'title' ? colTitle :
              field.bind === 'url' ? colUrl :
              field.bind === 'username' ? colUsername :
              field.bind === 'password' ? colPassword :
              colNotes
            }
            onchange={(e) => {
              const val = parseInt((e.target as HTMLSelectElement).value, 10);
              if (field.bind === 'title') colTitle = val;
              else if (field.bind === 'url') colUrl = val;
              else if (field.bind === 'username') colUsername = val;
              else if (field.bind === 'password') colPassword = val;
              else colNotes = val;
            }}
            class="flex-1 rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface-2 px-2 py-1.5 text-body text-cryptiq-fg focus:border-cryptiq-accent focus:outline-none focus:ring-1 focus:ring-cryptiq-ring"
          >
            <option value={-1}>(not mapped)</option>
            {#each csvHeaders as header, i (i)}
              <option value={i}>{header}</option>
            {/each}
          </select>
        </div>
      {/each}
    </div>

    {#if csvHeaders.length > 0}
      <p class="mt-3 text-meta text-cryptiq-fg-subtle">
        Detected columns: {csvHeaders.join(', ')}
      </p>
    {/if}
  </FirstRunStep>

<!-- ── Step: preview ────────────────────────────────────────────────────── -->
{:else if step === 'preview'}
  <div class="grid min-h-screen place-items-center bg-cryptiq-bg px-6 py-10">
    <div class="w-full max-w-2xl rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface p-8 shadow-cryptiq-panel">
      <!-- Progress -->
      <div class="mb-7">
        <div class="flex gap-1.5" aria-hidden="true">
          {#each Array.from({ length: totalSteps }) as _, i (i)}
            <span class="h-1 flex-1 rounded-full transition-colors {i < stepNumber('preview') ? 'bg-cryptiq-accent' : 'bg-cryptiq-border'}"></span>
          {/each}
        </div>
        <p class="mt-2 text-meta font-medium text-cryptiq-fg-subtle">Step {stepNumber('preview')} of {totalSteps}</p>
      </div>

      <p class="mb-1.5 text-meta font-semibold tracking-wide uppercase text-cryptiq-accent">Preview</p>
      <h1 class="text-display font-semibold text-cryptiq-fg">Review your import.</h1>

      <!-- Summary counts -->
      <div class="mt-4 flex flex-wrap gap-4 text-body">
        <span class="text-cryptiq-fg">
          <strong class="text-cryptiq-accent">{rowsToImport}</strong> to import
        </span>
        <span class="text-cryptiq-fg-muted">
          <strong>{rowsToSkip}</strong> skipped
        </span>
        {#if malformedRows.length > 0}
          <span class="text-cryptiq-danger">
            <strong>{malformedRows.length}</strong> couldn't be read
          </span>
        {/if}
      </div>

      <!-- Malformed-row report (P6-04 — never silent drop) -->
      {#if malformedRows.length > 0}
        <details class="mt-4 rounded-cryptiq border border-cryptiq-danger-border bg-cryptiq-danger-surface px-3 py-2">
          <summary class="cursor-pointer text-meta font-medium text-cryptiq-danger">
            {malformedRows.length} {malformedRows.length === 1 ? 'row' : 'rows'} couldn't be read
          </summary>
          <ul class="mt-2 space-y-1">
            {#each malformedRows as bad (bad.rowIndex)}
              <li class="text-meta text-cryptiq-fg-muted">
                Imported-row {bad.rowIndex}: {bad.reason}
              </li>
            {/each}
            <!-- FIX 5: "Imported-row N" instead of "Row N" because papaparse
                 skipEmptyLines:true drops blank lines before rows reach the renderer,
                 so the index into the post-skip array does not match the physical
                 CSV line number. Backlog: attach true source line number via
                 papaparse step(result.meta.cursor) in csvWorker.ts for precise
                 physical-line reporting. -->
          </ul>
        </details>
      {/if}

      <!-- Preview table -->
      {#if previewRows.length > 0}
        <div class="mt-4 max-h-72 overflow-y-auto rounded-cryptiq border border-cryptiq-border">
          <table class="w-full text-left text-meta">
            <thead class="border-b border-cryptiq-border bg-cryptiq-surface-2 text-cryptiq-fg-muted">
              <tr>
                <th class="px-3 py-2 font-medium">Action</th>
                <th class="px-3 py-2 font-medium">Title</th>
                <th class="px-3 py-2 font-medium">Username</th>
                <th class="px-3 py-2 font-medium">URL</th>
              </tr>
            </thead>
            <tbody>
              {#each previewRows as result, i (i)}
                <tr class="border-b border-cryptiq-border last:border-0 {result.isDuplicate ? 'opacity-60' : ''}">
                  <td class="px-3 py-2">
                    <button
                      type="button"
                      onclick={() => toggleRowAction(i)}
                      class="rounded px-2 py-0.5 text-meta font-semibold transition-colors
                             {result.action === 'import'
                               ? 'bg-cryptiq-accent text-cryptiq-accent-fg'
                               : 'bg-cryptiq-surface-2 text-cryptiq-fg-muted hover:bg-cryptiq-hover'}"
                      title={result.isDuplicate ? 'Duplicate entry — defaults to skip' : ''}
                    >
                      {result.action === 'import' ? 'Import' : 'Skip'}
                    </button>
                    {#if result.isDuplicate}
                      <span class="ml-1 text-meta text-cryptiq-fg-subtle" title="Matches an existing entry">
                        dup
                      </span>
                    {/if}
                  </td>
                  <td class="max-w-[12rem] truncate px-3 py-2 text-cryptiq-fg">{result.row.title}</td>
                  <td class="max-w-[12rem] truncate px-3 py-2 text-cryptiq-fg-muted">{result.row.username}</td>
                  <td class="max-w-[14rem] truncate px-3 py-2 text-cryptiq-fg-subtle font-mono">{result.row.url}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <p class="mt-4 text-body text-cryptiq-fg-muted">No valid rows were found in this file.</p>
      {/if}

      {#if error}
        <p class="mt-4 text-body text-cryptiq-danger" role="alert">{error}</p>
      {/if}

      <!-- Footer -->
      <div class="mt-8 flex items-center justify-between gap-3">
        <button
          type="button"
          onclick={() => { step = 'pick-file'; error = null; }}
          class="rounded-cryptiq px-3 py-2 text-body font-medium text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
        >
          Back
        </button>
        <button
          type="button"
          onclick={() => { step = 'commit'; void handleCommit(); }}
          disabled={rowsToImport === 0}
          class="rounded-cryptiq bg-cryptiq-accent px-5 py-2 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover disabled:cursor-not-allowed disabled:opacity-40"
        >
          Import {rowsToImport} {rowsToImport === 1 ? 'entry' : 'entries'}
        </button>
      </div>
    </div>
  </div>

<!-- ── Step: commit (async progress) ───────────────────────────────────── -->
{:else if step === 'commit'}
  <div class="grid h-screen place-items-center bg-cryptiq-bg px-6 py-10">
    <div class="w-full max-w-lg space-y-4 rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface p-8 shadow-cryptiq-panel text-center">
      {#if committing}
        <div
          class="mx-auto size-8 animate-spin rounded-full border-2 border-cryptiq-border border-t-cryptiq-accent"
          aria-hidden="true"
        ></div>
        <p class="text-body text-cryptiq-fg-muted">Importing entries…</p>
      {:else if error}
        <p class="text-body text-cryptiq-danger" role="alert">{error}</p>
        <button
          type="button"
          onclick={() => { step = 'preview'; }}
          class="rounded-cryptiq bg-cryptiq-accent px-5 py-2 text-body font-semibold text-cryptiq-accent-fg"
        >
          Back to preview
        </button>
      {/if}
    </div>
  </div>

<!-- ── Step: reminder (IMPORT-07) ───────────────────────────────────────── -->
{:else if step === 'reminder'}
  <FirstRunStep
    step={stepNumber('reminder')}
    total={totalSteps}
    eyebrow="Done"
    title="Import complete."
    continueLabel="Done"
    onContinue={() => go('main')}
    showContinue={true}
  >
    <p class="font-semibold text-cryptiq-fg">
      Now securely delete your {sourceIsTxt ? 'import' : 'CSV'} file — Cryptiq can't do this for you.
    </p>
    <p class="mt-3 text-cryptiq-fg-muted">
      Your {sourceIsTxt ? 'import' : 'CSV'} file contains your passwords in plain text. Use your
      operating system's secure-delete feature or empty the Recycle Bin after deleting to prevent
      recovery.
    </p>
    <p class="mt-3 text-cryptiq-fg-muted">
      Your imported entries are now in your vault. Check the <strong>Health</strong> view
      to review any weak or reused passwords from the import.
    </p>
  </FirstRunStep>
{/if}
