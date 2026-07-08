<script lang="ts">
  // apps/extension/entrypoints/popup/Popup.svelte
  //
  // D-10 (XSEC-06) base surface, extended by Plan 17-04 (D-01: the popup is
  // the ONLY clickable fill-trigger surface in this phase) into the
  // fill-trigger UI: on every open (MV3 popups are always a fresh script
  // instantiation -- no persistent-state assumption) this renders EXACTLY
  // ONE of six states:
  //   - not-paired            -> "Open Cryptiq to approve"
  //   - disconnected/app-closed -> "Cryptiq isn't running"
  //   - locked                -> "Cryptiq is locked — unlock it to fill"
  //   - connected-matches     -> single Fill button (FILL-04), a picker
  //                              (FILL-05, current-tab matches only per
  //                              Phase 16 matchByOrigin), a "Fill anyway"
  //                              affordance when no field was auto-detected
  //                              (FILL-06), and passive weak/reused badges
  //                              (HEALTH-02, D-04)
  //   - connected-no-matches  -> "No saved logins for this site"
  //
  // HARD CONSTRAINT (XSEC-06): every state renders counts/status/metadata
  // text ONLY -- NEVER a password/secret value, in any state or markup
  // branch. The one secret this file ever touches (`fill-entry`'s returned
  // `secret`) lives only as a plain local variable inside handleFillClick's
  // async call stack -- never assigned to a `$state` variable (which would
  // proxy it, risking DevTools exposure per CLAUDE.md's $state.raw
  // discipline) and never bound into any template expression.
  //
  // The popup never holds a popup-local `chrome.runtime.Port` (Pitfall 4 /
  // MV3 SW teardown) -- every RPC (match-origin/fill-entry/focus-app) is
  // relayed through background.ts's 'cryptiq-rpc' message handler. The fill
  // secret itself, once returned by that RPC, is sent DIRECTLY from this
  // popup to the content script via chrome.tabs.sendMessage -- it NEVER
  // re-enters background.ts/the native port a second time (17-RESEARCH.md
  // "Common Pitfalls": "Sending the secret through background.ts a second
  // time").
  //
  // Before sending the secret, recheckTabUnchanged (popupFill.ts) re-verifies
  // the active tab's id + origin are unchanged since the match list was
  // fetched (XSEC-03 TOCTOU) -- fill is ABORTED on any mismatch.
  import type { Component } from 'svelte';
  import { loadAssociation } from '../../src/lib/associationStore';
  import type { BridgeErrorCode } from '../../src/lib/bridgeRpc';
  import type { DetectResult, EntryMatchMetadata, FillResult } from '../../src/lib/contentScriptMessages';
  import {
    buildFillRequest,
    buildPickerViewModel,
    buildSearchViewModel,
    decideFillFlow,
    ensureContentScript,
    recheckTabUnchanged,
    type FillEntryPayload,
    type SearchEntryResult,
    type SearchRow,
  } from '../../src/lib/popupFill';
  // Plan 19-04: capture-buffer + never-save + decision-logic imports come from
  // the SHARED src/lib/ modules Plan 02/03 published -- NEVER from
  // entrypoints/background.ts (cross-entrypoint imports are forbidden; popup
  // <-> background otherwise talk only via runtime messages).
  import { readCapture, clearCaptureForTab } from '../../src/lib/captureBuffer';
  import { isNeverSave, markNeverSave } from '../../src/lib/neverSaveStore';
  import { buildSaveParams, decideCaptureFlow, shouldNudgeGenerate, type CaptureDecision } from '../../src/lib/captureFlow';

  let DevEchoComponent: Component | null = $state(null);

  if (import.meta.env.DEV) {
    // D-18: dev-only echo trigger, dynamically imported so Vite/WXT's
    // import.meta.env.DEV replacement strips this chunk from production.
    import('./DevEcho.svelte').then((mod) => {
      DevEchoComponent = mod.default;
    });
  }

  type PopupStatus =
    | { kind: 'loading' }
    | { kind: 'not-paired' }
    | { kind: 'disconnected' }
    | { kind: 'locked' }
    | {
        kind: 'connected-matches';
        candidates: EntryMatchMetadata[];
        fieldsDetected: boolean;
        tabId: number;
        origin: string;
      }
    | { kind: 'connected-no-matches' }
    | {
        /** CAP-01/02/03/D-06: a buffered capture exists, its origin passed the
         * TOCTOU recheck against the live tab, and the domain is not
         * never-saved -- decideCaptureFlow has classified it new/update/picker.
         * `allCandidates` is the full (username-unfiltered) match-origin list,
         * kept only for title lookups when rendering an update/picker choice
         * (structurally password-free, EntryMatchMetadata). */
        kind: 'capture';
        decision: CaptureDecision;
        allCandidates: EntryMatchMetadata[];
        registrableDomain: string;
        origin: string;
        tabId: number;
      };

  /** UI state for the fill dispatch itself, separate from the page-load
   * `status` above -- tracks which entry (if any) is currently being filled
   * and surfaces a refusal/failure message. Never carries the secret. */
  type FillUiState = { kind: 'idle' } | { kind: 'pending'; entryId: string } | { kind: 'error'; message: string };

  let status: PopupStatus = $state({ kind: 'loading' });
  let unlockRequested = $state(false);
  let fillState: FillUiState = $state({ kind: 'idle' });

  /** Plan 18-03 (UX-01/02): the live current tab id + origin, refreshed by
   * `refreshStatus` on every popup open -- kept OUTSIDE `status` (unlike the
   * original `connected-matches`-only `tabId`/`origin` fields) so search-
   * result rows can Fill (via the SAME `handleFillClick`/`recheckTabUnchanged`
   * TOCTOU flow, XSEC-03) even while `status.kind === 'connected-no-matches'`
   * -- a full-vault search can surface an entry for a site other than the one
   * `match-origin` matched, and Fill must still work in that case. Plain
   * (non-`$state`) local -- never rendered, only read inside async handlers. */
  let currentTabInfo: CurrentTab | null = null;

  // --- Plan 18-03: search box + result rows (UX-01) + copy (UX-02) --------
  //
  // `searchRows` is the ONLY vault-derived state here and is structurally
  // metadata-only (`SearchRow` has no password field, T-18-12) via
  // `buildSearchViewModel`. `copyFeedback` is an entryId+field acknowledgment
  // string only ("<entryId>:<field>") -- `copy-field`'s RPC response never
  // carries the copied value (T-18-13), so this file structurally cannot
  // render or log it.
  type SearchUiState = { kind: 'idle' } | { kind: 'pending' } | { kind: 'error'; message: string };
  type CopyUiState =
    | { kind: 'idle' }
    | { kind: 'pending'; entryId: string; field: 'username' | 'password' }
    | { kind: 'error'; message: string };

  let searchQuery = $state('');
  let searchRows: SearchRow[] = $state([]);
  let searchState: SearchUiState = $state({ kind: 'idle' });
  let copyState: CopyUiState = $state({ kind: 'idle' });
  /** entryId+field acknowledgment string ("<id>:<field>"), or null. Cleared a
   * couple seconds after a successful copy (UI-SPEC "Copy success feedback"
   * -- transient, non-modal, never a toast). */
  let copyFeedback: string | null = $state(null);
  let copyFeedbackTimeout: ReturnType<typeof setTimeout> | undefined;

  /** D-06: which entry the user picked from a multi-match capture picker,
   * before the update prompt renders for that specific entry. Reset whenever
   * a fresh capture is (re)classified (a new pick is required each time). No
   * secret ever lives here -- entryId only. */
  let pickedEntryId: string | null = $state(null);

  // --- Plan 19-04 Task 2: capture save-prompt form state -------------------
  //
  // `captureTitle`/`captureUsername` are non-secret and reactive ($state) --
  // ordinary editable text the user may adjust before saving. The PASSWORD
  // never follows this pattern (T-19-13): `capturePasswordEl` is only an
  // element reference (itself not a secret), and the actual password value
  // lives ONLY in that uncontrolled <input>'s own DOM `.value` -- read
  // on-demand (Save click, debounced scoring) and written on-demand
  // (Generate), NEVER copied into a Svelte-reactive variable. `initialCapturedPassword`
  // is a plain (non-`$state`) local that seeds the input's value exactly once
  // at mount via the `seedPasswordValue` action below -- it is the one place
  // the buffered secret briefly rests outside the DOM element itself.
  let captureTitle = $state('');
  let captureUsername = $state('');
  let capturePasswordEl: HTMLInputElement | null = $state(null);
  let initialCapturedPassword = '';
  let generating = $state(false);
  type CaptureSaveState = { kind: 'idle' } | { kind: 'pending' } | { kind: 'error'; message: string };
  let captureSaveState: CaptureSaveState = $state({ kind: 'idle' });

  // --- Plan 19-04 Task 3: live debounced strength meter + weak nudge -------
  //
  // Only the NUMERIC score enters reactive display state (HEALTH-01/03) --
  // the password itself is read fresh off the DOM input at score time and
  // immediately discarded, mirroring OBSERVER_DEBOUNCE_MS's precedent
  // (fill.content.ts:44) for the debounce window. Never caches a native port
  // to speed this up (Anti-Pattern -- resurrects BUG-5); only the CALLER is
  // debounced.
  const SCORE_DEBOUNCE_MS = 300;
  let strengthScore = $state(0);
  let scoreDebounceHandle: ReturnType<typeof setTimeout> | undefined;

  function handlePasswordInput(): void {
    if (scoreDebounceHandle !== undefined) clearTimeout(scoreDebounceHandle);
    scoreDebounceHandle = setTimeout(() => {
      scoreDebounceHandle = undefined;
      void scoreCurrentPassword();
    }, SCORE_DEBOUNCE_MS);
  }

  async function scoreCurrentPassword(el?: HTMLInputElement | null): Promise<void> {
    const password = (el ?? capturePasswordEl)?.value ?? '';
    const outcome = await sendRpcViaBackground({ method: 'score-password', params: { password } });
    const score =
      outcome.ok && typeof outcome.payload === 'object' && outcome.payload !== null
        ? (outcome.payload as { score?: unknown }).score
        : undefined;
    strengthScore = typeof score === 'number' ? score : 0;
  }

  /** Score → semantic token mapping mirroring StrengthMeter.svelte's bands.
   * Phase 27 (XUI-02): now expressed as `cryptiq-*` token utility classes
   * (bg-cryptiq-success/attention/danger) instead of literal hex -- the
   * popup shares the desktop's design system, never invents its own colors. */
  function scoreColorClass(score: number): string {
    if (score >= 3) return 'bg-cryptiq-success'; // fair/excellent
    if (score === 2) return 'bg-cryptiq-attention'; // weak
    return 'bg-cryptiq-danger'; // very weak
  }

  /** Svelte action: sets the input's DOM value ONCE at mount, reading
   * `initialCapturedPassword` from closure (deliberately NOT as a templated
   * `use:seedPasswordValue={...}` parameter -- referencing the secret inside
   * `{...}` markup makes the Svelte compiler flag it as "should be `$state`",
   * which is exactly what T-19-13 forbids). No `update()` callback, so this
   * runs exactly once and the secret is never tracked as reactive state. */
  function seedPasswordValue(node: HTMLInputElement): void {
    node.value = initialCapturedPassword;
    // HEALTH-01/03: score the seeded (captured) password immediately so the
    // meter isn't blank until the user's first keystroke. `node` is passed
    // explicitly (not via `capturePasswordEl`) since `bind:this` may not have
    // settled yet relative to this action at mount.
    if (initialCapturedPassword.length > 0) void scoreCurrentPassword(node);
  }

  interface RpcMessageOutcome {
    ok: boolean;
    code?: BridgeErrorCode;
    payload?: unknown;
  }

  /**
   * Relay one inner `{ method, params }` RPC through background.ts's
   * 'cryptiq-rpc' handler. Never throws — a missing/torn-down background
   * context resolves as a transport failure, which callers fail closed on.
   */
  async function sendRpcViaBackground(innerPayload: Record<string, unknown>): Promise<RpcMessageOutcome> {
    try {
      const result = (await chrome.runtime.sendMessage({ type: 'cryptiq-rpc', payload: innerPayload })) as
        | RpcMessageOutcome
        | undefined;
      return result ?? { ok: false, code: 'unknown' };
    } catch {
      return { ok: false, code: 'unknown' };
    }
  }

  interface CurrentTab {
    tabId: number;
    origin: string;
  }

  /**
   * Read the current active tab's id + top-level origin in one query.
   * Extends D-10's original origin-only read (Task 2 additionally needs the
   * tab id for ensureContentScript/chrome.tabs.sendMessage targeting and the
   * TOCTOU recheck). Requires `activeTab` (granted for the duration of this
   * popup-open user gesture) — returns null if unavailable, which fails
   * closed to the `disconnected` state rather than guessing.
   */
  async function getCurrentTab(): Promise<CurrentTab | null> {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id || !tab.url) return null;
      return { tabId: tab.id, origin: new URL(tab.url).origin };
    } catch {
      return null;
    }
  }

  /**
   * CAP-01/02/03/04, D-06 (Plan 19-04 Task 1): on every popup open, check for
   * a buffered capture BEFORE falling into the ordinary fill-status flow
   * below. Returns `true` (and has already set `status`) when a capture
   * prompt should render; returns `false` when there is nothing captured, the
   * TOCTOU recheck failed, the domain is never-saved, or the match-origin
   * round trip itself failed -- in every `false` case the caller falls
   * through to the EXISTING fill-status flow unchanged (which will render its
   * own correct locked/disconnected state for the same match-origin failure,
   * or the ordinary connected-matches/no-matches view when there is simply no
   * capture for this tab).
   *
   * Order matters: (1) read the buffer, (2) TOCTOU-recheck the buffered
   * origin against the LIVE active tab (reuses popupFill.ts's
   * `recheckTabUnchanged` discipline -- T-19-12: a reused tab must never
   * resurface a prior origin's capture), (3) fetch `match-origin` for the
   * registrableDomain (needed for the never-save check, CAP-04/D-04 -- the
   * extension holds no local eTLD+1 computation of its own), (4) never-save
   * gate, (5) `decideCaptureFlow` classifies new/update/picker. Any refusal
   * step also clears the buffer (Pitfall 5: a suppressed capture must never
   * leave a stale buffer/badge behind for a later popup open to resurface).
   */
  async function tryRenderCapture(tab: CurrentTab): Promise<boolean> {
    const capture = await readCapture(tab.tabId);
    if (capture === null) return false;

    const unchanged = await recheckTabUnchanged(tab.tabId, capture.origin);
    if (!unchanged) {
      await clearCaptureForTab(tab.tabId);
      return false;
    }

    const outcome = await sendRpcViaBackground({ method: 'match-origin', params: { origin: tab.origin } });
    if (!outcome.ok) {
      // Let the caller's own match-origin call (below) render the correct
      // locked/disconnected state for this same failure -- no need to
      // duplicate that branching here.
      return false;
    }

    const payload = outcome.payload;
    const registrableDomain =
      payload !== null &&
      typeof payload === 'object' &&
      typeof (payload as { registrableDomain?: unknown }).registrableDomain === 'string'
        ? (payload as { registrableDomain: string }).registrableDomain
        : '';
    const allCandidates =
      payload !== null && typeof payload === 'object' && Array.isArray((payload as { candidates?: unknown }).candidates)
        ? (payload as { candidates: EntryMatchMetadata[] }).candidates
        : [];

    if (registrableDomain !== '' && (await isNeverSave(registrableDomain))) {
      await clearCaptureForTab(tab.tabId);
      return false;
    }

    const decision = decideCaptureFlow(allCandidates, capture.username);

    pickedEntryId = null; // a fresh classification always requires a fresh pick
    captureTitle = registrableDomain !== '' ? registrableDomain : tab.origin; // CAP-02
    captureUsername = capture.username;
    initialCapturedPassword = capture.password; // consumed once by seedPasswordValue at mount
    captureSaveState = { kind: 'idle' };
    strengthScore = 0; // re-scored once the seeded input mounts (below) or the user types

    status = {
      kind: 'capture',
      decision,
      allCandidates,
      registrableDomain,
      origin: tab.origin,
      tabId: tab.tabId,
    };
    return true;
  }

  /**
   * D-10 / RESEARCH.md Pattern 3, extended by Plan 17-04: on-open status
   * query. (1) check association, (2) fetch the current tab id + origin,
   * (3) fire a lock-aware `match-origin` RPC, (4) on a non-empty candidate
   * list, ensure the content script is present and ask it whether it
   * detected a fillable field (FILL-06's escape-hatch signal) — a failed
   * injection/detect fails closed to `fieldsDetected: false` rather than
   * guessing a field exists (D-02).
   */
  async function refreshStatus(): Promise<void> {
    const association = await loadAssociation();
    if (!association) {
      status = { kind: 'not-paired' };
      return;
    }

    const tab = await getCurrentTab();
    if (tab === null) {
      // No readable tab (e.g. a chrome:// page) — fail closed the same as
      // any other transport-level failure rather than guessing.
      status = { kind: 'disconnected' };
      return;
    }

    currentTabInfo = tab; // Plan 18-03: available to search-triggered Fill regardless of match state

    const captureRendered = await tryRenderCapture(tab);
    if (captureRendered) return;

    const outcome = await sendRpcViaBackground({ method: 'match-origin', params: { origin: tab.origin } });

    if (!outcome.ok) {
      // vault-locked is a distinct, honest render (XSEC-06) — branch it off
      // BEFORE the generic disconnected fallback below. Every OTHER failure
      // (timeout, not-associated, protocol-error, app-not-running) stays
      // disconnected, fail closed (RESEARCH.md Pattern 3).
      if (outcome.code === 'vault-locked') {
        status = { kind: 'locked' };
        return;
      }
      status = { kind: 'disconnected' };
      return;
    }

    // Success payload is now a decrypted, authenticated JSON value (BUG-2
    // fix) — the bytes are authenticated, but JSON.parse can still yield any
    // shape, so treat a real match list as ONLY an object carrying an array
    // `candidates`; anything else renders connected-no-matches rather than
    // mis-driving the picker.
    const payload = outcome.payload;
    const candidates =
      payload !== null && typeof payload === 'object' && Array.isArray((payload as { candidates?: unknown }).candidates)
        ? ((payload as { candidates: EntryMatchMetadata[] }).candidates)
        : [];

    if (candidates.length === 0) {
      status = { kind: 'connected-no-matches' };
      void handleSearchInput(); // Plan 18-03: seed the search list even with zero current-tab matches
      return;
    }

    let fieldsDetected = false;
    const injected = await ensureContentScript(tab.tabId);
    if (injected) {
      try {
        const detectResult = (await chrome.tabs.sendMessage(tab.tabId, { type: 'cryptiq-detect' })) as
          | DetectResult
          | undefined;
        fieldsDetected = detectResult?.ok === true && detectResult.fieldsDetected === true;
      } catch {
        fieldsDetected = false; // fail closed — never guess a field exists
      }
    }

    status = { kind: 'connected-matches', candidates, fieldsDetected, tabId: tab.tabId, origin: tab.origin };
    void handleSearchInput(); // Plan 18-03: seed the search list alongside the current-tab picker
  }

  void refreshStatus();

  /**
   * D-11: best-effort "Unlock Cryptiq" focus-raise. Fires a `focus-app` RPC
   * and ignores the result entirely — the locked message stays shown
   * regardless of whether the app's window was actually raised (Windows
   * foreground-lock restrictions can silently no-op set_focus()).
   */
  async function handleUnlockClick(): Promise<void> {
    unlockRequested = true;
    await sendRpcViaBackground({ method: 'focus-app', params: {} });
  }

  /**
   * FILL-04/05/06 fill dispatch: (1) fetch the secret via the existing
   * `fill-entry` RPC (same authenticated round trip `match-origin` already
   * uses); (2) recheckTabUnchanged — ABORT on any tab id/origin mismatch
   * (XSEC-03 TOCTOU); (3) send the secret DIRECTLY to the content script via
   * chrome.tabs.sendMessage — never re-entering background.ts/the native
   * port. `entryId`/`username`/`email` are the only identifiers threaded
   * through; the secret/card/identity payload itself is a plain local,
   * never retained past this call and never assigned to a `$state` variable
   * (XSEC-06).
   *
   * Phase 26 (CFILL-04, D-03): dispatches on the freshly-decrypted
   * `fill-entry` RPC response's OWN `type` discriminant — never the clicked
   * row's `EntryMatchMetadata.type` (fetched earlier, could have drifted) —
   * and builds the matching `kind`-tagged `FillRequest` via the pure
   * `buildFillRequest` helper (popupFill.ts). `email` is threaded from the
   * widened `PickerRow`/`SearchRow` (D-04) for the login branch's IDENT-02
   * precedence.
   *
   * Reads tab id/origin from `currentTabInfo` (Plan 18-03) rather than
   * `status`, so search-result rows can Fill even from `connected-no-matches`
   * (a full-vault search can surface an entry for a site `match-origin`
   * didn't match for the current tab) — the picker's own Fill call site is
   * unchanged (still calls this exact function).
   */
  async function handleFillClick(entryId: string, username: string, email?: string): Promise<void> {
    if (currentTabInfo === null) return;
    const { tabId, origin } = currentTabInfo;

    fillState = { kind: 'pending', entryId };

    // CR-01: inject the content script on demand before dispatching the fill.
    // `refreshStatus` only injects in the `connected-matches` branch (for the
    // current-tab picker); a search-result Fill fired from the
    // `connected-no-matches` state — the motivating full-vault-search case —
    // would otherwise deliver `cryptiq-fill` to a tab with no listener and fail
    // silently. Mirrors the context-menu path (`handleContextFill` injects
    // first). Idempotent (ping-then-inject), fails closed on a non-injectable
    // page (e.g. chrome://).
    const injected = await ensureContentScript(tabId);
    if (!injected) {
      fillState = { kind: 'error', message: 'Could not fill this page.' };
      return;
    }

    const outcome = await sendRpcViaBackground({ method: 'fill-entry', params: { entryId } });
    // T-26-07 (Tampering): runtime-guard the discriminated payload BEFORE
    // trusting any field — extends the existing typeof==='object'&&!==null
    // guard shape (unchanged) with an explicit type-literal + matching-field
    // check per variant. Never a bare `as` cast on the raw payload.
    const raw =
      outcome.ok && typeof outcome.payload === 'object' && outcome.payload !== null
        ? (outcome.payload as { type?: unknown; secret?: unknown; card?: unknown; identity?: unknown })
        : null;
    let payload: FillEntryPayload | null = null;
    if (raw !== null && raw.type === 'login' && typeof raw.secret === 'string') {
      payload = { type: 'login', secret: raw.secret };
    } else if (raw !== null && raw.type === 'card' && typeof raw.card === 'object' && raw.card !== null) {
      payload = { type: 'card', card: raw.card as Extract<FillEntryPayload, { type: 'card' }>['card'] };
    } else if (raw !== null && raw.type === 'identity' && typeof raw.identity === 'object' && raw.identity !== null) {
      payload = { type: 'identity', identity: raw.identity as Extract<FillEntryPayload, { type: 'identity' }>['identity'] };
    }
    if (payload === null) {
      fillState = { kind: 'error', message: 'Could not retrieve the password.' };
      return;
    }

    const unchanged = await recheckTabUnchanged(tabId, origin);
    if (!unchanged) {
      // The tab navigated between the match list being fetched and this
      // click — refuse rather than fill a possibly-different page (XSEC-03).
      // Runs for EVERY kind (T-26-09), not just login.
      fillState = { kind: 'error', message: 'The page changed — reopen the popup to fill.' };
      return;
    }

    try {
      const request = buildFillRequest(payload, { username, ...(email !== undefined ? { email } : {}) }, origin);
      const result = (await chrome.tabs.sendMessage(tabId, request)) as FillResult | undefined;
      fillState = result?.ok ? { kind: 'idle' } : { kind: 'error', message: 'Could not fill this page.' };
    } catch {
      fillState = { kind: 'error', message: 'Could not fill this page.' };
    }
  }

  /**
   * UX-01: full-vault metadata-only search. Reads the live current tab's
   * origin fresh (via `getCurrentTab`, same pattern as `refreshStatus`) so a
   * search fired seconds after popup-open still pins the CURRENT tab, not a
   * stale one. Maps the RPC's `{ results }` payload through
   * `buildSearchViewModel` (Svelte-free, no-reorder/no-filter, structurally
   * no password field — T-18-12) into `searchRows`. Called once automatically
   * on every successful `connected-*` status resolution (seeds the list
   * before the user types anything) and again on every `oninput`.
   */
  async function handleSearchInput(): Promise<void> {
    // WR-01: capture the query at call time so out-of-order responses can be
    // discarded. Each keystroke fires an un-debounced async round trip through
    // background.ts + a fresh native port, so responses can resolve out of
    // order (typing `a` then `ab` may resolve `a` last). Without this guard the
    // stale `a` results would clobber `searchRows`/`searchState` for a query no
    // longer in the box.
    const queryAtCall = searchQuery;
    searchState = { kind: 'pending' };

    const tab = await getCurrentTab();
    const outcome = await sendRpcViaBackground({
      method: 'search-entries',
      params: { query: queryAtCall, currentOrigin: tab?.origin ?? '' },
    });

    // A newer keystroke superseded this in-flight response — drop it.
    if (queryAtCall !== searchQuery) return;

    if (!outcome.ok) {
      searchState = { kind: 'error', message: 'Could not search the vault.' };
      return;
    }

    const payload = outcome.payload;
    const results =
      payload !== null && typeof payload === 'object' && Array.isArray((payload as { results?: unknown }).results)
        ? (payload as { results: SearchEntryResult[] }).results
        : [];

    searchRows = buildSearchViewModel(results);
    searchState = { kind: 'idle' };
  }

  /**
   * UX-02: app-side copy via `copy-field` — NEVER reads/renders/logs the
   * copied value (XSEC-06); `outcome.ok` is the only signal this function
   * ever touches. `copyFeedback` is cleared automatically after ~2s
   * (transient, non-modal acknowledgment per UI-SPEC — no toast mechanism
   * exists in this codebase and this phase does not introduce one).
   */
  async function handleCopyClick(entryId: string, field: 'username' | 'password'): Promise<void> {
    copyState = { kind: 'pending', entryId, field };

    const outcome = await sendRpcViaBackground({ method: 'copy-field', params: { entryId, field } });

    if (!outcome.ok) {
      copyState = { kind: 'error', message: 'Could not copy this field.' };
      copyFeedback = null;
      return;
    }

    copyState = { kind: 'idle' };
    const feedbackKey = `${entryId}:${field}`;
    copyFeedback = feedbackKey;
    if (copyFeedbackTimeout !== undefined) clearTimeout(copyFeedbackTimeout);
    copyFeedbackTimeout = setTimeout(() => {
      copyFeedbackTimeout = undefined;
      if (copyFeedback === feedbackKey) copyFeedback = null;
    }, 2000);
  }

  /**
   * Pitfall 5 (SC-3 no-ghost-prompt): the SINGLE dismissal seam every capture
   * exit path (Save success, Update success, plain Dismiss, Never-save) routes
   * through. Always clears the shared buffer+badge together, resets all
   * capture-local UI state, then re-runs `refreshStatus` so the popup falls
   * back to the ordinary fill flow now that the buffer is gone.
   */
  async function dismissCapture(tabId: number): Promise<void> {
    await clearCaptureForTab(tabId);
    pickedEntryId = null;
    captureSaveState = { kind: 'idle' };
    strengthScore = 0;
    if (scoreDebounceHandle !== undefined) {
      clearTimeout(scoreDebounceHandle);
      scoreDebounceHandle = undefined;
    }
    await refreshStatus();
  }

  async function handleCaptureDismissClick(): Promise<void> {
    if (status.kind !== 'capture') return;
    await dismissCapture(status.tabId);
  }

  /** CAP-04/D-04: mark the registrable domain never-save, THEN run the same
   * shared dismissal seam (Never-save always clears too — a suppressed
   * domain must never leave a stale buffer/badge behind). */
  async function handleNeverSaveClick(): Promise<void> {
    if (status.kind !== 'capture') return;
    if (status.registrableDomain !== '') {
      await markNeverSave(status.registrableDomain);
    }
    await dismissCapture(status.tabId);
  }

  /**
   * GEN-01/02, D-02/D-03: request a fresh CSPRNG password from the app's
   * saved generator preset (no override params), write it directly into the
   * popup's own password input (plain DOM write, never `$state` — T-19-13),
   * and best-effort mirror it onto the actual page field via the existing
   * `cryptiq-fill` content-script message so the user sees it applied on the
   * real signup form. Generation is a suggestion (D-03) — never auto-applied
   * without this explicit click, and the user may still edit/replace it
   * before saving.
   */
  async function handleGenerateClick(): Promise<void> {
    if (status.kind !== 'capture') return;
    const { tabId, origin } = status;

    generating = true;
    const outcome = await sendRpcViaBackground({ method: 'generate-password', params: {} });
    generating = false;

    const generated =
      outcome.ok && typeof outcome.payload === 'object' && outcome.payload !== null
        ? (outcome.payload as { password?: unknown }).password
        : undefined;
    if (typeof generated !== 'string') return;

    if (capturePasswordEl) capturePasswordEl.value = generated;
    void scoreCurrentPassword(); // HEALTH-01/03: re-score immediately, don't wait for the debounce

    // Best-effort mirror onto the real page field — XSEC-03 TOCTOU recheck
    // first (same discipline as handleFillClick); a mismatch skips ONLY the
    // page-fill, the popup's own field is still updated.
    const unchanged = await recheckTabUnchanged(tabId, origin);
    if (unchanged) {
      try {
        await chrome.tabs.sendMessage(tabId, {
          type: 'cryptiq-fill',
          secret: generated,
          username: captureUsername,
          expectedOrigin: origin,
        });
      } catch {
        // Best-effort only — the popup's own input is still filled.
      }
    }
  }

  /**
   * Explicit Save/Update confirm (CAP-01/03, GEN-02): reads the CURRENT
   * password straight off the DOM input (never a `$state` copy), threads it
   * through `buildSaveParams` (Plan 02's GEN-02 seam — proves a generated
   * value is carried unchanged), and calls `save-or-update-entry`. On
   * success, routes through the shared `dismissCapture` seam; on failure,
   * surfaces a typed, non-secret error message.
   */
  async function handleCaptureSaveClick(mode: 'new' | 'update', entryId: string | undefined): Promise<void> {
    if (status.kind !== 'capture') return;

    const password = capturePasswordEl?.value ?? '';
    if (password.length === 0) {
      captureSaveState = { kind: 'error', message: 'Enter or generate a password first.' };
      return;
    }

    captureSaveState = { kind: 'pending' };

    const params = buildSaveParams({
      mode,
      ...(entryId !== undefined ? { entryId } : {}),
      title: captureTitle,
      username: captureUsername,
      password,
      url: status.origin,
    });

    const outcome = await sendRpcViaBackground({ method: 'save-or-update-entry', params });

    if (outcome.ok) {
      await dismissCapture(status.tabId);
      return;
    }

    captureSaveState = {
      kind: 'error',
      message: outcome.code === 'vault-locked' ? 'Cryptiq is locked — unlock it to save.' : 'Could not save this entry.',
    };
  }
</script>

<main class="bg-cryptiq-bg font-sans text-cryptiq-fg">
  <h1 class="m-0 mb-3 text-emphasis font-semibold text-cryptiq-fg">Cryptiq</h1>

  {#if status.kind === 'loading'}
    <p class="m-0 text-meta text-cryptiq-fg-subtle">Checking status…</p>
  {:else if status.kind === 'not-paired'}
    <p class="m-0 text-body text-cryptiq-fg-muted">Open Cryptiq to approve</p>
  {:else if status.kind === 'disconnected'}
    <p class="m-0 text-body text-cryptiq-fg-muted">Cryptiq isn't running</p>
  {:else if status.kind === 'locked'}
    <p class="m-0 mb-3 text-body text-cryptiq-fg-muted">Cryptiq is locked — unlock it to fill</p>
    <button
      onclick={handleUnlockClick}
      disabled={unlockRequested}
      class="rounded-cryptiq bg-cryptiq-accent px-3 py-1.5 text-body font-medium text-cryptiq-accent-fg disabled:opacity-60"
    >
      {unlockRequested ? 'Unlock requested' : 'Unlock Cryptiq'}
    </button>
  {:else if status.kind === 'connected-no-matches'}
    <p class="m-0 text-body text-cryptiq-fg-muted">No saved logins for this site</p>
  {:else if status.kind === 'capture'}
    {#if status.decision.kind === 'picker' && pickedEntryId === null}
      <!-- D-06: reuses the connected-matches picker list idiom (below) to let
           the user choose which existing entry this capture updates. -->
      <p class="m-0 mb-2 text-body text-cryptiq-fg-muted">Which login is this for?</p>
      <ul class="m-0 list-none p-0">
        {#each status.decision.candidates as row (row.id)}
          <li class="mb-1.5">
            <button
              onclick={() => (pickedEntryId = row.id)}
              class="w-full rounded-cryptiq px-2.5 py-2 text-left text-body text-cryptiq-fg hover:bg-cryptiq-hover"
            >
              {row.title}
            </button>
            {#if row.weak || row.reused}
              <span class="text-meta text-cryptiq-attention">
                {row.weak ? 'Weak' : ''}{row.weak && row.reused ? ' · ' : ''}{row.reused ? 'Reused' : ''}
              </span>
            {/if}
          </li>
        {/each}
      </ul>
    {:else}
      {@const mode = status.decision.kind === 'new' ? 'new' : 'update'}
      {@const entryId = status.decision.kind === 'update' ? status.decision.entryId : (pickedEntryId ?? undefined)}
      {@const existingTitle =
        entryId !== undefined ? (status.allCandidates.find((c) => c.id === entryId)?.title ?? status.registrableDomain) : status.registrableDomain}

      <p class="m-0 mb-1 text-body text-cryptiq-fg">
        {mode === 'new' ? `Save password for ${existingTitle}?` : `Update password for ${existingTitle}?`}
      </p>
      <p class="m-0 mb-3 text-meta text-cryptiq-fg-subtle">{status.origin}</p>

      {#if mode === 'new'}
        <label for="capture-title" class="mb-0.5 block text-meta text-cryptiq-fg-subtle">Title</label>
        <input
          id="capture-title"
          type="text"
          bind:value={captureTitle}
          class="mb-2.5 box-border w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-2.5 py-1.5 text-body text-cryptiq-fg focus:outline-none focus:ring-2 focus:ring-cryptiq-ring"
        />
      {/if}

      <label for="capture-username" class="mb-0.5 block text-meta text-cryptiq-fg-subtle">Username</label>
      <input
        id="capture-username"
        type="text"
        bind:value={captureUsername}
        class="mb-2.5 box-border w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-2.5 py-1.5 text-body text-cryptiq-fg focus:outline-none focus:ring-2 focus:ring-cryptiq-ring"
      />

      <label for="capture-password" class="mb-0.5 block text-meta text-cryptiq-fg-subtle">Password</label>
      <input
        id="capture-password"
        type="password"
        use:seedPasswordValue
        bind:this={capturePasswordEl}
        oninput={handlePasswordInput}
        class="mb-2 box-border w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-2.5 py-1.5 font-mono text-body text-cryptiq-fg focus:outline-none focus:ring-2 focus:ring-cryptiq-ring"
      />

      <!-- HEALTH-01/03: live debounced strength meter -- only the numeric
           score is reactive display state, never the password itself. -->
      <div class="mb-2.5 flex gap-0.5" aria-hidden="true">
        {#each [0, 1, 2, 3] as i (i)}
          <div
            class="h-1 flex-1 rounded-cryptiq {strengthScore >= i + 1 ? scoreColorClass(strengthScore) : 'bg-cryptiq-border-strong'}"
          ></div>
        {/each}
      </div>

      {#if shouldNudgeGenerate(strengthScore)}
        <p class="m-0 mb-3 text-meta text-cryptiq-attention">
          Weak password —
          <button onclick={handleGenerateClick} disabled={generating} class="text-meta font-medium text-cryptiq-accent underline disabled:opacity-60">
            {generating ? 'Generating…' : 'Generate a strong one instead'}
          </button>
        </p>
      {:else}
        <button
          onclick={handleGenerateClick}
          disabled={generating}
          class="mb-3 rounded-cryptiq border border-cryptiq-border-strong px-2.5 py-1 text-meta text-cryptiq-fg hover:bg-cryptiq-hover disabled:opacity-60"
        >
          {generating ? 'Generating…' : 'Generate strong password'}
        </button>
      {/if}

      <div class="flex gap-1.5">
        <button
          onclick={() => handleCaptureSaveClick(mode, entryId)}
          disabled={captureSaveState.kind === 'pending'}
          class="rounded-cryptiq bg-cryptiq-accent px-3 py-1.5 text-body font-medium text-cryptiq-accent-fg disabled:opacity-60"
        >
          {captureSaveState.kind === 'pending' ? 'Saving…' : mode === 'new' ? 'Save' : 'Update'}
        </button>
        <button
          onclick={handleCaptureDismissClick}
          disabled={captureSaveState.kind === 'pending'}
          class="rounded-cryptiq border border-cryptiq-border-strong px-2.5 py-1.5 text-body text-cryptiq-fg hover:bg-cryptiq-hover disabled:opacity-60"
        >
          Dismiss
        </button>
        <button
          onclick={handleNeverSaveClick}
          disabled={captureSaveState.kind === 'pending'}
          class="rounded-cryptiq border border-cryptiq-border-strong px-2.5 py-1.5 text-meta text-cryptiq-fg-muted hover:bg-cryptiq-hover disabled:opacity-60"
        >
          Never save this site
        </button>
      </div>

      {#if captureSaveState.kind === 'error'}
        <p class="m-0 mt-1.5 text-meta text-cryptiq-danger">{captureSaveState.message}</p>
      {/if}
    {/if}
  {:else if status.kind === 'connected-matches'}
    {@const flow = decideFillFlow({ candidates: status.candidates, fieldsDetected: status.fieldsDetected })}
    {@const rows = buildPickerViewModel(status.candidates)}

    {#if !status.fieldsDetected}
      <p class="m-0 mb-2 text-meta text-cryptiq-fg-subtle">No login field detected on this page.</p>
    {/if}

    {#if flow.kind === 'single'}
      {@const row = rows[0]}
      <button
        onclick={() => handleFillClick(row.id, row.username, row.email)}
        disabled={fillState.kind === 'pending'}
        class="rounded-cryptiq bg-cryptiq-accent px-3 py-1.5 text-body font-medium text-cryptiq-accent-fg disabled:opacity-60"
      >
        {fillState.kind === 'pending' ? 'Filling…' : flow.fillAnyway ? 'Fill anyway' : 'Fill'}
      </button>
      {#if row.weak || row.reused}
        <p class="m-0 mt-1 text-meta text-cryptiq-attention">
          {row.weak ? 'Weak password' : ''}{row.weak && row.reused ? ' · ' : ''}{row.reused ? 'Reused password' : ''}
        </p>
      {/if}
    {:else if flow.kind === 'picker'}
      <ul class="m-0 list-none p-0">
        {#each rows as row (row.id)}
          <li class="mb-1.5">
            <button
              onclick={() => handleFillClick(row.id, row.username, row.email)}
              disabled={fillState.kind === 'pending'}
              class="w-full rounded-cryptiq px-2.5 py-2 text-left text-body text-cryptiq-fg hover:bg-cryptiq-hover"
            >
              {fillState.kind === 'pending' && fillState.entryId === row.id
                ? 'Filling…'
                : flow.fillAnyway
                  ? `Fill anyway — ${row.title}`
                  : row.title}
            </button>
            {#if row.weak || row.reused}
              <span class="text-meta text-cryptiq-attention">
                {row.weak ? 'Weak' : ''}{row.weak && row.reused ? ' · ' : ''}{row.reused ? 'Reused' : ''}
              </span>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}

    {#if fillState.kind === 'error'}
      <p class="m-0 mt-1.5 text-meta text-cryptiq-danger">{fillState.message}</p>
    {/if}
  {/if}

  {#if status.kind === 'connected-matches' || status.kind === 'connected-no-matches'}
    <!-- Plan 18-03 (UX-01/02): full-vault search + Fill/Copy rows, rendered
         alongside (below) the existing current-tab status/picker above —
         does not replace or gate that surface. Hidden during loading/
         not-paired/disconnected/locked/capture (no readable vault or a
         full-takeover form already occupying the popup). -->
    <hr class="my-2.5 border-0 border-t border-cryptiq-border" />
    <input
      type="text"
      placeholder="Search vault…"
      bind:value={searchQuery}
      oninput={handleSearchInput}
      class="mb-2.5 box-border w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-2.5 py-1.5 text-body text-cryptiq-fg focus:outline-none focus:ring-2 focus:ring-cryptiq-ring"
    />

    {#if searchState.kind === 'error'}
      <p class="m-0 mb-2 text-meta text-cryptiq-danger">{searchState.message}</p>
    {:else if searchRows.length === 0}
      <p class="m-0 text-body text-cryptiq-fg-subtle">
        {searchQuery === '' ? 'No saved logins yet.' : 'No matches for that search.'}
      </p>
    {:else}
      <ul class="m-0 list-none p-0">
        {#each searchRows as row (row.id)}
          <li class="mb-1.5 flex items-center justify-between gap-1">
            <span class="overflow-hidden text-ellipsis whitespace-nowrap text-body text-cryptiq-fg">
              {row.title}{row.currentTab ? ' 📌' : ''}
            </span>
            <span class="flex flex-shrink-0 gap-1">
              <!-- WR-03 (anti-phishing): a full-vault search lets any entry be
                   filled into the CURRENT tab, even one saved for a different
                   site. The origin guards only prove the secret reaches the
                   page the popup opened on — not that the entry's domain
                   matches it. When `currentTab` is false, surface a visible
                   caution (color + ⚠ + tooltip) so a cross-domain Fill never
                   has the same affordance as a same-domain Fill. -->
              <button
                onclick={() => handleFillClick(row.id, row.username, row.email)}
                disabled={fillState.kind === 'pending'}
                title={row.currentTab
                  ? undefined
                  : 'This login is saved for a different site than the page you are on — only fill it if you trust this page.'}
                class="rounded-cryptiq border border-cryptiq-border-strong px-2 py-1 text-meta hover:bg-cryptiq-hover disabled:opacity-60 {row.currentTab
                  ? 'text-cryptiq-fg'
                  : 'text-cryptiq-attention'}"
              >
                {fillState.kind === 'pending' && fillState.entryId === row.id
                  ? 'Filling…'
                  : row.currentTab
                    ? 'Fill'
                    : 'Fill ⚠'}
              </button>
              <button
                onclick={() => handleCopyClick(row.id, 'username')}
                disabled={copyState.kind === 'pending'}
                class="rounded-cryptiq border border-cryptiq-border-strong px-2 py-1 text-meta text-cryptiq-fg hover:bg-cryptiq-hover disabled:opacity-60"
              >
                {copyState.kind === 'pending' && copyState.entryId === row.id && copyState.field === 'username'
                  ? 'Copying…'
                  : copyFeedback === `${row.id}:username`
                    ? 'Copied'
                    : 'Copy user'}
              </button>
              <button
                onclick={() => handleCopyClick(row.id, 'password')}
                disabled={copyState.kind === 'pending'}
                class="rounded-cryptiq border border-cryptiq-border-strong px-2 py-1 text-meta text-cryptiq-fg hover:bg-cryptiq-hover disabled:opacity-60"
              >
                {copyState.kind === 'pending' && copyState.entryId === row.id && copyState.field === 'password'
                  ? 'Copying…'
                  : copyFeedback === `${row.id}:password`
                    ? 'Copied'
                    : 'Copy pass'}
              </button>
            </span>
          </li>
        {/each}
      </ul>
    {/if}

    {#if copyState.kind === 'error'}
      <p class="m-0 mt-1.5 text-meta text-cryptiq-danger">{copyState.message}</p>
    {/if}
  {/if}

  {#if import.meta.env.DEV && DevEchoComponent}
    <DevEchoComponent />
  {/if}
</main>
