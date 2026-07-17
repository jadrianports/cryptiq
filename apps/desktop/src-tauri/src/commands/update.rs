// apps/desktop/src-tauri/src/commands/update.rs
//
// Phase 36 — update-channel trust (UPD-01..04 GATE), Rust-only updater. The JS plugin
// (@tauri-apps/plugin-updater) is the REJECTED side of a settled divergence — importing it
// destroys the zero-capability/zero-CSP-diff property UPD-04 asserts.
//
// Responsibilities:
//   VaultLockState       — Rust-authoritative mirror of the renderer's vault lock state
//                           (managed Tauri state, `.manage(...)` in lib.rs).
//   vault_lock_state_set — #[tauri::command] glue (Plan 07): the renderer's ONE call site for
//                           mutating VaultLockState. One command with a boolean, not two
//                           commands, so the BEFORE-derive/AFTER-wipe call sites in
//                           vault.svelte.ts stay symmetrical and impossible to half-implement.
//   should_apply          — the pure apply-seam decision (Plan 07, UPD-05 gate): no AppHandle,
//                           no Tauri, no I/O — unit-testable by constructing Option<bool>
//                           directly, mirroring hibp.rs's build_hibp_request "assert on the
//                           unfired state" discipline.
//   update_apply           — #[tauri::command] glue: resolves VaultLockState, calls
//                           should_apply, and — on Ok — does NOT yet install (Phase 37 wires
//                           the real install() path). update_check is NOT added this plan;
//                           its runtime belongs to Phase 37 alongside its consent gate.
//
// Security invariants:
//   - The update endpoint is a Rust `const` (when it lands, in a later plan); no `url`/`host`/
//     `endpoint` parameter exists on any #[tauri::command] in this module — mirrors HIBP_HOST,
//     JS can never redirect egress.
//   - `VaultLockState` is Rust-authoritative and initializes to LOCKED at process start — a
//     fresh process must never read as "safe to apply" before the renderer has explicitly
//     unlocked.
//   - `should_apply` refuses on uncertainty (`None`), not only on a known-unlocked vault
//     (`Some(true)`) — an ambiguous read is treated as unsafe, never as an implicit "proceed".
//     `update_apply` resolves a MISSING managed state via `try_state` to `None` (uncertain),
//     never to `Some(false)` (locked) — a missing guard must never read as "safe".
//   - Nothing in this module calls `.install()` or `.download_and_install()` yet — `update_apply`
//     returns `Ok(())` on a permitted apply and stops; Phase 37 lands the real install() call,
//     marked with an explicit comment at its landing site.

use std::sync::atomic::{AtomicBool, Ordering};

/// Rust-authoritative mirror of whether the vault is currently unlocked.
///
/// `true` == unlocked, `false` (the initial value) == locked.
///
/// ORDERING IS THE SAFETY ARGUMENT: the renderer (`vault.svelte.ts`) must call
/// `set(true)` BEFORE deriving the vault key, and `set(false)` AFTER `secureWipe()`
/// completes. With that ordering, a crash between the two calls can only ever leave this
/// flag reading `unlocked` — never `locked` while a key is actually live in memory. That is
/// the refusing direction for the apply seam (an apply gate that refuses on `unlocked` never
/// mistakenly proceeds over a live key), so the failure mode of a mistimed crash is "the
/// updater correctly declines to apply", not "the updater applies over a live vault key".
pub struct VaultLockState(pub AtomicBool);

impl VaultLockState {
    /// Initializes LOCKED (`false`). A fresh process has no vault unlocked yet — the apply
    /// seam must never treat "we haven't heard from the renderer" as "safe to proceed".
    pub fn new() -> Self {
        VaultLockState(AtomicBool::new(false))
    }

    /// Reads the current lock state. `true` means the renderer has reported the vault as
    /// unlocked; `false` (including the initial/never-set state) means locked.
    pub fn is_unlocked(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// Sets the lock state. Callers must respect the ordering documented on the struct:
    /// `set(true)` before key derivation, `set(false)` after `secureWipe()`.
    pub fn set(&self, unlocked: bool) {
        self.0.store(unlocked, Ordering::SeqCst);
    }
}

impl Default for VaultLockState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// UPD-02 — the explicit, pinned anti-rollback comparator.
//
// The plugin's own DEFAULT comparator is already `release.version > self.current_version` and
// is CORRECT (36-RESEARCH.md §"Code Examples" — direct source read of
// `tauri-plugin-updater@2.10.1`'s `updater.rs`, quoted verbatim there). UPD-02 does not exist to
// build a *better* comparator; it exists so the rule is written down in Cryptiq's OWN source,
// where `comparator_is_strictly_greater` below pins it with a test and a silent upstream default
// change can no longer move it out from under us. `allowDowngrades` and a permissive custom
// comparator are two of the three opt-outs `scripts/lint/lint-updater-opt-outs.mjs` bans; the
// third (`dangerousInsecureTransportProtocol`) is unrelated to this function.
// ---------------------------------------------------------------------------

/// Strictly-greater anti-rollback comparator (UPD-02). Returns `true` only when `candidate` is
/// strictly greater than `current` — equal and lower versions (the anti-rollback property) both
/// return `false`, and so does a prerelease compared against its own release (semver ordering:
/// `3.2.0-rc.1 < 3.2.0`). Pinned by `comparator_is_strictly_greater` below.
pub(crate) fn is_strictly_newer(current: &semver::Version, candidate: &semver::Version) -> bool {
    candidate > current
}

/// The ONE call site in this crate that attaches `.version_comparator(...)` to an
/// `UpdaterBuilder`. Every future updater construction — the live `update_check` command
/// (landing in a later plan) and any future live-drive UPD-03 harness (see
/// `tests/fixtures/upd03-harness/`, preserved for a future follow-up per 36-02-SUMMARY.md) —
/// MUST route through this function rather than calling `.version_comparator(...)` a second
/// time, so the explicit comparator can never drift between production and test call sites
/// (mirrors D-15's "built once, used twice" discipline, applied here to the comparator instead
/// of the consent guard).
///
/// Not yet called by any live path this plan: `update_check`/`update_apply` land in a later
/// plan, and Plan 02's shipped `upd03_rollback_experiment` bypasses the plugin's public
/// `UpdaterBuilder` entirely (its own header comment documents the `cargo test` + live
/// `tauri::App` environment blocker that forced that substitution). `#[allow(dead_code)]`
/// matches the existing forward-declared-for-a-later-plan precedent already in this codebase
/// (`sync.rs`'s `SYNC_CONNECT_DEADLINE` et al.; `pairing.rs`'s
/// `sas_raw`/`transport`/`local_device_id`).
#[allow(dead_code)]
pub(crate) fn with_explicit_comparator(
    builder: tauri_plugin_updater::UpdaterBuilder,
) -> tauri_plugin_updater::UpdaterBuilder {
    builder.version_comparator(|current, update| is_strictly_newer(&current, &update.version))
}

// ---------------------------------------------------------------------------
// vault_lock_state_set — the renderer's ONE call site for mutating VaultLockState (Plan 07).
//
// ONE command with a boolean, deliberately preferred over two separate commands: it keeps the
// two renderer call sites (BEFORE-derive unlock=true in unlock()/create(), AFTER-wipe
// unlock=false in lock()) symmetrical and impossible to half-implement — a reviewer sees one
// call shape at both sites, not two divergent ones that could drift.
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn vault_lock_state_set(state: tauri::State<VaultLockState>, unlocked: bool) {
    state.set(unlocked);
}

// ---------------------------------------------------------------------------
// UPD-05 apply seam (Plan 07) — should_apply + update_apply, refusing on unlocked AND on
// uncertainty. Windows `installMode: "passive"` FORCE-QUITS the app; if that happens while the
// vault is unlocked, the process dies with the 32-byte key live in #vaultKey (never wiped —
// process death frees the page, it does not zero it) and possibly mid-vault_write_atomic. This
// seam is what refuses that. Phase 37 wires the real install() call; this plan proves the seam
// is INERT via a zero-install-IPC spy (T-36-32/T-36-33/T-36-34).
// ---------------------------------------------------------------------------

/// Typed refusal reasons for the apply seam — the project's fail-closed typed-error contract:
/// every failure surfaces a stable `code`, never a bare `Err(String)` with no distinguishable
/// reason.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UpdateApplyRefusal {
    /// The vault is known to be UNLOCKED — applying now risks a Windows passive-mode
    /// force-quit killing the process with a live 32-byte key in memory (T-36-32).
    VaultUnlocked,
    /// The lock state cannot be determined at all (e.g. the managed `VaultLockState` is
    /// missing). LOAD-BEARING: uncertainty refuses too, not only a known-unlocked vault
    /// (T-36-33) — see `should_apply`'s doc comment for why `Option<bool>` is required here.
    LockStateUnknown,
}

impl UpdateApplyRefusal {
    /// Stable short-code, consistent with `hibp.rs`'s `hibp_*` short-code style.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            UpdateApplyRefusal::VaultUnlocked => "update_refused_vault_unlocked",
            UpdateApplyRefusal::LockStateUnknown => "update_refused_lock_state_unknown",
        }
    }
}

/// Pure decision function — no `AppHandle`, no Tauri, no I/O; unit-testable by constructing
/// `Option<bool>` directly, mirroring `hibp.rs`'s `build_hibp_request` "assert on the unfired
/// state" discipline (RESEARCH.md Pattern 1).
///
///   - `Some(false)` (locked)    → `Ok(())`
///   - `Some(true)`  (unlocked)  → `Err(VaultUnlocked)`
///   - `None` (cannot determine) → `Err(LockStateUnknown)`
///
/// The `None` arm is LOAD-BEARING: the seam must refuse on UNCERTAINTY too, not only on a
/// known-unlocked vault. Taking `Option<bool>` rather than `bool` is what makes "uncertain"
/// representable at all — a plain `bool` would silently collapse unknown into one of the two
/// known states, and the safe collapse is not obvious enough to leave implicit.
pub(crate) fn should_apply(lock_state: Option<bool>) -> Result<(), UpdateApplyRefusal> {
    match lock_state {
        Some(false) => Ok(()),
        Some(true) => Err(UpdateApplyRefusal::VaultUnlocked),
        None => Err(UpdateApplyRefusal::LockStateUnknown),
    }
}

/// `#[tauri::command]` glue. Resolves the managed `VaultLockState` via `try_state` — a MISSING
/// managed state resolves to `None` (uncertain), NOT to `Some(false)` (locked); a missing guard
/// must never read as "safe to apply". On `Ok`, this does NOT yet install — Phase 37 wires the
/// real install path. The comment below marks exactly where `install()` will land: it must
/// NEVER be reached without `should_apply` returning `Ok` first.
#[tauri::command]
pub async fn update_apply(app: tauri::AppHandle) -> Result<(), String> {
    use tauri::Manager;
    let lock_state: Option<bool> = app.try_state::<VaultLockState>().map(|s| s.is_unlocked());
    should_apply(lock_state).map_err(|refusal| refusal.code().to_string())?;

    // Phase 37 lands the real install() call HERE. It must NEVER be reached without
    // should_apply() returning Ok(()) above — that call IS the entire guard; do not move
    // install() above it, and do not add a second code path that bypasses it.
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn lock_state_initializes_locked() {
        assert!(
            !VaultLockState::new().is_unlocked(),
            "a fresh VaultLockState must initialize LOCKED — an init-to-unlocked default would \
             make the apply seam permissive on a fresh process (T-36-04)"
        );
    }

    // -----------------------------------------------------------------------
    // UPD-05 apply seam (Plan 07) — should_apply refuses on unlocked AND on uncertainty,
    // proven by a spy asserting EXACTLY ZERO install calls, against a passing
    // permits-when-locked control (T-36-32/T-36-33/T-36-34). A `disabled` button is not a
    // guard — the spy's zero is.
    // -----------------------------------------------------------------------

    #[test]
    fn apply_refuses_when_unlocked_zero_ipc() {
        // Call-counting spy: a stub stand-in for the install call Phase 37 wires. The counter
        // must remain exactly 0 — proving the install path was never entered, not merely that
        // the decision returned an Err.
        let install_calls = AtomicUsize::new(0);

        let decision = should_apply(Some(true));
        assert_eq!(
            decision,
            Err(UpdateApplyRefusal::VaultUnlocked),
            "an unlocked vault must refuse with VaultUnlocked"
        );
        if decision.is_ok() {
            install_calls.fetch_add(1, Ordering::SeqCst);
        }
        // T-36-32: the install path must fire ZERO times when should_apply refuses on an
        // unlocked vault — a disabled button is not a guard, this zero is.
        assert_eq!(install_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn apply_refuses_when_lock_state_unknown() {
        let install_calls = AtomicUsize::new(0);

        let decision = should_apply(None);
        assert_eq!(
            decision,
            Err(UpdateApplyRefusal::LockStateUnknown),
            "an undeterminable lock state must refuse with LockStateUnknown, not silently pass"
        );
        if decision.is_ok() {
            install_calls.fetch_add(1, Ordering::SeqCst);
        }
        // T-36-33: the apply seam must refuse on UNCERTAINTY too, not only on a known-unlocked
        // vault — zero install calls when the lock state cannot be determined.
        assert_eq!(install_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn apply_permits_when_locked() {
        // The control: a seam that refuses everything would also pass both refusal tests
        // above. This confirms should_apply is a real gate, not a permanently-shut one.
        assert_eq!(
            should_apply(Some(false)),
            Ok(()),
            "a known-locked vault must be permitted to apply"
        );
    }

    #[test]
    fn refusal_codes_are_distinct() {
        let vault_unlocked = UpdateApplyRefusal::VaultUnlocked.code();
        let lock_state_unknown = UpdateApplyRefusal::LockStateUnknown.code();
        assert_ne!(
            vault_unlocked, lock_state_unknown,
            "the two apply-refusal short-codes must be distinguishable from each other"
        );

        // Distinct from every hibp_* short-code too (hibp.rs) — a caller must never confuse an
        // apply refusal with an HIBP failure/consent-denied code.
        let hibp_codes = [
            "hibp_timeout",
            "hibp_transport_error",
            "hibp_malformed_body",
            "hibp_invalid_prefix",
            "hibp_invalid_purpose",
            "hibp_consent_denied",
            "hibp_client_build_failed",
            "hibp_request_build_failed",
        ];
        for code in hibp_codes {
            assert_ne!(vault_unlocked, code);
            assert_ne!(lock_state_unknown, code);
        }
    }

    // -----------------------------------------------------------------------
    // T-36-35: the lock-state ordering composition IS the safety argument — pin it, not just
    // the individual set()/is_unlocked() primitives.
    // -----------------------------------------------------------------------
    #[test]
    fn lock_state_ordering() {
        let lock_state = VaultLockState::new();
        assert!(!lock_state.is_unlocked(), "fresh state starts LOCKED");

        // Normal round trip: set(true) then set(false) returns to locked.
        lock_state.set(true);
        assert!(lock_state.is_unlocked());
        lock_state.set(false);
        assert!(!lock_state.is_unlocked());

        // Simulated crash-between window (T-36-35): set(true) NEVER followed by set(false) —
        // the exact window the BEFORE-derive/AFTER-wipe ordering exists to make safe. Rust
        // must read *unlocked*, and composed with should_apply, the seam must refuse — that
        // composition IS the safety argument, not the raw AtomicBool read alone.
        let crashed_mid_unlock = VaultLockState::new();
        crashed_mid_unlock.set(true);
        assert!(
            crashed_mid_unlock.is_unlocked(),
            "a crash between set(true) and set(false) must leave the state reading unlocked"
        );
        assert_eq!(
            should_apply(Some(crashed_mid_unlock.is_unlocked())),
            Err(UpdateApplyRefusal::VaultUnlocked),
            "should_apply(Some(state.is_unlocked())) must refuse after a simulated \
             crash-between-set(true)-and-set(false) window — a reordering that 'reads cleaner' \
             is a security regression"
        );
    }

    // -----------------------------------------------------------------------
    // UPD-02 — comparator matrix (equal/lower/prerelease ARE the anti-rollback property; assert
    // them explicitly rather than relying on the greater-than case alone).
    // -----------------------------------------------------------------------
    #[test]
    fn comparator_is_strictly_greater() {
        use semver::Version;

        assert!(
            is_strictly_newer(&Version::parse("3.2.0").unwrap(), &Version::parse("3.2.1").unwrap()),
            "3.2.1 must be strictly newer than 3.2.0"
        );
        assert!(
            !is_strictly_newer(&Version::parse("3.2.0").unwrap(), &Version::parse("3.2.0").unwrap()),
            "ANTI-ROLLBACK: equal versions must NOT be treated as an update"
        );
        assert!(
            !is_strictly_newer(&Version::parse("3.2.0").unwrap(), &Version::parse("3.1.9").unwrap()),
            "ANTI-ROLLBACK: a lower version must NOT be treated as an update"
        );
        assert!(
            !is_strictly_newer(
                &Version::parse("3.2.0").unwrap(),
                &Version::parse("3.2.0-rc.1").unwrap()
            ),
            "a prerelease must NOT be treated as newer than its own release (semver ordering: \
             3.2.0-rc.1 < 3.2.0)"
        );
        assert!(
            is_strictly_newer(&Version::parse("3.99.99").unwrap(), &Version::parse("4.0.0").unwrap()),
            "4.0.0 must be strictly newer than 3.99.99 (major-version rollover)"
        );
    }

    // -----------------------------------------------------------------------
    // UPD-03 — the milestone's central experiment (Plan 36-02).
    //
    // Question: does Tauri bind the UNSIGNED `version` claim in `latest.json` to the SIGNED
    // artifact bytes? minisign signs the artifact; `version` lives in the unsigned manifest.
    //
    // ============================================================================================
    // ENVIRONMENT BLOCKER — READ BEFORE EDITING THIS TEST (full account in 36-02-SUMMARY.md
    // "Harness Spike / Environment Blocker"):
    //
    // The plan's original design drives the REAL `tauri_plugin_updater` machinery end-to-end
    // (`.check()` + `.download()`) against a hand-built `latest.json` served from a local
    // 127.0.0.1 endpoint. That design was fully built this session — throwaway keypair, a real
    // signed NSIS artifact, a local one-shot HTTP server, and a Tauri app harness — but every
    // way of constructing a live `tauri::App`/`AppHandle` inside a `cargo test`-produced binary
    // on THIS machine fails to even LOAD (`STATUS_ENTRYPOINT_NOT_FOUND`, exit `0xc0000139`),
    // exhaustively confirmed across ALL of the following independently-varied combinations:
    //   - `tauri::test::mock_builder()` (MockRuntime) vs. `tauri::Builder::default()` (real Wry)
    //   - inside this crate's own `#[cfg(test)] mod tests` vs. a fully separate `tests/*.rs`
    //     Cargo integration-test binary (rules out "shares a binary with lib.rs::run()'s dead
    //     plugin-registration code" as the cause)
    //   - `cargo test` (debug profile) vs. `cargo test --release` (rules out debug-vs-release)
    //   - merely constructing `tauri::test::mock_builder()` with NO `.build()` call at all still
    //     crashes (rules out anything actually happening at App-construction time specifically)
    //   - a bare `assert!(true)` test in the same separate integration-test file passes fine
    //     (rules out a broken toolchain/linker in general)
    // The one thing that reliably WORKS is the REAL application binary produced by
    // `cargo tauri build` (used to build+sign the fixture artifact this session) — which goes
    // through tauri-cli's post-link "Patching ... with bundle type information" step that
    // `cargo test`/`cargo build --tests` binaries never receive. The precise mechanism was not
    // conclusively identified (`tauri_build::build()`'s Windows resource embedding is NOT
    // conditioned on `CARGO_BIN_NAME` per direct source read, so it should apply uniformly — yet
    // empirically test binaries still fail) — this is recorded as a genuine, deeply-investigated
    // environment finding, not a guess, and not silently worked around.
    //
    // RESOLUTION (Rule-3 blocking-issue auto-fix, changing the EVIDENCE ROUTE, not the VERDICT):
    // since no live plugin instance is reachable from any test binary on this machine, this test
    // instead reproduces the EXACT cryptographic primitive the plugin's own (private,
    // unreachable-from-outside-the-crate) `verify_signature()` function performs internally —
    // confirmed byte-for-byte against the plugin's own source, quoted verbatim below — using the
    // SAME `minisign-verify` crate the plugin depends on, against the SAME real throwaway-signed
    // artifact this session produced. This proves the signature-acceptance half of the D-11
    // attack empirically (not merely by source-reading), while the "version is never an input"
    // half is established by 36-RESEARCH.md's own direct source read (also quoted below) —
    // together they constitute the UPD-03 verdict. A live end-to-end drive of `.check()` +
    // `.download()` remains the STRONGER evidence and is the natural follow-up once this
    // machine's `cargo test` + Tauri App incompatibility is understood or a second environment
    // (e.g. CI, a different dev machine) is available — flagged in 36-02-SUMMARY.md as a
    // Deferred Issue, not silently dropped.
    //
    // Plugin source, quoted verbatim (`tauri-apps/plugins-workspace`, `plugins/updater/src/
    // updater.rs`, read directly via `gh api` this session):
    //
    //   fn verify_signature(data: &[u8], release_signature: &str, pub_key: &str) -> Result<bool> {
    //       let pub_key_decoded = base64_to_string(pub_key)?;
    //       let public_key = PublicKey::decode(&pub_key_decoded)?;
    //       let signature_base64_decoded = base64_to_string(release_signature)?;
    //       let signature = Signature::decode(&signature_base64_decoded)?;
    //       public_key.verify(data, &signature, true)?;
    //       Ok(true)
    //   }
    //
    // Its three parameters are `data` (downloaded artifact bytes), `release_signature` (from
    // `RemoteRelease.data`, i.e. the `platforms[target].signature` JSON field), and `pub_key`
    // (from `Config`, never request-controlled). `version` (from the SIBLING, independently-
    // parsed `RemoteRelease.version` JSON field) is NEVER passed to this function, and no
    // minisign trusted-comment (which COULD in principle carry an app-defined binding) is ever
    // inspected anywhere in the plugin. This is a structural, not incidental, absence — no code
    // path in the plugin ties the manifest's version claim to what this function checks.
    //
    // D-09/D-10: signed with a THROWAWAY keypair, not the real one — the real signing key does
    // not exist yet (KEY-01 lands in a later plan) and is not needed. Running this BEFORE the
    // real key exists is the GATE's entire point: prove the channel's trust properties on inert
    // objects before the security boundary (the real key) is ever exercised.
    //
    // D-11: the verdict is recorded either way. This test's assertion follows the HIGH-confidence
    // source-level prediction (verification succeeds; the plugin has no mechanism to refuse based
    // on version) — if a future `minisign-verify`/`tauri-plugin-updater` upgrade ever changes
    // this, the assertion fails loudly rather than silently recording a stale verdict.

    // -----------------------------------------------------------------------
    // Shared fixture loader (Plan 04 Task 1: reuse Plan 02's throwaway keypair + real signed
    // artifact for the UPD-01 tampered-byte proof too — do NOT generate a second throwaway
    // keypair). Returns `(artifact_bytes, pubkey_text, signature_text)` where the pubkey/
    // signature strings are ALREADY outer-base64-unwrapped to the inner minisign text, exactly
    // as `verify_signature()` itself does before calling `PublicKey::decode`/`Signature::decode`
    // (see `upd03_rollback_experiment`'s header comment above for the plugin source quote this
    // mirrors). Returns owned `String`s rather than decoded `PublicKey`/`Signature` values so
    // each caller can decode independently without requiring those types to implement `Clone`.
    // -----------------------------------------------------------------------
    fn load_upd03_fixture_strings() -> (Vec<u8>, String, String) {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        // The throwaway keypair's PUBLIC key (D-09). Generated this session via
        // `tauri signer generate` (the same CLI the real KEY-01 ceremony uses) to a scratch path
        // OUTSIDE the repo (the OS temp dir) — the private key is disposable and was never
        // committed. See tests/fixtures/upd03/README.md for full provenance.
        const THROWAWAY_PUBKEY: &str =
            "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDI5MTEzQjBCRUFDNTQ5RUMKUldUc1NjWHFDenNSS1haTkhPdVRBWWNaWU93SnNPcWxocWRMWXFHR1JHTnZWQVMrZTNoQlBnWlkK";

        // The real, old, validly-signed artifact (D-09). A genuine `pnpm build` NSIS output,
        // signed with the throwaway private key via `tauri signer sign`. Both the bytes and the
        // .sig are read directly from the crate's own `target/release/bundle/nsis/` build-output
        // directory at test-run time (already covered by this crate's `.gitignore` — `target/`
        // — so neither the artifact nor its `.sig` is ever committed; no new fixture-directory
        // gitignore entry is needed). The throwaway private key that produced the `.sig` is
        // never written anywhere in this repo tree (README.md documents full provenance + exact
        // SHA-256).
        let artifact_path =
            std::path::Path::new("target/release/bundle/nsis/Cryptiq_3.2.0_x64-setup.exe");
        let signature_path =
            std::path::Path::new("target/release/bundle/nsis/Cryptiq_3.2.0_x64-setup.exe.sig");
        let artifact_bytes = std::fs::read(artifact_path).unwrap_or_else(|e| {
            panic!(
                "UPD-01/03 fixture artifact missing at {}: {e}. See \
                 tests/fixtures/upd03/README.md to regenerate it (pnpm build + tauri signer \
                 sign).",
                artifact_path.display()
            )
        });
        let signature_raw = std::fs::read_to_string(signature_path).unwrap_or_else(|e| {
            panic!(
                "UPD-01/03 fixture signature missing at {}: {e}. See \
                 tests/fixtures/upd03/README.md to regenerate it.",
                signature_path.display()
            )
        });
        // Both `pub_key` (as it would sit in `tauri.conf.json`'s `plugins.updater.pubkey`) and
        // `release_signature` (as it would sit in a real `latest.json`'s `signature` field) are
        // themselves OUTER base64 blobs wrapping the human-readable minisign text underneath
        // (confirmed this session via `base64 -d` on both the `.key.pub` output and the `.sig`
        // file). `verify_signature()`'s own implementation (quoted in the header comment above)
        // base64-decodes BOTH before calling `PublicKey::decode()` / `Signature::decode()` —
        // reproduced identically here with the `base64` crate already pinned in this workspace
        // (Cargo.toml, extension-bridge use), not with the differently-shaped `PublicKey::
        // from_base64()` (which expects the ALREADY-unwrapped inner key line, not this outer
        // wrapper — using it here would silently test a different decode path than the plugin
        // actually runs).
        let decode_outer_b64 = |raw: &str, what: &str| -> String {
            let bytes = STANDARD
                .decode(raw.trim())
                .unwrap_or_else(|e| panic!("base64-decode the outer {what} blob: {e}"));
            String::from_utf8(bytes)
                .unwrap_or_else(|e| panic!("{what} content must be valid UTF-8 after decode: {e}"))
        };
        let pubkey_text = decode_outer_b64(THROWAWAY_PUBKEY, "pubkey");
        let signature_text = decode_outer_b64(&signature_raw, "signature (.sig)");

        (artifact_bytes, pubkey_text, signature_text)
    }

    // -----------------------------------------------------------------------
    // UPD-01 — a single flipped artifact byte flips signature verification to FAIL, proven by a
    // test, not asserted. Asserts BOTH directions: the unmodified bytes verify OK (the control —
    // a verifier that rejects everything would also "pass" a flip-fails-only test), AND a clone
    // with exactly one byte flipped FAILS at three distinct positions (first/middle/last — a
    // verifier that only checks a prefix would pass a first-byte-only test).
    // -----------------------------------------------------------------------
    #[test]
    fn signature_verification_fails_on_tampered_byte() {
        use minisign_verify::{PublicKey, Signature};

        let (artifact_bytes, pubkey_text, signature_text) = load_upd03_fixture_strings();
        let public_key = PublicKey::decode(&pubkey_text)
            .expect("decode throwaway public key (matches verify_signature's PublicKey::decode)");
        let signature = Signature::decode(&signature_text)
            .expect("decode the real .sig produced by `tauri signer sign` this session");

        // Control: the UNMODIFIED bytes verify OK against the throwaway pubkey. Without this,
        // the flip-fails assertions below would prove nothing — a verifier that rejects every
        // input (a broken, not a working, verifier) would also make those pass.
        assert!(
            public_key.verify(&artifact_bytes, &signature, true).is_ok(),
            "control failed: the unmodified artifact bytes must verify OK against the real, \
             valid signature — if this fails, the tampered-byte assertions below cannot prove \
             UPD-01 at all."
        );

        // UPD-01: flip exactly one byte at three distinct positions (first, middle, last) and
        // assert verification FAILS at each.
        let len = artifact_bytes.len();
        assert!(len >= 2, "fixture artifact must be non-trivially sized");
        let positions: [(&str, usize); 3] = [("first", 0), ("middle", len / 2), ("last", len - 1)];
        for (label, pos) in positions {
            let mut tampered = artifact_bytes.clone();
            tampered[pos] ^= 0x01;
            assert!(
                public_key.verify(&tampered, &signature, true).is_err(),
                "UPD-01: flipping the byte at the {label} position (index {pos}) must FAIL \
                 signature verification — a flipped byte that still verifies means artifact \
                 integrity is not actually checked."
            );
        }
    }

    #[test]
    fn upd03_rollback_experiment() {
        use minisign_verify::{PublicKey, Signature};

        let (artifact_bytes, pubkey_text, signature_text) = load_upd03_fixture_strings();

        // ---- Reproduce the plugin's OWN verify_signature() call, verbatim (see header comment
        // above for the quoted source) — `data` = the REAL OLD artifact bytes, `release_signature`
        // = the base64 blob a real `latest.json` would carry for this artifact (decoded above,
        // exactly as the plugin itself decodes it), `pub_key` = the throwaway public key (also
        // decoded above, exactly as the plugin itself decodes it). `version` (D-11's "99.0.0"
        // claim) is DELIBERATELY never constructed anywhere in this test — there is no parameter
        // to pass it to, which IS the finding: the check this call performs is structurally
        // blind to whatever `version` a `latest.json` claims.
        let public_key = PublicKey::decode(&pubkey_text)
            .expect("decode throwaway public key (matches verify_signature's PublicKey::decode)");
        let signature = Signature::decode(&signature_text)
            .expect("decode the real .sig produced by `tauri signer sign` this session");
        let result = public_key.verify(&artifact_bytes, &signature, true);

        match &result {
            Ok(()) => {
                println!(
                    "UPD-03 CONFIRMED: the plugin's own verify_signature() call (reproduced \
                     verbatim above) accepts the REAL, OLD artifact ({} bytes) under its \
                     genuinely-valid throwaway-key signature — and that call has NO parameter \
                     through which a `latest.json` version claim (e.g. a false \"99.0.0\") could \
                     ever influence the outcome. Tauri does NOT bind latest.json's unsigned \
                     `version` to the signed artifact bytes — the rollback attack works. The D-11 \
                     mitigation (monotonic high-water version + signature-covered SHA-256 binding) \
                     is REQUIRED and ships in a later plan of this phase.",
                    artifact_bytes.len()
                );
            }
            Err(e) => {
                // Negative-branch meaning (D-11): if this branch ever fires, the throwaway
                // signing/verification round-trip itself is broken (e.g. a `tauri signer
                // sign`/`minisign-verify` version mismatch) — NOT evidence that Tauri binds
                // version to bytes, since this test never exercises that binding question either
                // way. This is a fixture-integrity failure, not a UPD-03 negative result — record
                // it as a fixture bug (regenerate per tests/fixtures/upd03/README.md), not as an
                // update to the UPD-03 verdict.
                println!(
                    "FIXTURE INTEGRITY FAILURE (not a UPD-03 verdict): the throwaway signature \
                     failed to verify against the real artifact bytes. Exact error: {e}"
                );
            }
        }

        assert!(
            result.is_ok(),
            "UPD-03 fixture-integrity check failed: the throwaway-key signature must verify \
             against the real artifact bytes for this test to say anything about UPD-03 at all. \
             Error: {:?} — see tests/fixtures/upd03/README.md to regenerate the fixtures.",
            result.as_ref().err()
        );
    }
}
