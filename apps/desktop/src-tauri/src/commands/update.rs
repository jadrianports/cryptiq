// apps/desktop/src-tauri/src/commands/update.rs
//
// Phase 36 — update-channel trust (UPD-01..04 GATE), Rust-only updater. The JS plugin
// (@tauri-apps/plugin-updater) is the REJECTED side of a settled divergence — importing it
// destroys the zero-capability/zero-CSP-diff property UPD-04 asserts.
//
// Responsibilities:
//   VaultLockState  — Rust-authoritative mirror of the renderer's vault lock state (managed
//                      Tauri state, `.manage(...)` in lib.rs). This module is otherwise INERT
//                      this plan: no #[tauri::command] exists yet, no network call is made, and
//                      no install path is reachable. update_check/update_apply land in later
//                      plans, following hibp.rs's pure-builder/async-executor split.
//
// Security invariants:
//   - The update endpoint is a Rust `const` (when it lands, in a later plan); no `url`/`host`/
//     `endpoint` parameter exists on any #[tauri::command] in this module — mirrors HIBP_HOST,
//     JS can never redirect egress.
//   - `VaultLockState` is Rust-authoritative and initializes to LOCKED at process start — a
//     fresh process must never read as "safe to apply" before the renderer has explicitly
//     unlocked.
//   - The apply seam (landing in a later plan) refuses on uncertainty, not only on a known-
//     unlocked vault — an ambiguous read is treated as unsafe, never as an implicit "proceed".
//   - Nothing in this module calls `.install()` or `.download_and_install()` yet.

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
// Not read/called yet this plan (registered as managed state only; the apply-seam guard and
// the renderer's set() call sites land in later plans). #[allow] rather than removal: no
// architectural change intended — mirrors the existing forward-declared-for-a-later-plan
// precedent already in this codebase (sync.rs SYNC_CONNECT_DEADLINE et al., pairing.rs
// sas_raw/transport/local_device_id).
#[allow(dead_code)]
pub struct VaultLockState(pub AtomicBool);

impl VaultLockState {
    /// Initializes LOCKED (`false`). A fresh process has no vault unlocked yet — the apply
    /// seam must never treat "we haven't heard from the renderer" as "safe to proceed".
    pub fn new() -> Self {
        VaultLockState(AtomicBool::new(false))
    }

    /// Reads the current lock state. `true` means the renderer has reported the vault as
    /// unlocked; `false` (including the initial/never-set state) means locked.
    #[allow(dead_code)]
    pub fn is_unlocked(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// Sets the lock state. Callers must respect the ordering documented on the struct:
    /// `set(true)` before key derivation, `set(false)` after `secureWipe()`.
    #[allow(dead_code)]
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
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_state_initializes_locked() {
        assert!(
            !VaultLockState::new().is_unlocked(),
            "a fresh VaultLockState must initialize LOCKED — an init-to-unlocked default would \
             make the apply seam permissive on a fresh process (T-36-04)"
        );
    }
}
