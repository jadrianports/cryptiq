// apps/desktop/src-tauri/src/commands/config_guard.rs
//
// Phase 36 — DEBT-01 / W-1. The single Rust-side device-local config consent primitive (D-13/
// D-15: guard the SEAM, not the call site — built once, used twice).
//
// Responsibilities:
//   config_bool_field — the single public entry point: reads a boolean field out of
//                        `$APPCONFIG/cryptiq/config.json` and resolves every "cannot determine"
//                        case (unresolvable config dir, missing/unreadable file, corrupt JSON,
//                        absent field, non-boolean field) to a caller-chosen `default_if_absent`.
//   resolve_bool       — the pure decision core, factored out so the polarity matrix can be
//                        pinned by `#[test]`s with zero `AppHandle`/filesystem I/O, mirroring
//                        hibp.rs's `build_hibp_request`/`execute_hibp_request` "test the pure
//                        part with no I/O" split.
//
// Security invariants:
//   - `default_if_absent` is the FAIL-DIRECTION and is a REQUIRED parameter — this module
//     derives no default trait implementation and has no defaulted argument anywhere. A Rust
//     default here would let a new call site inherit the wrong polarity silently, which is
//     exactly how W-1 happened: HIBP consent was checked at the call sites (breachAudit.svelte.ts,
//     ChangeMasterView.svelte, FirstRunWizard.svelte) while `hibp.rs`'s command boundary
//     egressed for anyone who reached it directly via `invoke()`.
//   - `default_if_absent: true` (fail-OPEN) is correct ONLY for `listenerEnabled` /
//     `extensionBridgeEnabled`, where absence means "Phase-14 always-on behavior" and only a
//     deliberate JSON `false` disables (T-20-04, accepted — see `extension_bridge.rs`'s own
//     `extension_bridge_enabled`, which now delegates to this function with that exact argument).
//   - `default_if_absent: false` (fail-CLOSED) is REQUIRED for every network-egress consent
//     flag — `hibpEntryScanEnabled` / `hibpMasterCheckEnabled` — because absence must never
//     authorize egress for a pre-consent install. Quoting `packages/core/src/config/config.ts`'s
//     own load-bearing comment on this exact field: "a `?? true` here would silently authorize
//     this app's first-ever network egress for every pre-Phase-31 install."
//   - This is the D-15 pattern the updater's own consent gate will reuse in Phase 37. Do not
//     write a second config-reading function anywhere in this codebase — parameterize this one.
//   - Every unresolvable branch (config dir unresolvable, file unreadable, JSON corrupt) is
//     treated IDENTICALLY to "field absent" — all four resolve to `default_if_absent`. A
//     corrupt/truncated config.json must never be usable to force a direction different from a
//     genuinely absent field.

/// Read a boolean field from `$APPCONFIG/cryptiq/config.json`.
///
/// `default_if_absent` is the FAIL-DIRECTION — see the module header for the full W-1 rationale.
/// It is deliberately a required parameter with no default: pass `true` for fail-OPEN flags
/// (`listenerEnabled`/`extensionBridgeEnabled` — Phase-14 always-on behavior, only a deliberate
/// `false` disables) and `false` for fail-CLOSED, opt-in network-egress consent flags
/// (`hibpEntryScanEnabled`/`hibpMasterCheckEnabled`, and the updater's own consent field when
/// Phase 37 lands it). A reader copying a fail-OPEN call site for a NEW egress-consent flag must
/// pass `false` here — copying `true` verbatim re-introduces the exact W-1 trap this helper
/// exists to close.
///
/// Resolution rules (every branch below matches `extension_bridge_enabled`'s pre-refactor
/// read path exactly — same `app_config_dir()` → `.join("cryptiq").join("config.json")` →
/// `std::fs::read` → `serde_json::from_slice::<serde_json::Value>` sequence):
///   - field present and is the JSON boolean `true`  → returns `true`
///   - field present and is the JSON boolean `false` → returns `false`
///   - field absent, non-boolean, config dir unresolvable, file unreadable, or JSON corrupt
///     → returns `default_if_absent`
pub fn config_bool_field(app: &tauri::AppHandle, field: &str, default_if_absent: bool) -> bool {
    use tauri::Manager;

    let config_dir = match app.path().app_config_dir() {
        Ok(p) => p,
        Err(_) => return resolve_bool(None, field, default_if_absent), // cannot resolve config dir
    };
    let config_path = config_dir.join("cryptiq").join("config.json");
    let bytes = match std::fs::read(&config_path) {
        Ok(b) => b,
        Err(_) => return resolve_bool(None, field, default_if_absent), // missing/unreadable config
    };
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return resolve_bool(None, field, default_if_absent), // corrupt config
    };
    resolve_bool(Some(&value), field, default_if_absent)
}

/// Pure decision core — zero I/O, zero `AppHandle`. `value: None` stands in for every
/// "cannot determine" case (unresolvable config dir / unreadable file / corrupt JSON); the
/// public `config_bool_field` collapses all three onto `None` before calling this. `pub(crate)`
/// (not `pub`) so sibling modules' own test suites (e.g. `extension_bridge.rs`'s
/// `extension_bridge_enabled_is_fail_open`) can exercise the exact polarity decision their
/// delegating call site relies on, without exposing a second public entry point — the crate's
/// only PUBLIC config-reading function remains `config_bool_field` (D-15: built once). Exercised
/// directly by the `#[cfg(test)] mod tests` below too, mirroring `hibp.rs`'s
/// `build_hibp_request` "test the pure part with no I/O" discipline.
pub(crate) fn resolve_bool(value: Option<&serde_json::Value>, field: &str, default_if_absent: bool) -> bool {
    match value.and_then(|v| v.get(field)).and_then(|v| v.as_bool()) {
        Some(b) => b,
        None => default_if_absent,
    }
}

// ---------------------------------------------------------------------------
// Tests — the polarity matrix (T-36-10/T-36-11/T-36-12 threat-register pins).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn absent_field_resolves_to_default_true() {
        let value = json!({ "otherField": true });
        assert!(resolve_bool(Some(&value), "extensionBridgeEnabled", true));
    }

    #[test]
    fn absent_field_resolves_to_default_false() {
        let value = json!({ "otherField": true });
        assert!(!resolve_bool(Some(&value), "hibpEntryScanEnabled", false));
    }

    #[test]
    fn explicit_true_returns_true_regardless_of_default() {
        let value = json!({ "hibpEntryScanEnabled": true });
        assert!(resolve_bool(Some(&value), "hibpEntryScanEnabled", false));
    }

    #[test]
    fn explicit_false_returns_false_regardless_of_default() {
        let value = json!({ "extensionBridgeEnabled": false });
        assert!(!resolve_bool(Some(&value), "extensionBridgeEnabled", true));
    }

    #[test]
    fn non_boolean_field_resolves_to_default_false() {
        // A string "yes" must NOT be treated as truthy consent (T-36-12: spoofing via a
        // non-boolean JSON value).
        let value = json!({ "hibpEntryScanEnabled": "yes" });
        assert!(!resolve_bool(Some(&value), "hibpEntryScanEnabled", false));
    }

    #[test]
    fn corrupt_or_missing_config_resolves_to_default_false() {
        // `None` stands in for every unresolvable branch (config dir / file / JSON) collapsed
        // by `config_bool_field` — an egress caller must get a refusal, not a pass (T-36-11).
        assert!(!resolve_bool(None, "hibpEntryScanEnabled", false));
    }

    #[test]
    fn corrupt_or_missing_config_resolves_to_default_true() {
        // Same unresolvable-branch collapse, but for a fail-OPEN caller — confirms the helper
        // truly lets the caller choose the direction rather than hardcoding one.
        assert!(resolve_bool(None, "extensionBridgeEnabled", true));
    }
}
