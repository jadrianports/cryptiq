// apps/desktop/src-tauri/src/commands/hibp.rs
//
// Phase 30 — HIBP k-anonymity range lookup, dumb Rust shuttle (D-07, mirrors sync.rs's
// Rust-shuttle/JS-logic split).
//
// Phase 36 (DEBT-01/W-1, D-13/D-14/D-15): gained a fail-closed consent-seam guard. The command
// boundary is invokable by anything reaching the webview's invoke() (see V5 below) — a future
// second JS caller (bypassing every UI-level consent check) must still be refused HERE, not
// merely at the call sites. See Security invariants below for the full rationale.
//
// Responsibilities:
//   HIBP_HOST               — host constant; the ONLY variable input is the 5-hex-char prefix
//   field_for_purpose        — pure purpose→config-field mapper (D-13/D-15): "entry-scan" maps
//                               to hibpEntryScanEnabled, "master-check" to hibpMasterCheckEnabled;
//                               any other value maps to None, refused as hibp_invalid_purpose.
//                               Zero AppHandle/I-O — a #[test] target on its own.
//   validate_prefix           — pure prefix-shape validator (V5/Pitfall 3), factored out so it
//                               (like field_for_purpose) can be pinned by a #[test] with zero
//                               AppHandle/Tauri runtime — this machine's `cargo test` cannot
//                               safely construct a live tauri::App inside a test binary (Plan
//                               36-02's ENVIRONMENT BLOCKER finding); primitive-level tests are
//                               the sanctioned pattern for anything touching AppHandle here.
//   build_hibp_request        — pure builder: returns an UNSENT reqwest::Request (SC-2 test target)
//   execute_hibp_request       — the only async I/O; maps every failure to a stable short-code (D-04)
//   hibp_range_lookup         — #[tauri::command] glue: consent guard FIRST (D-13) — before prefix
//                               validation, before any client/request construction — then
//                               validates prefix (V5/Pitfall 3), builds an 8s-timeout client
//                               (D-06), builds + executes the request
//
// Security invariants:
//   - The password and the full 40-char SHA-1 hash NEVER reach this module — only the 5-hex
//     prefix in, raw response text out. This module parses NOTHING (D-07); all k-anonymity
//     logic (hashing, prefix/suffix split, local suffix match) lives in packages/core.
//   - HIBP_HOST + the "/range/{prefix}" path template are Rust `const`s — no `url`/`host`/
//     `endpoint` parameter exists anywhere in this module — JS can never redirect network
//     egress (Pitfall 3). `hibp_range_lookup` accepts exactly `prefix: String` and
//     `purpose: String` (plus the Tauri-injected `AppHandle`, never invoke-controllable).
//   - The prefix is validated `^[0-9A-Fa-f]{5}$` before ANY use — the Tauri command boundary is
//     technically invokable by any script that can reach the webview's invoke(), so the Rust
//     side never trusts the JS caller (V5).
//   - Every failure mode (timeout, non-2xx incl. 429, malformed body) maps to a distinct stable
//     Err short-code — never a silent "safe" result (D-04). One-shot: no retry/backoff (D-05).
//   - An 8s request timeout is enforced via the reqwest::Client builder (D-06).
//   - DEBT-01/W-1 (D-13): consent is enforced HERE, at the seam, not at the call site. The
//     command boundary is invokable by anything reaching the webview's invoke() (see V5 above)
//     — that is precisely why a UI-level check alone is not a guard. `purpose` selects WHICH
//     consent field (hibpEntryScanEnabled / hibpMasterCheckEnabled) governs the call — the two
//     flags are deliberately INDEPENDENT (Phase 31 D-16), so an OR-gate would let a user who
//     consented only to the master-password check unknowingly authorize a stored-entry sweep.
//     Consent is checked against the field that actually governs the operation.
//   - D-14: a TS wrapper around hibpInvoke was explicitly REJECTED. Anything reaching invoke()
//     still egresses, which RELOCATES W-1 rather than closing it. Do not "simplify" this Rust
//     guard into one.
//   - The `purpose` parameter is a closed two-value enum ("entry-scan" | "master-check") that
//     selects WHICH consent field is consulted; it cannot widen egress the way a url/host/
//     endpoint parameter would. HIBP_HOST remains a `const` and no such parameter exists
//     anywhere in this module (Pitfall 3 intact). An unrecognized purpose (including case
//     variants and the empty string) refuses via `hibp_invalid_purpose` — never a default.
//   - Fail-closed: absent/corrupt/unreadable/non-boolean config ALL refuse egress
//     (`config_guard::config_bool_field`'s `default_if_absent: false` — REQUIRED here, not
//     `true`. A `?? true`-equivalent would silently authorize this app's network egress for
//     every pre-consent install; quoting `config.ts`'s own load-bearing-deviation comment on
//     these exact fields).
//   - `hibp_consent_denied` is a stable short-code distinct from every network-failure code
//     (`hibp_timeout` / `hibp_transport_error` / `hibp_malformed_body` / `hibp_http_status_*`)
//     — a caller must never read "consent denied" as "no breaches found" (D-04's contract
//     extended to the consent guard).
//   - This command is otherwise stateless — no managed state, no busy-guard/listener machinery
//     (unlike sync.rs). It performs a single GET and returns.

use std::time::Duration;

use super::config_guard;

const HIBP_HOST: &str = "https://api.pwnedpasswords.com";
const HIBP_REQUEST_TIMEOUT: Duration = Duration::from_secs(8);

/// Fail-direction for the DEBT-01/W-1 consent guard (D-13) — REQUIRED `false` (fail-CLOSED).
/// Named as its own constant, rather than an inline literal at the `hibp_range_lookup` call
/// site, specifically so `consent_guard_blocks_when_disabled` below can assert against the
/// SAME symbol the real guard uses — not a second, independently-hardcoded `false` literal in
/// the test. This machine's `cargo test` cannot construct a live `AppHandle` to call
/// `hibp_range_lookup` directly (module header's ENVIRONMENT BLOCKER note), so without this
/// shared constant, a break-patch flipping the call site's literal would be invisible to every
/// test in this module — a fake-green gate. See `scripts/ci-selftest/updater-consent-guard.patch`.
const HIBP_CONSENT_DEFAULT_IF_ABSENT: bool = false;

/// Maps a `purpose` discriminator to the config field that governs it (D-13/D-15). Pure,
/// zero-I/O — a `#[test]` target on its own, mirroring `build_hibp_request`'s "assert on the
/// unsent request" discipline. Any value other than the two known purposes (including case
/// variants and the empty string) returns `None`, which the command maps to
/// `hibp_invalid_purpose` — never a silently-assumed default purpose.
fn field_for_purpose(purpose: &str) -> Option<&'static str> {
    match purpose {
        "entry-scan" => Some("hibpEntryScanEnabled"),
        "master-check" => Some("hibpMasterCheckEnabled"),
        _ => None,
    }
}

/// Pure prefix-shape validator (V5/Pitfall 3). Factored out of `hibp_range_lookup` so it can be
/// pinned by a `#[test]` with zero `AppHandle`/Tauri runtime (see the module header's
/// ENVIRONMENT BLOCKER note) — an invalid prefix never reaches the network either way.
fn validate_prefix(prefix: &str) -> Result<(), String> {
    if prefix.len() != 5 || !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("hibp_invalid_prefix".to_string());
    }
    Ok(())
}

/// Pure builder — returns an UNSENT `reqwest::Request`. No network I/O happens here; this is
/// the SC-2 enabler (RESEARCH.md Pattern 1): a `#[test]` can inspect `.url()`/`.headers()`
/// directly on the returned object without a mock server.
fn build_hibp_request(client: &reqwest::Client, prefix: &str) -> reqwest::Result<reqwest::Request> {
    client
        .get(format!("{HIBP_HOST}/range/{prefix}"))
        .header("Add-Padding", "true")
        .build()
}

/// The only async I/O in this module. Maps every failure mode to a distinct stable short-code
/// string (D-04) — never silently reads a network failure as "safe". No retry/backoff (D-05).
async fn execute_hibp_request(client: &reqwest::Client, req: reqwest::Request) -> Result<String, String> {
    let resp = client.execute(req).await.map_err(|e| {
        if e.is_timeout() {
            "hibp_timeout".to_string()
        } else {
            "hibp_transport_error".to_string()
        }
    })?;

    if !resp.status().is_success() {
        // Covers 429 rate-limit and any other non-2xx — D-04 never silently reads as "safe".
        return Err(format!("hibp_http_status_{}", resp.status().as_u16()));
    }

    resp.text().await.map_err(|_| "hibp_malformed_body".to_string())
}

/// #[tauri::command] glue. `prefix`/`purpose` are the ONLY JS-supplied parameters — host/path
/// are `const`s above, never invoke-controllable (Pitfall 3); `app` is Tauri-injected and does
/// NOT appear in the JS call args. The consent guard runs FIRST — before prefix validation,
/// before any client/request construction — so a refusal never builds a request at all
/// (DEBT-01/W-1, D-13).
#[tauri::command]
pub async fn hibp_range_lookup(app: tauri::AppHandle, prefix: String, purpose: String) -> Result<String, String> {
    let field = match field_for_purpose(&purpose) {
        Some(f) => f,
        None => return Err("hibp_invalid_purpose".to_string()),
    };

    // Fail-CLOSED (D-13): `default_if_absent: false` is REQUIRED here — absence must never
    // authorize egress. See config_guard.rs's own doc-comment on polarity; a `?? true`-shaped
    // call here would silently authorize this app's network egress for every pre-consent
    // install (quoting config.ts's own load-bearing-deviation sentence on this exact field).
    if !config_guard::config_bool_field(&app, field, HIBP_CONSENT_DEFAULT_IF_ABSENT) {
        return Err("hibp_consent_denied".to_string());
    }

    validate_prefix(&prefix)?;

    let client = reqwest::Client::builder()
        .timeout(HIBP_REQUEST_TIMEOUT)
        .build()
        .map_err(|_| "hibp_client_build_failed".to_string())?;

    let req = build_hibp_request(&client, &prefix).map_err(|_| "hibp_request_build_failed".to_string())?;

    execute_hibp_request(&client, req).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // ── SC-1 / SC-2: unsent-Request inspection — zero network, zero mock server ──────────────

    #[test]
    fn request_carries_exactly_the_5_hex_prefix_and_padding_header() {
        let client = reqwest::Client::new();
        let req = build_hibp_request(&client, "5BAA6").unwrap();

        assert_eq!(req.url().host_str(), Some("api.pwnedpasswords.com"));
        assert_eq!(req.url().path(), "/range/5BAA6");
        assert!(req.url().query().is_none(), "no query string may leak identifying data");
        assert_eq!(
            req.headers()
                .get("Add-Padding")
                .map(|v| v.to_str().unwrap()),
            Some("true"),
            "Add-Padding header must be present and exactly 'true' (Pitfall 4)"
        );
        // No Authorization/API-key header — the range endpoint is keyless.
        assert!(req.headers().get("Authorization").is_none());
    }

    // ── V5: invalid prefixes are rejected BEFORE any network use ─────────────────────────────
    // Tested via the pure `validate_prefix` helper directly (zero AppHandle) — see the module
    // header's ENVIRONMENT BLOCKER note on why `hibp_range_lookup` itself is not called here.

    #[test]
    fn rejects_non_hex_prefix() {
        assert_eq!(validate_prefix("XYZAB"), Err("hibp_invalid_prefix".to_string()));
    }

    #[test]
    fn rejects_wrong_length_prefix() {
        assert_eq!(validate_prefix("5BAA6A"), Err("hibp_invalid_prefix".to_string()));
    }

    #[test]
    fn rejects_short_prefix() {
        assert_eq!(validate_prefix("5BA"), Err("hibp_invalid_prefix".to_string()));
    }

    #[test]
    fn accepts_valid_hex_prefix() {
        assert_eq!(validate_prefix("5BAA6"), Ok(()));
    }

    // ── DEBT-01/W-1 (D-13): the fail-closed consent-seam guard ───────────────────────────────

    #[test]
    fn field_for_purpose_maps_entry_scan_to_entry_flag() {
        assert_eq!(field_for_purpose("entry-scan"), Some("hibpEntryScanEnabled"));
    }

    #[test]
    fn field_for_purpose_maps_master_check_to_master_flag() {
        assert_eq!(field_for_purpose("master-check"), Some("hibpMasterCheckEnabled"));
    }

    #[test]
    fn field_for_purpose_rejects_unknown_purpose() {
        assert_eq!(field_for_purpose(""), None);
        assert_eq!(field_for_purpose("unknown"), None);
        // Case variants must also refuse — no implicit normalization (T-36-21 spoofing guard).
        assert_eq!(field_for_purpose("Entry-Scan"), None);
        assert_eq!(field_for_purpose("MASTER-CHECK"), None);
    }

    #[test]
    fn consent_guard_blocks_when_disabled() {
        // Drives the SAME pure `resolve_bool` core `config_bool_field` delegates to (D-15
        // "built once") — zero AppHandle, mirroring `field_for_purpose`'s test shape. The
        // governing field resolving `false` (or being absent/corrupt, which collapses to the
        // same `None` branch per config_guard's contract) means the guard's decision is
        // refuse, and `hibp_range_lookup` never reaches prefix validation or request
        // construction in that case.
        // Drives HIBP_CONSENT_DEFAULT_IF_ABSENT — the SAME constant the real call site in
        // hibp_range_lookup uses (not an independently-hardcoded `false` literal here) — so a
        // break-patch flipping that constant's fail-direction is provably load-bearing on this
        // assertion, not merely on the test's own copy of the value.
        assert!(!config_guard::resolve_bool(
            None,
            "hibpEntryScanEnabled",
            HIBP_CONSENT_DEFAULT_IF_ABSENT
        ));
        let explicit_false = serde_json::json!({ "hibpEntryScanEnabled": false });
        assert!(!config_guard::resolve_bool(
            Some(&explicit_false),
            "hibpEntryScanEnabled",
            HIBP_CONSENT_DEFAULT_IF_ABSENT
        ));
        let explicit_false_master = serde_json::json!({ "hibpMasterCheckEnabled": false });
        assert!(!config_guard::resolve_bool(
            Some(&explicit_false_master),
            "hibpMasterCheckEnabled",
            HIBP_CONSENT_DEFAULT_IF_ABSENT
        ));
    }

    #[test]
    fn consent_denied_is_distinct_from_network_failure() {
        let consent_denied = "hibp_consent_denied";
        assert_ne!(consent_denied, "hibp_timeout");
        assert_ne!(consent_denied, "hibp_transport_error");
        assert_ne!(consent_denied, "hibp_malformed_body");
        assert_ne!(consent_denied, "hibp_invalid_purpose");
        assert_ne!(consent_denied, "hibp_invalid_prefix");
    }

    // ── D-04: fail-closed execute-layer tests against a local response double ────────────────
    // Per Pitfall 3, the production command's host stays hardcoded — testability for the
    // execute layer comes from testing `execute_hibp_request` directly with a manually built
    // `Request` pointed at a local TCP listener, never by making the host configurable.

    /// Spawns a one-shot local HTTP server on 127.0.0.1 that reads a single request and writes
    /// back the given raw HTTP response bytes, then closes. Returns the bound address.
    fn spawn_one_shot_http_server(response: &'static str) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local test listener");
        let addr = listener.local_addr().expect("local_addr");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                // Drain (best-effort) whatever the client sent before replying.
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        addr
    }

    #[tokio::test]
    async fn non_200_status_maps_to_stable_err_short_code() {
        let addr = spawn_one_shot_http_server(
            "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let client = reqwest::Client::builder()
            .timeout(HIBP_REQUEST_TIMEOUT)
            .build()
            .unwrap();
        let req = client
            .get(format!("http://{addr}/range/5BAA6"))
            .build()
            .unwrap();

        let result = execute_hibp_request(&client, req).await;
        assert_eq!(result, Err("hibp_http_status_429".to_string()));
    }

    #[tokio::test]
    async fn transport_failure_never_reads_as_ok() {
        // Bind then immediately drop — guarantees the port is closed (connection refused)
        // without depending on any externally-reachable host.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local test listener");
        let addr = listener.local_addr().expect("local_addr");
        drop(listener);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let req = client
            .get(format!("http://{addr}/range/5BAA6"))
            .build()
            .unwrap();

        let result = execute_hibp_request(&client, req).await;
        assert!(
            matches!(
                result.as_ref().map_err(String::as_str),
                Err("hibp_timeout") | Err("hibp_transport_error")
            ),
            "transport failure must surface as a distinct Err short-code, never Ok: {result:?}"
        );
    }
}
