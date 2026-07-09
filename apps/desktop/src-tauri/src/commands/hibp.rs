// apps/desktop/src-tauri/src/commands/hibp.rs
//
// Phase 30 — HIBP k-anonymity range lookup, dumb Rust shuttle (D-07, mirrors sync.rs's
// Rust-shuttle/JS-logic split).
//
// Responsibilities:
//   HIBP_HOST             — host constant; the ONLY variable input is the 5-hex-char prefix
//   build_hibp_request     — pure builder: returns an UNSENT reqwest::Request (SC-2 test target)
//   execute_hibp_request   — the only async I/O; maps every failure to a stable short-code (D-04)
//   hibp_range_lookup      — #[tauri::command] glue: validates prefix (V5/Pitfall 3), builds an
//                             8s-timeout client (D-06), builds + executes the request
//
// Security invariants:
//   - The password and the full 40-char SHA-1 hash NEVER reach this module — only the 5-hex
//     prefix in, raw response text out. This module parses NOTHING (D-07); all k-anonymity
//     logic (hashing, prefix/suffix split, local suffix match) lives in packages/core.
//   - HIBP_HOST + the "/range/{prefix}" path template are Rust `const`s — the ONLY parameter
//     accepted by hibp_range_lookup is `prefix: String` (Pitfall 3). No `url`/`host`/`endpoint`
//     parameter exists anywhere in this module — JS can never redirect network egress.
//   - The prefix is validated `^[0-9A-Fa-f]{5}$` before ANY use — the Tauri command boundary is
//     technically invokable by any script that can reach the webview's invoke(), so the Rust
//     side never trusts the JS caller (V5).
//   - Every failure mode (timeout, non-2xx incl. 429, malformed body) maps to a distinct stable
//     Err short-code — never a silent "safe" result (D-04). One-shot: no retry/backoff (D-05).
//   - An 8s request timeout is enforced via the reqwest::Client builder (D-06).
//   - This command is stateless — no managed state, no busy-guard/listener machinery (unlike
//     sync.rs). It performs a single GET and returns.

use std::time::Duration;

const HIBP_HOST: &str = "https://api.pwnedpasswords.com";
const HIBP_REQUEST_TIMEOUT: Duration = Duration::from_secs(8);

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

/// #[tauri::command] glue. The ONLY parameter is `prefix: String` — host/path are `const`s
/// above, never invoke-controllable (Pitfall 3). Validates the prefix shape FIRST (V5), before
/// any client construction or network use — an invalid prefix never reaches the network.
#[tauri::command]
pub async fn hibp_range_lookup(prefix: String) -> Result<String, String> {
    if prefix.len() != 5 || !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("hibp_invalid_prefix".to_string());
    }

    let client = reqwest::Client::builder()
        .timeout(HIBP_REQUEST_TIMEOUT)
        .build()
        .map_err(|_| "hibp_client_build_failed".to_string())?;

    let req = build_hibp_request(&client, &prefix).map_err(|_| "hibp_request_build_failed".to_string())?;

    execute_hibp_request(&client, req).await
}
