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

    // ── SC-1 / V5: invalid prefixes are rejected BEFORE any network use ──────────────────────

    #[tokio::test]
    async fn rejects_non_hex_prefix() {
        let result = hibp_range_lookup("XYZAB".to_string()).await;
        assert_eq!(result, Err("hibp_invalid_prefix".to_string()));
    }

    #[tokio::test]
    async fn rejects_wrong_length_prefix() {
        let result = hibp_range_lookup("5BAA6A".to_string()).await;
        assert_eq!(result, Err("hibp_invalid_prefix".to_string()));
    }

    #[tokio::test]
    async fn rejects_short_prefix() {
        let result = hibp_range_lookup("5BA".to_string()).await;
        assert_eq!(result, Err("hibp_invalid_prefix".to_string()));
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
