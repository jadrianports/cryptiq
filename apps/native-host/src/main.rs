//! `cryptiq-nmhost` — the disposable native-messaging sidecar Chrome spawns per
//! `chrome.runtime.connectNative()`. Relays framed JSON between the browser's stdio pipe and
//! the Cryptiq app's named pipe (`\\.\pipe\cryptiq-bridge`), with a single bounded connect
//! attempt and no retry (D-09). If the app is not running, returns a typed `app-not-running`
//! envelope and exits cleanly — the "does nothing if the app is not running" half of BRIDGE-01.
//!
//! This binary is NEVER the Tauri GUI process — it must not race
//! `tauri_plugin_single_instance` (Pitfall 1), and every I/O error path must terminate the
//! process cleanly rather than loop-and-retry (Pitfall 5 — no zombie process, SC-2).
//!
//! ## Two distinct framings, by design — do NOT conflate them
//! - stdin/stdout (Chrome <-> sidecar): native byte order (little-endian on Windows), handled
//!   by `framing::read_message`/`framing::write_message` (synchronous `std::io`).
//! - the named pipe (sidecar <-> app): **big-endian**, matching `sync.rs`'s
//!   `recv_framed_large`/`send_framed_large` convention and the app-side listener (Plan 14-02).
//!   Handled by `read_pipe_frame`/`write_pipe_frame` below (async `tokio::io`).

mod framing;

use std::io::{stdin, stdout};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::time::timeout;

/// D-08: fixed, compile-time constant — the SAME literal the app-side listener binds
/// (Plan 14-02). Never derive this from configuration; both sides must agree at compile time.
const PIPE_NAME: &str = r"\\.\pipe\cryptiq-bridge";

/// D-09: short bounded connect timeout (~1-2s), NO retry. The bridge never auto-launches the
/// app and never makes the browser wait — a busy or absent pipe both resolve to a fast,
/// typed `app-not-running` response.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);

/// Hard cap on a single frame crossing the sidecar<->app named pipe, mirroring
/// `framing::MAX_NATIVE_MESSAGE_LEN` (1 MiB) and `sync.rs`'s `MAX_SYNC_FRAME`. Checked BEFORE
/// any buffer is allocated (D-05), on this side of the channel too.
const MAX_PIPE_FRAME: usize = framing::MAX_NATIVE_MESSAGE_LEN as usize;

/// Wire envelope shared with the app-side listener and the extension (D-01/D-02).
/// Transport-shaped — lives here, not in `packages/core` (mirrors `extension_bridge.rs`'s
/// `BridgeEnvelope` per ARCHITECTURE.md §7).
#[derive(serde::Serialize, serde::Deserialize)]
struct BridgeEnvelope {
    #[serde(rename = "protocolVersion")]
    protocol_version: u32,
    #[serde(rename = "type")]
    msg_type: String,
    id: Option<String>,
    payload: serde_json::Value,
}

const CURRENT_PROTOCOL_VERSION: u32 = 1;

/// Build a typed error envelope. Used for every fail-closed exit path (D-05): app-not-running,
/// disconnected, protocol-error.
///
/// BUG-4 fix: `id` MUST carry the triggering request's correlation id whenever one is known.
/// Every extension-side listener (`bridgeRpc.ts` sendRpc/sendAssociate, `background.ts`
/// sendEcho) gates on `if (msg.id !== id) return;` BEFORE processing any message — an
/// envelope stamped `id: None` can never match a real (non-null) request id and is silently
/// dropped, forcing the caller to fall through to its own client-side timeout instead of
/// seeing the real, fast, typed error this sidecar already sent. The caller passes `None` only
/// when no request has been read yet (this process's own app-not-running probe fires before
/// any stdin message is read) or the stdin frame itself was too malformed to parse an id from.
fn error_envelope(code: &str, message: &str, id: Option<String>) -> BridgeEnvelope {
    BridgeEnvelope {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        msg_type: "error".to_string(),
        id,
        payload: serde_json::json!({ "code": code, "message": message }),
    }
}

/// Best-effort peek at a raw (not-yet-validated) envelope's `id` field, so a typed error this
/// sidecar synthesizes AFTER successfully reading a stdin frame can still correlate with the
/// extension's per-request listener (BUG-4 fix — see `error_envelope`). Never fails: any
/// parse/shape mismatch simply yields `None`, which is the SAME (safe, pre-existing) behavior
/// as before this fix — `id` is a non-secret correlation token, so a fail-open peek here has no
/// security implication.
fn peek_message_id(bytes: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|v| v.get("id").and_then(|id| id.as_str().map(str::to_string)))
}

/// Read one length-prefixed frame from the named pipe using a 4-byte **big-endian** u32 prefix
/// (matches `sync.rs::recv_framed_large`, NOT `framing.rs`'s native-endian stdio convention).
///
/// SECURITY (D-05): the claimed length is checked against `MAX_PIPE_FRAME` BEFORE
/// `vec![0u8; len]` is allocated — an app-side bug or a compromised pipe peer sending a huge
/// prefix cannot force an oversized allocation in the sidecar.
async fn read_pipe_frame(pipe: &mut NamedPipeClient) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    pipe.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_PIPE_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "protocol-error: pipe frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    pipe.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Write one length-prefixed frame to the named pipe using a 4-byte **big-endian** u32 prefix
/// (matches `sync.rs::send_framed_large`).
async fn write_pipe_frame(pipe: &mut NamedPipeClient, data: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(data.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "pipe payload too large")
    })?;
    pipe.write_all(&len.to_be_bytes()).await?;
    pipe.write_all(data).await?;
    Ok(())
}

/// Relay loop: one stdin frame -> pipe -> one stdout frame, repeated until either side closes
/// or errors. Every I/O error path (D-05) emits a typed envelope over stdout and returns —
/// there is no `loop {}` that continues silently past an error (Pitfall 5).
///
/// For the echo path: the app listener is what echoes the payload back (Plan 14-02); this
/// sidecar only relays bytes — it does NOT synthesize echo content itself (D-04).
async fn relay_loop(mut pipe: NamedPipeClient) -> std::io::Result<()> {
    loop {
        // Chrome stdio side: native-endian, synchronous std::io via framing.rs. Reading stdin
        // is blocking, so run it on a blocking thread to avoid stalling the tokio runtime.
        let incoming = match tokio::task::spawn_blocking(|| framing::read_message(stdin().lock()))
            .await
            .expect("stdin read task must not panic")
        {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Chrome closed the port (e.g. service-worker teardown) — clean exit, not an
                // error condition worth surfacing to stdout (there is no reader left anyway).
                #[cfg(debug_assertions)]
                eprintln!("cryptiq-nmhost: stdin closed, exiting");
                return Ok(());
            }
            Err(_) => {
                // D-05: malformed or oversized frame from the browser side -> typed
                // protocol-error, then exit. No silent continue. No `id` is knowable here —
                // the stdin read itself failed, so there is no parseable envelope to peek one
                // from (this is the one genuinely id-less case; see `error_envelope`'s doc).
                let env = error_envelope("protocol-error", "malformed or oversized frame", None);
                let bytes = serde_json::to_vec(&env)?;
                framing::write_message(stdout().lock(), &bytes)?;
                #[cfg(debug_assertions)]
                eprintln!("cryptiq-nmhost: protocol-error on stdin, exiting");
                return Ok(());
            }
        };

        // BUG-4 fix: peek the request's `id` from the JUST-successfully-read stdin frame so
        // any error this sidecar synthesizes for THIS message correlates with the extension's
        // per-request listener instead of being silently dropped (see `error_envelope`'s doc).
        let request_id = peek_message_id(&incoming);

        // Forward to the app over the named pipe (big-endian framing).
        if write_pipe_frame(&mut pipe, &incoming).await.is_err() {
            let env = error_envelope(
                "disconnected",
                "lost connection to Cryptiq",
                request_id.clone(),
            );
            let bytes = serde_json::to_vec(&env)?;
            framing::write_message(stdout().lock(), &bytes)?;
            #[cfg(debug_assertions)]
            eprintln!("cryptiq-nmhost: pipe write failed, exiting");
            return Ok(());
        }

        // Read the app's response over the named pipe (big-endian framing).
        let response = match read_pipe_frame(&mut pipe).await {
            Ok(bytes) => bytes,
            Err(_) => {
                // Covers both a genuine mid-session pipe drop AND a malformed/oversized frame
                // from the app side — either way, D-05 requires a typed response then exit.
                let env =
                    error_envelope("disconnected", "lost connection to Cryptiq", request_id);
                let bytes = serde_json::to_vec(&env)?;
                framing::write_message(stdout().lock(), &bytes)?;
                #[cfg(debug_assertions)]
                eprintln!("cryptiq-nmhost: pipe read failed, exiting");
                return Ok(());
            }
        };

        // Relay the app's response back to Chrome over stdout (native-endian framing).
        if framing::write_message(stdout().lock(), &response).is_err() {
            #[cfg(debug_assertions)]
            eprintln!("cryptiq-nmhost: stdout write failed, exiting");
            return Ok(());
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // D-10: lifecycle-only logging, no payloads, dev-gated off by default.
    #[cfg(debug_assertions)]
    eprintln!("cryptiq-nmhost: started");

    // D-09: single attempt, bounded timeout, NO retry loop. This deliberately diverges from
    // tokio's own idiomatic client example, which retries on ERROR_PIPE_BUSY in a loop
    // [CITED: docs.rs/tokio/1.49.0 — Windows named_pipe ClientOptions]. Cryptiq's design
    // intent (never auto-launch the app, fail fast to a clean app-not-running response)
    // overrides that general-purpose retry pattern.
    //
    // review MED fix: `ClientOptions::open` is a SYNCHRONOUS/blocking OS call. Awaiting it
    // directly inside `timeout(...)` cannot actually preempt it — the timeout future only gets
    // polled once the blocking call returns, so a wedged pipe (e.g. ERROR_PIPE_BUSY spin inside
    // the OS) would defeat the bound entirely. Running it via `spawn_blocking` (mirrors the
    // stdin-read pattern in `relay_loop`) puts the blocking call on its own thread so the
    // timeout future can genuinely race it.
    let pipe = match timeout(
        CONNECT_TIMEOUT,
        tokio::task::spawn_blocking(|| ClientOptions::new().open(PIPE_NAME)),
    )
    .await
    {
        Ok(Ok(Ok(client))) => client,
        _ => {
            // D-09/D-19/D-05: typed app-not-running response over stdio, then exit 0 cleanly —
            // no zombie process (SC-2).
            //
            // KNOWN GAP (pre-existing, tracked separately from BUG-4's fix — see
            // 16-HUMAN-UAT.md SC-4 "PARTIAL"): this fires BEFORE any stdin message has been
            // read (the pipe-connect attempt runs first, by design — D-09's "never wait on the
            // browser to decide app-not-running fast"), so there is no request `id` available
            // to peek yet. Fixing this fully would require reordering to read the first stdin
            // frame before attempting the pipe connect — out of scope for BUG-4's evidenced
            // mid-relay disconnected-response mechanism; left as `None` here, unchanged from
            // pre-fix behavior for this ONE call site.
            let env = error_envelope("app-not-running", "Cryptiq is not running", None);
            let bytes = serde_json::to_vec(&env)?;
            framing::write_message(stdout().lock(), &bytes)?;
            #[cfg(debug_assertions)]
            eprintln!("cryptiq-nmhost: app-not-running, exiting");
            return Ok(());
        }
    };

    #[cfg(debug_assertions)]
    eprintln!("cryptiq-nmhost: connected");

    let result = relay_loop(pipe).await;

    #[cfg(debug_assertions)]
    eprintln!("cryptiq-nmhost: exit");

    result
}

// ---------------------------------------------------------------------------
// Tests — BUG-4 fix: sidecar-synthesized error envelopes must correlate with the
// triggering request's `id`, or the extension's per-request listener (which gates on
// `if (msg.id !== id) return;`) silently drops them and the caller falls through to its
// own client-side timeout instead of seeing the real, fast, typed error.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peek_message_id_extracts_id_from_valid_envelope() {
        let raw = serde_json::to_vec(&serde_json::json!({
            "protocolVersion": 1,
            "type": "rpc",
            "id": "req-abc-123",
            "payload": { "nonce": "n", "box": "b" }
        }))
        .unwrap();

        assert_eq!(peek_message_id(&raw), Some("req-abc-123".to_string()));
    }

    #[test]
    fn test_peek_message_id_returns_none_for_null_id() {
        let raw = serde_json::to_vec(&serde_json::json!({
            "protocolVersion": 1,
            "type": "echo",
            "id": null,
            "payload": {}
        }))
        .unwrap();

        assert_eq!(peek_message_id(&raw), None);
    }

    #[test]
    fn test_peek_message_id_fails_open_on_malformed_bytes() {
        // Not valid JSON at all — must yield None, never panic (fail-open, no security
        // implication: `id` is a non-secret correlation token).
        assert_eq!(peek_message_id(b"not json at all"), None);
    }

    #[test]
    fn test_peek_message_id_fails_open_on_missing_id_field() {
        let raw = serde_json::to_vec(&serde_json::json!({ "type": "echo", "payload": {} })).unwrap();
        assert_eq!(peek_message_id(&raw), None);
    }

    #[test]
    fn test_error_envelope_carries_the_supplied_id() {
        // BUG-4 pin: a disconnected/protocol-error response for a KNOWN request must carry
        // THAT request's id — never silently forced to None — so the extension's
        // `if (msg.id !== id) return;` listener guard actually matches it.
        let env = error_envelope(
            "disconnected",
            "lost connection to Cryptiq",
            Some("req-xyz-789".to_string()),
        );
        assert_eq!(env.id, Some("req-xyz-789".to_string()));
        assert_eq!(env.msg_type, "error");
        assert_eq!(env.payload["code"], "disconnected");
    }

    #[test]
    fn test_error_envelope_still_supports_none_for_genuinely_unknown_id() {
        // The one remaining legitimate None case: no request has been read yet (or the frame
        // was too malformed to parse), so there is genuinely nothing to correlate.
        let env = error_envelope("app-not-running", "Cryptiq is not running", None);
        assert_eq!(env.id, None);
    }

    #[test]
    fn test_disconnected_error_after_a_read_request_correlates_with_its_id() {
        // End-to-end-in-miniature: simulates the exact BUG-4 mechanism — a stdin frame is
        // successfully read (so its id IS knowable), then the pipe write/read fails
        // (reused/stale connection). The resulting `disconnected` envelope must carry the
        // SAME id as the incoming request, not None.
        let incoming = serde_json::to_vec(&serde_json::json!({
            "protocolVersion": 1,
            "type": "rpc",
            "id": "req-locked-retry-1",
            "payload": { "clientPublicKey": "x", "nonce": "n", "box": "b" }
        }))
        .unwrap();

        let request_id = peek_message_id(&incoming);
        let env = error_envelope("disconnected", "lost connection to Cryptiq", request_id);

        assert_eq!(
            env.id,
            Some("req-locked-retry-1".to_string()),
            "BUG-4: a disconnected response for a KNOWN request must correlate with its id, \
             or the extension silently drops it and falls through to a 5s client-side timeout \
             instead of seeing this fast, typed error"
        );
    }
}
