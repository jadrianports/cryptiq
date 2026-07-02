// apps/desktop/src-tauri/src/commands/extension_bridge.rs
//
// Phase 14 Plan 02 — always-on local named-pipe listener for the browser
// native-messaging bridge (BRIDGE-02). This is the APP-owned edge of the bridge:
// the `apps/native-host` sidecar (Plan 14-01) relays stdio <-> this pipe.
//
// Responsibilities:
//   PIPE_NAME                     — \\.\pipe\cryptiq-bridge, SAME literal as the sidecar (D-08)
//   CURRENT_PROTOCOL_VERSION      — versioned envelope gate (D-02)
//   MAX_BRIDGE_FRAME              — 1 MiB bound rejected BEFORE buffering (D-05)
//   BridgeEnvelope                — versioned typed envelope (D-01)
//   BridgeError                   — typed, single-source error enum (CLAUDE.md)
//   validate_envelope             — fail-closed protocolVersion check (D-02)
//   ExtensionBridgeState          — forward-compat managed-state stub (Phase 20 UX-05 kill-switch)
//   recv_framed_bridge/send_framed_bridge — BIG-ENDIAN u32 length-prefixed pipe framing
//                                    (shared sidecar<->app pipe-channel contract; distinct from
//                                    Chrome's native-endian stdio framing used by the sidecar
//                                    on its OTHER side, browser<->sidecar)
//   start_extension_bridge_listener — always-on accept loop, spawned once from lib.rs .setup()
//   handle_bridge_connection      — per-connection: read envelope, validate, echo or error
//
// Security invariants:
//   - reject_remote_clients(true) — pipe never accepts a network-origin client (D-03/T-14-05).
//   - protocolVersion mismatch fails closed with a typed error, no silent misbehavior (D-02/T-14-07).
//   - Frame length is capped at MAX_BRIDGE_FRAME BEFORE any buffer allocation (D-05/T-14-08).
//   - The echo handler carries ZERO vault data by construction (D-04) — it never touches vault
//     state, master password, or any secret. Cross-process authentication is explicitly deferred
//     to Phase 15 (crypto_box + pairing token); the default per-user pipe DACL does not isolate
//     other local Windows accounts (T-14-06, accepted risk — see reject_remote_clients comment).
//   - Every IO/framing error closes the connection cleanly; the accept loop never panics or hangs.
//   - Payloads are never logged (D-10) — any verbose diagnostic is lifecycle-only and dev-gated.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::oneshot;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Fixed well-known named-pipe name (D-08). Hardcoded identically in the sidecar
/// (`apps/native-host`) — do NOT change independently on either side.
pub const PIPE_NAME: &str = r"\\.\pipe\cryptiq-bridge";

/// Current wire-protocol version stamped into every `BridgeEnvelope` (D-01/D-02).
pub const CURRENT_PROTOCOL_VERSION: u32 = 1;

/// Hard cap on the 4-byte BE u32 length prefix accepted by the pipe frame reader BEFORE
/// allocating (D-05/T-14-08). Mirrors `sync.rs`'s `MAX_SYNC_FRAME` discipline: a peer-supplied
/// length could otherwise request up to 4 GiB, allowing a remote/local OOM/DoS by sending a
/// giant prefix and nothing else. 1 MiB is far above any real envelope yet small enough to make
/// an allocation attack harmless.
pub const MAX_BRIDGE_FRAME: usize = 1024 * 1024;

/// Bounded read timeout for a single incoming connection (review MED fix — listener DoS).
/// A client that connects and never completes a frame (partial write, zero bytes, or simply
/// never sends) would otherwise pin `read_exact` forever inside `recv_framed_bridge`. A local
/// echo round trip is sub-millisecond, so a few seconds is generous headroom with no risk of
/// false-positive timeouts under normal load.
pub const BRIDGE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

// ---------------------------------------------------------------------------
// BridgeEnvelope — versioned typed wire envelope (D-01)
// ---------------------------------------------------------------------------

/// Versioned typed envelope shared by both directions of the bridge wire protocol.
///
/// Shape is locked by D-01: `{ protocolVersion, type, id, payload }`. `id` is an optional
/// correlation identifier (the extension's background worker matches replies to requests).
/// No timestamp field (not needed yet, D-01). New `type` values are added in later phases
/// without reshaping this envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BridgeEnvelope {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: u32,
    #[serde(rename = "type")]
    pub msg_type: String,
    pub id: Option<String>,
    pub payload: serde_json::Value,
}

// ---------------------------------------------------------------------------
// BridgeError — typed, single-source error enum (CLAUDE.md "typed errors ... single source")
// ---------------------------------------------------------------------------

/// Typed bridge errors. Every validation/framing failure surfaces one of these — never a bare
/// `String`/`Error` — so callers can match on a stable shape (mirrors `packages/core`'s
/// `errors.ts` typed-error discipline, applied here on the Rust side of the wire).
#[derive(Debug, Clone, PartialEq)]
pub enum BridgeError {
    /// D-02: the envelope's `protocolVersion` does not match `CURRENT_PROTOCOL_VERSION`.
    ProtocolMismatch { expected: u32, got: u32 },
    /// D-05: a malformed/oversized frame or any other protocol-level violation.
    ProtocolError(String),
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::ProtocolMismatch { expected, got } => write!(
                f,
                "protocol version mismatch: expected {}, got {}",
                expected, got
            ),
            BridgeError::ProtocolError(msg) => write!(f, "protocol error: {}", msg),
        }
    }
}

impl std::error::Error for BridgeError {}

/// Validate a `BridgeEnvelope` against `CURRENT_PROTOCOL_VERSION`.
///
/// SECURITY (D-02): fails closed on any version mismatch — no silent misbehavior. This is the
/// groundwork for Phase 15's SC-4 version-negotiation guarantee.
pub fn validate_envelope(envelope: &BridgeEnvelope) -> Result<(), BridgeError> {
    if envelope.protocol_version != CURRENT_PROTOCOL_VERSION {
        return Err(BridgeError::ProtocolMismatch {
            expected: CURRENT_PROTOCOL_VERSION,
            got: envelope.protocol_version,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ExtensionBridgeState — forward-compat managed-state stub (Open Question 2)
// ---------------------------------------------------------------------------

/// Managed state for the extension-bridge listener lifecycle.
///
/// Copied VERBATIM (shape-only, renamed) from `sync.rs`'s `SyncListenerState` — forward-compat
/// for Phase 20's UX-05 kill-switch. Nothing calls `stop` this phase; no stop command exists yet.
/// Holds only a cancel channel; any live connection state lives on the task stack, not here.
pub struct ExtensionBridgeState {
    pub cancel_tx: Mutex<Option<oneshot::Sender<()>>>,
}

impl ExtensionBridgeState {
    pub fn new() -> Self {
        ExtensionBridgeState {
            cancel_tx: Mutex::new(None),
        }
    }
}

impl Default for ExtensionBridgeState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Pipe-side framing — BIG-ENDIAN u32 length prefix (sidecar<->app pipe-channel contract)
//
// This is DISTINCT from the sidecar's browser-facing stdio framing, which Chrome's
// native-messaging spec mandates use NATIVE byte order (little-endian on Windows). The
// sidecar translates between the two framings; this side always speaks big-endian, matching
// sync.rs's recv_framed_large/send_framed_large convention.
// ---------------------------------------------------------------------------

/// Read one length-prefixed message from `stream` using a 4-byte BE u32 length prefix.
///
/// SECURITY (D-05): the peer-supplied length is capped at `MAX_BRIDGE_FRAME` BEFORE
/// `buf.resize`, so a malicious multi-GiB prefix cannot trigger a huge allocation. Mirrors
/// `sync.rs::recv_framed_large`'s bounded-before-buffer discipline.
pub async fn recv_framed_bridge<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
) -> tokio::io::Result<usize> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_BRIDGE_FRAME {
        return Err(tokio::io::Error::new(
            tokio::io::ErrorKind::InvalidData,
            "bridge frame length exceeds cap",
        ));
    }
    buf.resize(len, 0);
    stream.read_exact(buf).await?;
    Ok(len)
}

/// Write one length-prefixed message to `stream` using a 4-byte BE u32 length prefix.
pub async fn send_framed_bridge<S: AsyncWrite + Unpin>(
    stream: &mut S,
    data: &[u8],
) -> tokio::io::Result<()> {
    let len = u32::try_from(data.len()).map_err(|_| {
        tokio::io::Error::new(
            tokio::io::ErrorKind::InvalidInput,
            "bridge frame too large for 4-byte u32 prefix",
        )
    })?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Listener — always-on accept loop (BRIDGE-02, spawned once from lib.rs .setup())
// ---------------------------------------------------------------------------

/// Start the always-on local named-pipe listener.
///
/// Spawned exactly once from `lib.rs`'s existing `.setup()` closure — NOT gated by
/// `#[cfg(debug_assertions)]` (unlike the dev MCP bridge) and NOT gated by vault-unlock state
/// (D-04: the echo endpoint carries zero vault data, so there is nothing to gate). Runs for the
/// lifetime of the app.
pub async fn start_extension_bridge_listener(app: tauri::AppHandle) -> std::io::Result<()> {
    // SECURITY (D-03/T-14-05): reject_remote_clients(true) blocks all NETWORK-origin clients —
    // only local processes on this machine may connect. This does NOT isolate other LOCAL
    // Windows accounts on a shared machine (default per-user pipe DACL, T-14-06 / RESEARCH.md
    // Open Question 1 / Pitfall 3) — accepted for this zero-vault-data skeleton because the echo
    // handler never touches vault state by construction (D-04); Phase 15's crypto_box pairing
    // token is the designed real mitigation for that residual risk.
    let mut server = ServerOptions::new()
        .reject_remote_clients(true)
        .first_pipe_instance(true)
        .create(PIPE_NAME)?;

    loop {
        if server.connect().await.is_err() {
            // App shutting down or pipe torn down — stop the accept loop cleanly.
            break;
        }
        let connected = server;

        // Rebuild the NEXT server instance BEFORE handing the connected one off to a
        // per-connection task. This is tokio's own idiomatic named-pipe accept-loop pattern —
        // it avoids a race where a second client sees NotFound in the gap between accepting
        // one connection and creating the next listening instance (RESEARCH.md Pitfall 3).
        server = match ServerOptions::new()
            .reject_remote_clients(true)
            .create(PIPE_NAME)
        {
            Ok(s) => s,
            Err(_) => break,
        };

        let app_clone = app.clone();
        tokio::spawn(async move {
            handle_bridge_connection(connected, app_clone).await;
        });
    }

    Ok(())
}

/// Handle a single connected pipe client: read one framed envelope, validate it, and respond.
///
/// - `msg_type == "echo"` → echo the SAME `id` and the SAME `payload` back verbatim (D-04: a
///   fixed, harmless echo with zero vault data and zero business logic).
/// - protocolVersion mismatch → typed `{type:"error", payload:{code, message}}` response, then
///   close (D-02/D-05).
/// - Any framing/IO/deserialize error → close the connection cleanly. No panic, no hang.
///
/// Never logs envelope payloads (D-10); any verbose diagnostic is lifecycle-only and dev-gated.
async fn handle_bridge_connection(mut connected: NamedPipeServer, _app: tauri::AppHandle) {
    #[cfg(debug_assertions)]
    eprintln!("extension_bridge: client connected");

    // review MED fix: a client that connects and then sends a partial/zero-byte frame (or
    // nothing at all) would otherwise block this task forever on `read_exact` inside
    // `recv_framed_bridge` — a trivial local DoS against the connection-handling task pool.
    // Bound the whole read side with a timeout (mirrors D-09's bounded-timeout discipline);
    // a local echo round trip completes in milliseconds, so a few seconds is ample headroom.
    let mut buf = Vec::new();
    let read_result = tokio::time::timeout(
        BRIDGE_READ_TIMEOUT,
        recv_framed_bridge(&mut connected, &mut buf),
    )
    .await;
    let raw = match read_result {
        Ok(Ok(_)) => buf,
        Ok(Err(_)) => {
            // Oversized/malformed frame or IO error — close cleanly, no response possible.
            #[cfg(debug_assertions)]
            eprintln!("extension_bridge: frame read failed, closing");
            return;
        }
        Err(_) => {
            // Timed out waiting for a complete frame — close cleanly. No payload to log (D-10);
            // this is a lifecycle-only diagnostic, dev-gated off by default.
            #[cfg(debug_assertions)]
            eprintln!("extension_bridge: read timed out, closing");
            return;
        }
    };

    let envelope: BridgeEnvelope = match serde_json::from_slice(&raw) {
        Ok(e) => e,
        Err(_) => {
            let error_envelope = error_response(
                None,
                BridgeError::ProtocolError("malformed envelope".to_string()),
            );
            let _ = respond(&mut connected, &error_envelope).await;
            return;
        }
    };

    if let Err(err) = validate_envelope(&envelope) {
        let error_envelope = error_response(envelope.id.clone(), err);
        let _ = respond(&mut connected, &error_envelope).await;
        return;
    }

    if envelope.msg_type == "echo" {
        // D-04: fixed harmless echo — the SAME id + payload, verbatim, zero vault data.
        let response = BridgeEnvelope {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            msg_type: "echo".to_string(),
            id: envelope.id.clone(),
            payload: envelope.payload.clone(),
        };
        let _ = respond(&mut connected, &response).await;
    }
    // Unrecognized msg_type: no response this phase (no other typed messages exist yet).
}

/// Build a typed `{type:"error", payload:{code, message}}` envelope from a `BridgeError`
/// (D-02/D-05) — single mapping site so both the malformed-envelope and version-mismatch
/// paths in `handle_bridge_connection` produce the same shape.
fn error_response(id: Option<String>, err: BridgeError) -> BridgeEnvelope {
    let (code, message) = match err {
        BridgeError::ProtocolMismatch { expected, got } => (
            "version-mismatch".to_string(),
            format!("expected protocolVersion {}, got {}", expected, got),
        ),
        BridgeError::ProtocolError(msg) => ("protocol-error".to_string(), msg),
    };
    BridgeEnvelope {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        msg_type: "error".to_string(),
        id,
        payload: serde_json::json!({ "code": code, "message": message }),
    }
}

/// Serialize and write a `BridgeEnvelope` response, mapping any failure to a clean return
/// (never a panic). Framing/IO errors here simply mean the connection closes without a reply.
async fn respond<S: AsyncWrite + Unpin>(
    stream: &mut S,
    envelope: &BridgeEnvelope,
) -> tokio::io::Result<()> {
    let bytes = serde_json::to_vec(envelope)?;
    send_framed_bridge(stream, &bytes).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_validate_envelope_accepts_current_version() {
        let envelope = BridgeEnvelope {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            msg_type: "echo".to_string(),
            id: Some("abc".to_string()),
            payload: serde_json::json!({ "hello": "world" }),
        };
        assert!(validate_envelope(&envelope).is_ok());
    }

    #[test]
    fn test_validate_envelope_rejects_version_mismatch() {
        let envelope = BridgeEnvelope {
            protocol_version: CURRENT_PROTOCOL_VERSION + 1,
            msg_type: "echo".to_string(),
            id: None,
            payload: serde_json::json!({}),
        };
        let err = validate_envelope(&envelope).unwrap_err();
        assert_eq!(
            err,
            BridgeError::ProtocolMismatch {
                expected: CURRENT_PROTOCOL_VERSION,
                got: CURRENT_PROTOCOL_VERSION + 1,
            }
        );
    }

    #[tokio::test]
    async fn test_recv_framed_bridge_rejects_oversize_before_buffering() {
        // A length prefix declaring more than MAX_BRIDGE_FRAME bytes MUST be rejected before
        // any large allocation — mirrors sync.rs's test_recv_framed_large_rejects_oversize.
        let oversized_len: u32 = (MAX_BRIDGE_FRAME as u32) + 1;
        let mut data = oversized_len.to_be_bytes().to_vec();
        // No body bytes follow — if the reader tried to allocate/read before checking the cap,
        // this would hang/err on read_exact rather than failing fast on the length check.
        let mut cursor = Cursor::new(&mut data);
        let mut buf = Vec::new();
        let result = recv_framed_bridge(&mut cursor, &mut buf).await;
        assert!(result.is_err());
        // No allocation should have occurred before the cap check rejected the frame.
        assert!(buf.capacity() <= MAX_BRIDGE_FRAME);
    }

    #[tokio::test]
    async fn test_echo_envelope_round_trip() {
        let original = BridgeEnvelope {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            msg_type: "echo".to_string(),
            id: Some("req-1".to_string()),
            payload: serde_json::json!({ "nested": { "n": 42 }, "arr": [1, 2, 3] }),
        };

        let mut buf: Vec<u8> = Vec::new();
        let bytes = serde_json::to_vec(&original).unwrap();
        send_framed_bridge(&mut buf, &bytes).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let mut read_buf = Vec::new();
        recv_framed_bridge(&mut cursor, &mut read_buf).await.unwrap();
        let round_tripped: BridgeEnvelope = serde_json::from_slice(&read_buf).unwrap();

        assert_eq!(round_tripped, original);
    }
}
