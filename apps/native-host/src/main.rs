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
fn error_envelope(code: &str, message: &str) -> BridgeEnvelope {
    BridgeEnvelope {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        msg_type: "error".to_string(),
        id: None,
        payload: serde_json::json!({ "code": code, "message": message }),
    }
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
                // protocol-error, then exit. No silent continue.
                let env = error_envelope("protocol-error", "malformed or oversized frame");
                let bytes = serde_json::to_vec(&env)?;
                framing::write_message(stdout().lock(), &bytes)?;
                #[cfg(debug_assertions)]
                eprintln!("cryptiq-nmhost: protocol-error on stdin, exiting");
                return Ok(());
            }
        };

        // Forward to the app over the named pipe (big-endian framing).
        if write_pipe_frame(&mut pipe, &incoming).await.is_err() {
            let env = error_envelope("disconnected", "lost connection to Cryptiq");
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
                let env = error_envelope("disconnected", "lost connection to Cryptiq");
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
            let env = error_envelope("app-not-running", "Cryptiq is not running");
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
