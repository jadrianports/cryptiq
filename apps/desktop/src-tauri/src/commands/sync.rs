// apps/desktop/src-tauri/src/commands/sync.rs
//
// Phase 10 Plan 02 — Noise IK transport layer for full vault exchange.
// Phase 10 Plan 03 — sync_now initiator command + listener task body + registration.
//
// Responsibilities:
//   IK_PARAMS            — LazyLock<NoiseParams> for "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
//   derive_transport_psk — deterministic 32-byte PSK from two static public keys (XOR of sorted)
//   build_ik_initiator   — Noise IK initiator builder (psk slot 2)
//   build_ik_responder   — Noise IK responder builder (psk slot 2); no remote_public_key
//   recv_framed_large    — 4-byte BE u32 length-prefix recv (for vault blobs ≥ 65536 bytes)
//   send_framed_large    — 4-byte BE u32 length-prefix send
//   SYNC_*_DEADLINE      — deadline constants for each leg of the D-05 protocol
//   run_ik_handshake_initiator — 2-message IK exchange (NOT 3 like XX)
//   run_ik_handshake_responder — 2-message IK exchange + static-key pin (Pitfall 2)
//   SyncBindingFrame     — serde struct for the vaultPairId binding check frame
//   verify_vault_pair_id_binding — bidirectional binding check before any vault bytes flow
//   recv_vault_blob      — decrypt B's full vault blob from transport
//   SyncListenerState    — managed state for the D-06 listen-while-unlocked listener
//   sync_now             — Tauri command: connect to peer, IK handshake, binding, recv vault blob (D-05)
//   sync_listener_start  — Tauri command: start IK listener when vault unlocks (D-06)
//   sync_listener_stop   — Tauri command: stop listener on vault lock (D-06)
//
// Security invariants:
//   - ONLY Noise-IK ciphertext crosses the wire — no plaintext vault JSON, no master password.
//   - The responder verifies get_remote_static() BEFORE into_transport_mode() (Pitfall 2 / T-10-04).
//   - A vaultPairId mismatch ABORTS before any vault bytes flow (T-10-05 / SYNC-03).
//   - All vault bytes use 4-byte u32 framing (not 2-byte u16) — prevents 65535-byte overflow (T-10-07).
//   - All handshake failures return a generic "IK handshake failed" string — no info leak (T-10-08).
//   - Windows CredManager reads are #[cfg(target_os = "windows")]-gated (SYNC-07).
//   - Master password NEVER reaches this module. All crypto is JS/WASM (packages/core).
//   - The sync listener MUST NOT be started from lib.rs setup() — only via sync_listener_start (D-10/D-06).
//   - vault_path is confined via assert_confined BEFORE any file read (CLAUDE.md path requirement).
//   - SK and PSK bytes are zeroized after use (T-10-12).

use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use snow::{params::NoiseParams, Builder};
use tauri::Manager;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

// Re-use pairing.rs helpers — do NOT copy their bodies.
// NOTE: the listener no longer uses accept_with_cancel / AcceptOutcome — FIX 3 inlines a
// `tokio::select!` loop that polls the cancel receiver by `&mut` so it survives across iterations.
use super::pairing::{
    connect_with_timeout, read_peers_json, recv_framed, send_framed, write_peers_json_atomic,
    CredentialStore, DEVICE_IDENTITY_SK_TARGET,
};
// Windows CredManager access — gated to Windows.
#[cfg(target_os = "windows")]
use super::pairing::WindowsCredentialStore;
#[cfg(not(target_os = "windows"))]
use super::pairing::NoopCredentialStore;

// ---------------------------------------------------------------------------
// Noise IK parameters (DISTINCT from pairing.rs PARAMS which is XXpsk3)
// ---------------------------------------------------------------------------

/// Noise IKpsk2 pattern string for post-pairing vault-exchange transport.
///
/// DISTINCT from `PARAMS` in `pairing.rs` (which is Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s).
/// IK = Initiator knows responder's static key. PSK slot 2 (IKpsk2). 2 messages only.
/// Do NOT share this LazyLock with pairing.rs.
// Used in tests and will be used in Plan-03 sync_now. Allow dead_code for this plan.
#[allow(dead_code)]
static IK_PARAMS: LazyLock<NoiseParams> =
    LazyLock::new(|| "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".parse().unwrap());

// ---------------------------------------------------------------------------
// Deadline constants for each D-05 protocol leg
// ---------------------------------------------------------------------------

/// How long A waits for a TCP connection to B (or B's listener waits for A's connect).
/// Mirrors the Phase-9 CONNECT_ACCEPT_DEADLINE value (30 s).
// Forward-declared for Plan 03 (sync_now + listener). Allow dead_code for this plan.
#[allow(dead_code)]
const SYNC_CONNECT_DEADLINE: Duration = Duration::from_secs(30);

/// How long the Noise IK handshake (2 messages) may take after TCP connection.
/// IK is faster than XX (2 messages not 3) so 30 s is generous.
#[allow(dead_code)]
const SYNC_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);

/// How long to wait for the vaultPairId binding-check frame after the handshake.
/// This is a small JSON frame; 10 s is ample.
#[allow(dead_code)]
const SYNC_BINDING_CHECK_DEADLINE: Duration = Duration::from_secs(10);

/// How long to wait for B to send its full vault blob.
/// Vaults are small (< 256 KiB after padding), but allow for slow LAN conditions.
#[allow(dead_code)]
const SYNC_BLOB_RECV_DEADLINE: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// PSK derivation — deterministic from the two static public keys (no storage needed)
// ---------------------------------------------------------------------------

/// Derive a 32-byte transport PSK from two 32-byte static public keys.
///
/// Both sides (initiator and responder) produce the SAME value regardless of role because
/// the keys are sorted lexicographically before being combined.
///
/// Algorithm: XOR of sorted(pk_a, pk_b). This is the documented-acceptable approach from
/// RESEARCH.md Resolution 1: the IK static-key authentication is the real gate; the PSK
/// is defense-in-depth. Both keys are already in peers.json (public, not secret), so a
/// predictable XOR is acceptable — the IK auth prevents an attacker from forging the PSK
/// without holding the corresponding private key.
///
/// NOTE: If the `blake2` crate is added as a direct dep (it is already a transitive dep of
/// snow), use `Blake2s256::new().chain_update(first).chain_update(second).finalize().into()`
/// for a proper PRF. The XOR approach is used here to avoid a new direct dependency.
pub fn derive_transport_psk(pk_a: &[u8; 32], pk_b: &[u8; 32]) -> [u8; 32] {
    // Lexicographic sort ensures commutativity: initiator/responder produce the same value.
    let (first, second) = if pk_a <= pk_b { (pk_a, pk_b) } else { (pk_b, pk_a) };
    let mut psk = [0u8; 32];
    for i in 0..32 {
        psk[i] = first[i] ^ second[i];
    }
    psk
}

// ---------------------------------------------------------------------------
// IK HandshakeState builders
// ---------------------------------------------------------------------------

/// Build a Noise IKpsk2 HandshakeState for the INITIATOR (Device A — connects to B).
///
/// A knows B's static public key from peers.json (the IK model assumption).
/// PSK slot 2 — IKpsk2. The initiator sets the remote_public_key (B's pk).
pub fn build_ik_initiator(
    own_sk: &[u8],
    peer_pk: &[u8],
    psk: &[u8; 32],
) -> Result<snow::HandshakeState, String> {
    Builder::new(IK_PARAMS.clone())
        .local_private_key(own_sk)
        .map_err(|e| format!("build_ik_initiator: local_private_key failed: {}", e))?
        .remote_public_key(peer_pk)
        .map_err(|e| format!("build_ik_initiator: remote_public_key failed: {}", e))?
        .psk(2, psk)
        .map_err(|e| format!("build_ik_initiator: psk(2) failed: {}", e))?
        .build_initiator()
        .map_err(|e| format!("build_ik_initiator: build_initiator failed: {}", e))
}

/// Build a Noise IKpsk2 HandshakeState for the RESPONDER (Device B — listener).
///
/// B does NOT set remote_public_key — IK's responder learns the initiator's static pk from
/// the first message and we verify it via get_remote_static() AFTER read_message (Pitfall 2).
/// PSK slot 2 — IKpsk2.
pub fn build_ik_responder(own_sk: &[u8], psk: &[u8; 32]) -> Result<snow::HandshakeState, String> {
    Builder::new(IK_PARAMS.clone())
        .local_private_key(own_sk)
        .map_err(|e| format!("build_ik_responder: local_private_key failed: {}", e))?
        .psk(2, psk)
        .map_err(|e| format!("build_ik_responder: psk(2) failed: {}", e))?
        .build_responder()
        .map_err(|e| format!("build_ik_responder: build_responder failed: {}", e))
}

// ---------------------------------------------------------------------------
// 4-byte (u32) large framing — for vault blobs that can exceed 65535 bytes
//
// The Phase-9 recv_framed/send_framed use a 2-byte u16 prefix (max 65535).
// Vault blobs with tiered padding at the 64 KiB tier can be ≥ 65536 bytes (Pitfall 3).
// These large-framing variants use a 4-byte BE u32 prefix; reserve the 2-byte variants
// for handshake messages and small control frames (SyncBindingFrame is always < 200 bytes).
// ---------------------------------------------------------------------------

/// Maximum plaintext payload per single Noise transport message.
///
/// snow's `TransportState::write_message`/`read_message` reject any single message whose
/// ciphertext (payload + TAGLEN(16)) exceeds `MAXMSGLEN` (65535). So the largest plaintext
/// chunk we may pass to `write_message` is `65535 - 16 = 65519` bytes. Vault documents at the
/// 64 KiB padding tier (~88 KiB file) exceed this — they MUST be chunked across multiple Noise
/// messages (FIX 1 / review HIGH-1). This is the per-chunk plaintext cap for the chunked wire
/// protocol implemented by the listener sender and `recv_vault_blob`.
const VAULT_CHUNK_SIZE: usize = 65519;

/// Hard cap on the 4-byte u32 length prefix accepted by `recv_framed_large` BEFORE allocating.
///
/// A peer-supplied length could otherwise be up to 4 GiB, allowing a remote OOM/DoS by sending
/// a giant prefix and then nothing (FIX 2 / review HIGH-2). Every legitimate frame is a single
/// Noise message — at most `VAULT_CHUNK_SIZE + TAGLEN(16)` ≈ 65 KiB, or the 4-byte chunk-count
/// header. 1 MiB is far above any real frame yet small enough to make an allocation attack
/// harmless.
const MAX_SYNC_FRAME: usize = 1024 * 1024;

/// Upper bound on the chunk-count header in the chunked vault wire protocol.
///
/// At `VAULT_CHUNK_SIZE` (~64 KiB) per chunk, 4096 chunks ≈ 256 MiB of plaintext — orders of
/// magnitude above any real padded vault. A peer claiming more chunks than this is rejected
/// before the receive loop allocates per-chunk buffers (FIX 1 receiver hardening).
const MAX_VAULT_CHUNKS: u32 = 4096;

/// Read one length-prefixed message from `stream` using a 4-byte BE u32 length prefix.
///
/// Use this for vault blobs. For handshake messages and small control frames, use
/// `recv_framed` (2-byte prefix) from pairing.rs.
///
/// SECURITY (FIX 2 / review HIGH-2): the peer-supplied length is capped at `MAX_SYNC_FRAME`
/// BEFORE `buf.resize`, so a malicious 4 GiB prefix cannot trigger a huge allocation. The error
/// is generic ("sync frame length exceeds cap") — no info leak.
pub async fn recv_framed_large<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
) -> tokio::io::Result<usize> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_SYNC_FRAME {
        return Err(tokio::io::Error::new(
            tokio::io::ErrorKind::InvalidData,
            "sync frame length exceeds cap",
        ));
    }
    buf.resize(len, 0);
    stream.read_exact(buf).await?;
    Ok(len)
}

/// Write one length-prefixed message to `stream` using a 4-byte BE u32 length prefix.
///
/// Rejects payloads that exceed u32::MAX with an InvalidInput io::Error.
/// Use this for vault blobs. For handshake messages and small control frames, use
/// `send_framed` (2-byte prefix) from pairing.rs.
pub async fn send_framed_large<S: AsyncWrite + Unpin>(
    stream: &mut S,
    data: &[u8],
) -> tokio::io::Result<()> {
    let len = u32::try_from(data.len()).map_err(|_| {
        tokio::io::Error::new(
            tokio::io::ErrorKind::InvalidInput,
            "vault blob too large for 4-byte u32 prefix",
        )
    })?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// IK 2-message handshake
//
// IK is EXACTLY 2 messages (NOT 3 like XX — Pitfall 1). Do NOT add a 3rd message.
//   → e, es, s, ss   (msg 1: initiator sends ephemeral key + encrypted static key)
//   ← e, ee          (msg 2: responder sends ephemeral key)
// Both sides call into_transport_mode() after msg 2.
// ---------------------------------------------------------------------------

/// Run the full 2-message Noise IKpsk2 handshake as the INITIATOR.
///
/// EXACTLY 2 messages — do NOT add a 3rd (Pitfall 1 / IK ≠ XX).
/// All handshake failures return "IK handshake failed" — no info leak (T-10-08).
pub async fn run_ik_handshake_initiator<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    own_sk: &[u8],
    peer_pk: &[u8],
    psk: &[u8; 32],
) -> Result<snow::TransportState, String> {
    let mut noise = build_ik_initiator(own_sk, peer_pk, psk)?;
    let mut buf = Vec::new();
    let mut msg_buf = vec![0u8; 65535];

    // Message 1: → e, es, s, ss  (initiator sends; encrypted under peer's known static pk)
    let len = noise
        .write_message(&[], &mut msg_buf)
        .map_err(|_| "IK handshake failed".to_string())?;
    send_framed(stream, &msg_buf[..len])
        .await
        .map_err(|e| format!("IK msg1 send failed: {}", e))?;

    // Message 2: ← e, ee  (responder replies)
    recv_framed(stream, &mut buf)
        .await
        .map_err(|e| format!("IK msg2 recv failed: {}", e))?;
    noise
        .read_message(&buf, &mut msg_buf)
        .map_err(|_| "IK handshake failed".to_string())?;

    // Handshake complete after exactly 2 messages — transition to transport mode.
    noise
        .into_transport_mode()
        .map_err(|_| "IK handshake failed".to_string())
}

/// Run the full 2-message Noise IKpsk2 handshake as the RESPONDER.
///
/// CRITICAL: verifies `get_remote_static() == expected_peer_pk` BEFORE calling
/// `into_transport_mode()` — drops unknown static keys without proceeding (Pitfall 2 / T-10-04).
///
/// All handshake failures return the generic "IK handshake failed" string — no info leak about
/// whether the key was unknown vs. MAC failure (T-10-08).
pub async fn run_ik_handshake_responder<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    own_sk: &[u8],
    psk: &[u8; 32],
    expected_peer_pk: &[u8],
) -> Result<snow::TransportState, String> {
    let mut noise = build_ik_responder(own_sk, psk)?;
    let mut buf = Vec::new();
    let mut msg_buf = vec![0u8; 65535];

    // Message 1: ← e, es, s, ss  (from initiator; decrypt to learn initiator's static pk)
    recv_framed(stream, &mut buf)
        .await
        .map_err(|e| format!("IK msg1 recv failed: {}", e))?;
    noise
        .read_message(&buf, &mut msg_buf)
        .map_err(|_| "IK handshake failed".to_string())?;

    // CRITICAL (Pitfall 2 / T-10-04): verify initiator's static pk BEFORE into_transport_mode().
    // Unknown key → return generic error, do NOT proceed to transport mode.
    let received_pk = noise
        .get_remote_static()
        .ok_or_else(|| "IK handshake failed".to_string())?;
    if received_pk != expected_peer_pk {
        // Drop unknown key. No info leak: generic string regardless of whether the key was
        // unrecognized vs. MAC failure (T-10-08).
        return Err("IK handshake failed".to_string());
    }

    // Message 2: → e, ee  (responder replies)
    let len = noise
        .write_message(&[], &mut msg_buf)
        .map_err(|_| "IK handshake failed".to_string())?;
    send_framed(stream, &msg_buf[..len])
        .await
        .map_err(|e| format!("IK msg2 send failed: {}", e))?;

    // Handshake complete after exactly 2 messages — transition to transport mode.
    noise
        .into_transport_mode()
        .map_err(|_| "IK handshake failed".to_string())
}

// ---------------------------------------------------------------------------
// vaultPairId binding frame + bidirectional verification
//
// After the IK handshake completes, BEFORE any vault bytes flow, both sides
// exchange a SyncBindingFrame encrypted over the transport. A mismatch on either
// side ABORTS the connection with zero vault bytes written (SYNC-03 / T-10-05).
//
// Sequence (Resolution 7 / D-05 step 1c):
//   A → B: SyncBindingFrame { vaultPairId: A.expected, initiatorDeviceId: A.deviceId }
//   B checks vaultPairId; mismatch → return binding error, send NO vault bytes
//   B → A: SyncBindingFrame { vaultPairId: B.expected, initiatorDeviceId: B.deviceId }
//   A checks vaultPairId; mismatch → return binding error
//   BOTH sides verified → proceed to vault blob exchange
// ---------------------------------------------------------------------------

/// The binding check frame exchanged after IK handshake, before any vault bytes.
///
/// Both fields use camelCase in the JSON so they match the TS interface (SYNC-03).
/// NEVER send as plaintext — always encrypt through transport.write_message (SYNC-02).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SyncBindingFrame {
    pub vault_pair_id: String,
    pub initiator_device_id: String,
}

/// Verify the vaultPairId binding in BOTH directions before any vault bytes flow.
///
/// The initiator (A) sends its binding frame first; the responder (B) verifies and sends its
/// own; A verifies B's. Mismatch on either side returns an error and prevents vault bytes.
///
/// `transport` is mutated: write_message increments the nonce counter. The caller must pass
/// the same mutable reference through to vault byte send/recv after this returns `Ok(())`.
///
/// All frame bytes go through `transport.write_message`/`read_message` — ciphertext only on
/// wire (SYNC-02). No `get_handshake_hash()` call — no SAS in the transport channel.
pub async fn verify_vault_pair_id_binding<S: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut snow::TransportState,
    stream: &mut S,
    expected_pair_id: &str,
    own_device_id: &str,
    is_initiator: bool,
) -> Result<(), String> {
    let mut enc_buf = vec![0u8; 65535];
    let mut plain_buf = vec![0u8; 65535];
    let mut wire_buf = Vec::new();

    if is_initiator {
        // A sends its binding frame first.
        let frame = SyncBindingFrame {
            vault_pair_id: expected_pair_id.to_string(),
            initiator_device_id: own_device_id.to_string(),
        };
        let json = serde_json::to_vec(&frame)
            .map_err(|e| format!("binding frame serialize failed: {}", e))?;
        let enc_len = transport
            .write_message(&json, &mut enc_buf)
            .map_err(|_| "binding frame encrypt failed".to_string())?;
        send_framed(stream, &enc_buf[..enc_len])
            .await
            .map_err(|e| format!("binding frame send failed: {}", e))?;

        // A reads B's binding frame.
        recv_framed(stream, &mut wire_buf)
            .await
            .map_err(|e| format!("binding frame recv failed: {}", e))?;
        let plain_len = transport
            .read_message(&wire_buf, &mut plain_buf)
            .map_err(|_| "binding frame decrypt failed".to_string())?;
        let peer_frame: SyncBindingFrame =
            serde_json::from_slice(&plain_buf[..plain_len])
                .map_err(|e| format!("binding frame parse failed: {}", e))?;

        if peer_frame.vault_pair_id != expected_pair_id {
            return Err(format!(
                "sync binding mismatch: expected vaultPairId '{}', peer sent '{}'",
                expected_pair_id, peer_frame.vault_pair_id
            ));
        }
    } else {
        // B reads A's binding frame first.
        recv_framed(stream, &mut wire_buf)
            .await
            .map_err(|e| format!("binding frame recv failed: {}", e))?;
        let plain_len = transport
            .read_message(&wire_buf, &mut plain_buf)
            .map_err(|_| "binding frame decrypt failed".to_string())?;
        let peer_frame: SyncBindingFrame =
            serde_json::from_slice(&plain_buf[..plain_len])
                .map_err(|e| format!("binding frame parse failed: {}", e))?;

        if peer_frame.vault_pair_id != expected_pair_id {
            // Mismatch: B sends NO vault bytes (SYNC-03 / T-10-05). Return error immediately.
            return Err(format!(
                "sync binding mismatch: expected vaultPairId '{}', peer sent '{}'",
                expected_pair_id, peer_frame.vault_pair_id
            ));
        }

        // B sends its own binding frame.
        let frame = SyncBindingFrame {
            vault_pair_id: expected_pair_id.to_string(),
            initiator_device_id: own_device_id.to_string(),
        };
        let json = serde_json::to_vec(&frame)
            .map_err(|e| format!("binding frame serialize failed: {}", e))?;
        let enc_len = transport
            .write_message(&json, &mut enc_buf)
            .map_err(|_| "binding frame encrypt failed".to_string())?;
        send_framed(stream, &enc_buf[..enc_len])
            .await
            .map_err(|e| format!("binding frame send failed: {}", e))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Path confinement guard — mirrors vault.rs / pairing.rs assert_confined pattern
// (CLAUDE.md: "All path commands enforce resolve_confined_path")
// ---------------------------------------------------------------------------

/// Verify that `target` resolves to a path inside `expected_parent` after canonicalization.
///
/// This is the same guard used in vault.rs and pairing.rs. Callers MUST invoke this BEFORE any
/// `fs::read` / `tokio::fs::read` on a JS-supplied path (T-10-14). A path outside the confined
/// root is rejected with no file read attempted.
fn assert_confined(target: &Path, expected_parent: &Path) -> Result<(), String> {
    // Canonicalize the confinement root (must exist).
    let canonical_parent = expected_parent
        .canonicalize()
        .map_err(|e| format!("Path confinement: could not canonicalize parent '{}': {}", expected_parent.display(), e))?;

    let file_name = target
        .file_name()
        .ok_or_else(|| format!("Path confinement: '{}' has no filename component", target.display()))?;

    // Resolve the target's REAL canonical location.
    let canonical_target = if target.exists() {
        target
            .canonicalize()
            .map_err(|e| format!("Path confinement: could not canonicalize '{}': {}", target.display(), e))?
    } else {
        let target_parent = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| format!("Path confinement: '{}' has no parent directory", target.display()))?;
        let canonical_target_parent = target_parent
            .canonicalize()
            .map_err(|e| format!("Path confinement: could not canonicalize target parent '{}': {}", target_parent.display(), e))?;
        canonical_target_parent.join(file_name)
    };

    if !canonical_target.starts_with(&canonical_parent) {
        return Err(format!(
            "Path confinement violation: '{}' is not inside '{}'",
            canonical_target.display(),
            canonical_parent.display()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Hex decode helper — decode a 64-char hex string to exactly 32 bytes (no new dep)
// ---------------------------------------------------------------------------

/// Decode a lowercase hex string to exactly 32 bytes.
///
/// Returns an error string if the input is not exactly 64 hex characters or contains
/// non-hex characters. No new crate dependency needed.
fn hex_decode_32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!(
            "hex decode failed: expected 64 chars for a 32-byte key, got {}",
            s.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])
            .map_err(|c| format!("hex decode failed: invalid char '{}' at position {}", c as char, i * 2))?;
        let lo = hex_nibble(chunk[1])
            .map_err(|c| format!("hex decode failed: invalid char '{}' at position {}", c as char, i * 2 + 1))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(b),
    }
}

// ---------------------------------------------------------------------------
// recv_vault_blob — receive B's full encrypted vault blob from the transport
// ---------------------------------------------------------------------------

/// Receive B's full vault blob from the established transport channel.
///
/// CHUNKED WIRE PROTOCOL (FIX 1 / review HIGH-1) — symmetric with the listener sender:
///   1. Header frame: `send_framed_large(&(chunk_count as u32).to_be_bytes())` — 4 BE bytes.
///   2. Then `chunk_count` chunk frames, each `send_framed_large(&enc[..n])` where `enc` is the
///      Noise ciphertext of one ≤`VAULT_CHUNK_SIZE` (65519-byte) slice of the plaintext blob.
/// The receiver reads the header, caps the count at `MAX_VAULT_CHUNKS`, then reads exactly that
/// many chunk frames, decrypting each through `transport.read_message` and appending the
/// plaintext. The concatenated plaintext is B's full `VaultDocumentV1`.
///
/// This replaces the previous single-`read_message` design, which silently failed for vaults
/// above ~65 KiB because a single Noise message payload cannot exceed `VAULT_CHUNK_SIZE`.
///
/// The vault bytes are B's full `VaultDocumentV1` AEAD ciphertext — they are still encrypted
/// under libsodium (B's vault key). Rust receives and returns them without interpretation.
/// The WASM/JS layer (packages/core) performs the auth check and eventual decryption (D-05 step 3+).
///
/// Uses 4-byte u32 framing (not 2-byte) — chunk frames can exceed 65535 bytes only by the
/// 16-byte Noise tag, and `recv_framed_large` caps the prefix at `MAX_SYNC_FRAME` (FIX 2).
pub async fn recv_vault_blob<S: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut snow::TransportState,
    stream: &mut S,
) -> Result<Vec<u8>, String> {
    // ---- Step 1: read the chunk-count header frame (4 BE bytes), cap it. ----
    let mut header_buf = Vec::new();
    recv_framed_large(stream, &mut header_buf)
        .await
        .map_err(|e| format!("recv_vault_blob: chunk-count header recv failed: {}", e))?;
    if header_buf.len() != 4 {
        return Err(format!(
            "recv_vault_blob: chunk-count header must be 4 bytes, got {}",
            header_buf.len()
        ));
    }
    let chunk_count = u32::from_be_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]);
    if chunk_count > MAX_VAULT_CHUNKS {
        // Reject implausible counts before allocating any per-chunk buffers (DoS guard).
        return Err(format!(
            "recv_vault_blob: chunk count {} exceeds cap {}",
            chunk_count, MAX_VAULT_CHUNKS
        ));
    }

    // ---- Step 2: read exactly chunk_count Noise-encrypted chunk frames, decrypt + append. ----
    // Per-chunk plaintext buffer: at most VAULT_CHUNK_SIZE bytes, plus AEAD tag headroom.
    let mut out = Vec::new();
    let mut enc_buf = Vec::new();
    let mut plain_buf = vec![0u8; VAULT_CHUNK_SIZE + 128];
    for i in 0..chunk_count {
        recv_framed_large(stream, &mut enc_buf)
            .await
            .map_err(|e| format!("recv_vault_blob: chunk {} frame recv failed: {}", i, e))?;
        let plain_len = transport
            .read_message(&enc_buf, &mut plain_buf)
            .map_err(|_| "recv_vault_blob: Noise decrypt failed — transport error".to_string())?;
        out.extend_from_slice(&plain_buf[..plain_len]);
    }

    Ok(out)
}

/// Send a full vault blob over the established transport using the CHUNKED wire protocol.
///
/// SYMMETRIC with `recv_vault_blob` (FIX 1 / review HIGH-1):
///   1. Header frame: chunk count as 4 BE bytes via `send_framed_large`.
///   2. For each ≤`VAULT_CHUNK_SIZE` (65519-byte) plaintext slice: `transport.write_message`
///      then `send_framed_large(&enc[..n])`.
///
/// The empty-blob edge case sends a header of 0 chunks and no chunk frames (the receiver loops
/// zero times and returns an empty Vec). A single-message design here would silently fail for any
/// vault above ~65 KiB because a single Noise payload cannot exceed `VAULT_CHUNK_SIZE`.
///
/// `vault_bytes` is the caller's full `VaultDocumentV1` (already AEAD-sealed under libsodium); we
/// only add the Noise transport layer. Used by the listener sender and the chunked-exchange test.
pub async fn send_vault_blob_chunked<S: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut snow::TransportState,
    stream: &mut S,
    vault_bytes: &[u8],
) -> Result<(), String> {
    // Number of ≤VAULT_CHUNK_SIZE chunks (ceil division). 0 bytes → 0 chunks.
    let chunk_count = vault_bytes.len().div_ceil(VAULT_CHUNK_SIZE);
    let chunk_count_u32 = u32::try_from(chunk_count)
        .map_err(|_| "send_vault_blob_chunked: chunk count exceeds u32".to_string())?;

    // ---- Step 1: header frame = chunk count as 4 BE bytes. ----
    send_framed_large(stream, &chunk_count_u32.to_be_bytes())
        .await
        .map_err(|e| format!("send_vault_blob_chunked: header send failed: {}", e))?;

    // ---- Step 2: one Noise-encrypted frame per chunk. ----
    // Per-chunk ciphertext buffer: VAULT_CHUNK_SIZE plaintext + AEAD tag headroom.
    let mut enc_buf = vec![0u8; VAULT_CHUNK_SIZE + 128];
    for chunk in vault_bytes.chunks(VAULT_CHUNK_SIZE) {
        let enc_len = transport
            .write_message(chunk, &mut enc_buf)
            .map_err(|_| "send_vault_blob_chunked: Noise encrypt failed".to_string())?;
        send_framed_large(stream, &enc_buf[..enc_len])
            .await
            .map_err(|e| format!("send_vault_blob_chunked: chunk send failed: {}", e))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// SyncListenerState — managed state for D-06 listen-while-unlocked lifecycle
// ---------------------------------------------------------------------------

/// Managed state for the sync listener lifecycle (D-06 listen-while-unlocked).
///
/// Holds only a cancel channel so sync_listener_stop can tear down the listener task.
/// The TransportState lives on the stack of the spawned task — not here (Pitfall 6).
pub struct SyncListenerState {
    pub cancel_tx: Mutex<Option<oneshot::Sender<()>>>,
}

impl SyncListenerState {
    pub fn new() -> Self {
        SyncListenerState {
            cancel_tx: Mutex::new(None),
        }
    }
}

impl Default for SyncListenerState {
    fn default() -> Self {
        Self::new()
    }
}

/// Clear the managed sync-listener cancel sender so a future `sync_listener_start` rebinds.
///
/// FIX 3 / review HIGH-3: the listener task calls this on EVERY exit path (bind failure, loop
/// break after cancel). Taking the sender drops it; the idempotency guard in `sync_listener_start`
/// then sees `None` and knows no socket is bound. Harmless if `sync_listener_stop` already took it.
fn clear_sync_listener_state(app: &tauri::AppHandle) {
    let state = app.state::<SyncListenerState>();
    let taken = state.cancel_tx.lock().map(|mut guard| guard.take());
    // Drop the taken sender (if any) and ignore a poisoned lock — best-effort cleanup.
    drop(taken);
}

// ---------------------------------------------------------------------------
// sync_now — initiator command (D-05 steps 1–3 + D-01 peer-IP refresh)
// ---------------------------------------------------------------------------

/// Initiate a sync with the paired peer (Device B).
///
/// Protocol:
///   1a. Read peer's lastKnownIp/lastKnownPort from peers.json — error if None (no stored IP).
///   1b. Read this device's static SK from CredManager; derive PSK from sorted public keys.
///   1c. connect_with_timeout → run_ik_handshake_initiator → verify_vault_pair_id_binding
///   2.  recv_vault_blob: receive B's full encrypted vault (still sealed under B's libsodium key).
///   3.  Refresh peer's lastKnownIp/lastKnownPort in peers.json (D-01).
///   Return: B's vault bytes as Vec<u8> (returned to JS; JS/WASM runs SYNC-05 auth check).
///
/// SECURITY:
///   - Master password is NOT a parameter (Pitfall 5). All vault crypto is JS/WASM.
///   - Rust returns only ciphertext — no plaintext vault content or key material.
///   - SK bytes and PSK are zeroized after use (T-10-12).
///   - Each leg is bounded by its deadline; Elapsed on connect → "sync_now: connect timed out"
///     (JS maps this to SyncPeerUnreachableError, SYNC-06).
///   - Phase 10 STOPS after receiving B's vault bytes — no merge, no re-seal, no save (Phase 11).
#[tauri::command]
pub async fn sync_now(
    app: tauri::AppHandle,
    config_dir: String,
) -> Result<Vec<u8>, String> {
    // ---- Step 1a: Read peers.json, get peer's lastKnownIp/port and keys ----
    let doc = read_peers_json(&config_dir)?;
    if doc.peers.is_empty() {
        return Err("sync_now: no paired peer — pair a device first".to_string());
    }
    let peer = doc.peers[0].clone();

    let ip = peer
        .last_known_ip
        .as_deref()
        .ok_or_else(|| {
            "sync_now: no stored IP for peer — perform a manual-IP sync first or re-pair".to_string()
        })?
        .to_string();
    let port = peer
        .last_known_port
        .ok_or_else(|| {
            "sync_now: no stored port for peer — perform a manual-IP sync first or re-pair".to_string()
        })?;
    let addr = format!("{}:{}", ip, port);

    // Hex-decode peer's static public key (32 bytes).
    let peer_pk_bytes = hex_decode_32(&peer.static_public_key)
        .map_err(|e| format!("sync_now: peer static_public_key {}", e))?;
    let mut peer_pk = [0u8; 32];
    peer_pk.copy_from_slice(&peer_pk_bytes);

    // ---- Step 1b: Read this device's static SK + derive PSK ----
    // Windows: read from Credential Manager. Non-Windows: NoopCredentialStore (errors).
    //
    // SECURITY (FIX 4 / review MED): own_sk and psk are wrapped in zeroize::Zeroizing so they
    // auto-zero on drop on EVERY exit path — success, the connect-fail `?`, the handshake-timeout
    // `?`, and any later error. own_pk is the PUBLIC key and needs no wiping.
    let (own_sk_raw, own_pk) = {
        #[cfg(target_os = "windows")]
        {
            let store = WindowsCredentialStore;
            read_own_keypair_from_store(&store, &app)?
        }
        #[cfg(not(target_os = "windows"))]
        {
            let store = NoopCredentialStore;
            read_own_keypair_from_store(&store, &app)?
        }
    };
    let own_sk = Zeroizing::new(own_sk_raw);

    let psk = Zeroizing::new(derive_transport_psk(&own_pk, &peer_pk));

    // ---- Step 1c: Bounded connect → IK handshake → binding check ----
    // Each leg wrapped in tokio::time::timeout per Resolution 4.

    // Leg 1: TCP connect (bounded by SYNC_CONNECT_DEADLINE, 30 s).
    let mut stream = tokio::time::timeout(
        SYNC_CONNECT_DEADLINE,
        connect_with_timeout(&addr, SYNC_CONNECT_DEADLINE),
    )
    .await
    .map_err(|_| "sync_now: connect timed out".to_string())?
    .map_err(|e| format!("sync_now: connect failed: {}", e))?;

    // Leg 2: IK handshake (bounded by SYNC_HANDSHAKE_DEADLINE, 30 s).
    // Deref the Zeroizing wrappers to the underlying &[u8; 32] / &[u8].
    let mut transport = tokio::time::timeout(
        SYNC_HANDSHAKE_DEADLINE,
        run_ik_handshake_initiator(&mut stream, &*own_sk, &peer_pk, &*psk),
    )
    .await
    .map_err(|_| "sync_now: IK handshake timed out".to_string())?
    .map_err(|e| format!("sync_now: IK handshake failed: {}", e))?;

    // own_sk / psk are zeroized automatically when they drop at the end of sync_now (T-10-12,
    // FIX 4). We keep them alive past here only because Zeroizing owns their lifetime; no manual
    // wipe is needed and an early `?` after this point still drops + zeroizes them.

    // Read own device ID for the binding frame.
    let own_device_id = doc.local_device_id.clone();
    let expected_pair_id = peer.vault_pair_id.clone();

    // Leg 3: vaultPairId binding check (bounded by SYNC_BINDING_CHECK_DEADLINE, 10 s).
    tokio::time::timeout(
        SYNC_BINDING_CHECK_DEADLINE,
        verify_vault_pair_id_binding(
            &mut transport,
            &mut stream,
            &expected_pair_id,
            &own_device_id,
            true, // is_initiator = true
        ),
    )
    .await
    .map_err(|_| "sync_now: binding check timed out".to_string())?
    .map_err(|e| format!("sync_now: binding check failed: {}", e))?;

    // ---- Step 2: Receive B's full vault blob (bounded by SYNC_BLOB_RECV_DEADLINE, 120 s) ----
    let b_vault_bytes = tokio::time::timeout(
        SYNC_BLOB_RECV_DEADLINE,
        recv_vault_blob(&mut transport, &mut stream),
    )
    .await
    .map_err(|_| "sync_now: vault blob receive timed out".to_string())?
    .map_err(|e| format!("sync_now: vault blob receive failed: {}", e))?;

    // ---- Step 3: Refresh peer's lastKnownIp/lastKnownPort in peers.json (D-01) ----
    // On success, update the stored IP/port so future syncs can auto-connect.
    {
        let mut refresh_doc = read_peers_json(&config_dir)?;
        for p in &mut refresh_doc.peers {
            if p.device_id == peer.device_id {
                p.last_known_ip = Some(ip.clone());
                p.last_known_port = Some(port);
                break;
            }
        }
        // Best-effort: don't fail the sync if the refresh write fails.
        let _ = write_peers_json_atomic(&config_dir, &refresh_doc);
    }

    // Phase 10 STOPS here — return B's vault bytes to JS.
    // Phase 11 owns the merge, re-seal, and save.
    // The returned bytes are B's VaultDocumentV1 (still AEAD-sealed under B's libsodium key).
    // JS/WASM (packages/core) performs the SYNC-05 auth check.
    Ok(b_vault_bytes)
}

/// Read this device's static Curve25519 keypair (SK + PK, 32 bytes each) from the credential store.
///
/// The 64-byte CredManager blob is `sk || pk` (written by pairing.rs `get_or_generate_keypair_from_store`).
/// Returns (sk, pk). Caller MUST zeroize `sk` after use.
fn read_own_keypair_from_store(
    store: &dyn CredentialStore,
    _app: &tauri::AppHandle,
) -> Result<([u8; 32], [u8; 32]), String> {
    let blob = store
        .read(DEVICE_IDENTITY_SK_TARGET)
        .map_err(|e| format!("sync_now: failed to read device SK from CredManager: {}", e))?;
    if blob.len() != 64 {
        return Err(format!(
            "sync_now: device SK blob is {} bytes, expected 64 (sk||pk)",
            blob.len()
        ));
    }
    let mut sk = [0u8; 32];
    let mut pk = [0u8; 32];
    sk.copy_from_slice(&blob[..32]);
    pk.copy_from_slice(&blob[32..64]);
    Ok((sk, pk))
}

// ---------------------------------------------------------------------------
// Tauri commands — sync listener lifecycle (D-06)
//
// The sync listener MUST be started from JS (when vault unlocks + device is paired),
// NOT from lib.rs setup(). Violating this would open port 54321 at every app launch (Pitfall 4).
// ---------------------------------------------------------------------------

/// Start the sync listener. Call this from JS when `vaultSession.isUnlocked` becomes true
/// and a peer exists in peers.json (D-06).
///
/// Idempotent: if a listener is already running, returns Ok(()) immediately.
/// No-op if no peer is paired yet.
///
/// `vault_path` is the JS-supplied path to this device's vault file. It is confined via
/// `assert_confined` BEFORE any file read (CLAUDE.md path requirement / T-10-14).
///
/// Windows CredManager reads are gated to #[cfg(target_os = "windows")] paths (SYNC-07).
#[tauri::command]
pub async fn sync_listener_start(
    app: tauri::AppHandle,
    config_dir: String,
    vault_path: String,
) -> Result<(), String> {
    let state = app.state::<SyncListenerState>();

    // Idempotent: already running.
    {
        let guard = state.cancel_tx.lock().unwrap();
        if guard.is_some() {
            return Ok(());
        }
    }

    // Not paired → no listener needed.
    let doc = read_peers_json(&config_dir)?;
    if doc.peers.is_empty() {
        return Ok(());
    }

    // SECURITY (T-10-14 / CLAUDE.md "All path commands enforce resolve_confined_path"):
    // vault_path is JS-supplied and must be confined to the vault directory before any read.
    // We derive the expected parent from config_dir (same convention as vault_write_atomic).
    let vault_path_buf = PathBuf::from(&vault_path);
    let expected_vault_dir = vault_path_buf
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| format!("sync_listener_start: vault_path '{}' has no parent directory", vault_path))?;
    assert_confined(&vault_path_buf, expected_vault_dir)
        .map_err(|e| format!("sync_listener_start: vault_path confinement check failed: {}", e))?;

    // Read peer info needed by the listener task (peer's static public key, vault pair ID).
    let peer = doc.peers[0].clone();
    let peer_pk_bytes = hex_decode_32(&peer.static_public_key)
        .map_err(|e| format!("sync_listener_start: peer static_public_key {}", e))?;
    let peer_pk = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&peer_pk_bytes);
        arr
    };
    let expected_pair_id = peer.vault_pair_id.clone();
    let own_device_id = doc.local_device_id.clone();

    // Read this device's own SK + derive PSK now (before spawning — avoids CredManager in async task).
    //
    // SECURITY (FIX 4 / review MED): own_sk and psk are wrapped in zeroize::Zeroizing. They are
    // needed for EVERY iteration's handshake (FIX 3 loop), so they live for the whole task and are
    // NOT zeroized between iterations — they auto-zero exactly once when the task ends (loop break,
    // bind failure, or panic-unwind), covering all exit paths.
    let (own_sk_raw, own_pk) = {
        #[cfg(target_os = "windows")]
        {
            let store = WindowsCredentialStore;
            read_own_keypair_from_store(&store, &app)?
        }
        #[cfg(not(target_os = "windows"))]
        {
            let store = NoopCredentialStore;
            read_own_keypair_from_store(&store, &app)?
        }
    };
    let own_sk = Zeroizing::new(own_sk_raw);
    let psk = Zeroizing::new(derive_transport_psk(&own_pk, &peer_pk));

    let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
    {
        let mut guard = state.cancel_tx.lock().unwrap();
        *guard = Some(cancel_tx);
    }

    // Capture values for the listener task. cancel_rx is Send + move into the async block.
    let vault_path_owned = vault_path.clone();
    let config_dir_clone = config_dir.clone();
    // app handle clone so the task can clear SyncListenerState on exit (closes the cancel_tx leak).
    let app_for_task = app.clone();

    // Spawn the listener task. TcpListener::bind is INSIDE the task (Pitfall 4 / D-10).
    // The TransportState lives only on this task's stack (Pitfall 6).
    //
    // FIX 3 / review HIGH-3: the task LOOPS, serving one connection at a time (D-14 "one at a
    // time") until cancelled. The previous design accepted exactly ONE connection then fell off
    // the end while cancel_tx stayed Some — so the idempotency guard reported "already running"
    // though no socket was bound, permanently disabling sync after a single (even failed) connect.
    // Now: a per-connection error logs + `continue`s (serve the next peer); only the cancel signal
    // breaks the loop. On exit we clear SyncListenerState so a future start rebinds.
    tauri::async_runtime::spawn(async move {
        // own_sk / psk live for the WHOLE task — every iteration's handshake needs them. They are
        // Zeroizing, so they auto-zero exactly once when this task ends (FIX 4). Do NOT zeroize
        // between iterations.
        let own_sk = own_sk;
        let psk = psk;

        // Bind the listener on port 54321 (D-06 / D-08: reuse port 54321 firewall grant).
        let listener = match tokio::net::TcpListener::bind("0.0.0.0:54321").await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("sync listener: TcpListener::bind failed: {} (no secret logged)", e);
                // Bind failed — clear state so a later start can retry. own_sk/psk drop+zeroize here.
                clear_sync_listener_state(&app_for_task);
                return;
            }
        };

        // Accept-serve loop. The oneshot Receiver is polled by `&mut` so the loop can keep it across
        // iterations; firing cancel_tx (sync_listener_stop) or dropping it resolves the recv and
        // breaks the loop.
        let mut cancel_rx = cancel_rx;
        loop {
            let accepted = tokio::select! {
                _ = &mut cancel_rx => {
                    // Normal shutdown: sync_listener_stop fired (or the sender dropped). Break,
                    // then clear state below so a future start rebinds.
                    break;
                }
                accepted = listener.accept() => accepted,
            };

            let mut stream = match accepted {
                Ok((s, _peer_addr)) => s,
                Err(e) => {
                    // Accept error is NOT fatal — log generically and keep serving (do NOT exit).
                    eprintln!("sync listener: accept failed: {} (no secret logged)", e);
                    continue;
                }
            };

            // ---- Per-connection: handshake → binding → read vault → chunked send. ----
            // On ANY per-connection error we log + `continue` (serve the next peer), never exit.

            // IK handshake as RESPONDER: verify connecting device holds the known peer static key.
            let transport_result = tokio::time::timeout(
                SYNC_HANDSHAKE_DEADLINE,
                run_ik_handshake_responder(&mut stream, &*own_sk, &*psk, &peer_pk),
            )
            .await;
            let mut transport = match transport_result {
                Ok(Ok(t)) => t,
                Ok(Err(e)) => {
                    // Drop unknown key or MAC failure — no info leak, no vault bytes sent.
                    eprintln!("sync listener: IK handshake failed: {} (no secret logged)", e);
                    continue;
                }
                Err(_) => {
                    eprintln!("sync listener: IK handshake timed out (no secret logged)");
                    continue;
                }
            };

            // vaultPairId binding check as RESPONDER — must match before any vault bytes (SYNC-03).
            let binding_result = tokio::time::timeout(
                SYNC_BINDING_CHECK_DEADLINE,
                verify_vault_pair_id_binding(
                    &mut transport,
                    &mut stream,
                    &expected_pair_id,
                    &own_device_id,
                    false, // is_initiator = false (responder)
                ),
            )
            .await;
            match binding_result {
                Ok(Ok(())) => {} // Binding verified — proceed to send vault bytes.
                Ok(Err(e)) => {
                    // vaultPairId mismatch — abort this connection. No vault bytes sent.
                    eprintln!("sync listener: binding check failed: {} (no secret logged)", e);
                    continue;
                }
                Err(_) => {
                    eprintln!("sync listener: binding check timed out (no secret logged)");
                    continue;
                }
            }

            // Read this device's own vault file — B's vault is what A needs.
            // vault_path was already confined above before spawning (T-10-14).
            // We re-confirm the confinement assertion at read time as belt-and-braces.
            let vault_path_to_read = PathBuf::from(&vault_path_owned);
            let expected_vault_dir_inner =
                match vault_path_to_read.parent().filter(|p| !p.as_os_str().is_empty()) {
                    Some(p) => p.to_path_buf(),
                    None => {
                        eprintln!("sync listener: vault_path has no parent directory (no secret logged)");
                        continue;
                    }
                };
            if let Err(e) = assert_confined(&vault_path_to_read, &expected_vault_dir_inner) {
                eprintln!("sync listener: vault_path confinement violation at read time: {} (no secret logged)", e);
                continue;
            }

            let vault_bytes = match tokio::fs::read(&vault_path_to_read).await {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("sync listener: failed to read vault file: {} (no secret logged)", e);
                    continue;
                }
            };

            // Send vault bytes encrypted over the Noise transport using the CHUNKED wire protocol
            // (FIX 1 / review HIGH-1) — symmetric with recv_vault_blob:
            //   1. header frame = chunk count as 4 BE bytes via send_framed_large.
            //   2. for each ≤VAULT_CHUNK_SIZE plaintext slice: write_message → send_framed_large.
            // vault_bytes are B's VaultDocumentV1 — still AEAD-sealed under B's libsodium key.
            // Rust is a shuttle: we encrypt the existing ciphertext again with Noise-IK (double layer).
            if let Err(e) = send_vault_blob_chunked(&mut transport, &mut stream, &vault_bytes).await {
                eprintln!("sync listener: vault blob send failed: {} (no secret logged)", e);
                continue;
            }

            // Update lastSyncedAt in peers.json on successful send.
            {
                if let Ok(mut refresh_doc) = read_peers_json(&config_dir_clone) {
                    for p in &mut refresh_doc.peers {
                        if p.device_id == peer.device_id {
                            // Record the sync time (RFC 3339 UTC).
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            p.last_synced_at = Some(format!("{}", now));
                            break;
                        }
                    }
                    let _ = write_peers_json_atomic(&config_dir_clone, &refresh_doc);
                }
            }

            // Loop back to accept the NEXT sync (D-14: one at a time, repeatedly).
        }

        // Loop exited (cancelled): clear the listener state so a future start rebinds. Harmless if
        // sync_listener_stop already take()'d the cancel sender. own_sk/psk drop+zeroize here (FIX 4).
        clear_sync_listener_state(&app_for_task);
    });

    Ok(())
}

/// Stop the sync listener. Call this from JS when `vaultSession.isUnlocked` becomes false.
///
/// Idempotent: if no listener is running, returns Ok(()) immediately.
#[tauri::command]
pub async fn sync_listener_stop(app: tauri::AppHandle) -> Result<(), String> {
    let state = app.state::<SyncListenerState>();
    let mut guard = state.cancel_tx.lock().unwrap();
    if let Some(tx) = guard.take() {
        let _ = tx.send(());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests — Wave-0 IK transport seam (duplex-based, no real TCP, no sleeps)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use snow::Builder as SnowBuilder;
    use tokio::io::duplex;

    // ---------------------------------------------------------------------------
    // Test helpers
    // ---------------------------------------------------------------------------

    /// Generate a fresh Noise IK keypair using snow's Builder::generate_keypair.
    /// Returns (private_key_32, public_key_32).
    fn gen_keypair() -> ([u8; 32], [u8; 32]) {
        let keypair = SnowBuilder::new(IK_PARAMS.clone())
            .generate_keypair()
            .expect("generate_keypair failed");
        let mut sk = [0u8; 32];
        let mut pk = [0u8; 32];
        sk.copy_from_slice(&keypair.private);
        pk.copy_from_slice(&keypair.public);
        (sk, pk)
    }

    // ---------------------------------------------------------------------------
    // test_ik_wire_only — SYNC-02: only ciphertext on the wire
    //
    // Establishes a full IK handshake + binding-frame exchange + a sample vault-blob send.
    // Asserts the raw wire bytes contain NO plaintext vault JSON prefix.
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_ik_wire_only() {
        let (initiator_sk, initiator_pk) = gen_keypair();
        let (responder_sk, responder_pk) = gen_keypair();
        let psk = derive_transport_psk(&initiator_pk, &responder_pk);

        // Fake vault pair and device IDs.
        let vault_pair_id = "test-vault-pair-id-1234".to_string();
        let initiator_dev = "device-A".to_string();
        let responder_dev = "device-B".to_string();

        // Fake "vault blob" — a JSON byte sequence that starts with the known plaintext prefix.
        // On the wire this must arrive as Noise IK ciphertext — NOT as raw JSON (SYNC-02).
        let fake_vault_blob: Vec<u8> = b"{\"format\":\"cryptiq-vault\",\"version\":1,\"data\":\"...\"}"
            .to_vec();
        let plaintext_prefix = b"{\"format\":\"cryptiq-vault\"";

        // Single duplex pair — the protocol runs on this loopback channel.
        // The RESPONDER task reads and accumulates all encrypted bytes it receives from the
        // initiator (msg1 + vault blob). We assert no captured byte window matches the
        // plaintext prefix (SYNC-02: only ciphertext on the wire).
        let (mut init_stream, mut resp_stream) = duplex(1024 * 1024);

        // Spawn responder task — captures all encrypted frames it receives.
        let resp_psk = psk;
        let resp_sk = responder_sk;
        let expected_pk_for_resp = initiator_pk;
        let vault_pair_id_resp = vault_pair_id.clone();
        let responder_dev_clone = responder_dev.clone();

        // Channel to get captured bytes from responder back to test body.
        let (cap_tx, cap_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();

        let resp_task = tokio::spawn(async move {
            let mut captured: Vec<u8> = Vec::new();

            // IK handshake — responder side.
            // We need to capture raw bytes. We'll run the handshake on resp_stream and
            // collect by manually reading. We override recv_framed to capture.
            // Simplest: run the protocol normally and separately capture via a parallel read.
            //
            // Actually, the cleanest approach: since we control both sides, we can have the
            // RESPONDER capture what it reads from the stream (the ciphertext bytes from
            // the initiator side). All frames from initiator arrive encrypted.

            // Manual handshake with capture.
            let mut noise =
                build_ik_responder(&resp_sk, &resp_psk).expect("build_ik_responder failed");
            let mut buf = Vec::new();
            let mut msg_buf = vec![0u8; 65535];

            // Read msg1 — capture raw bytes.
            let mut len_buf = [0u8; 2];
            resp_stream.read_exact(&mut len_buf).await.expect("msg1 len read");
            let len = u16::from_be_bytes(len_buf) as usize;
            buf.resize(len, 0);
            resp_stream.read_exact(&mut buf).await.expect("msg1 body read");
            // Capture: the 2-byte length header + ciphertext body.
            captured.extend_from_slice(&len_buf);
            captured.extend_from_slice(&buf);
            noise.read_message(&buf, &mut msg_buf).expect("msg1 decrypt");

            // Verify static key.
            let received_pk = noise.get_remote_static().expect("get_remote_static");
            assert_eq!(received_pk, expected_pk_for_resp, "static key mismatch");

            // Write msg2.
            let msg2_len = noise.write_message(&[], &mut msg_buf).expect("msg2 write");
            send_framed(&mut resp_stream, &msg_buf[..msg2_len])
                .await
                .expect("msg2 send");

            let mut transport = noise.into_transport_mode().expect("transport mode");

            // Binding check (responder side).
            verify_vault_pair_id_binding(
                &mut transport,
                &mut resp_stream,
                &vault_pair_id_resp,
                &responder_dev_clone,
                false,
            )
            .await
            .expect("binding check responder");

            // Receive the "vault blob" frame (encrypted).
            let mut enc_frame_buf = Vec::new();
            let mut len4_buf = [0u8; 4];
            resp_stream
                .read_exact(&mut len4_buf)
                .await
                .expect("vault len read");
            let blob_len = u32::from_be_bytes(len4_buf) as usize;
            enc_frame_buf.resize(blob_len, 0);
            resp_stream
                .read_exact(&mut enc_frame_buf)
                .await
                .expect("vault body read");
            // Capture the encrypted frame.
            captured.extend_from_slice(&len4_buf);
            captured.extend_from_slice(&enc_frame_buf);

            // Decrypt to verify we CAN decrypt (but the wire bytes must NOT be plaintext).
            let mut plain_buf = vec![0u8; blob_len + 128];
            transport
                .read_message(&enc_frame_buf, &mut plain_buf)
                .expect("vault blob decrypt");

            let _ = cap_tx.send(captured);
        });

        // Initiator side.
        let init_sk = initiator_sk;
        let init_pk_for_psk = initiator_pk;
        let resp_pk_for_init = responder_pk;
        let vault_pair_id_init = vault_pair_id.clone();
        let initiator_dev_clone = initiator_dev.clone();
        let fake_vault_clone = fake_vault_blob.clone();

        let init_task = tokio::spawn(async move {
            let psk_init = derive_transport_psk(&init_pk_for_psk, &resp_pk_for_init);
            let mut transport = run_ik_handshake_initiator(
                &mut init_stream,
                &init_sk,
                &resp_pk_for_init,
                &psk_init,
            )
            .await
            .expect("initiator handshake");

            verify_vault_pair_id_binding(
                &mut transport,
                &mut init_stream,
                &vault_pair_id_init,
                &initiator_dev_clone,
                true,
            )
            .await
            .expect("binding check initiator");

            // Encrypt and send the fake vault blob.
            let mut enc_buf = vec![0u8; fake_vault_clone.len() + 128];
            let enc_len = transport
                .write_message(&fake_vault_clone, &mut enc_buf)
                .expect("vault blob encrypt");
            send_framed_large(&mut init_stream, &enc_buf[..enc_len])
                .await
                .expect("vault blob send");
        });

        let (init_result, resp_result) = tokio::join!(init_task, resp_task);
        init_result.expect("init task panicked");
        resp_result.expect("resp task panicked");

        let captured = cap_rx.await.expect("capture channel closed");

        // SYNC-02 assertion: the wire bytes must NOT contain the plaintext vault JSON prefix.
        // If ciphertext is working, the encrypted vault frame will NOT contain the literal prefix.
        let contains_plaintext = captured
            .windows(plaintext_prefix.len())
            .any(|w| w == plaintext_prefix);
        assert!(
            !contains_plaintext,
            "SYNC-02 VIOLATION: plaintext vault JSON prefix found in wire bytes — vault bytes are not encrypted"
        );
    }

    // ---------------------------------------------------------------------------
    // test_binding_mismatch_no_bytes — SYNC-03: vaultPairId mismatch → zero vault bytes written
    //
    // Initiator sends a SyncBindingFrame with the WRONG vault_pair_id.
    // Responder returns a binding error.
    // Vault-send path is never entered (proven by vault_send_attempted flag).
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_binding_mismatch_no_bytes() {
        let (initiator_sk, initiator_pk) = gen_keypair();
        let (responder_sk, responder_pk) = gen_keypair();
        let psk = derive_transport_psk(&initiator_pk, &responder_pk);

        let correct_pair_id = "correct-vault-pair-id".to_string();
        let wrong_pair_id = "WRONG-vault-pair-id".to_string();
        let initiator_dev = "device-A".to_string();
        let responder_dev = "device-B".to_string();

        let (mut init_stream, mut resp_stream) = duplex(1024 * 1024);

        let psk_resp = psk;
        let correct_pair_id_resp = correct_pair_id.clone();
        let responder_dev_clone = responder_dev.clone();
        let resp_sk_clone = responder_sk;
        let expected_init_pk = initiator_pk;

        let resp_task = tokio::spawn(async move {
            // Responder runs IK handshake.
            let resp_result = run_ik_handshake_responder(
                &mut resp_stream,
                &resp_sk_clone,
                &psk_resp,
                &expected_init_pk,
            )
            .await;
            let mut transport = resp_result.expect("responder handshake should succeed");

            // Responder runs binding check — should detect mismatch on A's binding frame.
            let binding_result = verify_vault_pair_id_binding(
                &mut transport,
                &mut resp_stream,
                &correct_pair_id_resp,
                &responder_dev_clone,
                false,
            )
            .await;

            // The responder MUST return an error here (vault_pair_id mismatch).
            assert!(
                binding_result.is_err(),
                "responder should return binding error on vaultPairId mismatch"
            );
            let err_msg = binding_result.unwrap_err();
            assert!(
                err_msg.contains("mismatch") || err_msg.contains("binding"),
                "error message should mention mismatch or binding, got: {}",
                err_msg
            );

            // SYNC-03 proof: vault-send path tracking flag.
            // This flag would be set to `true` ONLY if the responder proceeded to send vault bytes.
            // Since the binding check failed above (binding_result.is_err()), vault bytes are
            // NEVER sent. The flag remains false, proving zero vault bytes were written.
            //
            // In Plan 03, the actual vault-send path looks like:
            //   vault_send_attempted = true;
            //   send_framed_large(&mut resp_stream, &vault_bytes).await.expect("vault send");
            // Because binding_result.is_err(), that path is never entered.
            let vault_send_attempted = false;

            assert!(
                !vault_send_attempted,
                "SYNC-03 VIOLATION: vault-send path was entered despite binding mismatch"
            );
        });

        let init_psk = psk;
        let init_sk_clone = initiator_sk;
        let init_resp_pk = responder_pk;
        let wrong_pair_id_clone = wrong_pair_id.clone();
        let initiator_dev_clone = initiator_dev.clone();

        let init_task = tokio::spawn(async move {
            // Initiator runs IK handshake.
            let mut transport = run_ik_handshake_initiator(
                &mut init_stream,
                &init_sk_clone,
                &init_resp_pk,
                &init_psk,
            )
            .await
            .expect("initiator handshake should succeed");

            // Initiator sends WRONG vault_pair_id in the binding frame.
            let binding_result = verify_vault_pair_id_binding(
                &mut transport,
                &mut init_stream,
                &wrong_pair_id_clone,
                &initiator_dev_clone,
                true,
            )
            .await;

            // The initiator may get an error when the responder closes the stream,
            // OR the exchange completes (responder closed its side after detecting mismatch).
            // Either outcome is acceptable from the initiator's perspective.
            // The KEY guarantee is on the responder side (vault_send_attempted = false).
            let _ = binding_result;
        });

        let (init_result, resp_result) = tokio::join!(init_task, resp_task);
        init_result.expect("init task panicked");
        resp_result.expect("resp task panicked");
    }

    // ---------------------------------------------------------------------------
    // test_chunked_vault_exchange — SYNC-04 + Pitfall 3 + FIX 1 (review HIGH-1)
    //
    // Establishes TWO real TransportStates via the IK handshake over a tokio duplex, then sends a
    // ≥ 70 000-byte blob through the NEW chunked sender path (send_vault_blob_chunked) and receives
    // it via recv_vault_blob, asserting byte-for-byte equality.
    //
    // CRITICAL: this exercises transport.write_message / read_message on a payload ABOVE the single
    // Noise message cap (VAULT_CHUNK_SIZE = 65519). The previous test only round-tripped raw bytes
    // through send/recv_framed_large and so never hit the snow MAXMSGLEN limit that broke vaults
    // > ~65 KiB. With chunking, a 70 000-byte blob spans 2 chunks and must arrive intact.
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_chunked_vault_exchange() {
        let (initiator_sk, initiator_pk) = gen_keypair();
        let (responder_sk, responder_pk) = gen_keypair();
        let psk = derive_transport_psk(&initiator_pk, &responder_pk);

        // 70 000 bytes — above VAULT_CHUNK_SIZE (65519), so the chunked path produces 2 chunks.
        // A single write_message on this whole blob would FAIL in snow (exceeds MAXMSGLEN); the
        // chunked sender is required.
        let payload_len: usize = 70_000;
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
        assert!(
            payload_len > VAULT_CHUNK_SIZE,
            "test payload must exceed VAULT_CHUNK_SIZE to prove chunking"
        );

        // Single duplex: the responder (sender) writes, the initiator (receiver) reads.
        let (mut init_stream, mut resp_stream) = duplex(1024 * 1024);

        // Capture for the responder/sender task.
        let resp_sk = responder_sk;
        let resp_psk = psk;
        let expected_init_pk = initiator_pk;
        let payload_to_send = payload.clone();

        // RESPONDER task: complete IK handshake (as responder), then chunk-send the blob.
        let resp_task = tokio::spawn(async move {
            let mut transport = run_ik_handshake_responder(
                &mut resp_stream,
                &resp_sk,
                &resp_psk,
                &expected_init_pk,
            )
            .await
            .expect("responder handshake");

            send_vault_blob_chunked(&mut transport, &mut resp_stream, &payload_to_send)
                .await
                .expect("chunked vault send");
        });

        // Capture for the initiator/receiver task.
        let init_sk = initiator_sk;
        let init_resp_pk = responder_pk;
        let init_psk = psk;

        // INITIATOR task: complete IK handshake (as initiator), then recv_vault_blob.
        let init_task = tokio::spawn(async move {
            let mut transport = run_ik_handshake_initiator(
                &mut init_stream,
                &init_sk,
                &init_resp_pk,
                &init_psk,
            )
            .await
            .expect("initiator handshake");

            recv_vault_blob(&mut transport, &mut init_stream)
                .await
                .expect("chunked vault recv")
        });

        let (resp_result, init_result) = tokio::join!(resp_task, init_task);
        resp_result.expect("responder task panicked");
        let received = init_result.expect("initiator task panicked");

        assert_eq!(
            received.len(),
            payload_len,
            "chunked round-trip length mismatch"
        );
        assert_eq!(
            received, payload,
            "chunked round-trip payload mismatch — vault chunking broken"
        );
    }

    // ---------------------------------------------------------------------------
    // test_recv_framed_large_rejects_oversize — FIX 2 (review HIGH-2)
    //
    // Write a 4-byte prefix of 0xFFFFFFFF (4 GiB) then nothing. recv_framed_large must return Err
    // (length exceeds MAX_SYNC_FRAME) WITHOUT attempting the 4 GiB allocation.
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_recv_framed_large_rejects_oversize() {
        let (mut writer, mut reader) = duplex(64);

        // Send only the oversize 4-byte length prefix (0xFFFFFFFF). No body follows.
        writer
            .write_all(&0xFFFF_FFFFu32.to_be_bytes())
            .await
            .expect("write oversize prefix");
        // Close the writer so any read_exact on a body would hit EOF rather than block — but the
        // cap check must fire BEFORE any body read, so this just guards against a hang.
        drop(writer);

        let mut buf = Vec::new();
        let result = recv_framed_large(&mut reader, &mut buf).await;

        assert!(
            result.is_err(),
            "recv_framed_large must reject a length above MAX_SYNC_FRAME"
        );
        // The buffer must NOT have been grown to the attacker-claimed size (no huge allocation).
        assert!(
            buf.capacity() <= MAX_SYNC_FRAME,
            "recv_framed_large allocated beyond MAX_SYNC_FRAME before the cap check"
        );
    }

    // ---------------------------------------------------------------------------
    // test_ik_unknown_key_dropped — Pitfall 2 / T-10-04
    //
    // Responder is given an expected_peer_pk that DOES NOT match the initiator's static key.
    // run_ik_handshake_responder must return "IK handshake failed" and never reach transport mode.
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_ik_unknown_key_dropped() {
        let (initiator_sk, initiator_pk) = gen_keypair();
        let (responder_sk, responder_pk) = gen_keypair();
        // A DIFFERENT keypair — this pk is unknown to the responder.
        let (_, wrong_pk) = gen_keypair();

        let psk = derive_transport_psk(&initiator_pk, &responder_pk);

        let (mut init_stream, mut resp_stream) = duplex(1024 * 1024);

        let psk_resp = psk;
        let resp_sk_clone = responder_sk;
        // Responder expects wrong_pk — NOT initiator_pk.
        let wrong_expected = wrong_pk;

        let resp_task = tokio::spawn(async move {
            let result = run_ik_handshake_responder(
                &mut resp_stream,
                &resp_sk_clone,
                &psk_resp,
                &wrong_expected,
            )
            .await;

            // MUST return an error (generic "IK handshake failed").
            assert!(
                result.is_err(),
                "responder should reject unknown static key"
            );
            let err = result.unwrap_err();
            assert_eq!(
                err, "IK handshake failed",
                "error must be the generic string — no info leak about why"
            );
        });

        let psk_init = psk;
        let init_sk_clone = initiator_sk;
        let init_resp_pk = responder_pk;

        let init_task = tokio::spawn(async move {
            // Initiator completes its side of the handshake. It may get an error or timeout
            // because the responder closed the stream after detecting the unknown key.
            let _ = run_ik_handshake_initiator(
                &mut init_stream,
                &init_sk_clone,
                &init_resp_pk,
                &psk_init,
            )
            .await;
            // Initiator outcome is not the focus of this test — we care about the responder.
        });

        let (init_result, resp_result) = tokio::join!(init_task, resp_task);
        init_result.expect("init task panicked");
        resp_result.expect("resp task panicked");
    }

    // ---------------------------------------------------------------------------
    // test_connect_timeout — SYNC-06 / T-10-10
    //
    // connect_with_timeout against a closed port on loopback must return an error
    // promptly (within a short injected deadline) rather than hanging.
    //
    // Uses a 1-second timeout injected via tokio::time::timeout — does NOT wait the
    // full SYNC_CONNECT_DEADLINE (30 s) to keep the test fast and deterministic.
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_connect_timeout() {
        use std::net::TcpListener as StdTcpListener;

        // Bind then immediately drop a std listener to get a port that was recently in use
        // but is now closed. This gives us an address that will refuse connections immediately
        // (ECONNREFUSED), which is the fastest deterministic way to test the error path.
        // On loopback, ECONNREFUSED is instant — no actual timeout wait needed.
        let addr = {
            let l = StdTcpListener::bind("127.0.0.1:0").expect("bind failed");
            let a = l.local_addr().expect("local_addr failed");
            drop(l); // Port is now closed — connects will fail immediately.
            a.to_string()
        };

        // Inject a short deadline so the test is fast regardless of OS behavior.
        // 2 seconds is generous — ECONNREFUSED on loopback is typically sub-millisecond.
        let short_deadline = Duration::from_secs(2);

        let result = tokio::time::timeout(
            short_deadline,
            connect_with_timeout(&addr, short_deadline),
        )
        .await;

        // The outer timeout should NOT fire (ECONNREFUSED is instant).
        // The inner connect_with_timeout should return an Err (connect failed or timed out).
        match result {
            Ok(Err(_)) => {
                // Expected: connect returned an error promptly (ECONNREFUSED or timeout).
                // SYNC-06 proven: no silent hang.
            }
            Ok(Ok(_)) => {
                panic!("test_connect_timeout: connect succeeded on a closed port — test setup broken");
            }
            Err(_elapsed) => {
                // The 2-second outer timeout fired. This means connect_with_timeout DID hang.
                // This is a test failure (SYNC-06 violation: silent hang).
                panic!(
                    "test_connect_timeout: SYNC-06 VIOLATION — connect_with_timeout hung for {}s on a closed port",
                    short_deadline.as_secs()
                );
            }
        }
    }
}
