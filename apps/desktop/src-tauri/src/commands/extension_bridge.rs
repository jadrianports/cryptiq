// apps/desktop/src-tauri/src/commands/extension_bridge.rs
//
// Phase 14 Plan 02 — always-on local named-pipe listener for the browser
// native-messaging bridge (BRIDGE-02). This is the APP-owned edge of the bridge:
// the `apps/native-host` sidecar (Plan 14-01) relays stdio <-> this pipe.
//
// Phase 15 Plan 03 — the SECURITY HEART of authenticated association: the TOFU
// `associate`/`associate-ok` handshake (bounded human approval + durable, hash-only
// persistence), `crypto_box` (SalsaBox) encryption on every subsequent `rpc`, the
// app-layer pairing-token verification carried INSIDE the box (constant-time hash
// compare, fail closed), and the directional protocol-version-mismatch message.
//
// Responsibilities:
//   PIPE_NAME                     — \\.\pipe\cryptiq-bridge, SAME literal as the sidecar (D-08)
//   CURRENT_PROTOCOL_VERSION      — versioned envelope gate (D-02)
//   MAX_BRIDGE_FRAME              — 1 MiB bound rejected BEFORE buffering (D-05)
//   BridgeEnvelope                — versioned typed envelope (D-01)
//   BridgeError                   — typed, single-source error enum (CLAUDE.md)
//   validate_envelope             — fail-closed protocolVersion check (D-02)
//   ExtensionBridgeState          — forward-compat managed-state stub (Phase 20 UX-05 kill-switch)
//   PendingAssociation/PendingAssociationMap — bounded (60s) TOFU approval wait, a SEPARATE lock
//                                    from the steady-state peer-lookup cache (Pitfall 4)
//   ExtensionPeerCache             — in-memory clientPublicKey -> {pairing_token_hash} lookup,
//                                    populated at association time, consulted on every `rpc`
//   process_associate/finalize_new_association/check_already_associated — TOFU core (Task 1)
//   encrypt_rpc_box/decrypt_rpc_box/verify_pairing_token — crypto_box + token-hash gate (Task 2)
//   recv_framed_bridge/send_framed_bridge — BIG-ENDIAN u32 length-prefixed pipe framing
//                                    (shared sidecar<->app pipe-channel contract; distinct from
//                                    Chrome's native-endian stdio framing used by the sidecar
//                                    on its OTHER side, browser<->sidecar)
//   run_extension_bridge_accept_loop — cancellable accept loop; spawned via
//                                    spawn_extension_bridge_listener from lib.rs .setup() (gated
//                                    on extensionBridgeEnabled) and the UX-05 start/stop commands
//   extension_bridge_enabled        — reads config.json's extensionBridgeEnabled kill-switch (D-04)
//   handle_bridge_connection      — per-connection: read envelope, validate, dispatch by msg_type
//
// Security invariants:
//   - reject_remote_clients(true) — pipe never accepts a network-origin client (D-03/T-14-05).
//   - protocolVersion mismatch fails closed with a typed, DIRECTIONAL error (D-02/D-05/T-14-07).
//   - Frame length is capped at MAX_BRIDGE_FRAME BEFORE any buffer allocation (D-05/T-14-08).
//   - The echo handler carries ZERO vault data by construction (D-04).
//   - No `rpc` dispatches to anything until BOTH a successful `crypto_box` open AND a
//     constant-time pairing-token-HASH match succeed (T-15-01/T-15-06, Pitfall 1) — arrival on
//     the pipe is never treated as proof of identity.
//   - The raw pairing token is NEVER written to app disk — only its BLAKE2b hash
//     (`extension_peers::hash_pairing_token`) is persisted (T-15-04). The raw token crosses the
//     wire exactly once, in the one-time plaintext `associate-ok` response.
//   - The TOFU `associate`/`associate-ok` exchange is plaintext by design (no shared secret
//     exists yet) — never encrypted, never carries the token in the outer envelope for any
//     OTHER message type.
//   - Every IO/framing/crypto error closes the connection cleanly with a typed response; the
//     accept loop never panics or hangs. The pending-approval wait never blocks other
//     connections (separate `Mutex`, Pitfall 4).
//   - Payloads are never logged (D-10) — any verbose diagnostic is lifecycle-only and dev-gated;
//     key bytes and the pairing token are never logged in any form.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use crypto_box::aead::{Aead, AeadCore, OsRng as BoxOsRng};
use crypto_box::{PublicKey as BoxPublicKey, SalsaBox, SecretKey as BoxSecretKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tauri::{Emitter, Manager};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::oneshot;

use super::extension_peers::{
    hash_pairing_token, read_extension_peers_json, revoke_extension_association,
    write_extension_peers_json_atomic, ExtensionPeerRecord, EXTENSION_IDENTITY_SK_TARGET,
};
#[cfg(test)]
use super::extension_peers::ExtensionPeersDoc;
use super::pairing::CredentialStore;
#[cfg(not(target_os = "windows"))]
use super::pairing::NoopCredentialStore;
#[cfg(target_os = "windows")]
use super::pairing::WindowsCredentialStore;

/// Bounded wait for a human Allow/Deny decision on a first-time `associate` request (Pitfall 4,
/// mirrors pairing.rs's 60s SAS-confirmation window). Applies ONLY to the one-time TOFU flow —
/// never to steady-state `rpc` traffic, which has no human-in-the-loop wait at all.
pub const ASSOCIATION_APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);

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
    /// Phase 15/T-15-01/Pitfall 1: an `rpc` arrived whose `clientPublicKey` has no persisted
    /// association (never approved, or since revoked) — NO dispatch, fail closed.
    NotAssociated,
    /// Phase 15/T-15-01/Pitfall 1: the `crypto_box` failed to open, OR it opened but the
    /// decrypted pairing token's hash did not constant-time-match the stored
    /// `pairing_token_hash` — NO dispatch, fail closed. Deliberately the SAME variant for both
    /// failure modes so a timing/behavior difference between "bad box" and "bad token" is never
    /// observable to an attacker.
    InvalidToken,
    /// Phase 15/Pitfall 4: a first-time `associate` was Denied by the human, or the 60s
    /// approval window elapsed with no decision — no association is persisted either way.
    AssociationDenied,
    /// Phase 16/D-09/XSEC-05: a vault-touching RPC (`match-origin`/`fill-entry`) arrived while
    /// there is no unlocked vault in the renderer. Carries NO data — fail closed.
    VaultLocked,
    /// Phase 16/V4: `fill-entry` was dispatched for an `entryId` that does not exist, or that
    /// exists but is soft-deleted (`deletedAt !== null`) — never trust an unvalidated id.
    RpcNotFound,
    /// Phase 16: the decrypted inner `{method, params}` named an unsupported/unknown method, or
    /// `params` was malformed for the given method.
    RpcInvalidRequest,
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
            BridgeError::NotAssociated => write!(f, "extension is not associated"),
            BridgeError::InvalidToken => write!(f, "crypto_box open or pairing-token check failed"),
            BridgeError::AssociationDenied => write!(f, "association was denied or timed out"),
            BridgeError::VaultLocked => write!(f, "vault is locked"),
            BridgeError::RpcNotFound => write!(f, "requested entry not found"),
            BridgeError::RpcInvalidRequest => write!(f, "unsupported or malformed rpc request"),
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
/// Copied (shape-only, renamed) from `sync.rs`'s `SyncListenerState`. Phase 20 UX-05 now wires it
/// live: `spawn_extension_bridge_listener` registers the `cancel_tx`, `stop_extension_bridge_listener`
/// fires it, and the accept loop clears it back to `None` on exit.
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
// PendingAssociation / PendingAssociationMap — bounded TOFU approval wait (Pitfall 4)
// ---------------------------------------------------------------------------

/// One in-flight `associate` request awaiting a human Allow/Deny decision.
///
/// Mirrors `pairing.rs`'s session-map pattern, simplified to a single oneshot (no `Notify` —
/// this is a one-shot decision, not a mutual-confirm exchange). `decision_tx` is consumed by
/// `bridge_approve`/`bridge_deny` (Plan 04's Tauri commands); `true` = Approve, `false` = Deny.
pub struct PendingAssociation {
    // Never read after being set — retained for diagnostics/future use, not dead state (the
    // decision itself flows solely through `decision_tx`). #[allow] rather than removal: no
    // architectural change intended by this lint cleanup (2026-07-10 CI clippy gate landing).
    #[allow(dead_code)]
    pub client_public_key: [u8; 32],
    #[allow(dead_code)]
    pub label: String,
    pub decision_tx: oneshot::Sender<bool>,
}

/// Tauri managed state: session_id -> PendingAssociation.
///
/// SECURITY (Pitfall 4): this is a DIFFERENT `Mutex` from `ExtensionPeerCache` below — a
/// long-held lock while awaiting one human decision must never be able to stall another,
/// already-associated extension's steady-state `rpc` traffic.
pub struct PendingAssociationMap(pub Mutex<HashMap<String, PendingAssociation>>);

impl PendingAssociationMap {
    pub fn new() -> Self {
        PendingAssociationMap(Mutex::new(HashMap::new()))
    }
}

impl Default for PendingAssociationMap {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ExtensionPeerCache — steady-state clientPublicKey -> pairing_token_hash lookup
// ---------------------------------------------------------------------------

/// A cached, already-associated peer's fast-lookup fields — no secrets: `pairing_token_hash` is
/// a one-way BLAKE2b digest, never the raw token (T-15-04).
#[derive(Clone, Copy)]
pub struct CachedPeer {
    pub pairing_token_hash: [u8; 32],
}

/// Tauri managed state: clientPublicKey (raw 32 bytes) -> `CachedPeer`.
///
/// SECURITY (Pitfall 4): a SEPARATE `Mutex` from `PendingAssociationMap` — populated at
/// association time (Task 1) and consulted on every `rpc` (Task 2) so steady-state dispatch
/// never contends with a pending approval's 60s wait.
pub struct ExtensionPeerCache(pub Mutex<HashMap<[u8; 32], CachedPeer>>);

impl ExtensionPeerCache {
    pub fn new() -> Self {
        ExtensionPeerCache(Mutex::new(HashMap::new()))
    }
}

impl Default for ExtensionPeerCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PendingRpcMap — non-human-gated pending-RPC map (Phase 16, mirrors PendingAssociationMap)
// ---------------------------------------------------------------------------

/// Bounded wait for the renderer's answer to a `match-origin`/`fill-entry` dispatch (Pattern 1,
/// RESEARCH.md). Short and NOT human-gated — a renderer that never answers (crashed, reloaded,
/// vault-touch code threw) must fail closed quickly, never hang the pipe (T-16-06).
pub const RPC_DISPATCH_TIMEOUT: Duration = Duration::from_secs(3);

/// Tauri managed state: requestId -> oneshot sender for a single in-flight RPC dispatch.
///
/// SECURITY (Pitfall 1/4, T-16-07): this is a THIRD, independent `Mutex` — never merged with
/// `PendingAssociationMap` (bounded human wait, 60s) or `ExtensionPeerCache` (steady-state
/// lookup). A burst of `match-origin`/`fill-entry` traffic must never be able to stall a pending
/// human association decision, or vice versa.
pub struct PendingRpcMap(pub Mutex<HashMap<String, oneshot::Sender<Result<serde_json::Value, BridgeError>>>>);

impl PendingRpcMap {
    pub fn new() -> Self {
        PendingRpcMap(Mutex::new(HashMap::new()))
    }
}

impl Default for PendingRpcMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve a pending RPC dispatch's renderer-side result. Looks up `request_id` in `map`,
/// removes + takes its sender, and sends the result. Returns `Err` (never panics) if the
/// request is unknown — already timed out, already resolved, or never existed.
fn resolve_pending_rpc(
    map: &Mutex<HashMap<String, oneshot::Sender<Result<serde_json::Value, BridgeError>>>>,
    request_id: &str,
    result: Result<serde_json::Value, BridgeError>,
) -> Result<(), String> {
    let pending = {
        let mut guard = map.lock().unwrap();
        guard.remove(request_id)
    };
    match pending {
        Some(tx) => tx.send(result).map_err(|_| {
            format!(
                "resolve_pending_rpc: receiver for request '{}' already dropped",
                request_id
            )
        }),
        None => Err(format!(
            "resolve_pending_rpc: unknown request_id '{}'",
            request_id
        )),
    }
}

// ---------------------------------------------------------------------------
// Small local encoding helpers (hex is the SAME encoding extension_peers.rs uses for
// `client_public_key`/`pairing_token_hash` at rest — kept local to avoid widening
// extension_peers.rs's scope for this plan).
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex_decode: odd-length string".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("hex_decode: {}", e))
        })
        .collect()
}

/// Generate an opaque random identifier (association `client_id` / pending-approval session id).
/// CSPRNG via `crypto_box`'s own `OsRng` — `Math.random`-equivalent is banned project-wide.
fn random_id() -> String {
    use crypto_box::aead::rand_core::RngCore;
    let mut bytes = [0u8; 16];
    BoxOsRng.fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

/// ISO 8601 UTC timestamp — copied verbatim (algorithm only, no shared state) from
/// `pairing.rs`'s `now_iso8601`/`days_to_ymd` so this module's `paired_at` field matches the
/// SAME format without widening `pairing.rs`'s visibility for this plan.
fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days_since_epoch = secs / 86400;
    let (y, mo, d) = days_to_ymd(days_since_epoch);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, m, s)
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let mut d = days + 719468;
    let era = d / 146097;
    let doe = d % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    d = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * d + 2) / 153;
    let day = d - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

// ---------------------------------------------------------------------------
// App identity keypair — ONE shared crypto_box keypair for every extension association
// ---------------------------------------------------------------------------

/// Load the app's persisted `crypto_box` identity secret key from `store`, generating and
/// persisting a fresh one on first use.
///
/// Mirrors `pairing.rs`'s `get_or_generate_keypair_from_store` shape, but stores ONLY the raw
/// 32-byte `SecretKey` (crypto_box has no separate "scalar" persistence need) under
/// `EXTENSION_IDENTITY_SK_TARGET` — SHARED across every browser-extension association (never
/// per-peer), matching `extension_peers.rs`'s documented invariant.
fn get_or_generate_app_identity_keypair(store: &dyn CredentialStore) -> Result<BoxSecretKey, String> {
    if let Ok(existing) = store.read(EXTENSION_IDENTITY_SK_TARGET) {
        if existing.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&existing);
            return Ok(BoxSecretKey::from(bytes));
        }
        // Any other stored length is unexpected/stale — fall through and regenerate.
    }

    let sk = BoxSecretKey::generate(&mut BoxOsRng);
    store.write(EXTENSION_IDENTITY_SK_TARGET, &sk.to_bytes()).map_err(|e| {
        format!("get_or_generate_app_identity_keypair: store write failed: {}", e)
    })?;
    Ok(sk)
}

// ---------------------------------------------------------------------------
// Task 1: associate/associate-ok TOFU handshake — bounded approval + hash-only persistence
// ---------------------------------------------------------------------------

/// Result of a successful `associate` flow (either silently-trusted or freshly approved).
///
/// `pairing_token` is `Some` ONLY on a fresh approval — the raw token is minted once, returned
/// ONCE in the plaintext `associate-ok` reply, and NEVER persisted (T-15-04). On the
/// already-associated (silently-trusted, SC-1) path there is no raw token to return — the app
/// holds only the HASH — so `pairing_token` is `None` and the extension is expected to already
/// hold its own copy from the original approval.
#[derive(Debug)]
pub struct AssociateOkResponse {
    pub host_public_key: [u8; 32],
    pub pairing_token: Option<[u8; 32]>,
}

/// Look up whether `client_public_key` already has a persisted association.
///
/// SC-1: an already-associated key must be silently trusted — no approval prompt.
pub fn check_already_associated(
    config_dir: &str,
    client_public_key: &[u8; 32],
) -> Result<Option<ExtensionPeerRecord>, String> {
    let doc = read_extension_peers_json(config_dir)?;
    let hex_key = hex_encode(client_public_key);
    Ok(doc
        .associations
        .into_iter()
        .find(|a| a.client_public_key == hex_key))
}

/// Bounded wait for the human's Allow/Deny decision (Pitfall 4).
///
/// Returns `true` only on an explicit Approve delivered before `timeout_duration` elapses.
/// Timeout, Deny, or a dropped sender all resolve to `false` (fail closed) — the caller MUST
/// NOT persist anything on a `false` result.
pub async fn await_association_decision(
    decision_rx: oneshot::Receiver<bool>,
    timeout_duration: Duration,
) -> bool {
    match tokio::time::timeout(timeout_duration, decision_rx).await {
        Ok(Ok(decision)) => decision,
        _ => false,
    }
}

/// Mint a fresh association: a 32-byte CSPRNG pairing token, the app identity keypair
/// (generated once, persisted to `store`), and the durable `ExtensionPeerRecord` (hash-only).
///
/// SECURITY (T-15-04): the raw token is hashed via `extension_peers::hash_pairing_token` BEFORE
/// the record is constructed — the raw bytes are returned to the caller for the ONE-TIME
/// plaintext `associate-ok` reply and are NEVER written to `extension-peers.json`.
fn finalize_new_association(
    config_dir: &str,
    store: &dyn CredentialStore,
    client_public_key: &[u8; 32],
    label: &str,
) -> Result<(AssociateOkResponse, [u8; 32] /* token hash, for the cache */), String> {
    let sk = get_or_generate_app_identity_keypair(store)?;
    let host_public_key = sk.public_key().to_bytes();

    let mut token = [0u8; 32];
    {
        use crypto_box::aead::rand_core::RngCore;
        BoxOsRng.fill_bytes(&mut token);
    }
    let token_hash = hash_pairing_token(&token);

    let mut doc = read_extension_peers_json(config_dir)?;
    doc.associations.push(ExtensionPeerRecord {
        client_id: random_id(),
        client_public_key: hex_encode(client_public_key),
        label: label.to_string(),
        paired_at: now_iso8601(),
        last_used_at: None,
        pairing_token_hash: hex_encode(&token_hash),
    });
    write_extension_peers_json_atomic(config_dir, &doc)?;

    Ok((
        AssociateOkResponse {
            host_public_key,
            pairing_token: Some(token),
        },
        token_hash,
    ))
}

/// Full `associate` orchestration — TOFU check, pending-approval wait, and finalize — with NO
/// dependency on a live `tauri::AppHandle` (testable in isolation, mirrors `pairing.rs`'s
/// `await_mutual_confirm` extraction). The real per-connection handler supplies `emit_request`
/// as a thin closure over `app.emit(...)`.
///
/// `pending_map` and `cache` are passed by reference so tests can drive them with a bare
/// `Mutex::new(HashMap::new())` — no Tauri managed state required.
#[allow(clippy::too_many_arguments)]
pub async fn process_associate(
    config_dir: &str,
    store: &dyn CredentialStore,
    pending_map: &Mutex<HashMap<String, PendingAssociation>>,
    cache: &Mutex<HashMap<[u8; 32], CachedPeer>>,
    session_id: String,
    client_public_key: [u8; 32],
    label: String,
    timeout_duration: Duration,
    emit_request: impl FnOnce(&str, &[u8; 32], &str),
) -> Result<AssociateOkResponse, BridgeError> {
    // SC-1: an already-associated key is silently trusted — NOTHING is persisted, NO approval
    // event is emitted, and the fast-lookup cache is (re)populated from disk so a subsequent
    // `rpc` on this same key does not need to re-read extension-peers.json.
    match check_already_associated(config_dir, &client_public_key) {
        Ok(Some(record)) => {
            let sk = get_or_generate_app_identity_keypair(store).map_err(BridgeError::ProtocolError)?;
            let hash_bytes = hex_decode(&record.pairing_token_hash).map_err(BridgeError::ProtocolError)?;
            if hash_bytes.len() == 32 {
                let mut hash_arr = [0u8; 32];
                hash_arr.copy_from_slice(&hash_bytes);
                cache.lock().unwrap().insert(
                    client_public_key,
                    CachedPeer {
                        pairing_token_hash: hash_arr,
                    },
                );
            }
            return Ok(AssociateOkResponse {
                host_public_key: sk.public_key().to_bytes(),
                pairing_token: None,
            });
        }
        Ok(None) => {}
        Err(e) => return Err(BridgeError::ProtocolError(e)),
    }

    // First-time association: create the pending entry BEFORE emitting, so a decision that
    // races the emit can never be lost.
    let (decision_tx, decision_rx) = oneshot::channel::<bool>();
    {
        let mut map = pending_map.lock().unwrap();
        map.insert(
            session_id.clone(),
            PendingAssociation {
                client_public_key,
                label: label.clone(),
                decision_tx,
            },
        );
    }

    emit_request(&session_id, &client_public_key, &label);

    let approved = await_association_decision(decision_rx, timeout_duration).await;

    // Always drop the pending entry once a decision (or timeout) is known — no leak, no
    // dangling partial association either way (Pitfall 4 / acceptance criteria).
    {
        let mut map = pending_map.lock().unwrap();
        map.remove(&session_id);
    }

    if !approved {
        return Err(BridgeError::AssociationDenied);
    }

    let (response, token_hash) =
        finalize_new_association(config_dir, store, &client_public_key, &label)
            .map_err(BridgeError::ProtocolError)?;

    cache.lock().unwrap().insert(
        client_public_key,
        CachedPeer {
            pairing_token_hash: token_hash,
        },
    );

    Ok(response)
}

// ---------------------------------------------------------------------------
// Task 2: crypto_box rpc encrypt/decrypt + token-hash-inside-box constant-time verify
// ---------------------------------------------------------------------------

/// Seal `plaintext` for `peer_pk` under this app's `app_sk`, with a FRESH CSPRNG nonce
/// (Pitfall 3 — never a counter). Returns `(nonce_base64, ciphertext_base64)`.
pub fn encrypt_rpc_box(
    app_sk: &BoxSecretKey,
    peer_pk: &BoxPublicKey,
    plaintext: &[u8],
) -> (String, String) {
    let cbox = SalsaBox::new(peer_pk, app_sk);
    let nonce = SalsaBox::generate_nonce(&mut BoxOsRng);
    let ciphertext = cbox
        .encrypt(&nonce, plaintext)
        .expect("crypto_box encrypt should not fail for well-formed input");
    (BASE64.encode(nonce.as_slice()), BASE64.encode(ciphertext))
}

/// Open a `crypto_box` sealed under `(peer_pk, app_sk)`. AEAD failure (wrong key, tampered
/// ciphertext, wrong nonce) maps to the SAME typed `BridgeError::InvalidToken` as a bad
/// app-layer token — never a panic, never partial plaintext (Pitfall 1).
pub fn decrypt_rpc_box(
    app_sk: &BoxSecretKey,
    peer_pk: &BoxPublicKey,
    nonce_b64: &str,
    box_b64: &str,
) -> Result<Vec<u8>, BridgeError> {
    let nonce_bytes = BASE64.decode(nonce_b64).map_err(|_| BridgeError::InvalidToken)?;
    if nonce_bytes.len() != 24 {
        return Err(BridgeError::InvalidToken);
    }
    let ciphertext = BASE64.decode(box_b64).map_err(|_| BridgeError::InvalidToken)?;
    let nonce = crypto_box::Nonce::clone_from_slice(&nonce_bytes);

    let cbox = SalsaBox::new(peer_pk, app_sk);
    cbox.decrypt(&nonce, ciphertext.as_slice())
        .map_err(|_| BridgeError::InvalidToken)
}

/// Parse the decrypted box plaintext as `{ pairingToken, ...innerPayload }` and verify the
/// pairing token's BLAKE2b hash against `stored_hash` using a CONSTANT-TIME compare
/// (`subtle::ConstantTimeEq`) — never `==`/`.eq()` on the token or its hash (Don't Hand-Roll).
///
/// Returns the parsed inner JSON on success so a future dispatch layer (Phase 16+) can read the
/// rest of the payload; returns the typed error otherwise. `NotAssociated` covers an absent
/// token field; `InvalidToken` covers a present-but-wrong token — both fail closed.
pub fn verify_pairing_token(
    decrypted_plaintext: &[u8],
    stored_hash: &[u8; 32],
) -> Result<serde_json::Value, BridgeError> {
    let inner: serde_json::Value =
        serde_json::from_slice(decrypted_plaintext).map_err(|_| BridgeError::InvalidToken)?;

    let token_b64 = inner
        .get("pairingToken")
        .and_then(|v| v.as_str())
        .ok_or(BridgeError::NotAssociated)?;

    let token_bytes = BASE64.decode(token_b64).map_err(|_| BridgeError::InvalidToken)?;
    let incoming_hash = hash_pairing_token(&token_bytes);

    // Constant-time compare of the HASHES — never the raw tokens (the app stores no raw token
    // to compare against in the first place) and never `==`/`.eq()` (Don't Hand-Roll / T-15-01).
    // `subtle::ConstantTimeEq` is implemented for slices, so compare via `.as_slice()`/`&[..]`.
    let matches: bool = incoming_hash.as_slice().ct_eq(stored_hash.as_slice()).into();
    if !matches {
        return Err(BridgeError::InvalidToken);
    }

    Ok(inner)
}

/// Full `rpc` decrypt-then-verify pipeline: open the box, THEN check the token hash. Neither
/// check alone is sufficient (Pitfall 1) — both `decrypt_rpc_box` and `verify_pairing_token`
/// must succeed before ANY dispatch (dispatch itself is Phase 16+; this returns the inner JSON
/// as proof of a fully-authenticated round trip).
pub fn process_rpc(
    app_sk: &BoxSecretKey,
    peer_pk: &BoxPublicKey,
    stored_hash: &[u8; 32],
    nonce_b64: &str,
    box_b64: &str,
) -> Result<serde_json::Value, BridgeError> {
    let plaintext = decrypt_rpc_box(app_sk, peer_pk, nonce_b64, box_b64)?;
    verify_pairing_token(&plaintext, stored_hash)
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

/// Best-effort reset of `ExtensionBridgeState.cancel_tx` back to `None` so a later
/// `spawn_extension_bridge_listener` re-registers cleanly (idempotency, T-20-03). Mirrors
/// sync.rs's `clear_sync_listener_state`, minus the sync-only pending-blob cleanup — the bridge
/// listener holds no such renderer state. Ignores a poisoned lock (best-effort teardown).
fn clear_extension_bridge_state(app: &tauri::AppHandle) {
    let state = app.state::<ExtensionBridgeState>();
    let taken = state.cancel_tx.lock().map(|mut guard| guard.take());
    drop(taken);
}

/// Run the always-on local named-pipe accept loop, cancellable via `cancel_rx` (UX-05/D-01).
///
/// Renamed from the Phase-14 `start_extension_bridge_listener` and extended for the kill-switch:
/// the accept `select!` now also arms `cancel_rx`, so firing `ExtensionBridgeState.cancel_tx` (via
/// `stop_extension_bridge_listener`) breaks the loop AND drops the pending `server.connect()`,
/// closing the current listening pipe instance so the extension observes a plain disconnect
/// (D-01). Still NOT `#[cfg(debug_assertions)]`-gated and NOT gated by vault-unlock state (D-04:
/// the echo endpoint carries zero vault data). On EVERY exit path the `cancel_tx` is cleared back
/// to `None` so a later `spawn_extension_bridge_listener` re-registers cleanly (T-20-03).
async fn run_extension_bridge_accept_loop(
    app: tauri::AppHandle,
    mut cancel_rx: oneshot::Receiver<()>,
) {
    // SECURITY (D-03/T-14-05): reject_remote_clients(true) blocks all NETWORK-origin clients —
    // only local processes on this machine may connect. This does NOT isolate other LOCAL
    // Windows accounts on a shared machine (default per-user pipe DACL, T-14-06 / RESEARCH.md
    // Open Question 1 / Pitfall 3) — accepted for this zero-vault-data skeleton because the echo
    // handler never touches vault state by construction (D-04); Phase 15's crypto_box pairing
    // token is the designed real mitigation for that residual risk.
    let mut server = match ServerOptions::new()
        .reject_remote_clients(true)
        .first_pipe_instance(true)
        .create(PIPE_NAME)
    {
        Ok(s) => s,
        Err(e) => {
            // Initial pipe create failed (e.g. another instance already owns first_pipe_instance).
            // Clear cancel_tx so a later start can retry; no secret is ever logged.
            eprintln!("extension_bridge: initial pipe create failed: {} (no secret logged)", e);
            clear_extension_bridge_state(&app);
            return;
        }
    };

    loop {
        // Accept the next client OR observe the kill-switch. Polling `cancel_rx` by `&mut` keeps
        // it across iterations; firing cancel_tx (stop_extension_bridge_listener) resolves the
        // recv and breaks the loop. Dropping the pending `server.connect()` on cancel closes the
        // current listening pipe instance (D-01), so a fresh extension connect is refused.
        let accepted = tokio::select! {
            _ = &mut cancel_rx => {
                // UX-05 kill-switch OFF (or app shutdown / sender dropped): stop accepting.
                break;
            }
            r = server.connect() => r,
        };
        if accepted.is_err() {
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

    // Clear cancel_tx on every exit so a future start re-registers cleanly (T-20-03).
    clear_extension_bridge_state(&app);
}

/// Spawn the extension-bridge accept loop if not already running (idempotent — used by both the
/// `.setup()` boot spawn and the UX-05 kill-switch ON path). Takes the `ExtensionBridgeState`
/// lock, returns early if `cancel_tx.is_some()`, otherwise registers a fresh `cancel_tx` and
/// spawns `run_extension_bridge_accept_loop`. Mirrors `sync_listener_start`'s idempotency guard +
/// cancel_tx registration, minus the confinement/peer/keypair prep — the bridge listener carries
/// zero vault data by construction (D-04), so there is nothing to confine or key.
pub fn spawn_extension_bridge_listener(app: tauri::AppHandle) {
    let state = app.state::<ExtensionBridgeState>();
    let cancel_rx = {
        let mut guard = state.cancel_tx.lock().unwrap();
        if guard.is_some() {
            // Already running — idempotent no-op (T-20-03). A redundant start never double-binds
            // `first_pipe_instance`/`PIPE_NAME`.
            return;
        }
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        *guard = Some(cancel_tx);
        cancel_rx
    };
    tauri::async_runtime::spawn(run_extension_bridge_accept_loop(app.clone(), cancel_rx));
}

/// UX-05 kill-switch ON: (re)spawn the extension-bridge listener. Idempotent — a redundant call
/// while already running is a no-op (`spawn_extension_bridge_listener`'s guard). This is the JS
/// `invoke('start_extension_bridge_listener')` target (bridgeCommands.ts).
#[tauri::command]
pub async fn start_extension_bridge_listener(app: tauri::AppHandle) -> Result<(), String> {
    spawn_extension_bridge_listener(app);
    Ok(())
}

/// UX-05 kill-switch OFF: stop the extension-bridge listener. Fires `cancel_tx` to break the
/// accept loop and drop the pending pipe instance (D-01) so the extension observes a plain
/// disconnect. Idempotent — Ok(()) if no listener is running. Copied verbatim (renamed) from
/// sync.rs's `sync_listener_stop`.
#[tauri::command]
pub async fn stop_extension_bridge_listener(app: tauri::AppHandle) -> Result<(), String> {
    let state = app.state::<ExtensionBridgeState>();
    let mut guard = state.cancel_tx.lock().unwrap();
    if let Some(tx) = guard.take() {
        let _ = tx.send(());
    }
    Ok(())
}

/// Read the device-local `extensionBridgeEnabled` kill-switch from
/// `$APPCONFIG/cryptiq/config.json` (D-04). Called from lib.rs `.setup()` to gate the boot spawn
/// so an explicit OFF persists across an app restart.
///
/// SECURITY (T-20-04, accepted fail-OPEN): returns `false` ONLY when the field is explicitly the
/// JSON boolean `false`. An absent field, a missing file, a non-boolean value, or ANY read/parse
/// error all fail OPEN to `true` — preserving Phase-14's always-on behavior so a missing/corrupt
/// config never silently disables the feature. Only a deliberate `false` disables. The real
/// per-request auth is Phase-15's crypto_box pairing token, unchanged here.
pub fn extension_bridge_enabled(app: &tauri::AppHandle) -> bool {
    let config_dir = match app.path().app_config_dir() {
        Ok(p) => p,
        Err(_) => return true, // cannot resolve config dir — fail open
    };
    let config_path = config_dir.join("cryptiq").join("config.json");
    let bytes = match std::fs::read(&config_path) {
        Ok(b) => b,
        Err(_) => return true, // missing/unreadable config — fail open
    };
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return true, // corrupt config — fail open
    };
    // Only an explicit JSON `false` disables; Some(true), absent, or non-bool → fail open to true.
    !matches!(
        value.get("extensionBridgeEnabled").and_then(|v| v.as_bool()),
        Some(false)
    )
}

/// Handle a single connected pipe client: read one framed envelope, validate it, and respond.
///
/// - `msg_type == "echo"` → echo the SAME `id` and the SAME `payload` back verbatim (D-04: a
///   fixed, harmless echo with zero vault data and zero business logic).
/// - `msg_type == "associate"` → the Phase 15 TOFU handshake (Task 1): silently trust an
///   already-known key, or emit `bridge://associate-request` and await a bounded (60s) human
///   decision before minting + persisting a fresh association.
/// - `msg_type == "rpc"` → `crypto_box`-open the envelope THEN constant-time-verify the
///   pairing-token hash carried inside the box (Task 2) — fails closed (`NotAssociated`/
///   `InvalidToken`) on either check, never dispatching before both succeed (Pitfall 1).
/// - protocolVersion mismatch → typed, DIRECTIONAL `{type:"error", payload:{code, message}}`
///   response, then close (D-02/D-05/BRIDGE-10).
/// - Any framing/IO/deserialize error → close the connection cleanly. No panic, no hang.
///
/// Never logs envelope payloads (D-10); any verbose diagnostic is lifecycle-only and dev-gated.
/// Key bytes and the pairing token are never logged in any form.
async fn handle_bridge_connection(mut connected: NamedPipeServer, app: tauri::AppHandle) {
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

    match envelope.msg_type.as_str() {
        "echo" => {
            // D-04: fixed harmless echo — the SAME id + payload, verbatim, zero vault data.
            let response = BridgeEnvelope {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                msg_type: "echo".to_string(),
                id: envelope.id.clone(),
                payload: envelope.payload.clone(),
            };
            let _ = respond(&mut connected, &response).await;
        }
        "associate" => {
            let response = handle_associate_message(&app, &envelope).await;
            let _ = respond(&mut connected, &response).await;
        }
        "rpc" => {
            let response = handle_rpc_message(&app, &envelope).await;
            let _ = respond(&mut connected, &response).await;
        }
        _ => {
            // Unrecognized msg_type: no response (no other typed messages exist yet).
        }
    }
}

/// Parse an `associate` envelope's payload: `{ clientPublicKey (base64, 32 bytes), label }`.
fn parse_associate_payload(payload: &serde_json::Value) -> Result<([u8; 32], String), String> {
    let client_public_key_b64 = payload
        .get("clientPublicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "associate: missing clientPublicKey".to_string())?;
    let label = payload
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown browser")
        .to_string();

    let decoded = BASE64
        .decode(client_public_key_b64)
        .map_err(|_| "associate: clientPublicKey is not valid base64".to_string())?;
    if decoded.len() != 32 {
        return Err("associate: clientPublicKey must decode to exactly 32 bytes".to_string());
    }
    let mut client_public_key = [0u8; 32];
    client_public_key.copy_from_slice(&decoded);
    Ok((client_public_key, label))
}

/// Production wiring for the `associate` msg_type: resolves `config_dir` + the platform
/// `CredentialStore` from the live `AppHandle`, pulls the (Plan 04-managed)
/// `PendingAssociationMap`/`ExtensionPeerCache` state, emits `bridge://associate-request` on a
/// first-time request, and maps the outcome to a plaintext `associate-ok` or typed error
/// envelope. All actual TOFU logic lives in the AppHandle-free `process_associate` (unit-tested
/// directly below).
async fn handle_associate_message(app: &tauri::AppHandle, envelope: &BridgeEnvelope) -> BridgeEnvelope {
    let id = envelope.id.clone();

    let (client_public_key, label) = match parse_associate_payload(&envelope.payload) {
        Ok(v) => v,
        Err(msg) => return error_response(id, BridgeError::ProtocolError(msg)),
    };

    let config_dir = match app.path().app_config_dir() {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(e) => {
            return error_response(
                id,
                BridgeError::ProtocolError(format!("associate: could not resolve config dir: {}", e)),
            )
        }
    };

    #[cfg(target_os = "windows")]
    let store: WindowsCredentialStore = WindowsCredentialStore;
    #[cfg(not(target_os = "windows"))]
    let store: NoopCredentialStore = NoopCredentialStore;

    let session_id = random_id();
    let app_for_emit = app.clone();

    let pending_state = app.state::<PendingAssociationMap>();
    let cache_state = app.state::<ExtensionPeerCache>();

    let result = process_associate(
        &config_dir,
        &store,
        &pending_state.0,
        &cache_state.0,
        session_id,
        client_public_key,
        label,
        ASSOCIATION_APPROVAL_TIMEOUT,
        move |session_id, client_public_key, label| {
            // Never log key bytes or the token (D-10) — only the base64 public key (not a
            // secret) and label are ever emitted, and only to the frontend event channel.
            let _ = app_for_emit.emit(
                "bridge://associate-request",
                serde_json::json!({
                    "sessionId": session_id,
                    "clientPublicKey": BASE64.encode(client_public_key),
                    "label": label,
                }),
            );
        },
    )
    .await;

    match result {
        Ok(ok) => {
            let mut payload = serde_json::json!({ "hostPublicKey": BASE64.encode(ok.host_public_key) });
            if let Some(token) = ok.pairing_token {
                payload["pairingToken"] = serde_json::Value::String(BASE64.encode(token));
            }
            BridgeEnvelope {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                msg_type: "associate-ok".to_string(),
                id,
                payload,
            }
        }
        Err(err) => error_response(id, err),
    }
}

/// Dispatch a decrypted, authenticated `method`/`params` pair into the renderer (where the
/// unlocked vault lives) and await its plaintext answer, bounded by `RPC_DISPATCH_TIMEOUT`.
///
/// Mirrors `process_associate`'s "insert pending entry BEFORE emitting" discipline (lines
/// 502-515) so a racing response can never be lost, and ALWAYS removes the pending entry on
/// every exit path (success or timeout) — no leaked oneshot senders.
///
/// AppHandle-free core (mirrors `process_associate`'s testability discipline): `pending_map` and
/// `emit_request` are passed in so tests can drive this with a bare `Mutex::new(HashMap::new())`
/// and a plain closure — no live Tauri app required. `dispatch_rpc_method` below is the thin
/// AppHandle-extracting production wrapper.
#[allow(clippy::too_many_arguments)]
async fn dispatch_rpc_core(
    pending_map: &Mutex<HashMap<String, oneshot::Sender<Result<serde_json::Value, BridgeError>>>>,
    request_id: String,
    timeout_duration: Duration,
    method: &str,
    params: serde_json::Value,
    emit_request: impl FnOnce(&str, &str, &serde_json::Value),
) -> Result<serde_json::Value, BridgeError> {
    let (tx, rx) = oneshot::channel::<Result<serde_json::Value, BridgeError>>();

    // Insert BEFORE emitting — a response that races the emit can never be lost (mirrors
    // process_associate lines 502-515).
    {
        pending_map.lock().unwrap().insert(request_id.clone(), tx);
    }

    emit_request(&request_id, method, &params);

    match tokio::time::timeout(timeout_duration, rx).await {
        Ok(Ok(result)) => result,
        _ => {
            // Renderer never answered (view unmounted, JS exception, or genuinely slow) — fail
            // closed. NEVER hang the pipe connection (mirrors BRIDGE_READ_TIMEOUT discipline).
            pending_map.lock().unwrap().remove(&request_id);
            Err(BridgeError::ProtocolError("rpc dispatch timed out".to_string()))
        }
    }
}

/// Production wiring for `dispatch_rpc_core`: resolves `PendingRpcMap` from the live
/// `AppHandle` and emits `bridge://rpc-request` over the real Tauri event channel.
async fn dispatch_rpc_method(
    app: &tauri::AppHandle,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, BridgeError> {
    let request_id = random_id();
    let pending_state = app.state::<PendingRpcMap>();
    let app_for_emit = app.clone();

    dispatch_rpc_core(
        &pending_state.0,
        request_id,
        RPC_DISPATCH_TIMEOUT,
        method,
        params,
        move |request_id, method, params| {
            let _ = app_for_emit.emit(
                "bridge://rpc-request",
                serde_json::json!({
                    "requestId": request_id,
                    "method": method,
                    "params": params,
                }),
            );
        },
    )
    .await
}

/// Map a renderer-returned plain result value's `{code: "..."}` field (D-09: the renderer is the
/// source of truth for lock state and returns a typed code rather than throwing) to the matching
/// `BridgeError`, so app-level failures (vault-locked / not-found / invalid-request) produce the
/// SAME `{type:"error", payload:{code,message}}` wire shape as auth-boundary failures — a single
/// error_response mapping site for the whole `rpc` path, not two divergent shapes.
fn map_renderer_result_to_typed_error(result: &serde_json::Value) -> Option<BridgeError> {
    match result.get("code").and_then(|v| v.as_str()) {
        Some("vault-locked") => Some(BridgeError::VaultLocked),
        Some("not-found") => Some(BridgeError::RpcNotFound),
        Some("invalid-request") => Some(BridgeError::RpcInvalidRequest),
        _ => None,
    }
}

/// Production wiring for the `rpc` msg_type: looks up the caller's cached
/// `pairing_token_hash` by `clientPublicKey` (populated at association time — Task 1) and runs
/// the full `crypto_box`-open + constant-time token-hash `process_rpc` pipeline. Fails closed
/// with `NotAssociated` if the key has no cache entry, before any box is even attempted.
///
/// NOTE: the wire's `rpc` envelope carries `clientPublicKey` alongside `nonce`/`box` PURELY for
/// routing to the right cached peer — a public key is not secret, and the actual authentication
/// boundary remains the `crypto_box` open + token-hash match (never the presence of this field).
/// The pairing TOKEN itself stays inside the encrypted box, never in the outer envelope
/// (Anti-Pattern guardrail).
///
/// Phase 16: after the auth prologue succeeds, the decrypted inner `{method, params}` is
/// dispatched for real. `focus-app` is handled entirely Rust-side (no renderer round trip, no
/// vault touch — XSEC-05 idle isolation is trivially preserved). `match-origin`/`fill-entry`
/// (Phase 16) and `save-or-update-entry`/`generate-password`/`score-password` (Phase 19) are all
/// routed into the renderer via `dispatch_rpc_method` — the arm is a generic whitelist, no
/// per-method Rust logic. Any other method is `RpcInvalidRequest`.
async fn handle_rpc_message(app: &tauri::AppHandle, envelope: &BridgeEnvelope) -> BridgeEnvelope {
    let id = envelope.id.clone();

    let client_public_key_b64 = match envelope.payload.get("clientPublicKey").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return error_response(id, BridgeError::NotAssociated),
    };
    let nonce_b64 = match envelope.payload.get("nonce").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return error_response(id, BridgeError::InvalidToken),
    };
    let box_b64 = match envelope.payload.get("box").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return error_response(id, BridgeError::InvalidToken),
    };

    let client_public_key_bytes = match BASE64.decode(client_public_key_b64) {
        Ok(b) if b.len() == 32 => b,
        _ => return error_response(id, BridgeError::NotAssociated),
    };
    let mut client_public_key = [0u8; 32];
    client_public_key.copy_from_slice(&client_public_key_bytes);

    let cache_state = app.state::<ExtensionPeerCache>();
    let cached = { cache_state.0.lock().unwrap().get(&client_public_key).copied() };
    let cached = match cached {
        Some(c) => c,
        None => return error_response(id, BridgeError::NotAssociated),
    };

    #[cfg(target_os = "windows")]
    let store: WindowsCredentialStore = WindowsCredentialStore;
    #[cfg(not(target_os = "windows"))]
    let store: NoopCredentialStore = NoopCredentialStore;

    let app_sk = match get_or_generate_app_identity_keypair(&store) {
        Ok(sk) => sk,
        Err(e) => return error_response(id, BridgeError::ProtocolError(e)),
    };
    let peer_pk = BoxPublicKey::from(client_public_key);

    match process_rpc(&app_sk, &peer_pk, &cached.pairing_token_hash, nonce_b64, box_b64) {
        Ok(inner) => {
            let method = inner.get("method").and_then(|v| v.as_str());
            let params = inner.get("params").cloned().unwrap_or(serde_json::json!({}));

            let dispatch_result: Result<serde_json::Value, BridgeError> = match method {
                Some("focus-app") => {
                    // Rust-side only: no renderer round trip, no vault touch — XSEC-05 idle
                    // isolation is trivially preserved for this method.
                    focus_app_best_effort(app);
                    Ok(serde_json::json!({ "ok": true }))
                }
                Some("match-origin")
                | Some("fill-entry")
                | Some("save-or-update-entry")
                | Some("generate-password")
                | Some("score-password")
                | Some("search-entries")
                | Some("copy-field") => {
                    dispatch_rpc_method(app, method.unwrap(), params).await
                }
                _ => Err(BridgeError::RpcInvalidRequest),
            };

            match dispatch_result {
                Ok(result_value) => {
                    // D-09: the renderer answers with a typed `{code:...}` object instead of a
                    // Rust-level error for app-level failures (vault-locked / not-found /
                    // invalid-request) — route those through the SAME single error_response
                    // mapping site as auth-boundary failures, rather than boxing them as if they
                    // were a successful result.
                    if let Some(mapped_err) = map_renderer_result_to_typed_error(&result_value) {
                        return error_response(id, mapped_err);
                    }
                    let plaintext = match serde_json::to_vec(&result_value) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            return error_response(
                                id,
                                BridgeError::ProtocolError("rpc: failed to serialize result".to_string()),
                            )
                        }
                    };
                    let (nonce, ct) = encrypt_rpc_box(&app_sk, &peer_pk, &plaintext);
                    BridgeEnvelope {
                        protocol_version: CURRENT_PROTOCOL_VERSION,
                        msg_type: "rpc-ok".to_string(),
                        id,
                        payload: serde_json::json!({ "nonce": nonce, "box": ct }),
                    }
                }
                Err(err) => error_response(id, err),
            }
        }
        Err(err) => error_response(id, err),
    }
}

/// Build a typed `{type:"error", payload:{code, message}}` envelope from a `BridgeError`
/// (D-02/D-05) — single mapping site so every failure path in `handle_bridge_connection`
/// produces the same shape. Directional per BRIDGE-10/Pitfall 5: `got > expected` means the
/// APP is behind (the extension speaks a newer protocol); `got < expected` means the
/// EXTENSION is behind.
fn error_response(id: Option<String>, err: BridgeError) -> BridgeEnvelope {
    let (code, message) = match err {
        BridgeError::ProtocolMismatch { expected, got } if got > expected => (
            "app-outdated".to_string(),
            "Cryptiq is out of date for this extension version — update the Cryptiq desktop app."
                .to_string(),
        ),
        BridgeError::ProtocolMismatch { expected, got } if got < expected => (
            "extension-outdated".to_string(),
            "This browser extension is out of date — update the Cryptiq extension.".to_string(),
        ),
        BridgeError::ProtocolMismatch { .. } => {
            unreachable!("got == expected is handled by validate_envelope's Ok path")
        }
        BridgeError::ProtocolError(msg) => ("protocol-error".to_string(), msg),
        BridgeError::NotAssociated => (
            "not-associated".to_string(),
            "This browser is not paired with Cryptiq yet — open the app to approve it.".to_string(),
        ),
        BridgeError::InvalidToken => (
            "invalid-token".to_string(),
            "Pairing check failed — re-approve this extension in Cryptiq's Browser Extensions settings."
                .to_string(),
        ),
        BridgeError::AssociationDenied => (
            "association-denied".to_string(),
            "This browser extension was not approved.".to_string(),
        ),
        BridgeError::VaultLocked => (
            "vault-locked".to_string(),
            "Cryptiq is locked — unlock it to fill.".to_string(),
        ),
        BridgeError::RpcNotFound => (
            "not-found".to_string(),
            "That saved login no longer exists.".to_string(),
        ),
        BridgeError::RpcInvalidRequest => (
            "invalid-request".to_string(),
            "Unsupported request.".to_string(),
        ),
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
// Plan 04: bridge_approve/bridge_deny + list/rename/revoke Tauri commands
//
// The frontend's approval modal (Plan 05) resolves a pending TOFU decision via
// bridge_approve/bridge_deny; the Browser Extensions settings screen lists/renames/revokes
// persisted associations. Each command is a thin AppHandle-extracting wrapper around an
// AppHandle-free helper (mirrors process_associate's testability discipline above) so the core
// logic is unit-testable with a bare `Mutex::new(HashMap::new())` — no live Tauri app required.
// ---------------------------------------------------------------------------

/// Resolve a pending TOFU association's human decision with `true` (Approve) or `false` (Deny).
///
/// Looks up `session_id` in `pending_map`, removes + takes its `decision_tx`, and sends the
/// decision. Returns `Err` (never panics) if the session is unknown — already timed out, already
/// resolved (a consumed oneshot cannot be double-fired), or never existed (T-15-09).
fn resolve_pending_decision(
    pending_map: &Mutex<HashMap<String, PendingAssociation>>,
    session_id: &str,
    decision: bool,
) -> Result<(), String> {
    let pending = {
        let mut map = pending_map.lock().unwrap();
        map.remove(session_id)
    };
    match pending {
        Some(entry) => entry.decision_tx.send(decision).map_err(|_| {
            format!(
                "resolve_pending_decision: receiver for session '{}' already dropped",
                session_id
            )
        }),
        None => Err(format!(
            "resolve_pending_decision: unknown session_id '{}'",
            session_id
        )),
    }
}

/// Tauri command: resolve a pending association with Approve (`true`).
#[tauri::command]
pub async fn bridge_approve(app: tauri::AppHandle, session_id: String) -> Result<(), String> {
    let pending_state = app.state::<PendingAssociationMap>();
    resolve_pending_decision(&pending_state.0, &session_id, true)
}

/// Tauri command: resolve a pending association with Deny (`false`).
#[tauri::command]
pub async fn bridge_deny(app: tauri::AppHandle, session_id: String) -> Result<(), String> {
    let pending_state = app.state::<PendingAssociationMap>();
    resolve_pending_decision(&pending_state.0, &session_id, false)
}

// ---------------------------------------------------------------------------
// Phase 16: bridge_rpc_response + focus_app — RPC dispatch commands
// ---------------------------------------------------------------------------

/// Tauri command: the renderer's answer to a `bridge://rpc-request` — resolves the matching
/// `PendingRpcMap` oneshot with the plaintext result. Thin AppHandle-extracting wrapper over
/// `resolve_pending_rpc`, mirroring `bridge_approve`'s shape.
///
/// `result` is the renderer's plaintext JSON (e.g. `{candidates:[...]}`, `{secret:"..."}`, or a
/// typed error object like `{code:"vault-locked"}`) — the renderer is the source of truth for
/// lock state (D-09) and decides success vs. typed-error shape itself; this command simply
/// unblocks the waiting Rust dispatch with whatever JSON it was given.
#[tauri::command]
pub async fn bridge_rpc_response(
    app: tauri::AppHandle,
    request_id: String,
    result: serde_json::Value,
) -> Result<(), String> {
    let pending_state = app.state::<PendingRpcMap>();
    resolve_pending_rpc(&pending_state.0, &request_id, Ok(result))
}

/// Best-effort Windows window focus-raise (D-11) — shared by the `focus-app` rpc method (Rust-
/// side, no vault touch) and the `focus_app` Tauri command (invoked by the popup's "Unlock
/// Cryptiq" button). Windows' foreground-lock restrictions mean this can silently no-op if
/// Cryptiq is not the OS-designated "allowed to steal focus" process — the hard guarantee stays
/// the locked message shown regardless; this is pure convenience, never a blocking dependency.
fn focus_app_best_effort(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Tauri command: best-effort raise/focus the main window (D-11). Never touches the vault or
/// auth state — a bonus convenience only.
#[tauri::command]
pub fn focus_app(app: tauri::AppHandle) -> Result<(), String> {
    focus_app_best_effort(&app);
    Ok(())
}

/// List every persisted browser-extension association (mirrors `peers_json_read`).
#[tauri::command]
pub fn extension_peers_list(config_dir: String) -> Result<Vec<ExtensionPeerRecord>, String> {
    let doc = read_extension_peers_json(&config_dir)?;
    Ok(doc.associations)
}

/// Rename an association's LOCAL label (D-12 local-rename precedent) — never touches the
/// `pairing_token_hash`/`client_public_key`/`paired_at` fields, only `label`.
fn rename_extension_peer(config_dir: &str, client_id: &str, label: &str) -> Result<(), String> {
    let mut doc = read_extension_peers_json(config_dir)?;
    let record = doc
        .associations
        .iter_mut()
        .find(|a| a.client_id == client_id)
        .ok_or_else(|| {
            format!(
                "rename_extension_peer: association '{}' not found in extension-peers.json",
                client_id
            )
        })?;
    record.label = label.to_string();
    write_extension_peers_json_atomic(config_dir, &doc)
}

/// Tauri command: rename an association's local label.
#[tauri::command]
pub fn rename_extension_association(
    config_dir: String,
    client_id: String,
    label: String,
) -> Result<(), String> {
    rename_extension_peer(&config_dir, &client_id, &label)
}

/// Revoke one association AND evict its `client_public_key` from `cache` so the cut is
/// immediate (T-15-03): the revoked extension's very next `rpc` fails `NotAssociated`, never a
/// stale cache hit. Looks up the record's `client_public_key` BEFORE the sidecar rewrite removes
/// it. Never touches `EXTENSION_IDENTITY_SK_TARGET` — `extension_peers::revoke_extension_association`
/// only rewrites the sidecar file (V4 Access Control).
fn revoke_extension_peer_and_evict_cache(
    config_dir: &str,
    cache: &Mutex<HashMap<[u8; 32], CachedPeer>>,
    client_id: &str,
) -> Result<(), String> {
    let doc = read_extension_peers_json(config_dir)?;
    let client_public_key_hex = doc
        .associations
        .iter()
        .find(|a| a.client_id == client_id)
        .map(|a| a.client_public_key.clone());

    revoke_extension_association(config_dir, client_id)?;

    if let Some(hex_key) = client_public_key_hex {
        if let Ok(bytes) = hex_decode(&hex_key) {
            if bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                cache.lock().unwrap().remove(&key);
            }
        }
    }

    Ok(())
}

/// Tauri command: revoke an association and evict it from the live peer-lookup cache.
#[tauri::command]
pub fn revoke_extension_association_cmd(
    app: tauri::AppHandle,
    config_dir: String,
    client_id: String,
) -> Result<(), String> {
    let cache_state = app.state::<ExtensionPeerCache>();
    revoke_extension_peer_and_evict_cache(&config_dir, &cache_state.0, &client_id)
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

    // -----------------------------------------------------------------------
    // Task 1: associate/associate-ok TOFU handshake
    // -----------------------------------------------------------------------

    use crate::commands::pairing::tests::MockCredentialStore;
    use std::sync::Arc;

    fn fresh_config_dir(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("cryptiq_extension_bridge_test_{}", name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir.to_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn test_associate_first_connection_requires_approval_and_persists_nothing_until_decided() {
        let config_dir = fresh_config_dir("assoc_new");
        let store = MockCredentialStore::new();
        let pending_map: Mutex<HashMap<String, PendingAssociation>> = Mutex::new(HashMap::new());
        let cache: Mutex<HashMap<[u8; 32], CachedPeer>> = Mutex::new(HashMap::new());
        let client_public_key = [9u8; 32];

        let emitted = Arc::new(Mutex::new(false));
        let emitted_clone = emitted.clone();

        // Deny immediately once the approval request is "shown" (captured via emit_request).
        let result = process_associate(
            &config_dir,
            &store,
            &pending_map,
            &cache,
            "session-1".to_string(),
            client_public_key,
            "Chrome".to_string(),
            Duration::from_millis(200),
            move |_session_id, _pk, _label| {
                *emitted_clone.lock().unwrap() = true;
            },
        )
        .await;

        assert!(*emitted.lock().unwrap(), "an approval request must be emitted for a new key");
        // No decision was ever sent -> timeout -> denied.
        assert_eq!(result.unwrap_err(), BridgeError::AssociationDenied);

        // NOTHING must be persisted before/without a decision.
        let doc = read_extension_peers_json(&config_dir).unwrap();
        assert!(doc.associations.is_empty(), "no association may be persisted without an approval");
        assert!(pending_map.lock().unwrap().is_empty(), "the pending entry must be dropped after timeout");
    }

    #[tokio::test]
    async fn test_associate_approve_mints_token_persists_hash_and_returns_raw_token_once() {
        let config_dir = fresh_config_dir("assoc_approve");
        let store = MockCredentialStore::new();
        let pending_map: Mutex<HashMap<String, PendingAssociation>> = Mutex::new(HashMap::new());
        let cache: Mutex<HashMap<[u8; 32], CachedPeer>> = Mutex::new(HashMap::new());
        let client_public_key = [11u8; 32];

        // Simulate `bridge_approve`: once the pending entry exists, resolve it with `true`.
        let decision_fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let decision_fired_clone = decision_fired.clone();

        let result = {
            // We can't call the real bridge_approve command (Plan 04) here, so directly grab
            // the decision_tx out of the pending map inside emit_request and fire it — this
            // exercises the EXACT same oneshot resolution path bridge_approve will use.
            let pending_map_ref = &pending_map;
            process_associate(
                &config_dir,
                &store,
                &pending_map,
                &cache,
                "session-2".to_string(),
                client_public_key,
                "Firefox".to_string(),
                Duration::from_secs(5),
                move |session_id, _pk, _label| {
                    let mut map = pending_map_ref.lock().unwrap();
                    if let Some(pending) = map.remove(session_id) {
                        let _ = pending.decision_tx.send(true);
                        decision_fired_clone.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                },
            )
            .await
        };

        assert!(decision_fired.load(std::sync::atomic::Ordering::SeqCst));
        let ok = result.expect("approval must succeed");
        assert_eq!(ok.host_public_key.len(), 32);
        let raw_token = ok.pairing_token.expect("a fresh approval returns the RAW token once");
        assert_eq!(raw_token.len(), 32);

        // The peer-lookup cache must be populated so Task 2's rpc dispatch can find it.
        assert!(cache.lock().unwrap().contains_key(&client_public_key));

        // The durable record must exist and store ONLY the hash.
        let doc = read_extension_peers_json(&config_dir).unwrap();
        assert_eq!(doc.associations.len(), 1);
        let record = &doc.associations[0];
        assert_eq!(record.client_public_key, hex_encode(&client_public_key));
        let expected_hash_hex = hex_encode(&hash_pairing_token(&raw_token));
        assert_eq!(record.pairing_token_hash, expected_hash_hex);
    }

    #[tokio::test]
    async fn test_associate_no_secret_at_rest_raw_token_never_persisted() {
        let config_dir = fresh_config_dir("assoc_no_secret");
        let store = MockCredentialStore::new();
        let pending_map: Mutex<HashMap<String, PendingAssociation>> = Mutex::new(HashMap::new());
        let cache: Mutex<HashMap<[u8; 32], CachedPeer>> = Mutex::new(HashMap::new());
        let client_public_key = [22u8; 32];

        let pending_map_ref = &pending_map;
        let result = process_associate(
            &config_dir,
            &store,
            &pending_map,
            &cache,
            "session-3".to_string(),
            client_public_key,
            "Edge".to_string(),
            Duration::from_secs(5),
            move |session_id, _pk, _label| {
                let mut map = pending_map_ref.lock().unwrap();
                if let Some(pending) = map.remove(session_id) {
                    let _ = pending.decision_tx.send(true);
                }
            },
        )
        .await;

        let ok = result.unwrap();
        let raw_token = ok.pairing_token.unwrap();
        let raw_token_hex = hex_encode(&raw_token);
        let raw_token_b64 = BASE64.encode(raw_token);

        let path = std::path::PathBuf::from(&config_dir)
            .join("cryptiq")
            .join("extension-peers.json");
        let on_disk = std::fs::read_to_string(&path).expect("sidecar must exist");

        assert!(
            !on_disk.contains(&raw_token_hex),
            "the raw pairing token must NEVER appear (hex) in the persisted sidecar"
        );
        assert!(
            !on_disk.contains(&raw_token_b64),
            "the raw pairing token must NEVER appear (base64) in the persisted sidecar"
        );
    }

    #[tokio::test]
    async fn test_associate_deny_persists_nothing_and_drops_pending_entry() {
        let config_dir = fresh_config_dir("assoc_deny");
        let store = MockCredentialStore::new();
        let pending_map: Mutex<HashMap<String, PendingAssociation>> = Mutex::new(HashMap::new());
        let cache: Mutex<HashMap<[u8; 32], CachedPeer>> = Mutex::new(HashMap::new());
        let client_public_key = [33u8; 32];

        let pending_map_ref = &pending_map;
        let result = process_associate(
            &config_dir,
            &store,
            &pending_map,
            &cache,
            "session-4".to_string(),
            client_public_key,
            "Brave".to_string(),
            Duration::from_secs(5),
            move |session_id, _pk, _label| {
                let mut map = pending_map_ref.lock().unwrap();
                if let Some(pending) = map.remove(session_id) {
                    let _ = pending.decision_tx.send(false);
                }
            },
        )
        .await;

        assert_eq!(result.unwrap_err(), BridgeError::AssociationDenied);
        let doc = read_extension_peers_json(&config_dir).unwrap();
        assert!(doc.associations.is_empty());
        assert!(pending_map.lock().unwrap().is_empty());
        assert!(cache.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_associate_already_associated_key_is_silently_trusted_no_prompt() {
        let config_dir = fresh_config_dir("assoc_trusted");
        let store = MockCredentialStore::new();
        let pending_map: Mutex<HashMap<String, PendingAssociation>> = Mutex::new(HashMap::new());
        let cache: Mutex<HashMap<[u8; 32], CachedPeer>> = Mutex::new(HashMap::new());
        let client_public_key = [44u8; 32];

        // Pre-seed an existing association for this key.
        let existing_hash = hash_pairing_token(&[1u8; 32]);
        let doc = ExtensionPeersDoc {
            schema_version: 1,
            associations: vec![ExtensionPeerRecord {
                client_id: "client-existing".to_string(),
                client_public_key: hex_encode(&client_public_key),
                label: "Chrome".to_string(),
                paired_at: "2026-01-01T00:00:00Z".to_string(),
                last_used_at: None,
                pairing_token_hash: hex_encode(&existing_hash),
            }],
        };
        write_extension_peers_json_atomic(&config_dir, &doc).unwrap();

        let emitted = Arc::new(Mutex::new(false));
        let emitted_clone = emitted.clone();

        let result = process_associate(
            &config_dir,
            &store,
            &pending_map,
            &cache,
            "session-5".to_string(),
            client_public_key,
            "Chrome".to_string(),
            Duration::from_secs(5),
            move |_session_id, _pk, _label| {
                *emitted_clone.lock().unwrap() = true;
            },
        )
        .await;

        assert!(
            !*emitted.lock().unwrap(),
            "an ALREADY-associated key must NEVER trigger a new approval prompt (SC-1)"
        );
        let ok = result.expect("already-associated key must be silently trusted");
        assert!(ok.pairing_token.is_none(), "no raw token can be re-derived on the trusted path");

        // Still populates the fast-lookup cache for Task 2.
        let cached = cache.lock().unwrap().get(&client_public_key).copied();
        assert_eq!(cached.unwrap().pairing_token_hash, existing_hash);

        // The persisted doc is untouched (still exactly one association).
        let doc_after = read_extension_peers_json(&config_dir).unwrap();
        assert_eq!(doc_after.associations.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Task 2: crypto_box rpc encrypt/decrypt + token-hash-inside-box constant-time verify
    // -----------------------------------------------------------------------

    fn make_keypair() -> (BoxSecretKey, BoxPublicKey) {
        let sk = BoxSecretKey::generate(&mut BoxOsRng);
        let pk = sk.public_key();
        (sk, pk)
    }

    #[test]
    fn test_crypto_box_round_trip() {
        let (alice_sk, alice_pk) = make_keypair();
        let (bob_sk, bob_pk) = make_keypair();

        let plaintext = br#"{"pairingToken":"anything","rpcType":"noop"}"#;
        let (nonce, ct) = encrypt_rpc_box(&alice_sk, &bob_pk, plaintext);

        // Bob opens using Alice's public key + his own secret key.
        let opened = decrypt_rpc_box(&bob_sk, &alice_pk, &nonce, &ct).expect("must decrypt");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn test_crypto_box_rejects_wrong_key() {
        let (alice_sk, alice_pk) = make_keypair();
        let (_bob_sk, bob_pk) = make_keypair();
        let (mallory_sk, _mallory_pk) = make_keypair();

        // Alice seals a message for Bob.
        let plaintext = b"top secret";
        let (nonce, ct) = encrypt_rpc_box(&alice_sk, &bob_pk, plaintext);

        // Mallory (wrong secret key — she is not Bob) cannot open the box even though she
        // supplies Alice's correct public key; the DH shared secret differs -> AEAD fails.
        let result = decrypt_rpc_box(&mallory_sk, &alice_pk, &nonce, &ct);
        assert_eq!(result.unwrap_err(), BridgeError::InvalidToken);
    }

    #[test]
    fn test_missing_token_rejected() {
        let stored_hash = hash_pairing_token(&[5u8; 32]);
        let plaintext = br#"{"rpcType":"noop"}"#; // no pairingToken field at all
        let result = verify_pairing_token(plaintext, &stored_hash);
        assert_eq!(result.unwrap_err(), BridgeError::NotAssociated);
    }

    #[test]
    fn test_wrong_token_rejected() {
        let correct_token = [7u8; 32];
        let stored_hash = hash_pairing_token(&correct_token);

        let wrong_token = [8u8; 32];
        let inner = serde_json::json!({ "pairingToken": BASE64.encode(wrong_token), "rpcType": "noop" });
        let plaintext = serde_json::to_vec(&inner).unwrap();

        let result = verify_pairing_token(&plaintext, &stored_hash);
        assert_eq!(result.unwrap_err(), BridgeError::InvalidToken);
    }

    #[test]
    fn test_correct_token_accepted() {
        let correct_token = [7u8; 32];
        let stored_hash = hash_pairing_token(&correct_token);

        let inner = serde_json::json!({ "pairingToken": BASE64.encode(correct_token), "rpcType": "noop" });
        let plaintext = serde_json::to_vec(&inner).unwrap();

        let result = verify_pairing_token(&plaintext, &stored_hash).unwrap();
        assert_eq!(result.get("rpcType").unwrap(), "noop");
    }

    #[test]
    fn test_fresh_nonce_per_message() {
        let (alice_sk, _alice_pk) = make_keypair();
        let (_bob_sk, bob_pk) = make_keypair();

        let (nonce1, _ct1) = encrypt_rpc_box(&alice_sk, &bob_pk, b"same plaintext");
        let (nonce2, _ct2) = encrypt_rpc_box(&alice_sk, &bob_pk, b"same plaintext");

        assert_ne!(nonce1, nonce2, "every encrypt call MUST use a fresh CSPRNG nonce");
    }

    #[test]
    fn test_process_rpc_full_pipeline_requires_both_box_open_and_token_match() {
        let (app_sk, app_pk) = make_keypair();
        let (peer_sk, peer_pk) = make_keypair();

        let correct_token = [9u8; 32];
        let stored_hash = hash_pairing_token(&correct_token);

        let inner = serde_json::json!({ "pairingToken": BASE64.encode(correct_token), "rpcType": "match-origin" });
        let plaintext = serde_json::to_vec(&inner).unwrap();
        let (nonce, ct) = encrypt_rpc_box(&peer_sk, &app_pk, &plaintext);

        // Success: correct box + correct token.
        let ok = process_rpc(&app_sk, &peer_pk, &stored_hash, &nonce, &ct).unwrap();
        assert_eq!(ok.get("rpcType").unwrap(), "match-origin");

        // Failure: correct box, but token hash does not match a DIFFERENT stored hash.
        let other_hash = hash_pairing_token(&[10u8; 32]);
        let err = process_rpc(&app_sk, &peer_pk, &other_hash, &nonce, &ct).unwrap_err();
        assert_eq!(err, BridgeError::InvalidToken);

        // Failure: box does not open at all (garbage ciphertext) — never a panic.
        let err2 = process_rpc(&app_sk, &peer_pk, &stored_hash, &nonce, "not-valid-base64!!").unwrap_err();
        assert_eq!(err2, BridgeError::InvalidToken);
    }

    // -----------------------------------------------------------------------
    // Task 3: directional protocol-version-mismatch typed error
    // -----------------------------------------------------------------------

    #[test]
    fn test_version_mismatch_directional_message() {
        let app_outdated = error_response(
            None,
            BridgeError::ProtocolMismatch {
                expected: CURRENT_PROTOCOL_VERSION,
                got: CURRENT_PROTOCOL_VERSION + 1,
            },
        );
        let extension_outdated = error_response(
            None,
            BridgeError::ProtocolMismatch {
                expected: CURRENT_PROTOCOL_VERSION + 1,
                got: CURRENT_PROTOCOL_VERSION,
            },
        );

        let app_code = app_outdated.payload.get("code").unwrap().as_str().unwrap();
        let ext_code = extension_outdated.payload.get("code").unwrap().as_str().unwrap();
        let app_msg = app_outdated.payload.get("message").unwrap().as_str().unwrap();
        let ext_msg = extension_outdated.payload.get("message").unwrap().as_str().unwrap();

        assert_eq!(app_code, "app-outdated");
        assert_eq!(ext_code, "extension-outdated");
        assert_ne!(app_code, ext_code, "the two directions must produce DIFFERENT codes");
        assert_ne!(app_msg, ext_msg, "the two directions must produce DIFFERENT messages");
        assert!(app_msg.contains("update the Cryptiq desktop app") || app_msg.to_lowercase().contains("update"));
        assert!(ext_msg.to_lowercase().contains("extension"));
    }

    #[test]
    fn test_error_response_covers_not_associated_and_invalid_token_codes() {
        let not_associated = error_response(None, BridgeError::NotAssociated);
        let invalid_token = error_response(None, BridgeError::InvalidToken);

        assert_eq!(not_associated.payload.get("code").unwrap(), "not-associated");
        assert_eq!(invalid_token.payload.get("code").unwrap(), "invalid-token");
    }

    // -----------------------------------------------------------------------
    // Task 3 (Phase 16): dispatch_rpc_core round trip — metadata-only, single-secret,
    // locked-gate, and fail-closed-timeout pins (BRIDGE-08 / XSEC-05)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_match_origin_response_has_no_password_field() {
        // Mirrors the associate suite's "assert substring absent from serialized output" style
        // (test_associate_no_secret_at_rest_raw_token_never_persisted) — here pinning that a
        // match-origin dispatch result can NEVER carry a password/secret substring, structurally
        // (SC-1/BRIDGE-08/T-16-01).
        let pending_map: Mutex<HashMap<String, oneshot::Sender<Result<serde_json::Value, BridgeError>>>> =
            Mutex::new(HashMap::new());

        let result = dispatch_rpc_core(
            &pending_map,
            "req-match-1".to_string(),
            Duration::from_secs(5),
            "match-origin",
            serde_json::json!({ "origin": "https://accounts.google.com" }),
            |request_id, _method, _params| {
                // Simulate the renderer's matchByOrigin() answer arriving via
                // bridge_rpc_response -> resolve_pending_rpc.
                let candidates = serde_json::json!({
                    "candidates": [
                        { "id": "e1", "title": "Google", "username": "alice@example.com", "domainHint": "google.com" },
                        { "id": "e2", "title": "Google Work", "username": "alice.work@example.com", "domainHint": "google.com" },
                    ]
                });
                let _ = resolve_pending_rpc(&pending_map, request_id, Ok(candidates));
            },
        )
        .await
        .expect("dispatch must succeed");

        let serialized = serde_json::to_string(&result).unwrap();
        assert!(
            !serialized.to_lowercase().contains("password"),
            "match-origin dispatch result must never contain a password field/substring"
        );
        assert!(
            !serialized.to_lowercase().contains("secret"),
            "match-origin dispatch result must never contain a secret field/substring"
        );
        // Sanity: the metadata itself round-tripped correctly.
        assert_eq!(result["candidates"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_fill_entry_returns_only_requested_secret() {
        // Pins BRIDGE-08: fill-entry returns EXACTLY the requested entry's secret — no other
        // candidate's secret ever crosses, even though multiple candidates exist in the vault.
        let pending_map: Mutex<HashMap<String, oneshot::Sender<Result<serde_json::Value, BridgeError>>>> =
            Mutex::new(HashMap::new());

        let requested_secret = "only-e1-secret-value";
        let other_candidate_secret = "e2-secret-must-never-appear";
        let pending_map_ref = &pending_map;

        let result = dispatch_rpc_core(
            &pending_map,
            "req-fill-1".to_string(),
            Duration::from_secs(5),
            "fill-entry",
            serde_json::json!({ "entryId": "e1" }),
            |request_id, _method, params| {
                // Renderer-side handler would look up ONLY the requested entryId (V4 access
                // control: id exists AND deletedAt === null) and return exactly its secret.
                assert_eq!(params.get("entryId").unwrap(), "e1");
                let secret_response = serde_json::json!({ "secret": requested_secret });
                let _ = resolve_pending_rpc(pending_map_ref, request_id, Ok(secret_response));
            },
        )
        .await
        .expect("dispatch must succeed");

        assert_eq!(result.get("secret").unwrap(), requested_secret);
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(
            !serialized.contains(other_candidate_secret),
            "fill-entry must never leak another candidate's secret"
        );
    }

    // -----------------------------------------------------------------------
    // Phase 19 Plan 01: save-or-update-entry / generate-password / score-password
    // routing parity — the widened match arm is a generic whitelist (no new
    // Rust-side logic), so these tests pin ROUTING only: the method name reaches
    // the renderer via dispatch_rpc_method and the resolved JSON round-trips.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_save_or_update_entry_routes_through_dispatch_rpc_method() {
        let pending_map: Mutex<HashMap<String, oneshot::Sender<Result<serde_json::Value, BridgeError>>>> =
            Mutex::new(HashMap::new());

        let result = dispatch_rpc_core(
            &pending_map,
            "req-save-1".to_string(),
            Duration::from_secs(5),
            "save-or-update-entry",
            serde_json::json!({ "mode": "new", "title": "Example", "password": "x" }),
            |request_id, _method, params| {
                assert_eq!(params.get("mode").unwrap(), "new");
                let _ = resolve_pending_rpc(
                    &pending_map,
                    request_id,
                    Ok(serde_json::json!({ "ok": true, "entryId": "e1" })),
                );
            },
        )
        .await
        .expect("dispatch must succeed");

        assert_eq!(result.get("ok").unwrap(), true);
        assert_eq!(result.get("entryId").unwrap(), "e1");
    }

    #[tokio::test]
    async fn test_generate_password_routes_through_dispatch_rpc_method() {
        let pending_map: Mutex<HashMap<String, oneshot::Sender<Result<serde_json::Value, BridgeError>>>> =
            Mutex::new(HashMap::new());

        let result = dispatch_rpc_core(
            &pending_map,
            "req-gen-1".to_string(),
            Duration::from_secs(5),
            "generate-password",
            serde_json::json!({}),
            |request_id, _method, _params| {
                let _ =
                    resolve_pending_rpc(&pending_map, request_id, Ok(serde_json::json!({ "password": "a-generated-password" })));
            },
        )
        .await
        .expect("dispatch must succeed");

        let password = result.get("password").unwrap().as_str().unwrap();
        assert!(!password.is_empty());
    }

    #[tokio::test]
    async fn test_score_password_routes_through_dispatch_rpc_method() {
        let pending_map: Mutex<HashMap<String, oneshot::Sender<Result<serde_json::Value, BridgeError>>>> =
            Mutex::new(HashMap::new());

        let result = dispatch_rpc_core(
            &pending_map,
            "req-score-1".to_string(),
            Duration::from_secs(5),
            "score-password",
            serde_json::json!({ "password": "hunter2" }),
            |request_id, _method, params| {
                assert_eq!(params.get("password").unwrap(), "hunter2");
                let _ = resolve_pending_rpc(&pending_map, request_id, Ok(serde_json::json!({ "score": 2 })));
            },
        )
        .await
        .expect("dispatch must succeed");

        assert_eq!(result.get("score").unwrap(), 2);
    }

    #[tokio::test]
    async fn test_search_entries_routes_through_dispatch_rpc_method() {
        let pending_map: Mutex<HashMap<String, oneshot::Sender<Result<serde_json::Value, BridgeError>>>> =
            Mutex::new(HashMap::new());

        let result = dispatch_rpc_core(
            &pending_map,
            "req-search-1".to_string(),
            Duration::from_secs(5),
            "search-entries",
            serde_json::json!({ "query": "example" }),
            |request_id, _method, params| {
                assert_eq!(params.get("query").unwrap(), "example");
                let _ = resolve_pending_rpc(&pending_map, request_id, Ok(serde_json::json!({ "results": [] })));
            },
        )
        .await
        .expect("dispatch must succeed");

        assert!(result.get("results").unwrap().is_array());
    }

    #[tokio::test]
    async fn test_copy_field_routes_through_dispatch_rpc_method() {
        let pending_map: Mutex<HashMap<String, oneshot::Sender<Result<serde_json::Value, BridgeError>>>> =
            Mutex::new(HashMap::new());

        let result = dispatch_rpc_core(
            &pending_map,
            "req-copy-1".to_string(),
            Duration::from_secs(5),
            "copy-field",
            serde_json::json!({ "entryId": "e1", "field": "password" }),
            |request_id, _method, params| {
                assert_eq!(params.get("entryId").unwrap(), "e1");
                assert_eq!(params.get("field").unwrap(), "password");
                let _ = resolve_pending_rpc(&pending_map, request_id, Ok(serde_json::json!({ "ok": true })));
            },
        )
        .await
        .expect("dispatch must succeed");

        assert_eq!(result.get("ok").unwrap(), true);
    }

    #[tokio::test]
    async fn test_rpc_dispatch_locked_vault_returns_typed_error() {
        // Pins XSEC-05/D-09: a locked-vault renderer response maps to the typed `vault-locked`
        // error code via the SAME single error_response mapping site, carrying no data.
        let pending_map: Mutex<HashMap<String, oneshot::Sender<Result<serde_json::Value, BridgeError>>>> =
            Mutex::new(HashMap::new());

        let result = dispatch_rpc_core(
            &pending_map,
            "req-locked-1".to_string(),
            Duration::from_secs(5),
            "match-origin",
            serde_json::json!({ "origin": "https://example.com" }),
            |request_id, _method, _params| {
                // Renderer's isUnlocked check fails — it answers with a typed code, not data
                // (D-09), via the exact bridge_rpc_response/resolve_pending_rpc path.
                let locked_response = serde_json::json!({ "code": "vault-locked" });
                let _ = resolve_pending_rpc(&pending_map, request_id, Ok(locked_response));
            },
        )
        .await
        .expect("dispatch itself succeeds — the LOCK state is carried in the result payload");

        let mapped = map_renderer_result_to_typed_error(&result);
        assert_eq!(mapped, Some(BridgeError::VaultLocked));

        let envelope = error_response(Some("req-locked-1".to_string()), mapped.unwrap());
        assert_eq!(envelope.payload.get("code").unwrap(), "vault-locked");
        assert!(envelope.payload.get("message").unwrap().as_str().unwrap().len() > 0);
        // Carries no data — only `code` and `message` keys.
        let obj = envelope.payload.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
        keys.sort();
        assert_eq!(keys, vec!["code", "message"]);
    }

    #[tokio::test]
    async fn test_rpc_dispatch_timeout_fails_closed() {
        // Pins T-16-06: a renderer that never answers fails closed via a bounded timeout — the
        // pipe is never hung — and the pending entry is cleaned up (no leaked oneshot sender).
        let pending_map: Mutex<HashMap<String, oneshot::Sender<Result<serde_json::Value, BridgeError>>>> =
            Mutex::new(HashMap::new());

        let started = std::time::Instant::now();
        let result = dispatch_rpc_core(
            &pending_map,
            "req-timeout-1".to_string(),
            Duration::from_millis(100), // short bound so this test runs fast
            "match-origin",
            serde_json::json!({ "origin": "https://example.com" }),
            |_request_id, _method, _params| {
                // Deliberately never resolves the oneshot — simulates a crashed/unmounted
                // renderer listener.
            },
        )
        .await;

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the timeout bound must be honored, not the full BRIDGE_READ_TIMEOUT or longer"
        );
        match result {
            Err(BridgeError::ProtocolError(msg)) => {
                assert!(msg.contains("timed out"));
            }
            other => panic!("expected a timed-out ProtocolError, got {:?}", other),
        }
        assert!(
            pending_map.lock().unwrap().is_empty(),
            "the pending entry must be removed after a timeout — no leaked sender"
        );
    }

    // -----------------------------------------------------------------------
    // Plan 04: bridge_approve/bridge_deny + list/rename/revoke command-layer helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_pending_decision_approve_resolves_true_and_consumes_entry() {
        let pending_map: Mutex<HashMap<String, PendingAssociation>> = Mutex::new(HashMap::new());
        let (decision_tx, mut decision_rx) = oneshot::channel::<bool>();
        pending_map.lock().unwrap().insert(
            "session-approve".to_string(),
            PendingAssociation {
                client_public_key: [1u8; 32],
                label: "Chrome".to_string(),
                decision_tx,
            },
        );

        resolve_pending_decision(&pending_map, "session-approve", true)
            .expect("resolving a known session must succeed");

        // The oneshot must have been fired with `true` (bridge_approve semantics).
        assert_eq!(decision_rx.try_recv(), Ok(true));
        // A subsequent lookup finds the entry consumed (removed from the map).
        assert!(pending_map.lock().unwrap().get("session-approve").is_none());
    }

    #[test]
    fn test_resolve_pending_decision_deny_resolves_false() {
        let pending_map: Mutex<HashMap<String, PendingAssociation>> = Mutex::new(HashMap::new());
        let (decision_tx, mut decision_rx) = oneshot::channel::<bool>();
        pending_map.lock().unwrap().insert(
            "session-deny".to_string(),
            PendingAssociation {
                client_public_key: [2u8; 32],
                label: "Firefox".to_string(),
                decision_tx,
            },
        );

        resolve_pending_decision(&pending_map, "session-deny", false)
            .expect("resolving a known session must succeed");

        assert_eq!(decision_rx.try_recv(), Ok(false));
        assert!(pending_map.lock().unwrap().is_empty());
    }

    #[test]
    fn test_resolve_pending_decision_unknown_session_errs_no_panic() {
        let pending_map: Mutex<HashMap<String, PendingAssociation>> = Mutex::new(HashMap::new());
        let result = resolve_pending_decision(&pending_map, "does-not-exist", true);
        assert!(result.is_err(), "an unknown session_id must return Err, never panic");
    }

    #[test]
    fn test_extension_peers_list_returns_persisted_associations() {
        let config_dir = fresh_config_dir("cmd_list");
        let doc = ExtensionPeersDoc {
            schema_version: 1,
            associations: vec![
                ExtensionPeerRecord {
                    client_id: "client-list-1".to_string(),
                    client_public_key: hex_encode(&[5u8; 32]),
                    label: "Chrome".to_string(),
                    paired_at: "2026-01-01T00:00:00Z".to_string(),
                    last_used_at: None,
                    pairing_token_hash: hex_encode(&hash_pairing_token(&[6u8; 32])),
                },
            ],
        };
        write_extension_peers_json_atomic(&config_dir, &doc).unwrap();

        let listed = extension_peers_list(config_dir).expect("list must succeed");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].client_id, "client-list-1");
    }

    #[test]
    fn test_rename_extension_peer_updates_label_and_persists() {
        let config_dir = fresh_config_dir("cmd_rename");
        let doc = ExtensionPeersDoc {
            schema_version: 1,
            associations: vec![ExtensionPeerRecord {
                client_id: "client-rename-1".to_string(),
                client_public_key: hex_encode(&[7u8; 32]),
                label: "Unknown browser".to_string(),
                paired_at: "2026-01-01T00:00:00Z".to_string(),
                last_used_at: None,
                pairing_token_hash: hex_encode(&hash_pairing_token(&[8u8; 32])),
            }],
        };
        write_extension_peers_json_atomic(&config_dir, &doc).unwrap();

        rename_extension_peer(&config_dir, "client-rename-1", "My Chrome")
            .expect("rename must succeed");

        let after = read_extension_peers_json(&config_dir).unwrap();
        assert_eq!(after.associations[0].label, "My Chrome");

        // Renaming an unknown client_id must error, not silently succeed.
        let missing = rename_extension_peer(&config_dir, "no-such-client", "X");
        assert!(missing.is_err());
    }

    #[test]
    fn test_revoke_extension_peer_and_evict_cache_removes_record_and_cache_entry() {
        let config_dir = fresh_config_dir("cmd_revoke");
        let client_public_key = [9u8; 32];
        let store = MockCredentialStore::new();
        store
            .write(EXTENSION_IDENTITY_SK_TARGET, &[42u8; 32])
            .expect("seed the shared app identity key");

        let doc = ExtensionPeersDoc {
            schema_version: 1,
            associations: vec![ExtensionPeerRecord {
                client_id: "client-revoke-1".to_string(),
                client_public_key: hex_encode(&client_public_key),
                label: "Edge".to_string(),
                paired_at: "2026-01-01T00:00:00Z".to_string(),
                last_used_at: None,
                pairing_token_hash: hex_encode(&hash_pairing_token(&[10u8; 32])),
            }],
        };
        write_extension_peers_json_atomic(&config_dir, &doc).unwrap();

        let cache: Mutex<HashMap<[u8; 32], CachedPeer>> = Mutex::new(HashMap::new());
        cache.lock().unwrap().insert(
            client_public_key,
            CachedPeer {
                pairing_token_hash: hash_pairing_token(&[10u8; 32]),
            },
        );

        revoke_extension_peer_and_evict_cache(&config_dir, &cache, "client-revoke-1")
            .expect("revoke must succeed");

        // The sidecar record is gone.
        let after = read_extension_peers_json(&config_dir).unwrap();
        assert!(after.associations.is_empty());

        // The cache entry is evicted — a follow-up auth check (cache lookup) reports
        // NotAssociated (the caller sees `None`, matching handle_rpc_message's cache miss path).
        assert!(
            cache.lock().unwrap().get(&client_public_key).is_none(),
            "revoke must evict the peer-lookup cache entry so the next rpc is NotAssociated"
        );

        // The shared app identity key must survive (V4 Access Control / T-15-01).
        assert!(
            store.contains(EXTENSION_IDENTITY_SK_TARGET),
            "revoke must NEVER delete the shared app identity key"
        );
    }
}
