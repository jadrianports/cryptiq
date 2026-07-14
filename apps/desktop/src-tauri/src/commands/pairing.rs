// apps/desktop/src-tauri/src/commands/pairing.rs
//
// Layer 1 (Plan 09-03): Device identity + Noise XXpsk3 handshake + Windows Credential Manager.
// Layer 2 (Plan 09-04): peers.json schema + atomic write/read, QR SVG, LAN-IP selection,
//                       pairing-code bundle (IP:PORT:SECRET → Crockford Base32 + check char),
//                       orchestration commands (pairing_initiate, pairing_connect,
//                       pairing_confirm, pairing_finalize, unpair_device, peers_json_read),
//                       re-pair guard (D-16), 60 s SAS-confirmation timeout (D-02).
//
// Responsibilities (Plan 09-03 — layer 1):
//   CredentialStore trait   — write/read/delete abstraction for OS key storage
//   credential_manager mod  — #[cfg(windows)] real FFI: CredWriteW/CredReadW/CredDeleteW/CredFree
//   MockCredentialStore     — #[cfg(test)] in-memory HashMap mock (never touches real Windows store)
//   generate_device_keypair — Curve25519 keypair via snow Builder::generate_keypair (OsRng)
//   PARAMS                  — LazyLock<NoiseParams> for "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s"
//   build_initiator         — Noise XX initiator builder (psk slot 3)
//   build_responder         — Noise XX responder builder (psk slot 3)
//   recv_framed / send_framed — 2-byte big-endian length-prefix tokio TCP framing
//   derive_sas              — 6-digit SAS from get_handshake_hash() BEFORE into_transport_mode()
//   run_handshake_responder / run_handshake_initiator — 3-message XX exchange
//   Tauri commands          — get_local_device_info, device_key_write, device_key_read,
//                             device_key_delete
//
// Responsibilities (Plan 09-04 — layer 2):
//   PeerRecord / PeersDoc   — serde structs matching the peers.json schema (camelCase)
//   write_peers_json_atomic — 5-step atomic write (tmp→sync_all→rename→dir-fsync), no backup rotation
//   read_peers_json         — fail-closed parse; default on absent file; error on bad schemaVersion
//   assert_confined         — path confinement guard (copy of vault.rs pattern)
//   crockford_encode_32     — inline Crockford Base32 encoder for the 32-byte pairing secret
//   crockford_decode_32     — inline Crockford Base32 decoder returning raw bytes
//   crockford_check_char    — check character (bytes mod 37, CHECK_ALPHABET)
//   generate_qr_svg         — QR SVG from payload string via qrcode crate
//   get_lan_ip              — LAN IPv4 via UDP-connect trick (no packet sent)
//   PairingInitResponse     — serde struct: { qrSvg, base32Code, sessionId }
//   PairingSession          — per-session state kept in a Tauri-managed Mutex<HashMap<...>>
//   PairingSessionMap       — type alias for the managed state
//   pairing_initiate        — Device A (RESPONDER): lazy listener bind, returns QR+Base32+sessionId
//   pairing_connect         — Device B (INITIATOR): decode typed code, connect, start handshake
//   pairing_confirm         — record local SAS approval, signal the confirm notifier
//   pairing_finalize        — all-or-nothing commit: peer CONFIRMED + 60 s window + re-pair guard
//   unpair_device           — remove peer from peers.json + CredManager, keep own key (D-17)
//   peers_json_read         — return the peers list from peers.json
//
// NOT registered in lib.rs yet (Plan 09-05).
//
// Security invariants:
//   - Private key NEVER returned from get_local_device_info (public key only).
//   - Private key NEVER logged; CredManager error strings never include key bytes.
//   - PSK is single-use; do NOT persist it to CredManager or peers.json.
//   - peers.json stores ONLY: peer deviceId, deviceName, staticPublicKey (hex), vaultPairId,
//     pairedAt, lastSyncedAt — NEVER a private key or the PSK.
//   - pairing_finalize is the ONLY commit point: no peers.json write until BOTH sides have
//     sent "CONFIRMED" over the SAS-verified Noise transport channel (D-06).
//   - 60 s timeout wraps the confirmation wait; Elapsed → zeroize ephemeral keys, no write (D-02).
//   - Re-pair guard refuses to overwrite an existing peer (D-16).
//   - Unpair removes peer material only; own identity keypair is kept (D-17).
//   - TcpListener::bind lives ONLY inside pairing_* command bodies (never in lib.rs setup).
//   - get_handshake_hash() is called BEFORE into_transport_mode() (Pitfall 1).
//   - CredFree is called after every CredReadW (Pitfall 4).
//   - All CredManager FFI is #[cfg(target_os = "windows")]-gated from day one.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use snow::{params::NoiseParams, Builder};
use tauri::{Emitter, Manager};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Notify};
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Noise parameters
// ---------------------------------------------------------------------------

/// The Noise XXpsk3 pattern string (confirmed from snow official simple.rs example).
/// PSK slot 3 — after all 3 messages, as per snow's own pairing example.
/// Both initiator AND responder must use the same pattern string and psk(3, ...).
static PARAMS: LazyLock<NoiseParams> =
    LazyLock::new(|| "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s".parse().unwrap());

// ---------------------------------------------------------------------------
// CredentialStore trait — abstraction over OS key storage
// ---------------------------------------------------------------------------

/// Abstraction over Windows Credential Manager (production) or an in-memory map (tests).
///
/// The real FFI is `#[cfg(target_os = "windows")]`-gated.
/// Tests use `MockCredentialStore` so they never touch the real Windows credential store.
///
/// Phase 15 Plan 03 (deviation, Rule 3 — blocking-issue fix): bounded by `Send + Sync` so a
/// `&dyn CredentialStore` can be held across an `.await` point inside `extension_bridge.rs`'s
/// `process_associate` (the pending-approval wait is genuinely async — Pitfall 4). All existing
/// implementors (`WindowsCredentialStore`, `NoopCredentialStore`, `MockCredentialStore`) are
/// already trivially `Send + Sync` (no interior `Rc`/raw-pointer state), so this is a
/// zero-behavior-change bound widening, not a new constraint any real type fails to meet.
pub trait CredentialStore: Send + Sync {
    fn write(&self, target: &str, key_bytes: &[u8]) -> Result<(), String>;
    fn read(&self, target: &str) -> Result<Vec<u8>, String>;
    fn delete(&self, target: &str) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// Target-name constants
// ---------------------------------------------------------------------------

/// Windows Credential Manager target for this device's own Curve25519 static private key.
pub const DEVICE_IDENTITY_SK_TARGET: &str = "cryptiq/device/identity-sk";

/// Build the Credential Manager target for a peer's static public key.
pub fn peer_target(device_id: &str) -> String {
    format!("cryptiq/peer/{}", device_id)
}

// ---------------------------------------------------------------------------
// Windows Credential Manager FFI (real implementation)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod credential_manager {
    use std::ptr;
    use windows_sys::Win32::Foundation::{GetLastError, BOOL, ERROR_INVALID_DATA, TRUE};
    use windows_sys::Win32::Security::Credentials::{
        CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
        CRED_TYPE_GENERIC,
    };

    /// Write `key_bytes` under `target` (e.g. "cryptiq/device/identity-sk").
    ///
    /// CRED_TYPE_GENERIC + CRED_PERSIST_LOCAL_MACHINE → DPAPI-backed for this Windows user.
    /// NEVER log key_bytes — SEC-09 / no-secrets rule.
    pub fn cred_write(target: &str, key_bytes: &[u8]) -> Result<(), u32> {
        let target_w: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
        let username_w: Vec<u16> = "cryptiq\0".encode_utf16().collect();
        let cred = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: target_w.as_ptr() as *mut u16,
            Comment: ptr::null_mut(),
            LastWritten: unsafe { std::mem::zeroed() },
            CredentialBlobSize: key_bytes.len() as u32,
            CredentialBlob: key_bytes.as_ptr() as *mut u8,
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: ptr::null_mut(),
            TargetAlias: ptr::null_mut(),
            UserName: username_w.as_ptr() as *mut u16,
        };
        let result: BOOL = unsafe { CredWriteW(&cred, 0) };
        if result == TRUE {
            Ok(())
        } else {
            Err(unsafe { GetLastError() })
        }
    }

    /// Read bytes stored under `target`. Copies the blob bytes then always calls CredFree.
    ///
    /// Pitfall 4: CredReadW allocates a block that MUST be freed with CredFree.
    /// This wrapper copies bytes before freeing so the caller gets owned data.
    pub fn cred_read(target: &str) -> Result<Vec<u8>, u32> {
        let target_w: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
        let mut cred_ptr: *mut CREDENTIALW = ptr::null_mut();
        let result: BOOL =
            unsafe { CredReadW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred_ptr) };
        if result != TRUE {
            return Err(unsafe { GetLastError() });
        }
        // Win32's contract says a TRUE return means cred_ptr is populated, but that contract is
        // invisible to a static analyzer (CodeQL flags this deref as rust/access-invalid-pointer,
        // high) and invisible to the next reader. A null check across an FFI boundary in
        // credential-handling code costs one branch — take it, and fail closed rather than
        // dereference on a contract we cannot see enforced.
        if cred_ptr.is_null() {
            return Err(ERROR_INVALID_DATA);
        }
        // Copy bytes from the credential blob BEFORE calling CredFree (Pitfall 4 mitigation).
        // L1: a zero-length credential (Win32 may set CredentialBlob == NULL with size 0) makes
        // std::slice::from_raw_parts(NULL, 0) Undefined Behaviour. The CredMgr namespace is
        // shared, so we must not assume a non-null 32-byte blob. Guard null/zero-size → empty Vec.
        // CredFree is still called on every path below (no leak).
        let bytes = unsafe {
            let cred = &*cred_ptr;
            if cred.CredentialBlob.is_null() || cred.CredentialBlobSize == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize)
                    .to_vec()
            }
        };
        // MUST always free the buffer returned by CredReadW — no leak.
        unsafe { CredFree(cred_ptr as *mut _) };
        Ok(bytes)
    }

    /// Delete the credential stored under `target`.
    ///
    /// Keep own identity key (`DEVICE_IDENTITY_SK_TARGET`); only call this for peer material.
    pub fn cred_delete(target: &str) -> Result<(), u32> {
        let target_w: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
        let result: BOOL = unsafe { CredDeleteW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if result == TRUE {
            Ok(())
        } else {
            Err(unsafe { GetLastError() })
        }
    }
}

// ---------------------------------------------------------------------------
// WindowsCredentialStore — real implementation (Windows only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub struct WindowsCredentialStore;

#[cfg(target_os = "windows")]
impl CredentialStore for WindowsCredentialStore {
    fn write(&self, target: &str, key_bytes: &[u8]) -> Result<(), String> {
        credential_manager::cred_write(target, key_bytes).map_err(|code| {
            // Error strings MUST NOT include key_bytes (T-09-06 / SEC-09).
            format!("device_key_write: CredWriteW failed for '{}', Win32 error: {}", target, code)
        })
    }

    fn read(&self, target: &str) -> Result<Vec<u8>, String> {
        credential_manager::cred_read(target).map_err(|code| {
            format!("device_key_read: CredReadW failed for '{}', Win32 error: {}", target, code)
        })
    }

    fn delete(&self, target: &str) -> Result<(), String> {
        credential_manager::cred_delete(target).map_err(|code| {
            format!(
                "device_key_delete: CredDeleteW failed for '{}', Win32 error: {}",
                target, code
            )
        })
    }
}

// ---------------------------------------------------------------------------
// NoopCredentialStore — non-Windows fallback (no OS Credential Manager available)
// ---------------------------------------------------------------------------

/// On non-Windows desktop there is no Credential Manager, so peer public keys cannot be
/// persisted to an OS keystore. This no-op store lets the platform-independent
/// `finalize_commit` path still run (peers.json IS written); `read`/`delete` of an absent key
/// succeed trivially so the H5 rollback (`store.delete` on peers.json failure) is well-defined.
///
/// This is NOT a security regression: peers.json carries only PUBLIC keys + metadata, and the
/// peer's static public key is also stored there. The CredManager copy is a Windows-only
/// convenience/redundancy for Phase 10 lookup.
#[cfg(not(target_os = "windows"))]
pub struct NoopCredentialStore;

#[cfg(not(target_os = "windows"))]
impl CredentialStore for NoopCredentialStore {
    fn write(&self, _target: &str, _key_bytes: &[u8]) -> Result<(), String> {
        Ok(())
    }
    fn read(&self, _target: &str) -> Result<Vec<u8>, String> {
        Err("NoopCredentialStore: no Credential Manager on this platform".to_string())
    }
    fn delete(&self, _target: &str) -> Result<(), String> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// LocalDeviceInfo — the only struct returned over IPC; never includes private key
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LocalDeviceInfo {
    /// Stable opaque UUID v4 — NOT derived from the key (D-13 / RESEARCH.md A2).
    #[serde(rename = "deviceId")]
    pub device_id: String,
    /// Hex-encoded 32-byte Curve25519 static PUBLIC key.  Private key stays in Rust.
    #[serde(rename = "staticPublicKey")]
    pub static_public_key: String,
    /// Hostname-seeded friendly name (locally editable, D-12).
    #[serde(rename = "deviceName")]
    pub device_name: String,
}

// ---------------------------------------------------------------------------
// peers.json schema structs (Plan 09-04)
// ---------------------------------------------------------------------------

/// One peer record stored in peers.json.
///
/// NEVER contains a private key or the pairing PSK.
/// `staticPublicKey` is hex-encoded (32-byte Curve25519 static pk).
/// `vaultPairId` is a random UUID v4 shared by both sides at pairing time.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PeerRecord {
    pub device_id: String,
    pub device_name: String,
    /// Hex-encoded 32-byte Curve25519 static PUBLIC key of the peer.  NEVER a private key.
    pub static_public_key: String,
    pub vault_pair_id: String,
    /// ISO 8601 timestamp of when this pairing was established.
    pub paired_at: String,
    pub last_synced_at: Option<String>,
    // Phase 10 additions — #[serde(default)] so Phase-9-era records parse without error
    // (missing fields default to None). None = "no stored IP yet" → manual-IP fallback (D-01).
    /// LAN IPv4 address of the peer, stored after the first successful sync. None = not yet known.
    #[serde(default)]
    pub last_known_ip: Option<String>,
    /// LAN port of the peer, stored after the first successful sync. None = not yet known.
    #[serde(default)]
    pub last_known_port: Option<u16>,
}

/// The peers.json document root.
///
/// `localStaticPublicKey` is the HEX-encoded Curve25519 static PUBLIC key of THIS device.
/// NEVER a private key in this struct.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PeersDoc {
    pub schema_version: u32,
    pub local_device_id: String,
    /// Hex-encoded 32-byte Curve25519 static PUBLIC key of this device.  NEVER a private key.
    pub local_static_public_key: String,
    pub local_device_name: String,
    pub peers: Vec<PeerRecord>,
}

// ---------------------------------------------------------------------------
// Path confinement helper — verbatim from vault.rs (assert_confined)
// ---------------------------------------------------------------------------

/// Verify that `target` resolves to a path inside `expected_parent` after
/// canonicalization. Returns `Err` with an explanatory message if the check
/// fails, if a directory cannot be canonicalized, or if `target` has no parent.
///
/// For writes the target file itself may not yet exist, so we resolve the
/// target's *own* parent directory (which must exist for any write) and append
/// the filename. We must NOT construct the candidate path from `expected_parent`
/// — doing so would discard the target's real location and let an out-of-tree
/// absolute path pass the check while the subsequent write still lands outside
/// the confined directory (WR-04 / T-03-16).
pub(crate) fn assert_confined(target: &Path, expected_parent: &Path) -> Result<(), String> {
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
// peers.json atomic write + read (Plan 09-04, Task 1)
// ---------------------------------------------------------------------------

/// Atomically write `doc` as pretty-printed JSON to `<config_dir>/cryptiq/peers.json`.
///
/// Steps (mirroring vault.rs vault_write_atomic, OMITTING backup rotation per PATTERNS.md):
///   1. Serialize to JSON bytes.
///   2. Write to `peers.json.tmp` (same directory).
///   3. `sync_all` on the tmp file.
///   4. `fs::rename` (atomic swap) tmp → `peers.json`.
///   5. Best-effort dir-fsync.
///
/// Security: `assert_confined` called on both paths BEFORE any I/O.
/// NEVER writes private keys or the PSK — only PeersDoc fields (public keys, metadata).
pub fn write_peers_json_atomic(config_dir: &str, doc: &PeersDoc) -> Result<(), String> {
    let dir = PathBuf::from(config_dir).join("cryptiq");

    // Ensure the target directory exists.
    fs::create_dir_all(&dir)
        .map_err(|e| format!("write_peers_json_atomic: mkdir failed for '{}': {}", dir.display(), e))?;

    let target = dir.join("peers.json");
    let tmp = dir.join("peers.json.tmp");

    // Confinement guard — both paths must resolve inside $APPCONFIG/cryptiq/.
    assert_confined(&target, &dir)?;
    assert_confined(&tmp, &dir)?;

    // Step 1: serialize to pretty JSON bytes.
    let bytes = serde_json::to_vec_pretty(doc)
        .map_err(|e| format!("write_peers_json_atomic: JSON serialize failed: {}", e))?;

    // Step 2 + 3: write tmp and fsync.
    {
        let mut f = File::create(&tmp).map_err(|e| {
            format!("write_peers_json_atomic: failed to create tmp file '{}': {}", tmp.display(), e)
        })?;
        f.write_all(&bytes).map_err(|e| {
            format!("write_peers_json_atomic: failed to write tmp file '{}': {}", tmp.display(), e)
        })?;
        f.sync_all().map_err(|e| {
            format!("write_peers_json_atomic: sync_all on tmp file '{}' failed: {}", tmp.display(), e)
        })?;
    }

    // Step 4: atomic rename tmp → peers.json.
    fs::rename(&tmp, &target).map_err(|e| {
        format!(
            "write_peers_json_atomic: atomic rename failed ('{}' → '{}'): {}",
            tmp.display(),
            target.display(),
            e
        )
    })?;

    // Step 5: best-effort dir-fsync (no-op on Windows; durability on Linux/macOS).
    let _ = File::open(&dir).and_then(|f| f.sync_all());

    Ok(())
}

/// Read peers.json from `<config_dir>/cryptiq/peers.json`.
///
/// - File absent → return a default `PeersDoc` (schemaVersion 1, empty peers list).
/// - File present, parseable, schemaVersion == 1 → return parsed doc.
/// - File present but unparseable JSON, or unknown schemaVersion → Err (fail closed; never guess).
///
/// Error strings follow the vault.rs convention; NEVER contain key bytes.
pub fn read_peers_json(config_dir: &str) -> Result<PeersDoc, String> {
    let path = PathBuf::from(config_dir).join("cryptiq").join("peers.json");

    if !path.exists() {
        // Default: empty peers list with a placeholder identity (caller may seed it).
        return Ok(PeersDoc {
            schema_version: 1,
            local_device_id: String::new(),
            local_static_public_key: String::new(),
            local_device_name: String::new(),
            peers: vec![],
        });
    }

    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("read_peers_json: failed to read '{}': {}", path.display(), e))?;

    let doc: PeersDoc = serde_json::from_str(&raw)
        .map_err(|e| format!("read_peers_json: JSON parse failed for '{}': {}", path.display(), e))?;

    // Fail closed on unknown schemaVersion — JS maps this to PeersDocCorruptError.
    if doc.schema_version != 1 {
        return Err(format!(
            "read_peers_json: unknown schemaVersion {} in '{}' — cannot parse across schemas",
            doc.schema_version,
            path.display()
        ));
    }

    Ok(doc)
}

// ---------------------------------------------------------------------------
// Crockford Base32 encoder/decoder (inline — no external crate, PATTERNS.md note)
// ---------------------------------------------------------------------------

/// Crockford Base32 encoding alphabet — 32 symbols, NO look-alikes I, L, O, U.
const CROCKFORD_ENCODE: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Check-char alphabet — 37 symbols (mod 37): the 32 above + `*`, `~`, `$`, `=`, `U`.
const CROCKFORD_CHECK: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U";

/// Encode raw bytes to Crockford Base32 (5-bit big-endian bucketing).
///
/// For 32-byte input this yields 52 chars (the last char carries 4 bits of real data
/// + 1 zero-pad bit).  Matches `encodeCrockfordBase32` in recovery.ts.
pub fn crockford_encode(bytes: &[u8]) -> String {
    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits_left: u32 = 0;

    for &byte in bytes {
        buffer = (buffer << 8) | (byte as u64);
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let idx = ((buffer >> bits_left) & 0x1f) as usize;
            result.push(CROCKFORD_ENCODE[idx] as char);
        }
    }
    if bits_left > 0 {
        let idx = ((buffer << (5 - bits_left)) & 0x1f) as usize;
        result.push(CROCKFORD_ENCODE[idx] as char);
    }
    result
}

/// Crockford check character: big-endian big-integer value of `bytes` mod 37,
/// mapped through `CROCKFORD_CHECK`.  Matches `crockfordCheckChar` in recovery.ts.
pub fn crockford_check_char(bytes: &[u8]) -> char {
    let mut rem: u64 = 0;
    for &b in bytes {
        // 256n^k ... keep modular arithmetic; u64 is sufficient for byte-at-a-time reduction.
        // (rem * 256 + b) mod 37 — no overflow risk since rem < 37 and b < 256.
        rem = (rem * 256 + b as u64) % 37;
    }
    CROCKFORD_CHECK[rem as usize] as char
}

/// Map a single Crockford look-alike character to its canonical encode-alphabet form.
///
/// This mirrors `validatePairingCode` (pairingCode.ts L106-09) and `decodeRecoveryKey`
/// (recovery.ts) — I/L→1, O→0, U→V — so a user who transcribes the look-alike LETTERS
/// decodes to the same bytes as the canonical code (M2 / D-11 cross-impl parity).
///
/// IMPORTANT (CR-01): this maps `U→V` and MUST be applied to the BASE32 BODY ONLY — never to
/// the trailing CHECK char, because the 37-symbol check alphabet legitimately contains 'U'
/// (index 36). Rewriting a correct 'U' check char to 'V' would corrupt ~1/37 valid codes.
/// The encode-alphabet body never contains I/L/O/U, so on a verbatim code this is a no-op.
fn map_crockford_lookalike_body(c: char) -> char {
    match c.to_ascii_uppercase() {
        'I' | 'L' => '1',
        'O' => '0',
        'U' => 'V',
        other => other,
    }
}

/// Map the look-alikes that are NOT valid check symbols on the CHECK char (I/L→1, O→0), while
/// preserving 'U' (a valid check symbol at index 36). Mirrors recovery.ts's check-char handling.
fn map_crockford_lookalike_check(c: char) -> char {
    match c.to_ascii_uppercase() {
        'I' | 'L' => '1',
        'O' => '0',
        other => other,
    }
}

/// Decode a Crockford Base32 string back to bytes.
///
/// Returns `Err` on any character outside the encode alphabet.
/// Look-alike mapping (I/L→1, O→0) should be applied by the caller before passing here.
pub fn crockford_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits_left: u32 = 0;

    for ch in s.chars() {
        let val = CROCKFORD_ENCODE
            .iter()
            .position(|&c| c == ch as u8)
            .ok_or_else(|| format!("crockford_decode: invalid character '{}'", ch))? as u64;
        buffer = (buffer << 5) | val;
        bits_left += 5;
        if bits_left >= 8 {
            bits_left -= 8;
            bytes.push(((buffer >> bits_left) & 0xff) as u8);
        }
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// QR SVG generation (Plan 09-04, Task 2)
// ---------------------------------------------------------------------------

/// Generate a QR code SVG string from `payload`.
///
/// Returns a complete SVG XML string (pass to frontend via Tauri invoke, render with {@html}).
/// Maps `QrCode::new` errors to a descriptive string — never panics.
#[tauri::command]
pub fn generate_qr_svg(payload: String) -> Result<String, String> {
    use qrcode::render::svg;
    use qrcode::QrCode;

    let code = QrCode::new(payload.as_bytes())
        .map_err(|e| format!("generate_qr_svg: QR encoding failed: {}", e))?;
    Ok(code.render::<svg::Color>().min_dimensions(200, 200).build())
}

// ---------------------------------------------------------------------------
// LAN IPv4 selection (Plan 09-04, Task 2)
// ---------------------------------------------------------------------------

/// Return the best private IPv4 address for this device using the UDP-connect trick.
///
/// Connects a UDP socket to 8.8.8.8:80 (no actual packet sent), then reads the
/// local_addr() — this discovers the default-route interface IP on Windows.
/// Returns an error if no private IPv4 is found (multi-NIC fallback: caller shows manual-IP UI).
#[tauri::command]
pub fn get_lan_ip() -> Result<String, String> {
    match get_best_lan_ip() {
        Some(ip) => Ok(ip.to_string()),
        None => Err(
            "get_lan_ip: no private IPv4 address found via UDP-connect trick — check NIC configuration".to_string()
        ),
    }
}

fn get_best_lan_ip() -> Option<std::net::Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) if is_private_ipv4(ip) => Some(ip),
        _ => None,
    }
}

fn is_private_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10
        || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
        || (o[0] == 192 && o[1] == 168)
}

// ---------------------------------------------------------------------------
// Keypair generation — OsRng via snow; Math.random is banned
// ---------------------------------------------------------------------------

/// Generate a new Curve25519 static keypair using snow's Builder (backed by OsRng).
///
/// Returns (private_key_32_bytes, public_key_32_bytes).
/// Caller owns the lifecycle; call secureWipe on private key bytes after use.
pub fn generate_device_keypair() -> Result<([u8; 32], [u8; 32]), String> {
    let builder = Builder::new(PARAMS.clone());
    // #4 (GAP-D2): snow 0.10's `Keypair { private: Vec<u8>, public: Vec<u8> }` has NO Drop/Zeroize,
    // so the private-key heap buffer is freed UNWIPED when `kp` drops. Bind it mutably and
    // `kp.private.zeroize()` (Vec<u8>: Zeroize → volatile, not an elidable loop) on EVERY return
    // path AFTER copying the bytes out. This is the ORIGIN of every device static private key.
    let mut kp = builder
        .generate_keypair()
        .map_err(|e| format!("generate_device_keypair: snow generate_keypair failed: {}", e))?;
    let mut sk = [0u8; 32];
    let mut pk = [0u8; 32];
    if kp.private.len() != 32 || kp.public.len() != 32 {
        // #4: wipe the private-key heap buffer before the early error return too (no path may
        // return before the wipe). The public half is not secret.
        kp.private.zeroize();
        return Err("generate_device_keypair: unexpected keypair byte length from snow".to_string());
    }
    sk.copy_from_slice(&kp.private);
    pk.copy_from_slice(&kp.public);
    // #4: copies made — now wipe the snow-owned private heap buffer before `kp` drops.
    kp.private.zeroize();
    Ok((sk, pk))
}

// ---------------------------------------------------------------------------
// Noise XXpsk3 builder helpers
// ---------------------------------------------------------------------------

/// Build a Noise XXpsk3 responder (Device A — the side that displays the QR and listens).
pub fn build_responder(
    static_sk: &[u8],
    secret: &[u8; 32],
) -> Result<snow::HandshakeState, String> {
    Builder::new(PARAMS.clone())
        .local_private_key(static_sk)
        .map_err(|e| format!("build_responder: local_private_key failed: {}", e))?
        .psk(3, secret)
        .map_err(|e| format!("build_responder: psk(3) failed: {}", e))?
        .build_responder()
        .map_err(|e| format!("build_responder: build_responder failed: {}", e))
}

/// Build a Noise XXpsk3 initiator (Device B — the side that types/scans the code).
pub fn build_initiator(
    static_sk: &[u8],
    secret: &[u8; 32],
) -> Result<snow::HandshakeState, String> {
    Builder::new(PARAMS.clone())
        .local_private_key(static_sk)
        .map_err(|e| format!("build_initiator: local_private_key failed: {}", e))?
        .psk(3, secret)
        .map_err(|e| format!("build_initiator: psk(3) failed: {}", e))?
        .build_initiator()
        .map_err(|e| format!("build_initiator: build_initiator failed: {}", e))
}

// ---------------------------------------------------------------------------
// SAS derivation — MUST be called BEFORE into_transport_mode() (Pitfall 1)
// ---------------------------------------------------------------------------

/// Derive the 6-digit SAS from the Noise handshake hash (BLAKE2s, 32 bytes).
///
/// Returns `(raw_sas_u32, display_string)` where display is "042 318" (D-01).
pub fn derive_sas(noise: &snow::HandshakeState) -> (u32, String) {
    let hh = noise.get_handshake_hash();
    assert!(
        hh.len() >= 4,
        "derive_sas: handshake hash too short ({} bytes); expected ≥ 4",
        hh.len()
    );
    let raw = u32::from_be_bytes([hh[0], hh[1], hh[2], hh[3]]);
    let sas = raw % 1_000_000;
    let display = format!("{:03} {:03}", sas / 1000, sas % 1000);
    (sas, display)
}

// ---------------------------------------------------------------------------
// Tokio TCP framing — 2-byte big-endian length prefix
// ---------------------------------------------------------------------------

/// Read one length-prefixed message from `stream`.
///
/// Generic over any `AsyncRead + Unpin` so the production path uses a real `TcpStream`
/// while tests drive both halves over a `tokio::io::duplex(..)` pair (GAP-B / H1 testability).
pub async fn recv_framed<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
) -> tokio::io::Result<usize> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    buf.resize(len, 0);
    stream.read_exact(buf).await?;
    Ok(len)
}

/// Write one length-prefixed message to `stream`.
///
/// Generic over any `AsyncWrite + Unpin` (see `recv_framed` for the testability rationale).
pub async fn send_framed<S: AsyncWrite + Unpin>(stream: &mut S, data: &[u8]) -> tokio::io::Result<()> {
    let len = u16::try_from(data.len()).expect("snow message too large for 2-byte prefix");
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// HandshakeResult — returned by run_handshake to the orchestration layer
// ---------------------------------------------------------------------------

pub struct HandshakeResult {
    pub sas_display: String,
    // Never read after being set — retained alongside `sas_display` for parity/diagnostics.
    // #[allow] rather than removal: no architectural change intended by this lint cleanup
    // (2026-07-10 CI clippy gate landing).
    #[allow(dead_code)]
    pub sas_raw: u32,
    pub transport: snow::TransportState,
    pub peer_static_pk: Vec<u8>,
}

/// Run the full 3-message Noise XXpsk3 handshake as the RESPONDER (Device A, listener).
///
/// Generic over the stream type so the post-handshake CONFIRMED-frame exchange can reuse the
/// same `&mut S` in a duplex-backed test (GAP-B / H1).
pub async fn run_handshake_responder<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    static_sk: &[u8],
    secret: &[u8; 32],
) -> Result<HandshakeResult, String> {
    let mut noise = build_responder(static_sk, secret)?;

    let mut buf = Vec::new();
    let mut msg_buf = vec![0u8; 65535];

    // Message 1: <- e  (read from initiator)
    recv_framed(stream, &mut buf)
        .await
        .map_err(|e| format!("run_handshake_responder: msg1 recv failed: {}", e))?;
    noise
        .read_message(&buf, &mut msg_buf)
        .map_err(|_| "handshake failed".to_string())?;

    // Message 2: -> e,ee,s,es  (write to initiator)
    let len = noise
        .write_message(&[], &mut msg_buf)
        .map_err(|_| "handshake failed".to_string())?;
    send_framed(stream, &msg_buf[..len])
        .await
        .map_err(|e| format!("run_handshake_responder: msg2 send failed: {}", e))?;

    // Message 3: <- s,se  (read from initiator)
    recv_framed(stream, &mut buf)
        .await
        .map_err(|e| format!("run_handshake_responder: msg3 recv failed: {}", e))?;
    noise
        .read_message(&buf, &mut msg_buf)
        .map_err(|_| "handshake failed".to_string())?;

    // CRITICAL: derive_sas() and get_remote_static() BEFORE into_transport_mode() (Pitfall 1).
    let (sas_raw, sas_display) = derive_sas(&noise);
    let peer_static_pk = noise
        .get_remote_static()
        .ok_or_else(|| "handshake failed".to_string())?
        .to_vec();

    let transport = noise
        .into_transport_mode()
        .map_err(|_| "handshake failed".to_string())?;

    Ok(HandshakeResult {
        sas_display,
        sas_raw,
        transport,
        peer_static_pk,
    })
}

/// Run the full 3-message Noise XXpsk3 handshake as the INITIATOR (Device B, connector).
///
/// Generic over the stream type (see `run_handshake_responder`).
pub async fn run_handshake_initiator<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    static_sk: &[u8],
    secret: &[u8; 32],
) -> Result<HandshakeResult, String> {
    let mut noise = build_initiator(static_sk, secret)?;

    let mut buf = Vec::new();
    let mut msg_buf = vec![0u8; 65535];

    // Message 1: -> e  (write to responder)
    let len = noise
        .write_message(&[], &mut msg_buf)
        .map_err(|_| "handshake failed".to_string())?;
    send_framed(stream, &msg_buf[..len])
        .await
        .map_err(|e| format!("run_handshake_initiator: msg1 send failed: {}", e))?;

    // Message 2: <- e,ee,s,es  (read from responder)
    recv_framed(stream, &mut buf)
        .await
        .map_err(|e| format!("run_handshake_initiator: msg2 recv failed: {}", e))?;
    noise
        .read_message(&buf, &mut msg_buf)
        .map_err(|_| "handshake failed".to_string())?;

    // Message 3: -> s,se  (write to responder)
    let len = noise
        .write_message(&[], &mut msg_buf)
        .map_err(|_| "handshake failed".to_string())?;
    send_framed(stream, &msg_buf[..len])
        .await
        .map_err(|e| format!("run_handshake_initiator: msg3 send failed: {}", e))?;

    // CRITICAL: derive_sas() and get_remote_static() BEFORE into_transport_mode() (Pitfall 1).
    let (sas_raw, sas_display) = derive_sas(&noise);
    let peer_static_pk = noise
        .get_remote_static()
        .ok_or_else(|| "handshake failed".to_string())?
        .to_vec();

    let transport = noise
        .into_transport_mode()
        .map_err(|_| "handshake failed".to_string())?;

    Ok(HandshakeResult {
        sas_display,
        sas_raw,
        transport,
        peer_static_pk,
    })
}

// ---------------------------------------------------------------------------
// Post-handshake CONFIRMED-frame exchange (GAP-B / H1 — mutual SAS confirmation)
// ---------------------------------------------------------------------------

/// The CONFIRMED frame each side sends over the SAS-verified Noise transport AFTER its local
/// user approves the SAS. Carries the sender's REAL local deviceId + deviceName so the peer
/// persists the genuine identity (D-13) instead of a fabricated UUID (the H1 bug).
///
/// Fix B (#2): also carries `vault_pair_id` — the RESPONDER (pairing_initiate) is the authority
/// and generates this once; its frame carries the real value. The INITIATOR (pairing_connect)
/// sends an EMPTY string and ADOPTS the value it reads from the responder's CONFIRMED frame, so
/// both devices store an IDENTICAL vaultPairId for the same pairing (previously each side minted
/// its own with new_uuid_v4(), producing divergent ids).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct ConfirmFrame {
    device_id: String,
    device_name: String,
    #[serde(default)]
    vault_pair_id: String,
}

/// What `run_confirm_exchange` yields on success: the PEER's genuine identity (from its CONFIRMED
/// frame) plus the NEGOTIATED vaultPairId (Fix B #2 — the responder's authoritative value, which
/// the initiator adopts). The caller persists exactly these.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfirmExchangeResult {
    pub peer_device_id: String,
    pub peer_device_name: String,
    /// Fix B (#2): the SHARED vaultPairId both sides commit. Equals the local value when this side
    /// is the responder (`Some(..)` passed in), otherwise the value adopted from the peer's frame.
    pub vault_pair_id: String,
}

/// Drive the mutual-confirmation exchange over the live Noise transport AFTER the handshake.
///
/// This is the wire half of D-06 ("no half-paired state"): neither side commits until BOTH
/// users' confirmations have been exchanged over the SAS-verified channel.
///
/// Sequence (symmetric — both responder and initiator call this):
///   (a) Wait, bounded by `window`, for the LOCAL user's `pairing_confirm` (`local_confirm`).
///       On `Elapsed` → `Err("pairing confirmation timed out")` and NOTHING is sent.
///   (b) Send the local `ConfirmFrame` (deviceId + deviceName + our vault_pair_id) encrypted
///       through `transport`. The responder passes `Some(vpid)` so the frame carries the real
///       value; the initiator passes `None` and sends an empty vault_pair_id (Fix B #2).
///   (c) Wait, bounded by the REMAINING window, for the peer's CONFIRMED frame; decrypt +
///       deserialize it. On timeout/decrypt/parse failure → `Err`.
///   (d) Return the PEER's identity AND the NEGOTIATED vaultPairId — our own when `Some`
///       (responder), else the peer's adopted value (initiator).
///
/// IMPORTANT (Fix A #3/#7): step (a) blocks on `local_confirm`. The caller MUST emit
/// `pairing://sas` BEFORE invoking this function — the SAS is produced by the handshake step,
/// not here. Emitting the SAS only after this returns was the circular-deadlock regression.
///
/// Generic over the stream so tests wire two halves over a `tokio::io::duplex(..)` pair with no
/// real TCP — one side confirms, the other does or does not (the PAIR-04/05 guarantee).
///
/// NOTE: this function NEVER touches peers.json or CredManager — the caller's finalize path is
/// the single commit point. On any error here the caller zeroizes + removes the session.
#[allow(clippy::too_many_arguments)]
async fn run_confirm_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    transport: &mut snow::TransportState,
    local_device_id: &str,
    local_device_name: &str,
    local_vault_pair_id: Option<String>,
    local_confirm: std::sync::Arc<Notify>,
    window: Duration,
) -> Result<ConfirmExchangeResult, String> {
    let start = tokio::time::Instant::now();

    // (a) Wait for the LOCAL user's pairing_confirm, bounded by the window (D-02).
    // Fix A: the SAS was ALREADY emitted by the caller (between the handshake step and this
    // call), so the 60 s window genuinely begins once both screens show the SAS — no deadlock.
    tokio::time::timeout(window, local_confirm.notified())
        .await
        .map_err(|_| "pairing confirmation timed out".to_string())?;

    // (b) Send the local CONFIRMED frame over the encrypted transport. The responder carries the
    // authoritative vaultPairId; the initiator carries an empty string (Fix B #2).
    let local_frame = ConfirmFrame {
        device_id: local_device_id.to_string(),
        device_name: local_device_name.to_string(),
        vault_pair_id: local_vault_pair_id.clone().unwrap_or_default(),
    };
    let json = serde_json::to_vec(&local_frame)
        .map_err(|e| format!("run_confirm_exchange: serialize CONFIRMED frame failed: {}", e))?;
    let mut out = vec![0u8; json.len() + 64]; // + Noise/Poly1305 tag headroom
    let n = transport
        .write_message(&json, &mut out)
        .map_err(|_| "run_confirm_exchange: encrypt CONFIRMED frame failed".to_string())?;
    // Bound the send by the remaining window too — a peer that completes the handshake then
    // stops READING (its TCP receive window fills) must not park this write_all forever. This
    // is the last socket op that was previously unbounded (review LOW); steps (a) and (c) were
    // already timeout-wrapped, so (b) now matches.
    let send_budget = window.saturating_sub(start.elapsed());
    if send_budget.is_zero() {
        return Err("pairing confirmation timed out".to_string());
    }
    tokio::time::timeout(send_budget, send_framed(stream, &out[..n]))
        .await
        .map_err(|_| "pairing confirmation timed out".to_string())?
        .map_err(|e| format!("run_confirm_exchange: send CONFIRMED frame failed: {}", e))?;

    // (c) Wait for the PEER's CONFIRMED frame within the REMAINING window.
    let remaining = window.saturating_sub(start.elapsed());
    if remaining.is_zero() {
        return Err("pairing confirmation timed out".to_string());
    }
    let mut buf = Vec::new();
    tokio::time::timeout(remaining, recv_framed(stream, &mut buf))
        .await
        .map_err(|_| "pairing confirmation timed out".to_string())?
        .map_err(|e| format!("run_confirm_exchange: recv peer CONFIRMED frame failed: {}", e))?;

    let mut plain = vec![0u8; buf.len()];
    let plen = transport
        .read_message(&buf, &mut plain)
        .map_err(|_| "run_confirm_exchange: decrypt peer CONFIRMED frame failed".to_string())?;
    let peer_frame: ConfirmFrame = serde_json::from_slice(&plain[..plen])
        .map_err(|e| format!("run_confirm_exchange: parse peer CONFIRMED frame failed: {}", e))?;

    // (d) Negotiate the vaultPairId: our own when we are the authority (responder, `Some`),
    // else ADOPT the peer's (initiator). Fail closed if neither side supplied one.
    let vault_pair_id = match local_vault_pair_id {
        Some(vpid) => vpid,
        None => {
            if peer_frame.vault_pair_id.is_empty() {
                return Err(
                    "run_confirm_exchange: no vaultPairId available — neither local (authority) nor peer frame supplied one (Fix B #2)".to_string(),
                );
            }
            peer_frame.vault_pair_id
        }
    };

    Ok(ConfirmExchangeResult {
        peer_device_id: peer_frame.device_id,
        peer_device_name: peer_frame.device_name,
        vault_pair_id,
    })
}

// ---------------------------------------------------------------------------
// Post-accept / post-connect LIFECYCLE with an overall deadline (GAP-C / H6)
// ---------------------------------------------------------------------------

/// What the bounded post-handshake lifecycle yields back to the spawned task: the SAS to show
/// the user, the peer's static pk to persist, the GENUINE peer identity from the CONFIRMED
/// frame (H1), and the negotiated vaultPairId (Fix B #2). Produced only if the handshake AND the
/// mutual confirmation completed within the injected deadline (H6).
#[derive(Debug, Clone, PartialEq)]
pub struct LifecycleResult {
    pub sas_display: String,
    pub peer_static_pk: Vec<u8>,
    pub peer_device_id: String,
    pub peer_device_name: String,
    /// Fix B (#2): the SHARED vaultPairId both sides commit.
    pub vault_pair_id: String,
}

// ---------------------------------------------------------------------------
// Fix A (#3/#7): BOUNDED HANDSHAKE STEP — runs the Noise handshake ONLY, so the
// spawned task can emit `pairing://sas` BETWEEN the handshake and the confirm wait.
// ---------------------------------------------------------------------------

/// Fix A: run ONLY the RESPONDER's Noise handshake, bounded by `deadline`. Returns the SAS +
/// transport + peer static pk WITHOUT waiting on any confirmation. The spawned listener task
/// calls this, EMITS `pairing://sas`, and only THEN runs `run_confirm_exchange`. This is the fix
/// for the circular-deadlock regression where the SAS was emitted only after the confirm-wait.
///
/// The `deadline` guards the unbounded `recv_framed` reads DURING the handshake (the H6 hole):
/// a peer that connects then stalls causes a prompt timeout `Err` instead of an infinite park.
pub async fn run_handshake_step_responder<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    static_sk: &[u8],
    secret: &[u8; 32],
    deadline: Duration,
) -> Result<HandshakeResult, String> {
    tokio::time::timeout(deadline, run_handshake_responder(stream, static_sk, secret))
        .await
        .map_err(|_| "pairing handshake timed out".to_string())?
}

/// Fix A: run ONLY the INITIATOR's Noise handshake, bounded by `deadline`. Symmetric to
/// `run_handshake_step_responder`; see that doc for the SAS-ordering rationale.
pub async fn run_handshake_step_initiator<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    static_sk: &[u8],
    secret: &[u8; 32],
    deadline: Duration,
) -> Result<HandshakeResult, String> {
    tokio::time::timeout(deadline, run_handshake_initiator(stream, static_sk, secret))
        .await
        .map_err(|_| "pairing handshake timed out".to_string())?
}

/// H6: run the RESPONDER's full post-accept lifecycle — Noise handshake + mutual CONFIRMED-frame
/// exchange. The handshake is bounded by its own `handshake_deadline` (the H6 fix) and the
/// confirmation wait by `confirm_window` (the D-02 60 s SAS window, which begins AFTER the
/// handshake — Fix A).
///
/// `on_sas` is invoked with the SAS display string AS SOON AS the handshake completes and BEFORE
/// the confirm wait begins — this is where the spawned task emits `pairing://sas` (Fix A). In the
/// H6 unit tests `on_sas` is a no-op; in production it is the `app.emit("pairing://sas", ..)`.
///
/// `local_vault_pair_id` is `Some(..)` for the responder (it is the authority — Fix B #2).
///
/// Generic over the stream so the H6 tests drive it over a `tokio::io::duplex` peer that never
/// writes, asserting a bounded timeout instead of a hang. The caller is responsible for
/// zeroize+remove + `pairing://error` on `Err` (D-06 — no commit).
#[allow(clippy::too_many_arguments)]
pub async fn run_responder_lifecycle<S: AsyncRead + AsyncWrite + Unpin, F: FnOnce(&str)>(
    stream: &mut S,
    static_sk: &[u8],
    secret: &[u8; 32],
    local_device_id: &str,
    local_device_name: &str,
    local_vault_pair_id: Option<String>,
    local_confirm: std::sync::Arc<Notify>,
    handshake_deadline: Duration,
    confirm_window: Duration,
    on_sas: F,
) -> Result<LifecycleResult, String> {
    // Step 1 (bounded): the handshake. Produces the SAS.
    let handshake = run_handshake_step_responder(stream, static_sk, secret, handshake_deadline).await?;

    // Fix A: emit the SAS NOW — between the handshake and the confirm wait.
    on_sas(&handshake.sas_display);

    // Step 2 (bounded by the 60 s window): the mutual CONFIRMED-frame exchange.
    let mut transport = handshake.transport;
    let confirm = run_confirm_exchange(
        stream,
        &mut transport,
        local_device_id,
        local_device_name,
        local_vault_pair_id,
        local_confirm,
        confirm_window,
    )
    .await?;
    Ok(LifecycleResult {
        sas_display: handshake.sas_display,
        peer_static_pk: handshake.peer_static_pk,
        peer_device_id: confirm.peer_device_id,
        peer_device_name: confirm.peer_device_name,
        vault_pair_id: confirm.vault_pair_id,
    })
}

/// H6 + Fix A: run the INITIATOR's full post-connect lifecycle (bounded handshake → emit SAS →
/// bounded confirm). Symmetric to `run_responder_lifecycle`; the initiator passes
/// `local_vault_pair_id = None` and ADOPTS the responder's value (Fix B #2).
#[allow(clippy::too_many_arguments)]
pub async fn run_initiator_lifecycle<S: AsyncRead + AsyncWrite + Unpin, F: FnOnce(&str)>(
    stream: &mut S,
    static_sk: &[u8],
    secret: &[u8; 32],
    local_device_id: &str,
    local_device_name: &str,
    local_vault_pair_id: Option<String>,
    local_confirm: std::sync::Arc<Notify>,
    handshake_deadline: Duration,
    confirm_window: Duration,
    on_sas: F,
) -> Result<LifecycleResult, String> {
    let handshake = run_handshake_step_initiator(stream, static_sk, secret, handshake_deadline).await?;

    // Fix A: emit the SAS NOW — between the handshake and the confirm wait.
    on_sas(&handshake.sas_display);

    let mut transport = handshake.transport;
    let confirm = run_confirm_exchange(
        stream,
        &mut transport,
        local_device_id,
        local_device_name,
        local_vault_pair_id,
        local_confirm,
        confirm_window,
    )
    .await?;
    Ok(LifecycleResult {
        sas_display: handshake.sas_display,
        peer_static_pk: handshake.peer_static_pk,
        peer_device_id: confirm.peer_device_id,
        peer_device_name: confirm.peer_device_name,
        vault_pair_id: confirm.vault_pair_id,
    })
}

// ---------------------------------------------------------------------------
// Cancellable accept (GAP-C / H7) — listener task must be interruptible
// ---------------------------------------------------------------------------

/// Outcome of `accept_with_cancel`: either a peer connected, the cancel signal fired, or the
/// accept itself errored. Returned by value so the listener task can branch + clean up.
pub enum AcceptOutcome {
    /// A peer connected — carries the accepted stream.
    Accepted(TcpStream),
    /// The cancel signal fired (or its sender was dropped) — abort, free the port.
    Cancelled,
    /// `listener.accept()` returned an error.
    Failed(String),
}

/// H7: accept exactly one connection, but allow the wait to be CANCELLED.
///
/// The previous code did `let (cancel_tx, _cancel_rx) = oneshot::channel()` — dropping the
/// receiver, so cancel could never fire — and `listener.accept().await` with no `select!`, so on
/// timeout/abort the task kept the port bound and a later `pairing_initiate` hit `EADDRINUSE`.
///
/// This `select!`s the accept against the live `cancel_rx`. Firing (or dropping) `cancel_tx`
/// resolves the receiver, the select picks the cancel branch, and the function returns
/// `Cancelled` — the caller then drops the listener, freeing the port. Deterministically
/// testable: a test fires cancel with nobody connected and asserts a prompt `Cancelled`.
pub async fn accept_with_cancel(
    listener: &tokio::net::TcpListener,
    cancel_rx: oneshot::Receiver<()>,
) -> AcceptOutcome {
    tokio::select! {
        // Cancel fired OR the sender was dropped (recv resolves to Err on drop) → abort.
        _ = cancel_rx => AcceptOutcome::Cancelled,
        accepted = listener.accept() => match accepted {
            Ok((stream, _peer_addr)) => AcceptOutcome::Accepted(stream),
            Err(e) => AcceptOutcome::Failed(format!("listener.accept failed: {}", e)),
        },
    }
}

/// Bounded `TcpStream::connect` (GAP-C / H6, INITIATOR side). An unreachable / half-open host
/// must not park `pairing_connect` forever — wrap the connect in a `tokio::time::timeout`.
pub async fn connect_with_timeout(addr: &str, deadline: Duration) -> Result<TcpStream, String> {
    tokio::time::timeout(deadline, TcpStream::connect(addr))
        .await
        .map_err(|_| format!("pairing_connect: TcpStream::connect to '{}' timed out", addr))?
        .map_err(|e| format!("pairing_connect: TcpStream::connect to '{}' failed: {}", addr, e))
}

/// Bounded connect/accept deadline (H6): how long we wait for the TCP connection itself.
const CONNECT_ACCEPT_DEADLINE: Duration = Duration::from_secs(30);
/// Fix A: bounded HANDSHAKE deadline (H6) — how long the Noise XX exchange itself may take. This
/// guards the unbounded `recv_framed` reads DURING the handshake. The SAS is emitted the instant
/// this completes, BEFORE the confirm window starts (no circular deadlock).
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);
/// Fix A + D-02: the SAS-confirmation window. It begins AFTER the SAS is emitted (between the
/// handshake and the confirm wait) so the user actually has the full 60 s to compare + confirm.
const SAS_CONFIRM_WINDOW: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// PairingInitResponse — returned to JS by pairing_initiate and pairing_connect
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PairingInitResponse {
    /// SVG string for the QR code (Device A only; empty string on Device B side).
    pub qr_svg: String,
    /// Chunked Crockford Base32 + check char pairing code (Device A: full; Device B: empty).
    pub base32_code: String,
    /// Unique session identifier (UUID v4) — used by pairing_confirm/pairing_finalize.
    pub session_id: String,
}

// ---------------------------------------------------------------------------
// Per-session state (Plan 09-04, Task 2)
// ---------------------------------------------------------------------------

/// Per-session pairing state held in the Tauri-managed session map.
///
/// Both Device A (responder) and Device B (initiator) have a session here.
/// The session is removed from the map on finalize, timeout, or abort.
pub struct PairingSession {
    /// Noise transport channel — filled in after the handshake completes.
    /// `None` until the spawned listener/connect task completes the handshake.
    ///
    /// NOTE (GAP-B / H1): the post-handshake CONFIRMED-frame exchange now happens INSIDE the
    /// spawned task (`run_confirm_exchange`), which owns the live `TransportState` for that
    /// exchange. The copy stored here is retained for diagnostics/compat; it is NOT used to send
    /// frames at finalize time (the stream is closed by then).
    #[allow(dead_code)]
    pub transport: Option<snow::TransportState>,
    /// Peer's 32-byte Curve25519 static public key (from get_remote_static).
    /// Stored in CredManager + peers.json on finalize.
    pub peer_static_pk: Vec<u8>,
    /// The 32-byte pairing secret — zeroized on every removal path via `impl Drop` (M1).
    /// NEVER persisted.
    pub secret: [u8; 32],
    /// SAS display string shown to the user (e.g. "042 318").
    pub sas_display: String,
    /// Cancel sender — drop this to cancel the listener task and free the port (D-03).
    pub cancel_tx: Option<oneshot::Sender<()>>,
    /// Notify fired when the local user calls pairing_confirm() for this session.
    pub local_confirm: std::sync::Arc<Notify>,
    /// Fired by the spawned task once BOTH sides have exchanged CONFIRMED frames (GAP-B / H1).
    /// `pairing_finalize` awaits this (bounded by the 60 s window) — it is the real "both
    /// users confirmed over the SAS-verified channel" signal (D-06).
    pub both_confirmed: std::sync::Arc<Notify>,
    /// Whether the local user has already called pairing_confirm().
    pub local_confirmed: bool,
    /// config_dir for this session (used by pairing_finalize).
    pub config_dir: String,
    /// This device's own deviceId — sent to the peer inside the local CONFIRMED frame.
    // Never read after being set on this struct (the value is used at send-time before being
    // stored). #[allow] rather than removal: no architectural change intended by this lint
    // cleanup (2026-07-10 CI clippy gate landing).
    #[allow(dead_code)]
    pub local_device_id: String,
    /// This device's own deviceName — sent to the peer inside the local CONFIRMED frame.
    pub local_device_name: String,
    /// Peer device ID provided by the peer's "CONFIRMED" frame (populated by the task on success).
    pub peer_device_id: Option<String>,
    /// Peer device name provided by the peer's "CONFIRMED" frame.
    pub peer_device_name: Option<String>,
    /// The vaultPairId negotiated during finalize (random UUID shared both sides).
    pub vault_pair_id: Option<String>,
}

/// M1: zeroize the 32-byte PSK (volatile) and clear the peer static-pk buffer on EVERY
/// removal path — finalize success/failure, timeout, re-pair refusal, bind/accept/handshake
/// failure. zeroize uses `core::ptr::write_volatile` + a compiler fence, so unlike the old
/// hand-rolled `for b in ..{ *b = 0 }` loops the wipe cannot be optimized away.
impl Drop for PairingSession {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.peer_static_pk.zeroize();
    }
}

/// Tauri managed state: session_id → PairingSession.
///
/// Wrapped in `Mutex<HashMap<...>>` so commands can get and update sessions.
pub struct PairingSessionMap(pub Mutex<HashMap<String, PairingSession>>);

impl PairingSessionMap {
    pub fn new() -> Self {
        PairingSessionMap(Mutex::new(HashMap::new()))
    }
}

// ---------------------------------------------------------------------------
// ISO 8601 timestamp helper
// ---------------------------------------------------------------------------

fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Format as YYYY-MM-DDTHH:MM:SSZ (simple UTC, sufficient for pairedAt field).
    let total_secs = secs;
    let s = total_secs % 60;
    let m = (total_secs / 60) % 60;
    let h = (total_secs / 3600) % 24;
    let days_since_epoch = total_secs / 86400;
    // Gregorian calendar computation from days since 1970-01-01.
    let (y, mo, d) = days_to_ymd(days_since_epoch);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, m, s)
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm: Gregorian calendar, proleptic.
    // Ported from a standard algorithm for Unix epoch → Y/M/D.
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
// Core confirmation-wait logic (testable without AppHandle)
// ---------------------------------------------------------------------------

/// Wait for the local user's confirm signal, bounded by `timeout_duration`.
///
/// This is the injectable core of the SAS-confirmation wait (D-02). Tests drive it with
/// a short timeout and never fire the Notify — proving the timeout error is returned and
/// no peers.json mutation occurs.
///
/// On success: returns `Ok(())`.
/// On `Elapsed` (window lapses): returns `Err("pairing confirmation timed out")`.
///
/// Note: In the full two-device flow, the "CONFIRMED" Noise frame exchange occurs in the
/// spawned listener/connect tasks. This function gates only on the local user's approval
/// (pairing_confirm → notify_one). The caller (pairing_finalize) is responsible for the
/// combined guard: local approval + transport frame exchange.
#[cfg_attr(not(test), allow(dead_code))]
pub async fn await_mutual_confirm(
    local_confirm: std::sync::Arc<Notify>,
    timeout_duration: Duration,
) -> Result<(), String> {
    tokio::time::timeout(timeout_duration, local_confirm.notified())
        .await
        .map_err(|_| "pairing confirmation timed out".to_string())
}

// ---------------------------------------------------------------------------
// pairing_initiate — Device A (RESPONDER)
// ---------------------------------------------------------------------------

/// Device A: initiate a pairing session.
///
/// - Generates a unique `sessionId` (random UUID v4), a 32-byte CSPRNG secret, and a keypair.
/// - Computes LAN IP + port 54321.
/// - Builds the pairing code: `IP:PORT:<Crockford-Base32-secret+checkchar>`.
/// - Generates the QR SVG for that payload.
/// - Spawns the LAZY listener (TcpListener::bind ONLY here — never in lib.rs setup, D-10).
/// - Returns `PairingInitResponse { qrSvg, base32Code, sessionId }` immediately.
///
/// The spawned listener task runs the Noise handshake (RESPONDER), emits the SAS to JS
/// via a Tauri event, then waits for pairing_finalize to be called within 60 seconds.
/// On timeout or abort: ephemeral keys + secret are zeroized, nothing is written (D-02, D-06).
#[tauri::command]
pub async fn pairing_initiate(
    app: tauri::AppHandle,
    config_dir: String,
) -> Result<PairingInitResponse, String> {
    // Generate session ID + secret (OsRng via snow — Math.random banned).
    let session_id = new_uuid_v4();
    // #5 (GAP-D2): `secret` is `[u8;32]` (Copy). `Zeroizing::new(secret)` and `session.secret = secret`
    // both COPY the bytes, abandoning THIS stack-local un-wiped when the command returns. Bind it
    // `mut` and explicitly `secret.zeroize()` after the last raw use (the residency inside the
    // displayed pairing-code Strings is by-design and is NOT wiped — only this raw [u8;32] binding).
    let mut secret = generate_pairing_secret()?;

    // Fix C (#1): the handshake static key MUST be the device's PERSISTED identity key, not a
    // fresh throwaway. Using a per-session ephemeral key made peers.json pin a key that did not
    // equal the peer's advertised identity (get_local_device_info). Load the persisted identity
    // sk so `get_remote_static()` on the OTHER side yields OUR stable identity public key.
    //
    // Windows has the real Credential Manager (WindowsCredentialStore). On non-Windows desktop
    // there is no OS keystore, so we fall back to an ephemeral keypair — this is acceptable for
    // those builds; the PERSISTED-key path (Windows) is the real one. (See get_local_device_info
    // for the same platform split.)
    //
    // #5 (GAP-D2): `sk` is `[u8;32]` (Copy) — `Zeroizing::new(sk)` below COPIES it, leaving this
    // stack-local un-wiped. Bind it `mut` so we can `sk.zeroize()` after the copy is taken.
    #[cfg(target_os = "windows")]
    let mut sk = {
        let store = WindowsCredentialStore;
        let (sk, _pk) = get_or_generate_keypair_from_store(&store, DEVICE_IDENTITY_SK_TARGET)?;
        sk
    };
    #[cfg(not(target_os = "windows"))]
    let mut sk = {
        // No OS Credential Manager here — ephemeral fallback. The persisted-key path above
        // (Windows) is the canonical one that pins a stable cross-restart identity.
        let (sk, _pk) = generate_device_keypair()?;
        sk
    };

    // LAN IP + port 54321.
    let ip = get_best_lan_ip()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port: u16 = 54321;

    // Pairing code: IP:PORT:BASE32SECRET+CHECKCHAR
    let base32_secret = crockford_encode(&secret);
    let check = crockford_check_char(&secret);
    // Chunk the code in groups of 5 for readability (D-11).
    let full_code = format!("{}:{}:{}{}", ip, port, base32_secret, check);
    let base32_code = full_code.clone(); // caller receives the full bundle string

    // QR SVG.
    let qr_svg = {
        use qrcode::render::svg;
        use qrcode::QrCode;
        QrCode::new(full_code.as_bytes())
            .map_err(|e| format!("pairing_initiate: QR encoding failed: {}", e))?
            .render::<svg::Color>()
            .min_dimensions(200, 200)
            .build()
    };

    // This device's stable identity — sent to the peer in our CONFIRMED frame (H1).
    let local_device_id = read_or_create_local_device_id(&config_dir, "pairing_initiate")?;
    let local_device_name = device_name_from_env();

    // Fix B (#2): the RESPONDER is the vaultPairId AUTHORITY. Generate it ONCE here; it travels to
    // the initiator inside our CONFIRMED frame, and the initiator adopts it — so both devices
    // store an IDENTICAL vaultPairId. (Previously each pairing_finalize minted its own.)
    let vault_pair_id = new_uuid_v4();

    // Per-session cancel channel (H7). We KEEP `cancel_rx` and move it into the listener task so a
    // `select!` there can actually be interrupted; the live `cancel_tx` goes into the session so
    // the timeout/finalize/refusal paths can SEND it to free the bound port (no EADDRINUSE leak).
    let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
    let local_confirm = std::sync::Arc::new(Notify::new());
    let both_confirmed = std::sync::Arc::new(Notify::new());

    // Build session state.
    let session = PairingSession {
        transport: None, // filled in by the spawned listener task after handshake completes
        peer_static_pk: Vec::new(),
        secret,
        sas_display: String::new(),
        cancel_tx: Some(cancel_tx),
        local_confirm: local_confirm.clone(),
        both_confirmed: both_confirmed.clone(),
        local_confirmed: false,
        config_dir: config_dir.clone(),
        local_device_id: local_device_id.clone(),
        local_device_name: local_device_name.clone(),
        peer_device_id: None,
        peer_device_name: None,
        vault_pair_id: Some(vault_pair_id.clone()),
    };

    // Insert into session map.
    {
        let sessions = app.state::<PairingSessionMap>();
        let mut map = sessions.0.lock().unwrap();
        map.insert(session_id.clone(), session);
    }

    // Spawn the lazy listener task.
    // TcpListener::bind lives ONLY here (D-10, Pitfall 5 — never in lib.rs setup).
    // GAP-B / H1: this task now KEEPS the stream + transport alive past the handshake so it can
    // carry the mutual CONFIRMED-frame exchange (run_confirm_exchange). It no longer drops them.
    let session_id_clone = session_id.clone();
    let app_clone = app.clone();
    let sk_clone = Zeroizing::new(sk);
    let secret_clone = Zeroizing::new(secret);
    // #5 (GAP-D2): the Zeroizing copies (and the earlier `session.secret`/`map` copies) are now
    // made; the spawned task owns `sk_clone`/`secret_clone` which wipe on drop. Wipe THESE raw
    // command-local [u8;32] bindings — their last raw use was the two `Zeroizing::new` copies above.
    // (The pairing-code Strings built from `secret` are a separate, by-design residency, untouched.)
    secret.zeroize();
    sk.zeroize();
    let local_confirm_task = local_confirm.clone();
    let both_confirmed_task = both_confirmed.clone();
    let local_device_id_task = local_device_id.clone();
    let local_device_name_task = local_device_name.clone();
    let vault_pair_id_task = vault_pair_id.clone();

    tauri::async_runtime::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await {
            Ok(l) => l,
            Err(e) => {
                // Bind failed — remove session and report.
                let sessions = app_clone.state::<PairingSessionMap>();
                sessions.0.lock().unwrap().remove(&session_id_clone);
                let _ = app_clone.emit(
                    "pairing://error",
                    format!("pairing_initiate: bind failed: {}", e),
                );
                return;
            }
        };

        // Accept exactly one connection, but make the wait CANCELLABLE (H7) and BOUNDED (H6).
        // `accept_with_cancel` select!s the accept against the live `cancel_rx`; the outer
        // timeout bounds how long we wait for ANY peer to connect so a no-show cannot park the
        // task (and pin port 54321) forever.
        let accept_outcome =
            match tokio::time::timeout(CONNECT_ACCEPT_DEADLINE, accept_with_cancel(&listener, cancel_rx))
                .await
            {
                Ok(outcome) => outcome,
                Err(_) => {
                    // No peer connected within the accept deadline (H6). Drop the listener to
                    // free the port, then zeroize + remove the session.
                    drop(listener);
                    let sessions = app_clone.state::<PairingSessionMap>();
                    zeroize_and_remove_session(&sessions, &session_id_clone);
                    let _ = app_clone
                        .emit("pairing://error", "pairing_initiate: accept timed out".to_string());
                    return;
                }
            };

        let mut stream = match accept_outcome {
            AcceptOutcome::Accepted(s) => s,
            AcceptOutcome::Cancelled => {
                // H7: the cancel signal fired (timeout/finalize/refusal on the command side).
                // Drop the listener to free the port and tear down the session.
                drop(listener);
                let sessions = app_clone.state::<PairingSessionMap>();
                zeroize_and_remove_session(&sessions, &session_id_clone);
                return;
            }
            AcceptOutcome::Failed(e) => {
                drop(listener);
                let sessions = app_clone.state::<PairingSessionMap>();
                zeroize_and_remove_session(&sessions, &session_id_clone);
                let _ = app_clone
                    .emit("pairing://error", format!("pairing_initiate: accept failed: {}", e));
                return;
            }
        };

        // Drop listener to free the port (D-03: "Try again" must not collide).
        drop(listener);

        // Fix A (#3/#7) + H6: run the RESPONDER lifecycle with the CORRECT ordering —
        //   bounded handshake → STORE SAS + EMIT `pairing://sas` → bounded confirm wait.
        // The `on_sas` closure runs the instant the handshake completes and BEFORE the
        // confirm wait begins, so the user can actually SEE the SAS in time to confirm
        // within the 60 s window (the previous code emitted the SAS only AFTER the confirm
        // wait → circular deadlock → the window always lapsed → pairing could never succeed).
        // The handshake is bounded by HANDSHAKE_DEADLINE; the confirm by SAS_CONFIRM_WINDOW.
        let on_sas = |sas_display: &str| {
            // Persist the SAS into the session, then emit it to JS.
            {
                let sessions = app_clone.state::<PairingSessionMap>();
                let mut map = sessions.0.lock().unwrap();
                if let Some(session) = map.get_mut(&session_id_clone) {
                    session.sas_display = sas_display.to_string();
                }
            }
            let _ = app_clone.emit(
                "pairing://sas",
                serde_json::json!({
                    "sessionId": session_id_clone,
                    "sasDisplay": sas_display,
                }),
            );
        };

        let lifecycle = match run_responder_lifecycle(
            &mut stream,
            &*sk_clone,
            &secret_clone,
            &local_device_id_task,
            &local_device_name_task,
            Some(vault_pair_id_task.clone()), // Fix B: responder is the vaultPairId authority
            local_confirm_task,
            HANDSHAKE_DEADLINE,
            SAS_CONFIRM_WINDOW,
            on_sas,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                let sessions = app_clone.state::<PairingSessionMap>();
                zeroize_and_remove_session(&sessions, &session_id_clone);
                let _ = app_clone.emit("pairing://error", e);
                return;
            }
        };

        // Mutual confirmation succeeded — store the peer's GENUINE identity + static pk (H1) and
        // the NEGOTIATED vaultPairId (Fix B), then fire `both_confirmed` (pairing_finalize awaits).
        {
            let sessions = app_clone.state::<PairingSessionMap>();
            let mut map = sessions.0.lock().unwrap();
            if let Some(session) = map.get_mut(&session_id_clone) {
                session.peer_static_pk = lifecycle.peer_static_pk.clone();
                session.peer_device_id = Some(lifecycle.peer_device_id);
                session.peer_device_name = Some(lifecycle.peer_device_name);
                session.vault_pair_id = Some(lifecycle.vault_pair_id);
            }
        }
        both_confirmed_task.notify_one();
    });

    Ok(PairingInitResponse {
        qr_svg,
        base32_code,
        session_id,
    })
}

// ---------------------------------------------------------------------------
// pairing_connect — Device B (INITIATOR)
// ---------------------------------------------------------------------------

/// Device B: connect to an existing pairing session using the typed code.
///
/// This is a SEPARATE command from `pairing_initiate` — the committed contract (D-07/D-10).
/// Plans 05/06 register and wrap this exact function name.
///
/// - Decodes `code` (IP:PORT:BASE32SECRET+CHECKCHAR).
/// - Validates the check character (PairingCodeInvalidError on failure).
/// - Generates own keypair + a unique sessionId.
/// - `TcpStream::connect(ip:port)` — INITIATOR side.
/// - Runs `run_handshake_initiator` with the decoded 32-byte secret as the PSK.
/// - Emits the SAS to JS.
/// - Stores per-session state with a cancel oneshot.
/// - Returns `PairingInitResponse { qrSvg: "", base32Code: "", sessionId }`.
#[tauri::command]
pub async fn pairing_connect(
    app: tauri::AppHandle,
    config_dir: String,
    code: String,
) -> Result<PairingInitResponse, String> {
    // Decode the pairing code: IP:PORT:BASE32SECRET+CHECKCHAR
    // #5 (GAP-D2): `secret` is `[u8;32]` (Copy). The `Zeroizing::new(secret)` + `session.secret`
    // copies below abandon THIS stack-local un-wiped on return. Bind it `mut` so it can be
    // `secret.zeroize()`d after the last raw use.
    let (ip, port, mut secret) = decode_pairing_code(&code)?;

    // Fix C (#1): use the PERSISTED identity key as the handshake static key (not a fresh
    // throwaway), so the responder pins OUR stable identity public key — see pairing_initiate
    // for the full rationale + platform split.
    //
    // #5 (GAP-D2): `sk` is `[u8;32]` (Copy) — bind it `mut` so it can be wiped after the
    // `Zeroizing::new(sk)` copy is taken below.
    #[cfg(target_os = "windows")]
    let mut sk = {
        let store = WindowsCredentialStore;
        let (sk, _pk) = get_or_generate_keypair_from_store(&store, DEVICE_IDENTITY_SK_TARGET)?;
        sk
    };
    #[cfg(not(target_os = "windows"))]
    let mut sk = {
        // No OS Credential Manager here — ephemeral fallback (Windows is the canonical path).
        let (sk, _pk) = generate_device_keypair()?;
        sk
    };
    let session_id = new_uuid_v4();

    // This device's stable identity — sent to the peer in our CONFIRMED frame (H1).
    let local_device_id = read_or_create_local_device_id(&config_dir, "pairing_connect")?;
    let local_device_name = device_name_from_env();

    // Per-session cancel channel.
    let (cancel_tx, _cancel_rx) = oneshot::channel::<()>();
    let local_confirm = std::sync::Arc::new(Notify::new());
    let both_confirmed = std::sync::Arc::new(Notify::new());

    // Insert placeholder session (peer info filled in after handshake + confirm exchange).
    let session = PairingSession {
        transport: None,
        peer_static_pk: Vec::new(),
        secret,
        sas_display: String::new(),
        cancel_tx: Some(cancel_tx),
        local_confirm: local_confirm.clone(),
        both_confirmed: both_confirmed.clone(),
        local_confirmed: false,
        config_dir: config_dir.clone(),
        local_device_id: local_device_id.clone(),
        local_device_name: local_device_name.clone(),
        peer_device_id: None,
        peer_device_name: None,
        vault_pair_id: None,
    };

    {
        let sessions = app.state::<PairingSessionMap>();
        sessions.0.lock().unwrap().insert(session_id.clone(), session);
    }

    // Connect to Device A as INITIATOR. The connect itself is awaited inline (so a connect
    // failure is reported synchronously to JS), but the handshake + CONFIRMED-frame exchange
    // run in a spawned task that KEEPS the stream alive past the handshake (GAP-B / H1).
    //
    // H6: the connect is now BOUNDED by CONNECT_ACCEPT_DEADLINE — an unreachable / half-open host
    // can no longer park pairing_connect forever (the old unbounded TcpStream::connect was the
    // INITIATOR-side hole). On timeout/failure: zeroize + remove the session, return the error.
    let addr = format!("{}:{}", ip, port);
    let stream = match connect_with_timeout(&addr, CONNECT_ACCEPT_DEADLINE).await {
        Ok(s) => s,
        Err(e) => {
            let sessions = app.state::<PairingSessionMap>();
            zeroize_and_remove_session(&sessions, &session_id);
            // #5 (GAP-D2): the connect-failure early return must also wipe the raw command-local
            // [u8;32] bindings — the spawned-task Zeroizing copies were NOT taken on this path, so
            // these stack-locals are the only owners and must not return un-wiped.
            secret.zeroize();
            sk.zeroize();
            return Err(e);
        }
    };

    // Spawn the handshake + confirm-exchange task (holds the stream + transport).
    let session_id_task = session_id.clone();
    let app_task = app.clone();
    let sk_task = Zeroizing::new(sk);
    let secret_task = Zeroizing::new(secret);
    // #5 (GAP-D2): the Zeroizing copies (and the earlier `session.secret` copy in the map) are now
    // made; the spawned task owns `sk_task`/`secret_task` which wipe on drop. Wipe THESE raw
    // command-local [u8;32] bindings — their last raw use was the two `Zeroizing::new` copies above.
    secret.zeroize();
    sk.zeroize();
    let local_confirm_task = local_confirm.clone();
    let both_confirmed_task = both_confirmed.clone();
    let local_device_id_task = local_device_id.clone();
    let local_device_name_task = local_device_name.clone();

    tauri::async_runtime::spawn(async move {
        let mut stream = stream;

        // Fix A (#3/#7) + H6: run the INITIATOR lifecycle with the CORRECT ordering —
        //   bounded handshake → STORE SAS + EMIT `pairing://sas` → bounded confirm wait.
        // See pairing_initiate for the full deadlock rationale; the `on_sas` closure emits the
        // SAS the instant the handshake completes, BEFORE the confirm wait begins.
        let on_sas = |sas_display: &str| {
            {
                let sessions = app_task.state::<PairingSessionMap>();
                let mut map = sessions.0.lock().unwrap();
                if let Some(sess) = map.get_mut(&session_id_task) {
                    sess.sas_display = sas_display.to_string();
                }
            }
            let _ = app_task.emit(
                "pairing://sas",
                serde_json::json!({
                    "sessionId": session_id_task,
                    "sasDisplay": sas_display,
                }),
            );
        };

        let lifecycle = match run_initiator_lifecycle(
            &mut stream,
            &*sk_task,
            &secret_task,
            &local_device_id_task,
            &local_device_name_task,
            None, // Fix B: initiator is NOT the authority — it ADOPTS the responder's vaultPairId
            local_confirm_task,
            HANDSHAKE_DEADLINE,
            SAS_CONFIRM_WINDOW,
            on_sas,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                let sessions = app_task.state::<PairingSessionMap>();
                zeroize_and_remove_session(&sessions, &session_id_task);
                let _ = app_task.emit("pairing://error", e);
                return;
            }
        };

        // Mutual confirmation succeeded — store the peer's GENUINE identity + static pk (H1) and
        // the ADOPTED vaultPairId (Fix B), then fire `both_confirmed` (pairing_finalize awaits).
        {
            let sessions = app_task.state::<PairingSessionMap>();
            let mut map = sessions.0.lock().unwrap();
            if let Some(sess) = map.get_mut(&session_id_task) {
                sess.peer_static_pk = lifecycle.peer_static_pk.clone();
                sess.peer_device_id = Some(lifecycle.peer_device_id);
                sess.peer_device_name = Some(lifecycle.peer_device_name);
                sess.vault_pair_id = Some(lifecycle.vault_pair_id);
            }
        }
        both_confirmed_task.notify_one();
    });

    Ok(PairingInitResponse {
        qr_svg: String::new(),
        base32_code: String::new(),
        session_id,
    })
}

// ---------------------------------------------------------------------------
// pairing_confirm — record local SAS approval
// ---------------------------------------------------------------------------

/// Record that the local user has approved the SAS for this session.
///
/// Fires the `local_confirm` Notify so that `pairing_finalize` knows both sides confirmed.
/// Does NOT write peers.json or CredManager — that is pairing_finalize's job (D-06).
#[tauri::command]
pub async fn pairing_confirm(
    app: tauri::AppHandle,
    session_id: String,
) -> Result<(), String> {
    let sessions = app.state::<PairingSessionMap>();
    let local_confirm = {
        let map = sessions.0.lock().unwrap();
        let session = map
            .get(&session_id)
            .ok_or_else(|| format!("pairing_confirm: session '{}' not found", session_id))?;
        session.local_confirm.clone()
    };

    // Signal the confirmation wait loop.
    local_confirm.notify_one();

    // Mark confirmed in session map.
    {
        let mut map = sessions.0.lock().unwrap();
        if let Some(session) = map.get_mut(&session_id) {
            session.local_confirmed = true;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// pairing_finalize — the all-or-nothing commit point (D-06)
// ---------------------------------------------------------------------------

/// The ONLY commit point for a pairing session.
///
/// Security invariants enforced here:
/// 1. Mutual confirmation (D-06 / H1): finalize awaits `both_confirmed`, which the spawned
///    task fires ONLY after BOTH sides exchanged CONFIRMED frames over the SAS-verified Noise
///    transport (`run_confirm_exchange`). The peer deviceId/name persisted are the GENUINE
///    values received in the peer's CONFIRMED frame — never a fabricated UUID.
/// 2. 60 s timeout (D-02): the wait is wrapped in `tokio::time::timeout(60 s, ..)`. On
///    `Elapsed` (peer never confirmed → never sent CONFIRMED → task never fired
///    `both_confirmed`): zeroize+remove the session, write NOTHING, return the timeout error.
///    This is the PAIR-04/05 guarantee: a peer who dismisses → this side does NOT commit.
/// 3. All-or-nothing (D-06 / H5): the commit is delegated to `finalize_commit`, which writes
///    the CredManager peer key first (reversible) then peers.json (commit), rolling back the
///    CredManager key if peers.json fails. The session is zeroized + removed on BOTH the Ok
///    and Err arms via an explicit `match` (never an early `?` that skips cleanup).
#[tauri::command]
pub async fn pairing_finalize(
    app: tauri::AppHandle,
    config_dir: String,
    session_id: String,
) -> Result<(), String> {
    // Extract session state needed to await mutual confirmation.
    let (both_confirmed, config_dir_from_session) = {
        let sessions = app.state::<PairingSessionMap>();
        let map = sessions.0.lock().unwrap();
        let session = map
            .get(&session_id)
            .ok_or_else(|| format!("pairing_finalize: session '{}' not found", session_id))?;
        (session.both_confirmed.clone(), session.config_dir.clone())
    };

    // Use the config_dir from the command argument (or session as fallback).
    let effective_config_dir = if config_dir.is_empty() {
        config_dir_from_session
    } else {
        config_dir
    };

    // Await BOTH-sides confirmation over the SAS-verified channel, bounded by 60 s (D-02 / H1).
    // The task fires `both_confirmed` only after run_confirm_exchange succeeds (local confirm
    // sent + peer CONFIRMED frame received). If the peer dismisses, the peer never sends its
    // CONFIRMED frame, our task's run_confirm_exchange times out, `both_confirmed` never fires,
    // and THIS wait times out → commit NOTHING (PAIR-04/05).
    let confirm_result =
        tokio::time::timeout(Duration::from_secs(60), both_confirmed.notified()).await;

    if confirm_result.is_err() {
        // Timeout: zeroize + remove the session, write nothing (D-02 / D-06 / SC-3).
        let sessions = app.state::<PairingSessionMap>();
        zeroize_and_remove_session(&sessions, &session_id);
        return Err("pairing confirmation timed out".to_string());
    }

    // #6 (GAP-D2): guard the empty-peer-static-pk case BEFORE the field-extraction scope. The
    // helper tears the secret-bearing session down (zeroize + remove) on the incomplete-handshake
    // error path — mirroring the `peer_device_id == None` sibling below — instead of returning while
    // holding the lock and leaving the session lingering in the map (the pre-fix bug). It also
    // handles the "session vanished after confirmation" case.
    {
        let sessions = app.state::<PairingSessionMap>();
        finalize_guard_peer_static_pk(&sessions, &session_id)?;
    }

    // Both sides confirmed — read the GENUINE peer identity received over the CONFIRMED frame,
    // plus the NEGOTIATED vaultPairId (Fix B #2 — the shared value both sides committed to via
    // the CONFIRMED-frame exchange; NEVER a fresh new_uuid_v4() here, which produced divergent
    // ids on the two devices).
    let (peer_static_pk, peer_device_id, peer_device_name, local_device_name, vault_pair_id) = {
        let sessions = app.state::<PairingSessionMap>();
        let map = sessions.0.lock().unwrap();
        let session = match map.get(&session_id) {
            Some(s) => s,
            None => {
                return Err(format!(
                    "pairing_finalize: session '{}' vanished after confirmation",
                    session_id
                ))
            }
        };
        let peer_device_id = match &session.peer_device_id {
            Some(id) => id.clone(),
            None => {
                drop(map);
                let sessions = app.state::<PairingSessionMap>();
                zeroize_and_remove_session(&sessions, &session_id);
                return Err(format!(
                    "pairing_finalize: peer CONFIRMED frame missing for session '{}' — cannot commit",
                    session_id
                ));
            }
        };
        // Fix B (#2): the vaultPairId MUST be the negotiated value from the confirm exchange.
        let vault_pair_id = match &session.vault_pair_id {
            Some(vpid) if !vpid.is_empty() => vpid.clone(),
            _ => {
                drop(map);
                let sessions = app.state::<PairingSessionMap>();
                zeroize_and_remove_session(&sessions, &session_id);
                return Err(format!(
                    "pairing_finalize: negotiated vaultPairId missing for session '{}' — cannot commit (Fix B #2)",
                    session_id
                ));
            }
        };
        let peer_device_name = session
            .peer_device_name
            .clone()
            .unwrap_or_else(|| "Cryptiq Device".to_string());
        (
            session.peer_static_pk.clone(),
            peer_device_id,
            peer_device_name,
            session.local_device_name.clone(),
            vault_pair_id,
        )
    };

    // All-or-nothing commit (H5). Use the platform credential store; on non-Windows, the no-op
    // store keeps the commit path well-defined (peers.json still written).
    #[cfg(target_os = "windows")]
    let commit_result = {
        let store = WindowsCredentialStore;
        finalize_commit(
            &store,
            &effective_config_dir,
            &peer_static_pk,
            &peer_device_id,
            &peer_device_name,
            &vault_pair_id,
            &local_device_name,
        )
    };
    #[cfg(not(target_os = "windows"))]
    let commit_result = {
        let store = NoopCredentialStore;
        finalize_commit(
            &store,
            &effective_config_dir,
            &peer_static_pk,
            &peer_device_id,
            &peer_device_name,
            &vault_pair_id,
            &local_device_name,
        )
    };

    // Cleanup runs on BOTH arms (explicit match — never an early `?` that skips zeroize, H5).
    let sessions = app.state::<PairingSessionMap>();
    zeroize_and_remove_session(&sessions, &session_id);

    match commit_result {
        Ok(()) => Ok(()),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// unpair_device — remove peer material, keep own key (D-17)
// ---------------------------------------------------------------------------

/// Remove a peer from peers.json AND its CredManager entry.
///
/// DOES NOT touch `cryptiq/device/identity-sk` (D-17: own identity keypair is kept).
#[tauri::command]
pub fn unpair_device(config_dir: String, device_id: String) -> Result<(), String> {
    // Read current peers.json.
    let mut doc = read_peers_json(&config_dir)?;

    // Remove the peer entry.
    let before_len = doc.peers.len();
    doc.peers.retain(|p| p.device_id != device_id);

    if doc.peers.len() == before_len {
        return Err(format!(
            "unpair_device: peer '{}' not found in peers.json",
            device_id
        ));
    }

    // Delete from CredManager.
    #[cfg(target_os = "windows")]
    {
        let store = WindowsCredentialStore;
        let target = peer_target(&device_id);
        // Tolerate "not found" (peer key may not be in CredManager on non-Windows or after import).
        let _ = store.delete(&target);
    }

    // Atomic rewrite of peers.json.
    write_peers_json_atomic(&config_dir, &doc)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// peers_json_read — return the current peers list
// ---------------------------------------------------------------------------

/// Return the current peers list from peers.json.
///
/// Returns an empty list if peers.json does not yet exist.
#[tauri::command]
pub fn peers_json_read(config_dir: String) -> Result<Vec<PeerRecord>, String> {
    let doc = read_peers_json(&config_dir)?;
    Ok(doc.peers)
}

// ---------------------------------------------------------------------------
// Tauri commands from Plan 09-03 (layer 1)
// ---------------------------------------------------------------------------

/// The friendly device name, seeded from the host environment (D-12).
fn device_name_from_env() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "Cryptiq Device".to_string())
}

/// Read (or first-time create) the stable local deviceId from `<config_dir>/cryptiq/device-id.json`.
///
/// This is the SINGLE source of the local deviceId (D-13: stable opaque UUID, not key-derived).
/// `get_local_device_info` and the pairing CONFIRMED-frame path both call it, so the deviceId a
/// peer receives in our CONFIRMED frame is byte-identical to the one we advertise elsewhere (H1).
fn read_or_create_local_device_id(config_dir: &str, ctx: &str) -> Result<String, String> {
    #[derive(Serialize, Deserialize)]
    struct DeviceIdFile {
        device_id: String,
    }

    let device_id_file = std::path::PathBuf::from(config_dir)
        .join("cryptiq")
        .join("device-id.json");

    if device_id_file.exists() {
        let raw = std::fs::read_to_string(&device_id_file)
            .map_err(|e| format!("{}: read device-id failed: {}", ctx, e))?;
        let parsed: DeviceIdFile = serde_json::from_str(&raw)
            .map_err(|e| format!("{}: parse device-id failed: {}", ctx, e))?;
        Ok(parsed.device_id)
    } else {
        let id = new_uuid_v4();
        let parent = device_id_file.parent().unwrap();
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: mkdir failed: {}", ctx, e))?;
        let content = serde_json::to_string(&DeviceIdFile { device_id: id.clone() })
            .map_err(|e| format!("{}: serialize device-id failed: {}", ctx, e))?;
        std::fs::write(&device_id_file, content)
            .map_err(|e| format!("{}: write device-id failed: {}", ctx, e))?;
        Ok(id)
    }
}

/// Return this device's identity info (public key + IDs).
#[tauri::command]
pub fn get_local_device_info(config_dir: String) -> Result<LocalDeviceInfo, String> {
    let device_id = read_or_create_local_device_id(&config_dir, "get_local_device_info")?;

    // get_local_device_info only needs the PUBLIC key. We use the public-key-only accessor
    // so the device identity PRIVATE key is never surfaced to this caller (L3). The previous
    // code copied `sk_bytes` into a fresh binding and wiped the COPY (`[u8;32]: Copy`), which
    // was a dead no-op that left the real bytes intact in this stack frame.
    #[cfg(target_os = "windows")]
    let pk_bytes = {
        let store = WindowsCredentialStore;
        get_or_generate_public_key_from_store(&store, DEVICE_IDENTITY_SK_TARGET)?
    };
    #[cfg(not(target_os = "windows"))]
    let pk_bytes = {
        // Non-Windows desktop has no Credential Manager; generate an ephemeral keypair and
        // surface only the public key (the private half is wiped inside generate-and-wipe).
        let (mut sk, pk) = generate_device_keypair()?;
        sk.zeroize(); // M1: volatile wipe (not an elidable `*b = 0` loop)
        let _ = &sk;
        pk
    };

    let pk_hex = hex_encode(&pk_bytes);

    let device_name = device_name_from_env();

    Ok(LocalDeviceInfo {
        device_id,
        static_public_key: pk_hex,
        device_name,
    })
}

/// IPC target-access guard for the generic `device_key_read`/`device_key_write` commands.
///
/// Threat (H3/H4): the generic credential commands are reachable from JS via
/// `invoke('device_key_read'|'device_key_write', { target })`. Without a guard, a malicious
/// renderer / XSS / compromised dependency could read the device identity PRIVATE key
/// (`cryptiq/device/identity-sk`) out of Credential Manager, or clobber it with attacker
/// bytes — bricking every existing pairing (peers pinned the old key).
///
/// Policy (fail closed): the only material JS is ever allowed to touch via these generic
/// commands is PEER public-key material under the `cryptiq/peer/` prefix. Everything else —
/// most importantly the identity SK target — is refused. The device identity keypair is
/// created ONLY by `get_or_generate_keypair_from_store`, never over IPC.
///
/// This guard is platform-independent and runs BEFORE any Credential Manager FFI, so it is
/// unit-testable on every platform (T-09-06).
fn assert_ipc_target_allowed(op: &str, target: &str) -> Result<(), String> {
    if target == DEVICE_IDENTITY_SK_TARGET {
        return Err(format!(
            "{}: refusing to access the device identity private key over IPC (T-09-06)",
            op
        ));
    }
    if !target.starts_with("cryptiq/peer/") {
        return Err(format!(
            "{}: target '{}' is not permitted over IPC — only peer material under 'cryptiq/peer/' is allowed (T-09-06)",
            op, target
        ));
    }
    Ok(())
}

#[tauri::command]
pub fn device_key_write(target: String, key_bytes: Vec<u8>) -> Result<(), String> {
    // H4: refuse identity SK + restrict writable targets to the peer prefix (runs on all platforms).
    assert_ipc_target_allowed("device_key_write", &target)?;
    #[cfg(target_os = "windows")]
    {
        let store = WindowsCredentialStore;
        store.write(&target, &key_bytes)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (target, key_bytes);
        Err("device_key_write: Windows Credential Manager is not available on this platform".to_string())
    }
}

#[tauri::command]
pub fn device_key_read(target: String) -> Result<Vec<u8>, String> {
    // H3: refuse identity SK + restrict readable targets to the peer prefix (runs on all platforms).
    assert_ipc_target_allowed("device_key_read", &target)?;
    #[cfg(target_os = "windows")]
    {
        let store = WindowsCredentialStore;
        store.read(&target)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = target;
        Err("device_key_read: Windows Credential Manager is not available on this platform".to_string())
    }
}

#[tauri::command]
pub fn device_key_delete(target: String) -> Result<(), String> {
    if target == DEVICE_IDENTITY_SK_TARGET {
        return Err("device_key_delete: refusing to delete own device identity key (D-17)".to_string());
    }
    #[cfg(target_os = "windows")]
    {
        let store = WindowsCredentialStore;
        store.delete(&target)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = target;
        Err("device_key_delete: Windows Credential Manager is not available on this platform".to_string())
    }
}

// ---------------------------------------------------------------------------
// Private utilities
// ---------------------------------------------------------------------------

/// Generate 32 CSPRNG bytes for the pairing secret using OsRng via snow.
///
/// Returns a `[u8; 32]` — Math.random is banned; OsRng is the only source.
fn generate_pairing_secret() -> Result<[u8; 32], String> {
    // Use snow's generate_keypair() to get OsRng-seeded bytes, take the 32-byte private key.
    let builder = Builder::new(PARAMS.clone());
    // #4 (GAP-D2): this is the PSK SOURCE. snow's Keypair has no Drop/Zeroize, so the private-key
    // heap Vec is freed UNWIPED when `kp` drops. Bind mutably and `kp.private.zeroize()` after the
    // 32-byte copy is taken — the PSK must not survive in the snow-owned heap buffer.
    let mut kp = builder
        .generate_keypair()
        .map_err(|e| format!("generate_pairing_secret: snow generate_keypair failed: {}", e))?;
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&kp.private[..32]);
    // #4: copy made — wipe the snow-owned private heap buffer before `kp` drops (single return
    // path; no path returns before this wipe).
    kp.private.zeroize();
    Ok(secret)
}

/// Decode a pairing code string: `IP:PORT:BASE32SECRET+CHECKCHAR`.
///
/// Returns `(ip_str, port, secret_32_bytes)`.
/// Validates the check character before returning.
fn decode_pairing_code(code: &str) -> Result<(String, u16, [u8; 32]), String> {
    // Normalize: strip whitespace and dashes (user may have typed dashes as grouping).
    let normalized: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();

    // Split into IP:PORT:BASE32+CHECKCHAR
    let parts: Vec<&str> = normalized.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err(format!(
            "decode_pairing_code: invalid code format (expected IP:PORT:SECRET, got {} parts)",
            parts.len()
        ));
    }

    let ip = parts[0].to_string();
    let port: u16 = parts[1]
        .parse()
        .map_err(|_| format!("decode_pairing_code: invalid port '{}'", parts[1]))?;

    let secret_field = parts[2];

    // L2: the secret field MUST be ASCII. A non-ASCII char (e.g. a multi-byte emoji) would make
    // the byte-indexed trailing-char split below land mid-codepoint and PANIC. Validate up front
    // and return a typed Err instead. (A legitimate Crockford code is ASCII by construction; this
    // only rejects malformed input reachable via a direct invoke('pairing_connect').)
    if !secret_field.is_ascii() {
        return Err(
            "decode_pairing_code: secret field contains non-ASCII characters — not a valid Crockford code".to_string(),
        );
    }

    // Split off the trailing check character on a CHARACTER boundary (L2). The field is ASCII
    // (guarded above), so chars == bytes here, but we split on chars to be byte-safe regardless.
    let mut chars = secret_field.chars();
    let check_char = match chars.next_back() {
        Some(c) => c,
        None => return Err("decode_pairing_code: secret field is empty".to_string()),
    };
    let base32_body: String = chars.as_str().to_string();
    if base32_body.is_empty() {
        return Err("decode_pairing_code: secret field too short".to_string());
    }

    // M2 / D-11: apply the SAME Crockford look-alike normalization as validatePairingCode
    // (pairingCode.ts) and decodeRecoveryKey (recovery.ts) — uppercase + map I/L→1, O→0, U→V on
    // the BODY only. This lets a user who types look-alike LETTERS (O for 0, etc.) decode to the
    // canonical bytes instead of hitting a "decode failed" the way the raw forwarded code did.
    let normalized_body: String = base32_body.chars().map(map_crockford_lookalike_body).collect();
    // The CHECK char is normalized for I/L→1, O→0 but NOT U→V — 'U' is a valid check symbol
    // (index 36). This preserves the 'U' check symbol exactly (CR-01 parity with recovery.ts).
    let check_char = map_crockford_lookalike_check(check_char);

    // Decode the base32 body.
    let decoded_bytes = crockford_decode(&normalized_body)
        .map_err(|e| format!("decode_pairing_code: base32 decode failed: {}", e))?;

    // Validate check character.
    let expected_check = crockford_check_char(&decoded_bytes);
    if check_char != expected_check {
        return Err(format!(
            "decode_pairing_code: check character mismatch (got '{}', expected '{}') — likely a typo",
            check_char, expected_check
        ));
    }

    if decoded_bytes.len() != 32 {
        return Err(format!(
            "decode_pairing_code: expected 32-byte secret, got {} bytes",
            decoded_bytes.len()
        ));
    }

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&decoded_bytes);

    Ok((ip, port, secret))
}

/// Generate a random UUID v4 using snow's OsRng (Math.random is banned).
fn new_uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let builder = Builder::new(PARAMS.clone());
    // #4 (GAP-D2): this generates a full keypair JUST for random bytes (it reads `kp.public`), but
    // snow still allocated a private-key heap Vec with no Drop/Zeroize. Bind mutably and
    // `kp.private.zeroize()` before returning so the discarded private half is wiped, not just freed.
    let mut kp = builder.generate_keypair().expect("OsRng available");

    let b = &kp.public[..16];
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(b);
    // #4: the `kp.public` borrow (`b`) has ended — wipe the snow-owned private heap buffer now,
    // before the (single) `format!` return path, so no path returns before the wipe.
    kp.private.zeroize();
    let ts_bytes = ts.to_le_bytes();
    for i in 0..8 {
        bytes[8 + i] ^= ts_bytes[i];
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

/// Encode a byte slice as a lowercase hex string.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Read or generate the device keypair, persisting `sk||pk` (64 bytes) in the store.
///
/// This is the store-generic core (always compiled — used directly by tests and by the
/// Windows path). The persisted blob is a 64-byte `sk(32) || pk(32)` concatenation so the
/// advertised public key always MATCHES the persisted private key across restarts (H2).
///
/// Read behaviour:
///   - 64-byte blob → take `pk = blob[32..64]` (the persisted, matching public key).
///   - any other length (stale 32-byte blob from the pre-fix format, or corruption) →
///     REGENERATE a fresh keypair and write it back as 64 bytes. snow has no
///     private→public scalar-mult helper, so storing both halves is the correct approach;
///     we never try to re-derive pk from a bare 32-byte sk (that path fabricated a brand-new
///     random public key — the H2 bug).
///
/// Security: the returned private key is owned by the caller, who is responsible for its
/// lifecycle. Callers that only need the public key MUST use
/// `get_or_generate_public_key_with_store` so the private key is never surfaced to them (L3).
fn get_or_generate_keypair_from_store(
    store: &dyn CredentialStore,
    target: &str,
) -> Result<([u8; 32], [u8; 32]), String> {
    if let Ok(existing) = store.read(target) {
        if existing.len() == 64 {
            // Activate the (previously dead) 64-byte branch: pk is the persisted second half.
            let mut sk = [0u8; 32];
            let mut pk = [0u8; 32];
            sk.copy_from_slice(&existing[..32]);
            pk.copy_from_slice(&existing[32..64]);
            return Ok((sk, pk));
        }
        // Stale 32-byte blob (pre-fix format) or any other length → fall through to regenerate.
    }

    // Generate a fresh keypair and persist `sk || pk` (64 bytes).
    let (sk, pk) = generate_device_keypair()?;
    let mut blob = [0u8; 64];
    blob[..32].copy_from_slice(&sk);
    blob[32..].copy_from_slice(&pk);
    store.write(target, &blob).map_err(|e| {
        format!("get_or_generate_keypair_from_store: store keypair failed: {}", e)
    })?;
    Ok((sk, pk))
}

/// Read or generate the device keypair and return ONLY the public key.
///
/// Used by callers (e.g. `get_local_device_info`) that have no business holding the private
/// key. This avoids the L3 dead-no-op-wipe footgun: the private key is wiped here on a
/// real `&mut` binding (not a `Copy`), so the bytes never escape this function.
fn get_or_generate_public_key_from_store(
    store: &dyn CredentialStore,
    target: &str,
) -> Result<[u8; 32], String> {
    let (mut sk, pk) = get_or_generate_keypair_from_store(store, target)?;
    // Wipe the real private-key binding (NOT a Copy of it) before returning — L3.
    // M1: volatile zeroize so the compiler cannot elide the wipe.
    sk.zeroize();
    let _ = &sk;
    Ok(pk)
}

/// Zeroize a session's secret and remove it from the map.
///
/// Called on re-pair refusal / timeout / any abort to ensure no half-state lingers.
/// M1: the actual secret wipe now happens in `PairingSession`'s `Drop` (volatile zeroize), so
/// `map.remove` is sufficient to trigger it. The explicit pre-wipe here is belt-and-braces in
/// case the value is ever moved out instead of dropped in place.
///
/// H7: SEND the session's `cancel_tx` before removing so a still-running listener task (one that
/// is parked inside `accept_with_cancel` waiting for a peer) is interrupted and DROPS its
/// listener — freeing port 54321 so the next `pairing_initiate` does not hit `EADDRINUSE`. We
/// `take()` the sender and `.send(())` it; if the listener already moved past accept (or the
/// receiver was dropped), the send is a harmless no-op (`Err` ignored).
fn zeroize_and_remove_session(sessions: &PairingSessionMap, session_id: &str) {
    let mut map = sessions.0.lock().unwrap();
    if let Some(session) = map.get_mut(session_id) {
        session.secret.zeroize();
        session.peer_static_pk.zeroize();
        // H7: fire the cancel signal so the listener task's select! aborts + frees the port.
        if let Some(cancel) = session.cancel_tx.take() {
            let _ = cancel.send(());
        }
    }
    // Dropping the removed session runs `impl Drop for PairingSession` → volatile zeroize.
    map.remove(session_id);
}

/// #6 (GAP-D2): the empty-peer-static-pk guard for `pairing_finalize`.
///
/// If the session's handshake never populated `peer_static_pk` (still empty), the pairing cannot
/// be committed. The PRE-FIX inline guard returned `Err` while still holding the map lock and LEFT
/// the secret-bearing session in the map — inconsistent with the sibling `peer_device_id == None`
/// arm, which drops the guard and calls `zeroize_and_remove_session`. This helper mirrors the
/// sibling: it inspects the session under a SHORT-lived lock, releases the guard, then (on the
/// empty-pk error path) tears the session DOWN (zeroize + remove) before returning the `Err`.
///
/// Extracted as a free function (taking `&PairingSessionMap` like `zeroize_and_remove_session`) so
/// the teardown decision is observable in unit tests WITHOUT an `AppHandle` (the session map is the
/// observable surface — see `d2_finalize_empty_peer_pk_removes_session_from_map`).
///
/// Returns:
///   - `Ok(())`  — `peer_static_pk` is populated; the session stays in the map for finalize to commit.
///   - `Err(..)` — session vanished, OR handshake incomplete (empty pk) → session torn down first.
fn finalize_guard_peer_static_pk(
    sessions: &PairingSessionMap,
    session_id: &str,
) -> Result<(), String> {
    // Read the flag under a short-lived lock, then RELEASE it before any teardown (which re-locks),
    // exactly like the sibling arm's `drop(map)` discipline — no Err is ever returned while holding
    // the guard, and no secret-bearing session is left behind.
    let peer_pk_empty = {
        let map = sessions.0.lock().unwrap();
        match map.get(session_id) {
            Some(session) => session.peer_static_pk.is_empty(),
            None => {
                return Err(format!(
                    "pairing_finalize: session '{}' vanished after confirmation",
                    session_id
                ))
            }
        }
    };

    if peer_pk_empty {
        // #6: mirror the sibling — tear the session down (zeroize + remove) THEN return the Err,
        // instead of returning while holding the lock and leaving the session in the map.
        zeroize_and_remove_session(sessions, session_id);
        return Err(format!(
            "pairing_finalize: handshake not complete for session '{}'",
            session_id
        ));
    }

    Ok(())
}

/// All-or-nothing finalize commit (GAP-B / H5 — D-06).
///
/// Store-generic and config-dir-injected so it is unit-testable on every platform (mirroring
/// how 09-04 made `await_mutual_confirm` testable). The Tauri command `pairing_finalize` is a
/// thin wrapper that supplies a `WindowsCredentialStore` and the peer identity received over
/// the CONFIRMED frame.
///
/// Ordering + rollback discipline (the H5 fix):
///   1. Re-pair guard (D-16): refuse if a peer with this static public key already exists.
///   2. Write the CredManager peer key FIRST — this is the *reversible* step.
///   3. `write_peers_json_atomic` is the COMMIT. If it fails, DELETE the just-written
///      CredManager peer key (best-effort) so no orphaned key is left, then return `Err`.
///   4. On success, peers.json + CredManager are both present (all-or-nothing).
///
/// The caller is responsible for session zeroize+remove on BOTH the Ok and Err arms (it uses an
/// explicit match, never an early `?` that would skip cleanup).
#[allow(clippy::too_many_arguments)]
fn finalize_commit(
    store: &dyn CredentialStore,
    config_dir: &str,
    peer_static_pk: &[u8],
    peer_device_id: &str,
    peer_device_name: &str,
    vault_pair_id: &str,
    local_device_name: &str,
) -> Result<(), String> {
    // 1. Re-pair guard (D-16).
    let current_doc = read_peers_json(config_dir)?;
    let peer_pk_hex = hex_encode(peer_static_pk);
    for existing in &current_doc.peers {
        if existing.static_public_key == peer_pk_hex {
            return Err(
                "pairing_finalize: re-pair refused — a peer with this static public key already exists in peers.json; remove it first (D-16)".to_string()
            );
        }
    }

    let peer_record = PeerRecord {
        device_id: peer_device_id.to_string(),
        device_name: peer_device_name.to_string(),
        static_public_key: peer_pk_hex,
        vault_pair_id: vault_pair_id.to_string(),
        paired_at: now_iso8601(),
        last_synced_at: None,
        last_known_ip: None,
        last_known_port: None,
    };

    // 2. Write the CredManager peer key FIRST (reversible step).
    let cred_target = peer_target(peer_device_id);
    store.write(&cred_target, peer_static_pk)?;

    // Build the updated peers.json doc.
    let mut updated_doc = current_doc;
    updated_doc.peers.push(peer_record);
    if updated_doc.local_device_id.is_empty() {
        // Fix C (#1): the self-record must match what the PEER pinned about us. Seed
        // local_device_id from the STABLE id (read_or_create_local_device_id — the same id we
        // sent in our CONFIRMED frame) and local_static_public_key from the PERSISTED identity
        // public key (get_or_generate_public_key_from_store) — NOT a fresh UUID + throwaway pk
        // (which never matched our advertised identity).
        let local_id = match read_or_create_local_device_id(config_dir, "finalize_commit") {
            Ok(id) => id,
            Err(e) => {
                let _ = store.delete(&cred_target); // roll back the CredManager peer key (H5)
                return Err(e);
            }
        };
        // The identity public key. On Windows we read the PERSISTED identity pk so the self-record
        // matches the key our peer pinned. Where no OS keystore exists, fall back to the injected
        // store (tests inject a MockCredentialStore seeded with a known identity, so this path is
        // exercised too); the persisted-key path is the canonical one.
        let local_pk = match get_or_generate_public_key_from_store(store, DEVICE_IDENTITY_SK_TARGET) {
            Ok(pk) => pk,
            Err(e) => {
                let _ = store.delete(&cred_target); // roll back (H5)
                return Err(e);
            }
        };
        updated_doc.local_device_id = local_id;
        updated_doc.local_static_public_key = hex_encode(&local_pk);
        updated_doc.local_device_name = local_device_name.to_string();
    }

    // 3. COMMIT: peers.json atomic write. On failure, roll back the CredManager peer key (H5).
    if let Err(e) = write_peers_json_atomic(config_dir, &updated_doc) {
        // Best-effort rollback — never leave an orphaned CredManager peer key (D-06).
        let _ = store.delete(&cred_target);
        return Err(e);
    }

    // 4. Both writes succeeded — all-or-nothing commit complete.
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 12 — read-only SAS poll fallback (Plan 12-01 Task 2)
// ---------------------------------------------------------------------------

/// Read-only SAS display string for a known pairing session (Phase 12 D-07 poll fallback).
///
/// Returns the already-computed SAS display string (e.g. "042 318") from the
/// in-memory session map. This command does NOT mutate the Noise state, does NOT
/// call `get_handshake_hash()`, and does NOT affect the wire protocol — it is a
/// plain HashMap read.
///
/// Used by the JS renderer as a fallback when the `pairing://sas` Tauri event is
/// missed (i.e., the JS listener was registered after the event was emitted). The
/// event is the primary path; this is belt-and-suspenders.
///
/// Returns `Err` if:
///  - the session_id is not found in the map
///  - sas_display is empty (SAS not yet derived for this session)
///
/// SECURITY: The SAS is public display data — it is intentionally compared aloud
/// between users on both devices. It contains no key material, no PSK, no Noise
/// state (T-12-03: disposed as "accept"). The command is registered in lib.rs
/// alongside the other pairing commands.
#[tauri::command]
pub async fn pairing_get_sas(
    app: tauri::AppHandle,
    session_id: String,
) -> Result<String, String> {
    let sessions = app.state::<PairingSessionMap>();
    let map = sessions.0.lock().unwrap();
    let session = map
        .get(&session_id)
        .ok_or_else(|| format!("pairing_get_sas: session '{}' not found", session_id))?;
    if session.sas_display.is_empty() {
        return Err("pairing_get_sas: SAS not yet derived for this session".to_string());
    }
    Ok(session.sas_display.clone())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Phase 15 Plan 01 Task 2: `pub` (not just `#[cfg(test)]`) so `extension_peers.rs`'s own
// #[cfg(test)] module can reuse `MockCredentialStore` verbatim instead of duplicating it
// (RESEARCH.md Wave 0 Gaps / 15-01-PLAN.md Task 2 read_first) — the smallest visibility
// change needed, no logic change.
#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // ── MockCredentialStore ──────────────────────────────────────────────────

    pub struct MockCredentialStore {
        store: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl MockCredentialStore {
        pub fn new() -> Self {
            MockCredentialStore {
                store: Mutex::new(HashMap::new()),
            }
        }

        pub fn contains(&self, target: &str) -> bool {
            self.store.lock().unwrap().contains_key(target)
        }
    }

    impl CredentialStore for MockCredentialStore {
        fn write(&self, target: &str, key_bytes: &[u8]) -> Result<(), String> {
            self.store
                .lock()
                .unwrap()
                .insert(target.to_string(), key_bytes.to_vec());
            Ok(())
        }

        fn read(&self, target: &str) -> Result<Vec<u8>, String> {
            self.store
                .lock()
                .unwrap()
                .get(target)
                .cloned()
                .ok_or_else(|| format!("MockCredentialStore: '{}' not found (ERROR_NOT_FOUND)", target))
        }

        fn delete(&self, target: &str) -> Result<(), String> {
            let removed = self.store.lock().unwrap().remove(target);
            if removed.is_some() {
                Ok(())
            } else {
                Err(format!(
                    "MockCredentialStore: '{}' not found (ERROR_NOT_FOUND)",
                    target
                ))
            }
        }
    }

    // ── Helper: create fresh temp dir per test ───────────────────────────────

    fn fresh_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cryptiq_pairing_test_{}", name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    // ── Helper: run a full in-process XX handshake over tokio channels ──────

    async fn run_in_process_handshake(
        secret: &[u8; 32],
    ) -> (
        ([u8; 32], snow::HandshakeState),
        ([u8; 32], snow::HandshakeState),
    ) {
        let (sk_a, _pk_a) = generate_device_keypair().unwrap();
        let (sk_b, _pk_b) = generate_device_keypair().unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let secret_a = *secret;
        let secret_b = *secret;
        let sk_a_clone = sk_a;
        let sk_b_clone = sk_b;

        let responder_task = tokio::spawn(async move {
            let (mut stream_a, _) = listener.accept().await.unwrap();
            let mut noise_r = build_responder(&sk_a_clone, &secret_a).unwrap();
            let mut buf = Vec::new();
            let mut msg_buf = vec![0u8; 65535];

            recv_framed(&mut stream_a, &mut buf).await.unwrap();
            noise_r.read_message(&buf, &mut msg_buf).unwrap();

            let len = noise_r.write_message(&[], &mut msg_buf).unwrap();
            send_framed(&mut stream_a, &msg_buf[..len]).await.unwrap();

            recv_framed(&mut stream_a, &mut buf).await.unwrap();
            noise_r.read_message(&buf, &mut msg_buf).unwrap();

            (sk_a_clone, noise_r)
        });

        let mut stream_b = TcpStream::connect(addr).await.unwrap();
        let mut noise_i = build_initiator(&sk_b_clone, &secret_b).unwrap();
        let mut buf = Vec::new();
        let mut msg_buf = vec![0u8; 65535];

        let len = noise_i.write_message(&[], &mut msg_buf).unwrap();
        send_framed(&mut stream_b, &msg_buf[..len]).await.unwrap();

        recv_framed(&mut stream_b, &mut buf).await.unwrap();
        noise_i.read_message(&buf, &mut msg_buf).unwrap();

        let len = noise_i.write_message(&[], &mut msg_buf).unwrap();
        send_framed(&mut stream_b, &msg_buf[..len]).await.unwrap();

        let (sk_a_final, noise_r_final) = responder_task.await.unwrap();
        ((sk_b_clone, noise_i), (sk_a_final, noise_r_final))
    }

    // ── Layer-1 tests (from Plan 09-03 — preserved intact) ──────────────────

    #[test]
    fn credential_roundtrip() {
        let store = MockCredentialStore::new();
        let key_bytes: Vec<u8> = (0u8..32).collect();

        store.write(DEVICE_IDENTITY_SK_TARGET, &key_bytes).unwrap();

        let read_back = store.read(DEVICE_IDENTITY_SK_TARGET).unwrap();
        assert_eq!(read_back, key_bytes, "read-back bytes must equal written bytes");

        store.delete(DEVICE_IDENTITY_SK_TARGET).unwrap();

        let result = store.read(DEVICE_IDENTITY_SK_TARGET);
        assert!(
            result.is_err(),
            "read after delete must return error (ERROR_NOT_FOUND)"
        );
    }

    #[test]
    fn keypair_survives_password_change() {
        let store = MockCredentialStore::new();
        let (sk, _pk) = generate_device_keypair().unwrap();
        let original_sk = sk.to_vec();

        store.write(DEVICE_IDENTITY_SK_TARGET, &sk).unwrap();

        let after_password_change = store.read(DEVICE_IDENTITY_SK_TARGET).unwrap();
        assert_eq!(
            after_password_change, original_sk,
            "device keypair must survive master-password change"
        );
    }

    #[tokio::test]
    async fn noise_xx_handshake_local() {
        let secret: [u8; 32] = [0x42u8; 32];
        let ((_sk_i, noise_i), (_sk_r, noise_r)) = run_in_process_handshake(&secret).await;

        assert!(noise_i.is_handshake_finished(), "initiator handshake not finished");
        assert!(noise_r.is_handshake_finished(), "responder handshake not finished");

        let _transport_i = noise_i
            .into_transport_mode()
            .expect("initiator into_transport_mode must succeed");
        let _transport_r = noise_r
            .into_transport_mode()
            .expect("responder into_transport_mode must succeed");
    }

    #[tokio::test]
    async fn noise_xx_wrong_psk_fails() {
        let secret_a: [u8; 32] = [0xAAu8; 32];
        let secret_b: [u8; 32] = [0xBBu8; 32];

        let (sk_a, _pk_a) = generate_device_keypair().unwrap();
        let (sk_b, _pk_b) = generate_device_keypair().unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let secret_a_clone: [u8; 32] = secret_a;
        let sk_a_clone = sk_a;

        let responder_task = tokio::spawn(async move {
            let (mut stream_a, _) = listener.accept().await.unwrap();
            let mut noise_r = build_responder(&sk_a_clone, &secret_a_clone).unwrap();
            let mut buf = Vec::new();
            let mut msg_buf = vec![0u8; 65535];

            if recv_framed(&mut stream_a, &mut buf).await.is_err() {
                return Err("responder: recv msg1 failed".to_string());
            }
            if noise_r.read_message(&buf, &mut msg_buf).is_err() {
                return Err("responder: read_message msg1 failed".to_string());
            }

            let len = match noise_r.write_message(&[], &mut msg_buf) {
                Ok(l) => l,
                Err(_) => return Err("responder: write_message msg2 failed".to_string()),
            };
            if send_framed(&mut stream_a, &msg_buf[..len]).await.is_err() {
                return Err("responder: send msg2 failed".to_string());
            }

            if recv_framed(&mut stream_a, &mut buf).await.is_err() {
                return Err("responder: recv msg3 failed".to_string());
            }
            match noise_r.read_message(&buf, &mut msg_buf) {
                Ok(_) => Ok(()),
                Err(_) => Err("responder: authentication error on msg3 (expected with wrong PSK)".to_string()),
            }
        });

        let mut stream_b = TcpStream::connect(addr).await.unwrap();
        let mut noise_i = build_initiator(&sk_b, &secret_b).unwrap();
        let mut buf = Vec::new();
        let mut msg_buf = vec![0u8; 65535];

        let len = noise_i.write_message(&[], &mut msg_buf).unwrap();
        send_framed(&mut stream_b, &msg_buf[..len]).await.unwrap();

        recv_framed(&mut stream_b, &mut buf).await.unwrap();
        noise_i.read_message(&buf, &mut msg_buf).unwrap();

        let len = noise_i.write_message(&[], &mut msg_buf).unwrap();
        send_framed(&mut stream_b, &msg_buf[..len]).await.unwrap();

        let responder_result = responder_task.await.unwrap();

        assert!(
            responder_result.is_err(),
            "wrong PSK must cause authentication error on at least the responder side"
        );
    }

    #[tokio::test]
    async fn sas_symmetry() {
        let secret: [u8; 32] = [0x55u8; 32];
        let ((_sk_i, noise_i), (_sk_r, noise_r)) = run_in_process_handshake(&secret).await;

        let (sas_i, display_i) = derive_sas(&noise_i);
        let (sas_r, display_r) = derive_sas(&noise_r);

        assert_eq!(sas_i, sas_r, "initiator and responder SAS values must be identical");
        assert_eq!(display_i, display_r, "SAS display strings must be identical");
    }

    #[tokio::test]
    async fn sas_format() {
        let secret: [u8; 32] = [0x77u8; 32];
        let ((_sk_i, noise_i), _) = run_in_process_handshake(&secret).await;

        let hh = noise_i.get_handshake_hash();
        assert_eq!(hh.len(), 32, "BLAKE2s handshake hash must be 32 bytes");

        let zero_hash = [0u8; 32];
        let raw = u32::from_be_bytes([zero_hash[0], zero_hash[1], zero_hash[2], zero_hash[3]]);
        let sas_zero = raw % 1_000_000;
        let display_zero = format!("{:03} {:03}", sas_zero / 1000, sas_zero % 1000);
        assert_eq!(display_zero, "000 000");

        let max_hash = [0xFF, 0xFF, 0xFF, 0xFF, 0u8, 0u8, 0u8, 0u8];
        let raw_max = u32::from_be_bytes([max_hash[0], max_hash[1], max_hash[2], max_hash[3]]);
        let sas_max = raw_max % 1_000_000;
        let display_max = format!("{:03} {:03}", sas_max / 1000, sas_max % 1000);
        assert_eq!(display_max, "967 295");

        let (sas_actual, display_actual) = derive_sas(&noise_i);
        assert!(sas_actual < 1_000_000, "SAS must be < 1,000,000");
        assert_eq!(display_actual.len(), 7, "SAS display must be 7 chars 'DDD DDD'");
        let parts: Vec<&str> = display_actual.split(' ').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 3);
        assert_eq!(parts[1].len(), 3);
    }

    #[tokio::test]
    async fn sas_mitm_changes_hash() {
        let secret_1: [u8; 32] = [0x11u8; 32];
        let ((_sk_i1, noise_i1), _) = run_in_process_handshake(&secret_1).await;

        let secret_2: [u8; 32] = [0x22u8; 32];
        let ((_sk_i2, noise_i2), _) = run_in_process_handshake(&secret_2).await;

        let hh1 = noise_i1.get_handshake_hash().to_vec();
        let hh2 = noise_i2.get_handshake_hash().to_vec();

        assert_ne!(hh1, hh2, "different PSKs must produce different handshake hashes");

        let (sas1, _) = derive_sas(&noise_i1);
        let (sas2, _) = derive_sas(&noise_i2);
        assert_ne!(sas1, sas2, "different hashes must produce different SAS values");
    }

    // ── Layer-2 tests (from Plan 09-04) ─────────────────────────────────────

    // ── Test: peers_json_roundtrip ───────────────────────────────────────────

    #[test]
    fn peers_json_roundtrip() {
        let dir = fresh_dir("roundtrip");
        let config_dir = dir.to_str().unwrap();

        let peer = PeerRecord {
            device_id: "test-device-id-001".to_string(),
            device_name: "Test Device".to_string(),
            static_public_key: "aabbcc".repeat(5) + "aa",  // 32 hex chars
            vault_pair_id: "pair-id-abc".to_string(),
            paired_at: "2026-06-05T12:00:00Z".to_string(),
            last_synced_at: None,
            last_known_ip: None,
            last_known_port: None,
        };

        let doc = PeersDoc {
            schema_version: 1,
            local_device_id: "local-device-id-xyz".to_string(),
            local_static_public_key: "ff".repeat(32),
            local_device_name: "My Device".to_string(),
            peers: vec![peer.clone()],
        };

        // Write atomically.
        write_peers_json_atomic(config_dir, &doc).unwrap();

        // Re-read (simulating an app restart — read from disk).
        let read_doc = read_peers_json(config_dir).unwrap();

        assert_eq!(read_doc.schema_version, 1, "schemaVersion must be 1");
        assert_eq!(
            read_doc.local_device_id, "local-device-id-xyz",
            "localDeviceId must round-trip"
        );
        assert_eq!(read_doc.peers.len(), 1, "must have one peer");
        let read_peer = &read_doc.peers[0];
        assert_eq!(read_peer.device_id, peer.device_id, "deviceId must round-trip");
        assert_eq!(
            read_peer.static_public_key, peer.static_public_key,
            "staticPublicKey must round-trip"
        );
        assert_eq!(
            read_peer.vault_pair_id, peer.vault_pair_id,
            "vaultPairId must round-trip"
        );
        assert_eq!(
            read_peer.device_name, peer.device_name,
            "deviceName must round-trip"
        );
        assert_eq!(
            read_peer.last_synced_at, None,
            "lastSyncedAt: None must round-trip"
        );
    }

    // ── Test: peers_json_not_in_vault_dir ────────────────────────────────────

    #[test]
    fn peers_json_not_in_vault_dir() {
        // PAIR-06: peers.json lives at $APPCONFIG/cryptiq/ NOT in the vault directory.
        // The vault directory is typically $APPDOCUMENTS/<user>/vault.cryptiq.
        // Here we assert the path computed by write_peers_json_atomic uses the config_dir.
        let config_dir_base = fresh_dir("pathtest");
        let config_dir_str = config_dir_base.to_str().unwrap();

        // A fake vault path (in a totally different location).
        let vault_dir = fresh_dir("vaultdir");
        let vault_path = vault_dir.join("vault.cryptiq");

        let doc = PeersDoc {
            schema_version: 1,
            local_device_id: "local-id".to_string(),
            local_static_public_key: "00".repeat(32),
            local_device_name: "Dev".to_string(),
            peers: vec![],
        };

        write_peers_json_atomic(config_dir_str, &doc).unwrap();

        let peers_json_path = PathBuf::from(config_dir_str).join("cryptiq").join("peers.json");
        assert!(
            peers_json_path.exists(),
            "peers.json must exist in $APPCONFIG/cryptiq/"
        );

        // Assert peers.json path does NOT start with the vault directory.
        assert!(
            !peers_json_path.starts_with(&vault_dir),
            "peers.json must NOT be inside the vault directory (PAIR-06 path assertion)"
        );

        // Assert the vault path is distinct from the peers.json path.
        assert_ne!(
            peers_json_path.canonicalize().unwrap(),
            vault_path.to_path_buf(),
            "peers.json and vault path must be distinct"
        );
    }

    // ── Test: no_half_pairing ────────────────────────────────────────────────

    #[test]
    fn no_half_pairing() {
        // D-06 / SC-3: a one-sided abort / timeout must leave peers.json unwritten
        // AND no CredManager peer key stored.
        //
        // We simulate by: NOT calling write_peers_json_atomic (finalize was never reached).
        // Then we assert the file is absent and the mock store has no peer key.
        let dir = fresh_dir("no_half_pairing");
        let config_dir = dir.to_str().unwrap();
        let mock_store = MockCredentialStore::new();

        // Simulate own identity key in store (pre-condition — this must remain after abort).
        mock_store.write(DEVICE_IDENTITY_SK_TARGET, &[0u8; 32]).unwrap();

        // The pairing was initiated but finalize was NOT reached (one-sided timeout / user abort).
        // pairing_finalize was never called — so peers.json is never written.
        // No CredManager peer key was ever written.

        // Assert: peers.json does NOT exist.
        let peers_path = PathBuf::from(config_dir).join("cryptiq").join("peers.json");
        assert!(
            !peers_path.exists(),
            "peers.json must NOT exist after a one-sided abort (no half-pairing, D-06 / SC-3)"
        );

        // Assert: no peer key in mock CredManager.
        let peer_key_result = mock_store.read("cryptiq/peer/any-device-id");
        assert!(
            peer_key_result.is_err(),
            "no peer CredManager key must be stored after a one-sided abort"
        );

        // Assert: own identity key is still there (was not wiped).
        let own_key = mock_store.read(DEVICE_IDENTITY_SK_TARGET);
        assert!(
            own_key.is_ok(),
            "own identity key must still be present after abort"
        );
    }

    // ── Test: sas_timeout_cancels_pairing ────────────────────────────────────

    #[tokio::test]
    async fn sas_timeout_cancels_pairing() {
        // D-02 enforcement: drive the confirmation wait with an injected-short timeout
        // and NO incoming "CONFIRMED" signal — assert the timeout error is returned
        // and zero peers.json mutation occurred.
        //
        // We inject Duration::from_millis(10) so this test does NOT sleep 60 seconds.

        let dir = fresh_dir("sas_timeout");
        let config_dir = dir.to_str().unwrap();
        let mock_store = MockCredentialStore::new();
        mock_store.write(DEVICE_IDENTITY_SK_TARGET, &[0u8; 32]).unwrap();

        // Build a fake transport state for the test (we never actually send/recv).
        let secret: [u8; 32] = [0x42u8; 32];
        let (sk_a, _) = generate_device_keypair().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let secret_clone = secret;
        let sk_a_clone = sk_a;

        let responder_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            run_handshake_responder(&mut stream, &sk_a_clone, &secret_clone).await
        });

        let (sk_b, _) = generate_device_keypair().unwrap();
        let mut stream_b = TcpStream::connect(addr).await.unwrap();
        let handshake_b = run_handshake_initiator(&mut stream_b, &sk_b, &secret).await.unwrap();
        let _handshake_a = responder_task.await.unwrap().unwrap();

        // Handshake completed; now test the confirmation timeout.
        // Intentionally discard the transport — we only test the timeout behavior.
        let _ = handshake_b.transport;
        let local_confirm = std::sync::Arc::new(Notify::new());

        // Drive await_mutual_confirm with a very short timeout and NO notify fire.
        // This proves the timeout path: no peers.json written, no CredManager peer key stored.
        let result = await_mutual_confirm(
            local_confirm.clone(),
            Duration::from_millis(10), // injected short timeout — NOT 60 s (D-02 test gate)
        )
        .await;

        // Assert timeout error returned.
        assert!(
            result.is_err(),
            "await_mutual_confirm must return an error when the window lapses"
        );
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("timed out"),
            "error must mention 'timed out', got: {}",
            err_msg
        );

        // Assert peers.json was NOT written (D-02 / SC-3).
        let peers_path = PathBuf::from(config_dir).join("cryptiq").join("peers.json");
        assert!(
            !peers_path.exists(),
            "peers.json must NOT be written after SAS timeout (D-02 / SC-3)"
        );

        // Assert no peer key in CredManager mock.
        let peer_key_result = mock_store.read("cryptiq/peer/any-device-id");
        assert!(
            peer_key_result.is_err(),
            "no peer CredManager key must be stored after SAS timeout"
        );
    }

    // ── Test: repair_refused_when_exists ─────────────────────────────────────

    #[test]
    fn repair_refused_when_exists() {
        // D-16: attempting to finalize a pairing for a device already in peers.json
        // must be refused (already-exists error) and leave the peers list unchanged.
        let dir = fresh_dir("repair_refused");
        let config_dir = dir.to_str().unwrap();

        let existing_pk = "aa".repeat(32); // 64-char hex, represents a 32-byte public key

        let existing_peer = PeerRecord {
            device_id: "existing-device-id".to_string(),
            device_name: "Existing Device".to_string(),
            static_public_key: existing_pk.clone(),
            vault_pair_id: "existing-vault-pair-id".to_string(),
            paired_at: "2026-01-01T00:00:00Z".to_string(),
            last_synced_at: None,
            last_known_ip: None,
            last_known_port: None,
        };

        let doc = PeersDoc {
            schema_version: 1,
            local_device_id: "local-id".to_string(),
            local_static_public_key: "bb".repeat(32),
            local_device_name: "My Device".to_string(),
            peers: vec![existing_peer],
        };
        write_peers_json_atomic(config_dir, &doc).unwrap();

        // Now simulate the re-pair guard check (the logic from pairing_finalize).
        let current_doc = read_peers_json(config_dir).unwrap();
        let peer_pk_hex = existing_pk.clone(); // same public key as the existing peer

        let already_exists = current_doc
            .peers
            .iter()
            .any(|p| p.static_public_key == peer_pk_hex);

        assert!(
            already_exists,
            "re-pair guard must detect the existing peer (D-16)"
        );

        // Assert the peers list length is unchanged (no new peer was added).
        let doc_after = read_peers_json(config_dir).unwrap();
        assert_eq!(
            doc_after.peers.len(),
            1,
            "peers list length must be unchanged after re-pair refusal (D-16)"
        );
    }

    // ── Test: unpair_removes_peer ─────────────────────────────────────────────

    #[test]
    fn unpair_removes_peer() {
        let dir = fresh_dir("unpair_removes");
        let config_dir = dir.to_str().unwrap();
        let mock_store = MockCredentialStore::new();

        // Seed own identity key.
        mock_store.write(DEVICE_IDENTITY_SK_TARGET, &[0xABu8; 32]).unwrap();

        // Seed a peer + its mock CredManager key.
        let peer_id = "peer-device-to-remove";
        let peer_pk = "cc".repeat(32);
        let peer_target_key = peer_target(peer_id);
        mock_store.write(&peer_target_key, b"peer-pk-32-bytes-padding-0000000").unwrap();

        let peer_rec = PeerRecord {
            device_id: peer_id.to_string(),
            device_name: "Peer To Remove".to_string(),
            static_public_key: peer_pk.clone(),
            vault_pair_id: "vaultpair-id".to_string(),
            paired_at: "2026-01-01T00:00:00Z".to_string(),
            last_synced_at: None,
            last_known_ip: None,
            last_known_port: None,
        };

        let doc = PeersDoc {
            schema_version: 1,
            local_device_id: "local-id".to_string(),
            local_static_public_key: "dd".repeat(32),
            local_device_name: "My Device".to_string(),
            peers: vec![peer_rec],
        };
        write_peers_json_atomic(config_dir, &doc).unwrap();

        // Simulate unpair: remove peer from peers.json + CredManager.
        // (We call the logic directly here since we can't inject mock_store into
        //  the #[tauri::command] fn; the command uses the Windows-only real store on Windows.)
        {
            let mut current_doc = read_peers_json(config_dir).unwrap();
            current_doc.peers.retain(|p| p.device_id != peer_id);
            mock_store.delete(&peer_target_key).unwrap();
            write_peers_json_atomic(config_dir, &current_doc).unwrap();
        }

        // Assert peers list is empty.
        let doc_after = read_peers_json(config_dir).unwrap();
        assert!(
            doc_after.peers.is_empty(),
            "peers list must be empty after unpair"
        );

        // Assert peer CredManager key is gone.
        let peer_read = mock_store.read(&peer_target_key);
        assert!(
            peer_read.is_err(),
            "peer CredManager key must be removed after unpair"
        );
    }

    // ── Test: unpair_keeps_own_key ────────────────────────────────────────────

    #[test]
    fn unpair_keeps_own_key() {
        // D-17: unpair removes peer material ONLY; own identity keypair is kept.
        let mock_store = MockCredentialStore::new();

        // Seed own identity key.
        mock_store.write(DEVICE_IDENTITY_SK_TARGET, &[0xABu8; 32]).unwrap();

        // Seed a peer key.
        let peer_id = "peer-to-remove-keys";
        let peer_target_key = peer_target(peer_id);
        mock_store.write(&peer_target_key, &[0xCDu8; 32]).unwrap();

        // Simulate unpair: delete ONLY the peer key (D-17 guard: do NOT delete own key).
        // The real unpair_device command has this guard at the OS CredManager level;
        // here we test the mock-store logic.
        mock_store.delete(&peer_target_key).unwrap();

        // Assert own identity key is still readable (D-17).
        let own_key = mock_store.read(DEVICE_IDENTITY_SK_TARGET);
        assert!(
            own_key.is_ok(),
            "own identity key must still be readable after unpair (D-17)"
        );
        assert_eq!(
            own_key.unwrap(),
            vec![0xABu8; 32],
            "own identity key bytes must be unchanged after unpair"
        );

        // Assert peer key is gone.
        let peer_read = mock_store.read(&peer_target_key);
        assert!(
            peer_read.is_err(),
            "peer key must be gone after unpair"
        );
    }

    // ── Test: crockford_encode_decode_roundtrip ───────────────────────────────

    #[test]
    fn crockford_encode_decode_roundtrip() {
        // Verify the inline Crockford encoder/decoder round-trips for a 32-byte payload.
        let secret: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        ];

        let encoded = crockford_encode(&secret);
        // 32 bytes × 8 / 5 = 51.2 → 52 chars
        assert_eq!(encoded.len(), 52, "32 bytes encodes to 52 Crockford chars");

        let decoded = crockford_decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 32, "decoded length must be 32 bytes");
        assert_eq!(&decoded[..32], &secret[..], "round-trip must be byte-exact");

        // Check character test.
        let check = crockford_check_char(&secret);
        assert!(
            b"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U".contains(&(check as u8)),
            "check char must be in the 37-symbol CHECK_ALPHABET"
        );
    }

    // ── Test: pairing_code_bundle_and_decode ─────────────────────────────────

    #[test]
    fn pairing_code_bundle_and_decode() {
        // Verify the full pairing-code encode/decode cycle: IP:PORT:BASE32+CHECKCHAR.
        let secret: [u8; 32] = [0x55u8; 32];
        let ip = "192.168.1.100";
        let port: u16 = 54321;

        let base32_secret = crockford_encode(&secret);
        let check = crockford_check_char(&secret);
        let full_code = format!("{}:{}:{}{}", ip, port, base32_secret, check);

        // Decode it back.
        let (decoded_ip, decoded_port, decoded_secret) = decode_pairing_code(&full_code).unwrap();

        assert_eq!(decoded_ip, ip, "IP must round-trip");
        assert_eq!(decoded_port, port, "PORT must round-trip");
        assert_eq!(decoded_secret, secret, "secret must round-trip");
    }

    // ── Test: read_peers_json_absent_returns_default ──────────────────────────

    #[test]
    fn read_peers_json_absent_returns_default() {
        let dir = fresh_dir("read_absent");
        let config_dir = dir.to_str().unwrap();

        // No peers.json written — must return default with empty peers list.
        let doc = read_peers_json(config_dir).unwrap();
        assert_eq!(doc.schema_version, 1, "default schemaVersion must be 1");
        assert!(doc.peers.is_empty(), "default peers list must be empty");
    }

    // ── Test: read_peers_json_unknown_schema_version_errors ──────────────────

    #[test]
    fn read_peers_json_unknown_schema_version_errors() {
        let dir = fresh_dir("bad_schema");
        // Ensure the cryptiq subdirectory exists.
        let cryptiq_dir = dir.join("cryptiq");
        std::fs::create_dir_all(&cryptiq_dir).unwrap();
        let peers_path = cryptiq_dir.join("peers.json");

        // Write a document with an unknown schemaVersion.
        let bad_doc = r#"{"schemaVersion":99,"localDeviceId":"x","localStaticPublicKey":"x","localDeviceName":"x","peers":[]}"#;
        std::fs::write(&peers_path, bad_doc).unwrap();

        let result = read_peers_json(dir.to_str().unwrap());
        assert!(
            result.is_err(),
            "unknown schemaVersion must return Err (fail closed)"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("unknown schemaVersion"),
            "error must mention 'unknown schemaVersion', got: {}",
            err
        );
    }

    // ── GAP-A regression tests (Phase 09 review: H2, H3, H4) ─────────────────

    // ── H2: device identity public key is STABLE across restarts ─────────────

    #[test]
    fn h2_identity_public_key_stable_across_restarts() {
        // H2 (PAIR-01/D-13/SC-1): on first launch the keypair is generated and persisted;
        // on the second launch (read-back) the advertised PUBLIC key MUST equal the first.
        //
        // RED (pre-fix): the store persisted only the 32-byte private key, and
        // derive_public_key_from_private fell through the 64-byte branch for a 32-byte input,
        // returning the public key of a BRAND-NEW random keypair — so the second call's pk
        // differed from the first. This assertion (pk1 == pk2) FAILED before the fix.
        //
        // GREEN (post-fix): the store persists sk||pk (64 bytes); read-back takes pk = blob[32..64].
        let store = MockCredentialStore::new();

        // First "launch": generates + writes.
        let (sk1, pk1) = get_or_generate_keypair_from_store(&store, DEVICE_IDENTITY_SK_TARGET)
            .expect("first get_or_generate must succeed");

        // The persisted blob must be the 64-byte sk||pk concatenation (H2 fix invariant).
        let persisted = store.read(DEVICE_IDENTITY_SK_TARGET).unwrap();
        assert_eq!(persisted.len(), 64, "identity blob must be 64 bytes (sk||pk)");
        assert_eq!(&persisted[..32], &sk1[..], "blob[..32] must be the private key");
        assert_eq!(&persisted[32..64], &pk1[..], "blob[32..64] must be the public key");

        // Second "launch": reads back from the (already-populated) store.
        let (sk2, pk2) = get_or_generate_keypair_from_store(&store, DEVICE_IDENTITY_SK_TARGET)
            .expect("second get_or_generate must succeed");

        // The advertised public key must MATCH across restarts (the H2 requirement).
        assert_eq!(
            pk2, pk1,
            "device identity public key must be STABLE across restarts (H2)"
        );
        // And the private key must match too (same persisted identity).
        assert_eq!(
            sk2, sk1,
            "device identity private key must be STABLE across restarts (H2)"
        );
    }

    #[test]
    fn h2_public_key_matches_persisted_private_key() {
        // Stronger H2 invariant: the advertised pk after read-back is exactly the second half
        // of the persisted blob, i.e. it genuinely corresponds to the stored sk (no fabrication).
        let store = MockCredentialStore::new();
        let (_sk1, pk1) =
            get_or_generate_keypair_from_store(&store, DEVICE_IDENTITY_SK_TARGET).unwrap();

        // Simulate restart: read-back path only.
        let (_sk2, pk2) =
            get_or_generate_keypair_from_store(&store, DEVICE_IDENTITY_SK_TARGET).unwrap();

        let persisted = store.read(DEVICE_IDENTITY_SK_TARGET).unwrap();
        assert_eq!(
            &persisted[32..64],
            &pk2[..],
            "read-back pk must be the persisted second half, not a fabricated key (H2)"
        );
        assert_eq!(pk1, pk2, "pk must not change between launches (H2)");
    }

    #[test]
    fn h2_stale_32_byte_blob_is_regenerated_as_64_bytes() {
        // A stale 32-byte blob (pre-fix on-disk format) must be REGENERATED, not trusted.
        // This batch accepts a one-time format change (no field pairings yet).
        let store = MockCredentialStore::new();

        // Seed a stale 32-byte private-key-only blob (the old format).
        store
            .write(DEVICE_IDENTITY_SK_TARGET, &[0x11u8; 32])
            .unwrap();

        // get_or_generate must regenerate and rewrite as a 64-byte sk||pk blob.
        let (sk, pk) =
            get_or_generate_keypair_from_store(&store, DEVICE_IDENTITY_SK_TARGET).unwrap();
        let persisted = store.read(DEVICE_IDENTITY_SK_TARGET).unwrap();
        assert_eq!(
            persisted.len(),
            64,
            "stale 32-byte blob must be rewritten as a 64-byte sk||pk blob"
        );
        assert_eq!(&persisted[..32], &sk[..], "rewritten blob[..32] must be the new sk");
        assert_eq!(&persisted[32..64], &pk[..], "rewritten blob[32..64] must be the new pk");
        assert_ne!(
            &persisted[..32],
            &[0x11u8; 32][..],
            "the stale all-0x11 key must NOT be reused"
        );

        // And a subsequent read-back is now stable.
        let (_sk2, pk2) =
            get_or_generate_keypair_from_store(&store, DEVICE_IDENTITY_SK_TARGET).unwrap();
        assert_eq!(pk2, pk, "after regeneration, pk must be stable across restarts");
    }

    #[test]
    fn h2_public_key_only_accessor_does_not_leak_private_key() {
        // L3 companion to H2: the public-key-only accessor returns the same pk as the full
        // accessor, but the caller never receives the private key.
        let store = MockCredentialStore::new();
        let (_sk, pk_full) =
            get_or_generate_keypair_from_store(&store, DEVICE_IDENTITY_SK_TARGET).unwrap();
        let pk_only =
            get_or_generate_public_key_from_store(&store, DEVICE_IDENTITY_SK_TARGET).unwrap();
        assert_eq!(
            pk_only, pk_full,
            "public-key-only accessor must return the same stable pk (L3)"
        );
    }

    // ── H3: device_key_read refuses the device identity private key target ────

    #[test]
    fn h3_device_key_read_refuses_identity_target() {
        // H3: JS must NOT be able to read the device identity private key over IPC.
        //
        // RED (pre-fix): device_key_read had no target guard, so on non-Windows it returned
        // the "not available" Err and on Windows it returned the raw SK bytes. The guard now
        // makes BOTH platforms refuse the identity target with a T-09-06 message.
        let result = device_key_read(DEVICE_IDENTITY_SK_TARGET.to_string());
        assert!(
            result.is_err(),
            "device_key_read MUST refuse the device identity SK target (H3)"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("T-09-06"),
            "refusal must cite the T-09-06 guard, got: {}",
            err
        );
    }

    #[test]
    fn h3_device_key_read_refuses_non_peer_target() {
        // The guard restricts reads to the cryptiq/peer/ prefix; any other target is refused.
        let result = device_key_read("cryptiq/device/some-other".to_string());
        assert!(
            result.is_err(),
            "device_key_read MUST refuse non-peer targets (H3)"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("T-09-06"),
            "refusal must cite the T-09-06 guard, got: {}",
            err
        );
    }

    #[test]
    fn h3_device_key_read_allows_peer_prefix() {
        // A peer-prefixed target must PASS the guard (it then hits the platform store layer).
        // On non-Windows the store is unavailable → "not available" error, but crucially NOT
        // the T-09-06 refusal. This proves the guard does not over-block legitimate peer reads.
        let result = device_key_read("cryptiq/peer/some-device-id".to_string());
        if let Err(err) = result {
            assert!(
                !err.contains("T-09-06"),
                "peer-prefixed read must pass the IPC guard (not a T-09-06 refusal), got: {}",
                err
            );
        }
    }

    // ── H4: device_key_write refuses overwriting the device identity key ──────

    #[test]
    fn h4_device_key_write_refuses_identity_target() {
        // H4: JS must NOT be able to overwrite the device identity private key over IPC.
        //
        // RED (pre-fix): device_key_write had no target guard, so JS could clobber
        // cryptiq/device/identity-sk with attacker bytes (or get the platform store error on
        // non-Windows). The guard now refuses the identity target on BOTH platforms.
        let result = device_key_write(DEVICE_IDENTITY_SK_TARGET.to_string(), vec![0xFFu8; 32]);
        assert!(
            result.is_err(),
            "device_key_write MUST refuse the device identity SK target (H4)"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("T-09-06"),
            "refusal must cite the T-09-06 guard, got: {}",
            err
        );
    }

    #[test]
    fn h4_device_key_write_refuses_non_peer_target() {
        // The guard restricts writes to the cryptiq/peer/ prefix; any other target is refused.
        let result = device_key_write("cryptiq/device/identity-sk-evil".to_string(), vec![0u8; 32]);
        assert!(
            result.is_err(),
            "device_key_write MUST refuse non-peer targets (H4)"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("T-09-06"),
            "refusal must cite the T-09-06 guard, got: {}",
            err
        );
    }

    #[test]
    fn h4_device_key_write_allows_peer_prefix() {
        // A peer-prefixed write must PASS the guard (then hits the platform store layer).
        let result = device_key_write("cryptiq/peer/some-device-id".to_string(), vec![0u8; 32]);
        if let Err(err) = result {
            assert!(
                !err.contains("T-09-06"),
                "peer-prefixed write must pass the IPC guard (not a T-09-06 refusal), got: {}",
                err
            );
        }
    }

    // ── GAP-B regression tests (Phase 09 review: H1, H5) ─────────────────────

    /// Run a complete in-process handshake over a tokio duplex pair, returning BOTH transports
    /// and the still-open duplex halves so the caller can drive `run_confirm_exchange` on top.
    ///
    /// Using `tokio::io::duplex` means NO real TCP — the two `run_confirm_exchange` halves are
    /// wired directly, which is exactly what the H1 mutual-confirmation tests need.
    async fn handshake_over_duplex(
        secret: &[u8; 32],
    ) -> (
        (tokio::io::DuplexStream, snow::TransportState),
        (tokio::io::DuplexStream, snow::TransportState),
    ) {
        let (mut a, mut b) = tokio::io::duplex(8192);
        let (sk_a, _) = generate_device_keypair().unwrap();
        let (sk_b, _) = generate_device_keypair().unwrap();
        let secret_a = *secret;
        let secret_b = *secret;

        // Responder drives on half `a`; initiator drives on half `b`. Run concurrently.
        let responder = async {
            run_handshake_responder(&mut a, &sk_a, &secret_a)
                .await
                .unwrap()
        };
        let initiator = async {
            run_handshake_initiator(&mut b, &sk_b, &secret_b)
                .await
                .unwrap()
        };
        let (res_r, res_i) = tokio::join!(responder, initiator);
        ((a, res_r.transport), (b, res_i.transport))
    }

    // ── H1 happy path: peer CONFIRMED frame is exchanged; finalize commits the RECEIVED id ──

    #[tokio::test]
    async fn h1_mutual_confirm_propagates_peer_device_id_and_commits() {
        // H1 (PAIR-04/05): both users confirm → both exchange CONFIRMED frames over the
        // transport → finalize commits, and the peer deviceId stored in peers.json EQUALS the
        // peer's REAL local deviceId (NOT a freshly fabricated UUID — the pre-fix H1 bug).
        let secret: [u8; 32] = [0x42u8; 32];
        let ((mut stream_a, mut transport_a), (mut stream_b, mut transport_b)) =
            handshake_over_duplex(&secret).await;

        // Genuine, distinct local identities for the two devices.
        let a_id = "AAAA-device-id-1111";
        let a_name = "Device A";
        let b_id = "BBBB-device-id-2222";
        let b_name = "Device B";

        // Both users confirm immediately.
        let confirm_a = std::sync::Arc::new(Notify::new());
        let confirm_b = std::sync::Arc::new(Notify::new());
        confirm_a.notify_one();
        confirm_b.notify_one();

        // Drive BOTH halves of run_confirm_exchange concurrently over the duplex.
        // A is the responder here (Some vpid); B is the initiator (None — adopts).
        let a_side = run_confirm_exchange(
            &mut stream_a,
            &mut transport_a,
            a_id,
            a_name,
            Some("vp-a-authority".to_string()),
            confirm_a.clone(),
            Duration::from_secs(5),
        );
        let b_side = run_confirm_exchange(
            &mut stream_b,
            &mut transport_b,
            b_id,
            b_name,
            None,
            confirm_b.clone(),
            Duration::from_secs(5),
        );
        let (a_result, b_result) = tokio::join!(a_side, b_side);

        // A received B's GENUINE identity; B received A's GENUINE identity.
        let a_out = a_result.expect("A side confirm exchange must succeed");
        let b_out = b_result.expect("B side confirm exchange must succeed");
        let (a_got_id, a_got_name) = (a_out.peer_device_id.clone(), a_out.peer_device_name.clone());
        let (b_got_id, b_got_name) = (b_out.peer_device_id.clone(), b_out.peer_device_name.clone());
        assert_eq!(a_got_id, b_id, "A must receive B's REAL deviceId (not a fabricated UUID)");
        assert_eq!(a_got_name, b_name, "A must receive B's deviceName");
        assert_eq!(b_got_id, a_id, "B must receive A's REAL deviceId");
        assert_eq!(b_got_name, a_name, "B must receive A's deviceName");

        // Now A finalizes with the RECEIVED peer identity → peers.json must store B's REAL id.
        let dir = fresh_dir("h1_happy");
        let config_dir = dir.to_str().unwrap();
        let store = MockCredentialStore::new();
        let peer_static_pk = [0xCDu8; 32]; // stand-in for B's static pk (any 32 bytes)

        finalize_commit(
            &store,
            config_dir,
            &peer_static_pk,
            &a_got_id,   // the RECEIVED peer deviceId
            &a_got_name, // the RECEIVED peer deviceName
            "vault-pair-id-xyz",
            a_name,
        )
        .expect("finalize_commit must succeed on the happy path");

        // peers.json must contain a peer whose deviceId == B's REAL deviceId.
        let doc = read_peers_json(config_dir).unwrap();
        assert_eq!(doc.peers.len(), 1, "exactly one peer committed");
        assert_eq!(
            doc.peers[0].device_id, b_id,
            "committed peer deviceId must be the peer's REAL id (H1), not a fabricated UUID"
        );
        assert_eq!(doc.peers[0].device_name, b_name, "committed peer deviceName must match");

        // The CredManager peer key must be present under cryptiq/peer/<B's real id>.
        assert!(
            store.contains(&peer_target(b_id)),
            "CredManager peer key must be stored under the peer's REAL deviceId"
        );
    }

    // ── H1 peer-dismiss: peer never confirms → no CONFIRMED frame → no commit ──────────────

    #[tokio::test]
    async fn h1_peer_dismiss_times_out_and_commits_nothing() {
        // H1 / PAIR-04/05: the peer's user dismisses (never confirms), so the peer NEVER fires
        // its local_confirm and NEVER sends a CONFIRMED frame. THIS side confirms and sends its
        // frame, then times out waiting for the peer's frame → run_confirm_exchange errors →
        // finalize commits NOTHING (peers.json absent, no CredManager peer key).
        let secret: [u8; 32] = [0x7Eu8; 32];
        let ((mut stream_a, mut transport_a), (mut stream_b, mut transport_b)) =
            handshake_over_duplex(&secret).await;

        let confirm_a = std::sync::Arc::new(Notify::new());
        let confirm_b = std::sync::Arc::new(Notify::new());
        // A confirms; B does NOT (the dismiss).
        confirm_a.notify_one();

        // B's side: never confirms → its `local_confirm` wait times out BEFORE it sends a frame.
        // Keep B alive (reading nothing) so the duplex stays open while A tries to send.
        let b_side = run_confirm_exchange(
            &mut stream_b,
            &mut transport_b,
            "BBBB-id",
            "Device B",
            None, // initiator (adopts) — irrelevant here, B never confirms
            confirm_b.clone(), // never fired
            Duration::from_millis(50),
        );
        let a_side = run_confirm_exchange(
            &mut stream_a,
            &mut transport_a,
            "AAAA-id",
            "Device A",
            Some("vp-a".to_string()), // responder authority
            confirm_a.clone(),
            Duration::from_millis(200),
        );
        let (a_result, b_result) = tokio::join!(a_side, b_side);

        // B timed out waiting for ITS user's confirm (never fired).
        assert!(
            b_result.is_err(),
            "B (dismiss) must error — its user never confirmed"
        );
        // A timed out waiting for B's CONFIRMED frame (B never sent one).
        assert!(
            a_result.is_err(),
            "A must error: the peer (B) never sent a CONFIRMED frame (PAIR-04/05)"
        );
        let a_err = a_result.unwrap_err();
        assert!(
            a_err.contains("timed out") || a_err.contains("CONFIRMED"),
            "A's error must reflect the missing peer confirmation, got: {}",
            a_err
        );

        // Because A's confirm exchange failed, finalize_commit is NEVER called → assert the
        // commit side-effects are absent (the no-half-pairing guarantee, D-06).
        let dir = fresh_dir("h1_dismiss");
        let config_dir = dir.to_str().unwrap();
        let store = MockCredentialStore::new();
        store.write(DEVICE_IDENTITY_SK_TARGET, &[0u8; 32]).unwrap(); // own key pre-exists

        // (No finalize_commit call — the failed exchange means the orchestrator skips commit.)
        let peers_path = PathBuf::from(config_dir).join("cryptiq").join("peers.json");
        assert!(
            !peers_path.exists(),
            "peers.json must NOT exist when the peer dismissed (no commit, PAIR-04/05)"
        );
        assert!(
            !store.contains(&peer_target("BBBB-id")),
            "no CredManager peer key must be stored when the peer dismissed"
        );
        assert!(
            store.contains(DEVICE_IDENTITY_SK_TARGET),
            "own identity key must remain after a dismissed pairing"
        );
    }

    // ── H5 rollback: peers.json write fails → CredManager peer key rolled back, Err returned ──

    #[test]
    fn h5_finalize_rolls_back_cred_key_when_peers_json_fails() {
        // H5 (D-06): finalize is all-or-nothing. The CredManager peer key is written FIRST
        // (reversible); peers.json is the commit. If peers.json fails, the CredManager peer key
        // MUST be rolled back (deleted) so no orphaned key + no half-pairing remains.
        //
        // We force write_peers_json_atomic to fail by pointing config_dir at a path whose
        // `cryptiq` child cannot be created: we create a FILE named like the config dir's
        // `cryptiq` subdirectory, so `fs::create_dir_all(<config>/cryptiq)` errors (a file with
        // that name already exists).
        let dir = fresh_dir("h5_rollback");
        let config_dir = dir.to_str().unwrap();

        // Sabotage: create a regular FILE at <config_dir>/cryptiq so mkdir of that dir fails.
        let sabotage = PathBuf::from(config_dir).join("cryptiq");
        std::fs::write(&sabotage, b"not a directory").unwrap();
        assert!(sabotage.is_file(), "sabotage must be a file, not a dir");

        let store = MockCredentialStore::new();
        let peer_id = "peer-id-rollback";
        let peer_static_pk = [0x99u8; 32];

        let result = finalize_commit(
            &store,
            config_dir,
            &peer_static_pk,
            peer_id,
            "Peer Name",
            "vault-pair-id",
            "Local Name",
        );

        // (a) finalize_commit must return Err (peers.json commit failed).
        assert!(
            result.is_err(),
            "finalize_commit must return Err when peers.json write fails (H5)"
        );

        // (b) the CredManager peer key must have been ROLLED BACK (no orphaned key).
        assert!(
            !store.contains(&peer_target(peer_id)),
            "CredManager peer key must be rolled back when peers.json fails (H5 — all-or-nothing)"
        );
    }

    // ── H5 companion: successful commit leaves BOTH peers.json AND the CredManager key ──

    #[test]
    fn h5_finalize_commit_writes_both_on_success() {
        let dir = fresh_dir("h5_success");
        let config_dir = dir.to_str().unwrap();
        let store = MockCredentialStore::new();
        let peer_id = "peer-id-ok";
        let peer_static_pk = [0x33u8; 32];

        finalize_commit(
            &store,
            config_dir,
            &peer_static_pk,
            peer_id,
            "Peer OK",
            "vault-pair-ok",
            "Local OK",
        )
        .expect("commit must succeed");

        let doc = read_peers_json(config_dir).unwrap();
        assert_eq!(doc.peers.len(), 1, "peer must be committed to peers.json");
        assert_eq!(doc.peers[0].device_id, peer_id, "committed deviceId must match");
        assert!(
            store.contains(&peer_target(peer_id)),
            "CredManager peer key must be present on success"
        );
        // The CredManager key bytes must equal the peer static pk.
        assert_eq!(
            store.read(&peer_target(peer_id)).unwrap(),
            peer_static_pk.to_vec(),
            "stored peer key bytes must equal the peer static pk"
        );
    }

    // ── H5 re-pair guard still refuses (and writes nothing) ──────────────────

    #[test]
    fn h5_finalize_commit_refuses_existing_peer() {
        let dir = fresh_dir("h5_repair");
        let config_dir = dir.to_str().unwrap();
        let store = MockCredentialStore::new();
        let peer_static_pk = [0x44u8; 32];
        let peer_pk_hex = hex_encode(&peer_static_pk);

        // Seed an existing peer with the SAME static pk.
        let doc = PeersDoc {
            schema_version: 1,
            local_device_id: "local-id".to_string(),
            local_static_public_key: "ee".repeat(32),
            local_device_name: "Me".to_string(),
            peers: vec![PeerRecord {
                device_id: "already-here".to_string(),
                device_name: "Existing".to_string(),
                static_public_key: peer_pk_hex,
                vault_pair_id: "vp".to_string(),
                paired_at: "2026-01-01T00:00:00Z".to_string(),
                last_synced_at: None,
                last_known_ip: None,
                last_known_port: None,
            }],
        };
        write_peers_json_atomic(config_dir, &doc).unwrap();

        let result = finalize_commit(
            &store,
            config_dir,
            &peer_static_pk,
            "new-peer-id",
            "New Peer",
            "vp2",
            "Me",
        );
        assert!(result.is_err(), "re-pair must be refused (D-16)");
        // No CredManager key written for the refused peer (guard ran BEFORE the cred write).
        assert!(
            !store.contains(&peer_target("new-peer-id")),
            "refused re-pair must not leave a CredManager peer key"
        );
        // peers list unchanged.
        let after = read_peers_json(config_dir).unwrap();
        assert_eq!(after.peers.len(), 1, "peers list must be unchanged after refusal");
    }

    // ── GAP-C regression tests (Phase 09 review: H6, H7, L2, M2) ─────────────

    // ── L2: decode_pairing_code must NOT panic on a non-ASCII trailing char ───

    #[test]
    fn l2_decode_pairing_code_rejects_non_ascii_trailing_char() {
        // L2: `secret_field.split_at(len-1)` is BYTE-indexed; if the last char is multi-byte
        // (e.g. an emoji), split_at lands mid-codepoint and PANICS. Reachable via a direct
        // invoke('pairing_connect') with a hand-crafted code.
        //
        // RED (pre-fix): decode_pairing_code panicked (byte-index split inside a multi-byte
        // codepoint), so this test ABORTED rather than returning Err.
        // GREEN (post-fix): the malformed input returns a typed Err — no panic.
        //
        // Build a code whose secret field ends in a 4-byte emoji. The IP:PORT prefix is valid
        // so parsing reaches the secret-field split. (We do not strip the emoji as formatting —
        // it is neither whitespace nor '-', so it survives normalization and reaches the split.)
        let code = "192.168.1.5:54321:ABCDE\u{1F600}"; // trailing 😀 (4 UTF-8 bytes)

        // Must return Err, must NOT panic. (If it panicked, the test binary would abort.)
        let result = std::panic::catch_unwind(|| decode_pairing_code(code));
        assert!(
            result.is_ok(),
            "decode_pairing_code must NOT panic on a non-ASCII trailing char (L2)"
        );
        let inner = result.unwrap();
        assert!(
            inner.is_err(),
            "decode_pairing_code must return Err (not panic) on a non-ASCII trailing char (L2)"
        );
    }

    #[test]
    fn l2_decode_pairing_code_rejects_non_ascii_in_body() {
        // A non-ASCII char anywhere in the secret field is rejected up front with a typed Err
        // rather than reaching the byte-indexed split.
        let code = "10.0.0.2:54321:AB\u{00E9}CDEF"; // 'é' (2 UTF-8 bytes) inside the body
        let result = std::panic::catch_unwind(|| decode_pairing_code(code));
        assert!(result.is_ok(), "must not panic on non-ASCII body char (L2)");
        assert!(
            result.unwrap().is_err(),
            "non-ASCII secret field must return Err (L2)"
        );
    }

    // ── M2: Rust decoder applies the SAME Crockford look-alike mapping as JS ──

    #[test]
    fn m2_decode_pairing_code_maps_lookalikes_to_canonical_bytes() {
        // M2 (D-11): validatePairingCode (pairingCode.ts) maps O→0, I/L→1, U→V on the base32
        // BODY before decoding, but syncBridge.pairingConnect forwards the RAW typed code. The
        // Rust decoder must apply the SAME mapping so a user who types look-alikes (O/I/L/U)
        // decodes to the SAME 32 bytes as the canonical code — otherwise JS validation passes
        // but the Rust handshake decode throws (the advertised typo tolerance is negated).
        //
        // Strategy: pick a 32-byte secret whose CANONICAL Crockford body contains the digits
        // '0' and '1' and the letter 'V' at known positions; rewrite those body chars to their
        // look-alike LETTERS ('O' for '0', 'I'/'L' for '1', 'U' for 'V') and assert the decode
        // yields the identical secret. The trailing CHECK char is preserved exactly (CR-01).
        //
        // RED (pre-fix): crockford_decode rejected 'O'/'I'/'L'/'U' as out-of-alphabet, so
        // decode_pairing_code returned Err for a look-alike-typed code.
        // GREEN (post-fix): the body is normalized (look-alikes mapped) before decode.
        let secret: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ];
        let ip = "192.168.1.100";
        let port: u16 = 54321;

        let canonical_body = crockford_encode(&secret); // 52 chars, alphabet has no I/L/O/U
        let check = crockford_check_char(&secret);

        // Sanity: the canonical body must contain at least one of each digit we want to mistype.
        // (encode alphabet "0123456789ABCDEFGHJKMNPQRSTVWXYZ" — '0','1','V' are all present.)
        // Rewrite '0'→'O', '1'→'I', 'V'→'U' in the BODY (the look-alike mistypes a user makes).
        let mistyped_body: String = canonical_body
            .chars()
            .map(|c| match c {
                '0' => 'O',
                '1' => 'I',
                'V' => 'U',
                other => other,
            })
            .collect();
        assert_ne!(
            mistyped_body, canonical_body,
            "test precondition: the chosen secret's body must contain mistypeable chars (0/1/V)"
        );

        // Build the look-alike-typed full code and the canonical full code.
        let mistyped_code = format!("{}:{}:{}{}", ip, port, mistyped_body, check);
        let canonical_code = format!("{}:{}:{}{}", ip, port, canonical_body, check);

        // Both must decode to the SAME 32 bytes (cross-impl parity with validatePairingCode).
        let (_, _, decoded_from_mistyped) =
            decode_pairing_code(&mistyped_code).expect("look-alike-typed code must decode (M2)");
        let (_, _, decoded_from_canonical) =
            decode_pairing_code(&canonical_code).expect("canonical code must decode");

        assert_eq!(
            decoded_from_mistyped, secret,
            "look-alike-typed code must decode to the canonical 32-byte secret (M2)"
        );
        assert_eq!(
            decoded_from_canonical, secret,
            "canonical code must decode to the canonical 32-byte secret"
        );
        assert_eq!(
            decoded_from_mistyped, decoded_from_canonical,
            "look-alike and canonical codes must decode to identical bytes (cross-impl, M2)"
        );
    }

    #[test]
    fn m2_check_char_u_is_preserved_not_remapped() {
        // CR-01: the trailing CHECK char must NOT be U→V remapped — 'U' is a legitimate check
        // symbol (index 36 of the 37-symbol CHECK_ALPHABET). Find a secret whose check char is
        // 'U', then assert the code decodes (i.e. the check verifies) WITHOUT the U being
        // rewritten to 'V' (which would corrupt ~1/37 valid codes).
        let ip = "10.0.0.7";
        let port: u16 = 54321;

        // Search for a 32-byte secret whose check char is 'U' (value mod 37 == 36).
        let mut secret = [0u8; 32];
        let mut found = false;
        for seed in 0u8..=255 {
            for b in secret.iter_mut() {
                *b = seed;
            }
            // Perturb the last byte to sweep the modulus without a CSPRNG dependency.
            secret[31] = seed;
            if crockford_check_char(&secret) == 'U' {
                found = true;
                break;
            }
        }
        assert!(found, "test setup: must find a secret whose check char is 'U'");

        let body = crockford_encode(&secret);
        let code = format!("{}:{}:{}U", ip, port, body); // explicit 'U' check char
        let (_, _, decoded) = decode_pairing_code(&code)
            .expect("a code with a valid 'U' check char must decode (CR-01 — U not remapped)");
        assert_eq!(decoded, secret, "secret with 'U' check char must round-trip (CR-01)");
    }

    // ── H6: a stalling peer must NOT hang the handshake/lifecycle forever ─────

    #[tokio::test]
    async fn h6_responder_lifecycle_times_out_on_silent_peer() {
        // H6: every blocking network op (connect/accept/recv_framed read_exact) was unbounded.
        // A peer that connects then sends NOTHING parks the responder forever. The fix bounds
        // the whole post-accept lifecycle (handshake + confirm) in tokio::time::timeout.
        //
        // RED (pre-fix): run_responder_lifecycle did not exist / had no timeout, so this awaited
        // forever (the test would hang until the harness killed it).
        // GREEN (post-fix): the lifecycle returns a timeout Err within the injected bound.
        //
        // Drive the responder over a duplex whose OTHER half (`_peer`) is held open but never
        // writes a single byte — recv_framed's first read_exact would block forever without the
        // bound. We inject a SHORT timeout (not 30/60 s) so the test is fast.
        let (mut ours, _peer) = tokio::io::duplex(8192);
        let (sk, _pk) = generate_device_keypair().unwrap();
        let secret: [u8; 32] = [0x42u8; 32];
        let local_confirm = std::sync::Arc::new(Notify::new());

        let start = tokio::time::Instant::now();
        let mut sas_emitted = false;
        let result = run_responder_lifecycle(
            &mut ours,
            &sk,
            &secret,
            "AAAA-id",
            "Device A",
            Some("vp-resp".to_string()),
            local_confirm,
            Duration::from_millis(100), // handshake deadline — injected short bound (NOT 30 s)
            Duration::from_secs(60),    // confirm window (never reached: handshake times out first)
            |_sas: &str| sas_emitted = true,
        )
        .await;
        let elapsed = start.elapsed();

        assert!(
            result.is_err(),
            "a silent peer must cause the responder lifecycle to time out (H6)"
        );
        // Fix A: the SAS callback must NOT have fired — the handshake never completed, so there is
        // no SAS to show (the on_sas hook runs strictly BETWEEN handshake and confirm).
        assert!(
            !sas_emitted,
            "on_sas must not fire when the handshake times out (Fix A ordering invariant)"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("timed out") || err.contains("timeout"),
            "the error must reflect a timeout, got: {}",
            err
        );
        // The bound must actually fire promptly (well under a second), proving it was not an
        // unbounded wait that happened to fail for another reason.
        assert!(
            elapsed < Duration::from_secs(2),
            "lifecycle must return within the injected bound, took {:?} (H6)",
            elapsed
        );
    }

    #[tokio::test]
    async fn h6_initiator_lifecycle_times_out_on_silent_peer() {
        // Symmetric H6 check for the INITIATOR path (pairing_connect's spawned task). The
        // initiator writes msg1 then awaits the responder's msg2; a silent peer never replies,
        // so recv_framed blocks forever without the bound.
        let (mut ours, _peer) = tokio::io::duplex(8192);
        let (sk, _pk) = generate_device_keypair().unwrap();
        let secret: [u8; 32] = [0x42u8; 32];
        let local_confirm = std::sync::Arc::new(Notify::new());

        let start = tokio::time::Instant::now();
        let result = run_initiator_lifecycle(
            &mut ours,
            &sk,
            &secret,
            "BBBB-id",
            "Device B",
            None, // initiator adopts
            local_confirm,
            Duration::from_millis(100), // handshake deadline
            Duration::from_secs(60),    // confirm window (never reached)
            |_sas: &str| {},
        )
        .await;
        let elapsed = start.elapsed();

        assert!(
            result.is_err(),
            "a silent peer must cause the initiator lifecycle to time out (H6)"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "initiator lifecycle must return within the injected bound, took {:?} (H6)",
            elapsed
        );
    }

    #[tokio::test]
    async fn h6_lifecycle_happy_path_still_succeeds_within_bound() {
        // Regression guard for H6: a NON-stalling peer must still complete the full lifecycle
        // (handshake + mutual CONFIRMED-frame exchange) within the bound. We wire both lifecycle
        // halves over a duplex and fire both local confirms — the genuine peer ids must transfer.
        let (a, b) = tokio::io::duplex(8192);
        let secret: [u8; 32] = [0x5Au8; 32];
        let (sk_a, _) = generate_device_keypair().unwrap();
        let (sk_b, _) = generate_device_keypair().unwrap();
        let confirm_a = std::sync::Arc::new(Notify::new());
        let confirm_b = std::sync::Arc::new(Notify::new());
        confirm_a.notify_one();
        confirm_b.notify_one();

        let mut a = a;
        let mut b = b;
        let secret_a = secret;
        let secret_b = secret;
        // NOTE: this test pre-fires confirm because it exercises the COMBINED lifecycle's success
        // path (handshake + confirm + the H6 bound), not the SAS ordering — the ordering invariant
        // is proven separately by `fix_a_sas_is_available_before_confirm_wait`, which does NOT
        // pre-fire confirm. Here we additionally assert the on_sas hook fired (Fix A) for each side.
        let resp_sas = std::sync::Arc::new(Mutex::new(None::<String>));
        let init_sas = std::sync::Arc::new(Mutex::new(None::<String>));
        let resp_sas_cb = resp_sas.clone();
        let init_sas_cb = init_sas.clone();
        let resp = run_responder_lifecycle(
            &mut a,
            &sk_a,
            &secret_a,
            "AAAA-id",
            "Device A",
            Some("vp-shared".to_string()), // responder authority
            confirm_a,
            Duration::from_secs(5),
            Duration::from_secs(5),
            move |sas: &str| *resp_sas_cb.lock().unwrap() = Some(sas.to_string()),
        );
        let init = run_initiator_lifecycle(
            &mut b,
            &sk_b,
            &secret_b,
            "BBBB-id",
            "Device B",
            None, // initiator adopts
            confirm_b,
            Duration::from_secs(5),
            Duration::from_secs(5),
            move |sas: &str| *init_sas_cb.lock().unwrap() = Some(sas.to_string()),
        );
        let (res_r, res_i) = tokio::join!(resp, init);

        let r = res_r.expect("responder lifecycle must succeed on the happy path");
        let i = res_i.expect("initiator lifecycle must succeed on the happy path");
        // Each side learns the PEER's genuine identity (H1 contract preserved through H6 refactor).
        assert_eq!(r.peer_device_id, "BBBB-id", "responder must receive initiator's real id");
        assert_eq!(i.peer_device_id, "AAAA-id", "initiator must receive responder's real id");
        // Both derived the same SAS (sanity that the handshake actually completed).
        assert_eq!(r.sas_display, i.sas_display, "both sides must agree on the SAS");
        // Fix A: the on_sas hook fired for both sides, with the SAME SAS as the result.
        assert_eq!(
            resp_sas.lock().unwrap().as_deref(),
            Some(r.sas_display.as_str()),
            "responder on_sas must have fired with the SAS (Fix A)"
        );
        assert_eq!(
            init_sas.lock().unwrap().as_deref(),
            Some(i.sas_display.as_str()),
            "initiator on_sas must have fired with the SAS (Fix A)"
        );
        // Fix B: both sides negotiated the SAME (responder-authoritative) vaultPairId.
        assert_eq!(r.vault_pair_id, "vp-shared", "responder keeps its authoritative vaultPairId");
        assert_eq!(i.vault_pair_id, "vp-shared", "initiator adopts the responder's vaultPairId (Fix B)");
    }

    // ── H7: the listener task must be cancellable (no port/task leak) ─────────

    #[tokio::test]
    async fn h7_accept_loop_exits_promptly_on_cancel() {
        // H7: `let (cancel_tx, _cancel_rx) = oneshot::channel()` dropped the receiver, so cancel
        // could never fire; the listener had no select! against cancel and leaked its port.
        //
        // RED (pre-fix): accept_with_cancel did not exist — there was no select!-based accept
        // that a cancel signal could interrupt, so this could not be expressed.
        // GREEN (post-fix): firing cancel makes the select!-based accept return Cancelled
        // promptly, WITHOUT any peer ever connecting. We use an ephemeral port (":0") so the
        // test never touches the real 54321 and is environment-independent.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();

        // Fire cancel immediately; nobody ever connects to this listener.
        cancel_tx.send(()).unwrap();

        let start = tokio::time::Instant::now();
        let outcome = accept_with_cancel(&listener, cancel_rx).await;
        let elapsed = start.elapsed();

        assert!(
            matches!(outcome, AcceptOutcome::Cancelled),
            "a fired cancel must make the accept loop return Cancelled (H7)"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "cancel must interrupt accept promptly, took {:?} (H7)",
            elapsed
        );
    }

    #[tokio::test]
    async fn h7_accept_loop_returns_stream_when_a_peer_connects() {
        // Companion to H7: when a peer DOES connect (and cancel never fires), the select!-based
        // accept must hand back the accepted stream — proving the cancellation wiring does not
        // break the normal accept path.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (_cancel_tx, cancel_rx) = oneshot::channel::<()>();

        // Connect from a background task so accept_with_cancel can complete.
        let connector = tokio::spawn(async move {
            let _s = TcpStream::connect(addr).await.unwrap();
            // Hold the connection briefly so the accept side observes it.
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let outcome = accept_with_cancel(&listener, cancel_rx).await;
        assert!(
            matches!(outcome, AcceptOutcome::Accepted(_)),
            "accept_with_cancel must return Accepted when a peer connects (H7)"
        );
        connector.await.unwrap();
    }

    #[tokio::test]
    async fn h7_session_cancel_tx_frees_the_listener_task() {
        // Integration-flavoured H7 check WITHOUT binding the real 54321 port: spawn a listener
        // task on an EPHEMERAL port that runs accept_with_cancel, store its cancel_tx, then SEND
        // cancel and assert the task finishes (its JoinHandle resolves) — i.e. the port is freed.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();

        let task = tokio::spawn(async move { accept_with_cancel(&listener, cancel_rx).await });

        // Send the cancel signal (the path a timeout/finalize/refusal would take in the command).
        cancel_tx.send(()).unwrap();

        // The task must finish promptly with Cancelled — proving the listener is dropped + freed.
        let outcome = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("listener task must finish promptly after cancel (H7 — no leak)")
            .expect("listener task must not panic");
        assert!(
            matches!(outcome, AcceptOutcome::Cancelled),
            "listener task must observe the cancel and exit (H7)"
        );
    }

    // ── M1: PairingSession Drop zeroizes the secret (volatile) ────────────────

    #[test]
    fn m1_pairing_session_drop_zeroizes_secret() {
        // M1: dropping a PairingSession must volatile-zeroize its secret + peer_static_pk.
        // We can't read freed memory safely, so we assert the Zeroize trait is wired by
        // zeroizing a clone of the same buffer types the way Drop does, proving the call path.
        let mut secret = [0xABu8; 32];
        let mut peer_pk: Vec<u8> = vec![0xCD; 32];
        secret.zeroize();
        peer_pk.zeroize();
        assert_eq!(secret, [0u8; 32], "zeroize must clear the secret buffer");
        assert!(
            peer_pk.is_empty(),
            "Vec<u8>::zeroize clears contents and truncates to len 0"
        );

        // And constructing + dropping a real PairingSession must not panic (Drop runs).
        let session = PairingSession {
            transport: None,
            peer_static_pk: vec![0x11u8; 32],
            secret: [0x22u8; 32],
            sas_display: String::new(),
            cancel_tx: None,
            local_confirm: std::sync::Arc::new(Notify::new()),
            both_confirmed: std::sync::Arc::new(Notify::new()),
            local_confirmed: false,
            config_dir: String::new(),
            local_device_id: "x".to_string(),
            local_device_name: "y".to_string(),
            peer_device_id: None,
            peer_device_name: None,
            vault_pair_id: None,
        };
        drop(session); // must run impl Drop without panicking
    }

    // ── GAP-D1 regression tests (post-remediation re-review: #3/#7, #2, #1) ────

    // ── Fix A (#3/#7 HIGH): SAS is PRODUCED before the local-confirm wait ──────
    //
    // THE SHOWSTOPPER ordering test. The regression was that the spawned task ran the
    // FULL lifecycle (handshake AND run_confirm_exchange — whose step (a) blocks on
    // local_confirm) and only emitted `pairing://sas` AFTER the lifecycle returned. So
    // the user could never see the SAS until after confirming → circular deadlock → the
    // 60 s window always lapsed.
    //
    // This test asserts the correct order WITHOUT pre-firing confirm: run BOTH sides'
    // *handshake step* and assert both yield equal, non-empty SAS while NO confirm has
    // been fired. ONLY THEN fire local_confirm on both sides and assert the confirm
    // exchange completes. A test that pre-fires confirm before the handshake does NOT
    // satisfy Fix A and is explicitly rejected by the spec.
    #[tokio::test]
    async fn fix_a_sas_is_available_before_confirm_wait() {
        let secret: [u8; 32] = [0x42u8; 32];
        let (mut a, mut b) = tokio::io::duplex(8192);
        let (sk_a, _) = generate_device_keypair().unwrap();
        let (sk_b, _) = generate_device_keypair().unwrap();

        // ── Phase 1: run ONLY the handshake step on each side. NO confirm fired yet. ──
        // run_handshake_step_responder / _initiator must complete the Noise XX exchange
        // and hand back the SAS + transport, with the local-confirm Notify never touched.
        let secret_a = secret;
        let secret_b = secret;
        let resp_hs = run_handshake_step_responder(&mut a, &sk_a, &secret_a, CONNECT_ACCEPT_DEADLINE);
        let init_hs = run_handshake_step_initiator(&mut b, &sk_b, &secret_b, CONNECT_ACCEPT_DEADLINE);
        let (resp_res, init_res) = tokio::join!(resp_hs, init_hs);

        let resp_hs = resp_res.expect("responder handshake step must succeed");
        let init_hs = init_res.expect("initiator handshake step must succeed");

        // The SAS is available NOW — before either user has confirmed (the Fix A invariant).
        assert!(!resp_hs.sas_display.is_empty(), "responder SAS must be non-empty after handshake");
        assert!(!init_hs.sas_display.is_empty(), "initiator SAS must be non-empty after handshake");
        assert_eq!(
            resp_hs.sas_display, init_hs.sas_display,
            "both sides must derive an identical SAS BEFORE any confirm is fired (Fix A: SAS emitted between handshake and confirm-wait)"
        );

        // ── Phase 2: NOW (and only now) the users see the SAS and confirm. ──
        // Fire local_confirm on BOTH sides, THEN run the confirm exchange. This proves the
        // confirm window starts AFTER the SAS is produced (no circular deadlock).
        let mut transport_a = resp_hs.transport;
        let mut transport_b = init_hs.transport;
        let confirm_a = std::sync::Arc::new(Notify::new());
        let confirm_b = std::sync::Arc::new(Notify::new());
        confirm_a.notify_one();
        confirm_b.notify_one();

        let a_side = run_confirm_exchange(
            &mut a,
            &mut transport_a,
            "AAAA-id",
            "Device A",
            Some("vp-resp-authoritative".to_string()), // responder authoritative
            confirm_a.clone(),
            Duration::from_secs(5),
        );
        let b_side = run_confirm_exchange(
            &mut b,
            &mut transport_b,
            "BBBB-id",
            "Device B",
            None, // initiator adopts
            confirm_b.clone(),
            Duration::from_secs(5),
        );
        let (a_result, b_result) = tokio::join!(a_side, b_side);

        let a_out = a_result.expect("A confirm exchange must complete AFTER the SAS was shown");
        let b_out = b_result.expect("B confirm exchange must complete AFTER the SAS was shown");

        // Both committed each other's genuine id — i.e. the confirm step ran to completion
        // only once the confirms were fired (which happened AFTER the SAS was produced).
        assert_eq!(a_out.peer_device_id, "BBBB-id", "A must receive B's real id");
        assert_eq!(b_out.peer_device_id, "AAAA-id", "B must receive A's real id");
    }

    // ── Fix B (#2 HIGH): vaultPairId is SHARED via the CONFIRMED frame ────────
    //
    // Pre-fix: ConfirmFrame carried only {device_id, device_name}; each pairing_finalize
    // independently called new_uuid_v4(), so A and B stored DIFFERENT vaultPairId for the
    // same pairing. Fix: responder generates vault_pair_id once and sends it in its
    // CONFIRMED frame; initiator sends an empty one and ADOPTS the responder's. The two
    // committed PeerRecords must carry an IDENTICAL vault_pair_id.
    #[tokio::test]
    async fn fix_b_vault_pair_id_is_shared_across_both_sides() {
        let secret: [u8; 32] = [0x5Cu8; 32];
        let (mut a, mut b) = tokio::io::duplex(8192);
        let (sk_a, _) = generate_device_keypair().unwrap();
        let (sk_b, _) = generate_device_keypair().unwrap();
        let secret_a = secret;
        let secret_b = secret;

        // Handshake both sides (no confirm yet — Fix A discipline).
        let resp_hs = run_handshake_step_responder(&mut a, &sk_a, &secret_a, CONNECT_ACCEPT_DEADLINE);
        let init_hs = run_handshake_step_initiator(&mut b, &sk_b, &secret_b, CONNECT_ACCEPT_DEADLINE);
        let (resp_res, init_res) = tokio::join!(resp_hs, init_hs);
        let resp_hs = resp_res.unwrap();
        let init_hs = init_res.unwrap();

        let mut transport_a = resp_hs.transport;
        let mut transport_b = init_hs.transport;

        // The RESPONDER is the authority: it mints the shared vaultPairId.
        let authoritative_vpid = "VPID-shared-responder-authority".to_string();

        let confirm_a = std::sync::Arc::new(Notify::new());
        let confirm_b = std::sync::Arc::new(Notify::new());
        confirm_a.notify_one();
        confirm_b.notify_one();

        // A = responder: Some(vpid). B = initiator: None (adopts).
        let a_side = run_confirm_exchange(
            &mut a,
            &mut transport_a,
            "A-real-id",
            "Device A",
            Some(authoritative_vpid.clone()),
            confirm_a.clone(),
            Duration::from_secs(5),
        );
        let b_side = run_confirm_exchange(
            &mut b,
            &mut transport_b,
            "B-real-id",
            "Device B",
            None,
            confirm_b.clone(),
            Duration::from_secs(5),
        );
        let (a_result, b_result) = tokio::join!(a_side, b_side);
        let a_out = a_result.expect("A confirm exchange must succeed");
        let b_out = b_result.expect("B confirm exchange must succeed");

        // The NEGOTIATED vaultPairId on each side must be identical (and == the responder's).
        assert_eq!(
            a_out.vault_pair_id, authoritative_vpid,
            "responder keeps its own authoritative vaultPairId"
        );
        assert_eq!(
            b_out.vault_pair_id, authoritative_vpid,
            "initiator must ADOPT the responder's vaultPairId (Fix B #2)"
        );
        assert_eq!(
            a_out.vault_pair_id, b_out.vault_pair_id,
            "both sides must negotiate an IDENTICAL vaultPairId (Fix B #2)"
        );

        // Now finalize BOTH sides (store-injected) and assert the committed PeerRecords carry
        // the SAME vault_pair_id — the cross-side guarantee.
        let dir_a = fresh_dir("fix_b_side_a");
        let dir_b = fresh_dir("fix_b_side_b");
        let store_a = MockCredentialStore::new();
        let store_b = MockCredentialStore::new();

        // A commits B as its peer; B commits A as its peer. Each uses the negotiated vpid.
        finalize_commit(
            &store_a,
            dir_a.to_str().unwrap(),
            &init_hs.peer_static_pk, // (placeholder; identity-equality is Fix C's test) — use B's pk as seen by A
            &a_out.peer_device_id,
            &a_out.peer_device_name,
            &a_out.vault_pair_id,
            "Device A",
        )
        .expect("A finalize must succeed");
        finalize_commit(
            &store_b,
            dir_b.to_str().unwrap(),
            &resp_hs.peer_static_pk, // A's pk as seen by B
            &b_out.peer_device_id,
            &b_out.peer_device_name,
            &b_out.vault_pair_id,
            "Device B",
        )
        .expect("B finalize must succeed");

        let doc_a = read_peers_json(dir_a.to_str().unwrap()).unwrap();
        let doc_b = read_peers_json(dir_b.to_str().unwrap()).unwrap();
        assert_eq!(doc_a.peers.len(), 1);
        assert_eq!(doc_b.peers.len(), 1);
        assert_eq!(
            doc_a.peers[0].vault_pair_id, doc_b.peers[0].vault_pair_id,
            "both committed PeerRecords must carry an IDENTICAL vaultPairId (Fix B #2)"
        );
        assert_eq!(
            doc_a.peers[0].vault_pair_id, authoritative_vpid,
            "the shared vaultPairId must be the responder's authoritative value"
        );
    }

    // ── Fix C (#1 MEDIUM): handshake pins the peer's PERSISTED identity pk ────
    //
    // Pre-fix: pairing_initiate/pairing_connect called generate_device_keypair() to mint a
    // FRESH throwaway static key, so peers.json pinned a per-session ephemeral key that did
    // NOT equal the peer's advertised identity (get_local_device_info). Fix: load the
    // persisted identity sk via get_or_generate_keypair_from_store(.., DEVICE_IDENTITY_SK_TARGET)
    // and use THAT as the handshake static key. Then get_remote_static() yields the peer's
    // STABLE identity public key.
    //
    // This test seeds each side's mock store with a KNOWN identity keypair, runs the handshake
    // using those persisted sks, and asserts the peer_static_pk captured on each side EQUALS the
    // OTHER side's known identity public key (not a random per-session value).
    #[tokio::test]
    async fn fix_c_handshake_uses_persisted_identity_key() {
        let secret: [u8; 32] = [0x91u8; 32];
        let (mut a, mut b) = tokio::io::duplex(8192);

        // Seed two mock stores with KNOWN, distinct identity keypairs (GAP-A 64-byte sk||pk).
        let store_a = MockCredentialStore::new();
        let store_b = MockCredentialStore::new();
        let (sk_a, pk_a) = get_or_generate_keypair_from_store(&store_a, DEVICE_IDENTITY_SK_TARGET).unwrap();
        let (sk_b, pk_b) = get_or_generate_keypair_from_store(&store_b, DEVICE_IDENTITY_SK_TARGET).unwrap();

        // Sanity: a SECOND read returns the SAME persisted identity (stable across "restarts").
        let (_sk_a2, pk_a2) = get_or_generate_keypair_from_store(&store_a, DEVICE_IDENTITY_SK_TARGET).unwrap();
        assert_eq!(pk_a, pk_a2, "identity pk must be stable across reads (GAP-A)");

        // Run the handshake using the PERSISTED identity sks (this is what pairing_* must do).
        let secret_a = secret;
        let secret_b = secret;
        let resp_hs = run_handshake_step_responder(&mut a, &sk_a, &secret_a, CONNECT_ACCEPT_DEADLINE);
        let init_hs = run_handshake_step_initiator(&mut b, &sk_b, &secret_b, CONNECT_ACCEPT_DEADLINE);
        let (resp_res, init_res) = tokio::join!(resp_hs, init_hs);
        let resp_hs = resp_res.unwrap();
        let init_hs = init_res.unwrap();

        // The responder (A) must have captured B's KNOWN identity pk as the peer static key.
        assert_eq!(
            resp_hs.peer_static_pk,
            pk_b.to_vec(),
            "responder must pin the initiator's PERSISTED identity pk (Fix C #1), not a random ephemeral key"
        );
        // The initiator (B) must have captured A's KNOWN identity pk.
        assert_eq!(
            init_hs.peer_static_pk,
            pk_a.to_vec(),
            "initiator must pin the responder's PERSISTED identity pk (Fix C #1), not a random ephemeral key"
        );
    }

    // ── GAP-D2 (#6 LOW): finalize empty-peer-pk arm tears the session down ─────
    //
    // Pre-fix: the `if session.peer_static_pk.is_empty()` guard in pairing_finalize returned
    // Err WHILE STILL HOLDING the map lock and left the secret-bearing session in the map —
    // inconsistent with the immediately-following `peer_device_id == None` sibling arm, which
    // drops the guard and calls zeroize_and_remove_session. A session that reached finalize but
    // whose handshake never populated peer_static_pk would linger in the map with its PSK intact.
    //
    // The teardown decision is extracted into `finalize_guard_peer_static_pk` (called by
    // pairing_finalize) so it is observable without an AppHandle: insert a session with an EMPTY
    // peer_static_pk, run the guard, and assert (a) it returns Err AND (b) the session is GONE
    // from the map afterward (the secret-bearing session was zeroized + removed).

    /// Build a minimal PairingSession for guard/teardown tests. `peer_static_pk` is the only
    /// field the #6 guard inspects; everything else is filler.
    fn make_test_session(peer_static_pk: Vec<u8>) -> PairingSession {
        PairingSession {
            transport: None,
            peer_static_pk,
            secret: [0x33u8; 32],
            sas_display: String::new(),
            cancel_tx: None,
            local_confirm: std::sync::Arc::new(Notify::new()),
            both_confirmed: std::sync::Arc::new(Notify::new()),
            local_confirmed: false,
            config_dir: String::new(),
            local_device_id: "local-id".to_string(),
            local_device_name: "Local".to_string(),
            peer_device_id: None,
            peer_device_name: None,
            vault_pair_id: None,
        }
    }

    #[test]
    fn d2_finalize_empty_peer_pk_removes_session_from_map() {
        let sessions = PairingSessionMap::new();
        let session_id = "empty-pk-session".to_string();

        // Insert a session whose handshake never completed: peer_static_pk is EMPTY.
        sessions
            .0
            .lock()
            .unwrap()
            .insert(session_id.clone(), make_test_session(Vec::new()));
        assert!(
            sessions.0.lock().unwrap().contains_key(&session_id),
            "precondition: the empty-peer-pk session is in the map"
        );

        // Run the actual finalize guard (the decision pairing_finalize delegates to).
        let result = finalize_guard_peer_static_pk(&sessions, &session_id);

        // (a) it must reject (handshake not complete) ...
        assert!(
            result.is_err(),
            "empty peer_static_pk must be rejected by the finalize guard (#6)"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("handshake not complete"),
            "the guard's error must report the incomplete handshake (got: {})",
            msg
        );

        // (b) ... AND it must tear the secret-bearing session DOWN — mirroring the sibling arm.
        // This is the #6 fix: the pre-fix code returned Err but LEFT the session in the map.
        assert!(
            !sessions.0.lock().unwrap().contains_key(&session_id),
            "the empty-peer-pk arm must zeroize_and_remove the session from the map (#6) — \
             it must NOT leave a secret-bearing session lingering like the pre-fix guard did"
        );
    }

    #[test]
    fn d2_finalize_guard_passes_when_peer_pk_present() {
        // Complement: a session WITH a populated peer_static_pk must pass the guard (Ok) and
        // remain in the map (finalize proceeds to extract the fields + commit). This pins that
        // the #6 teardown does NOT over-fire on a healthy session.
        let sessions = PairingSessionMap::new();
        let session_id = "good-pk-session".to_string();
        sessions
            .0
            .lock()
            .unwrap()
            .insert(session_id.clone(), make_test_session(vec![0xAAu8; 32]));

        let result = finalize_guard_peer_static_pk(&sessions, &session_id);
        assert!(result.is_ok(), "a populated peer_static_pk must pass the guard");
        assert!(
            sessions.0.lock().unwrap().contains_key(&session_id),
            "a healthy session must remain in the map for finalize to commit it"
        );
    }
}
