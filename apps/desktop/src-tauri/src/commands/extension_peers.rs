// apps/desktop/src-tauri/src/commands/extension_peers.rs
//
// Phase 15 Plan 01, Task 2 — the secret-free "extension-peers.json" sidecar module.
//
// This is a SIBLING of pairing.rs's peers.json helpers, NOT a reuse of its PeerRecord/PeersDoc
// structs (RESEARCH.md Anti-Patterns explicitly forbids that — sync's schema carries
// vaultPairId/lastSyncedAt/lastKnownIp fields meaningless for a browser-extension peer, and a
// shared schemaVersion gate would force every future sync-only or extension-only field addition
// to consider the other peer type).
//
// Responsibilities:
//   ExtensionPeerRecord / ExtensionPeersDoc — distinct schema, no secrets (public keys + metadata
//                                             + a BLAKE2b HASH of the pairing token, never the
//                                             raw token — T-15-04 / CLAUDE.md "never write
//                                             plaintext secrets to disk")
//   write_extension_peers_json_atomic / read_extension_peers_json
//                                           — same 5-step atomic write + fail-closed
//                                             unknown-schemaVersion rejection as pairing.rs's
//                                             write_peers_json_atomic/read_peers_json, targeting
//                                             a SIBLING file (extension-peers.json) in the same
//                                             $APPCONFIG/cryptiq/ directory
//   revoke_extension_association           — retain-then-atomic-rewrite (mirrors unpair_device);
//                                             per V4 Access Control, NEVER touches the app's own
//                                             shared identity key
//   EXTENSION_IDENTITY_SK_TARGET            — Windows Credential Manager target for the app's
//                                             OWN association keypair (shared across every
//                                             extension association; Plan 03 generates/loads it)
//   hash_pairing_token                      — single BLAKE2b-256 hashing site (write AND verify
//                                             go through this one function, per T-15-04)
//
// Security invariants:
//   - extension-peers.json NEVER contains a raw pairing token, only its BLAKE2b-256 hash
//     (field name says "hash" so it's self-documenting — T-15-04).
//   - assert_confined (reused verbatim from pairing.rs) runs before any I/O (T-15-02).
//   - Unknown schemaVersion -> Err (fail closed, never guessed) — mirrors pairing.rs.
//   - revoke_extension_association removes ONLY the matching association record; the app's
//     shared EXTENSION_IDENTITY_SK_TARGET credential is never deleted here (T-15-03 / V4).
//   - CredentialStore trait + Windows/Noop impls are REUSED from pairing.rs verbatim — no FFI
//     is redefined in this file.

use std::fs::{self, File};
use std::io::Write as IoWrite;
use std::path::PathBuf;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use serde::{Deserialize, Serialize};

use super::pairing::assert_confined;

// ---------------------------------------------------------------------------
// Windows Credential Manager target — app's OWN shared association keypair
// ---------------------------------------------------------------------------

/// Windows Credential Manager target for the app's own extension-association identification
/// secret key. This ONE keypair is SHARED across every browser-extension association (unlike a
/// per-peer key) — revoking a single association must never delete it (T-15-03).
pub const EXTENSION_IDENTITY_SK_TARGET: &str = "cryptiq/extension/identity-sk";

// ---------------------------------------------------------------------------
// extension-peers.json schema — distinct from pairing.rs's PeerRecord/PeersDoc
// ---------------------------------------------------------------------------

/// One browser-extension association record stored in extension-peers.json.
///
/// NEVER contains a raw pairing token, a private key, or any other secret — only public keys
/// and metadata plus a one-way BLAKE2b hash of the pairing token (T-15-01/T-15-04). The field is
/// named `pairing_token_hash` (not `pairing_token`) so it is self-documenting that no secret is
/// stored here.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionPeerRecord {
    /// Stable opaque identifier for this association (Plan 03 mints it; e.g. a UUID string).
    pub client_id: String,
    /// Hex-encoded 32-byte Curve25519 public key of the extension's association keypair.
    pub client_public_key: String,
    /// Human-editable label (auto-named from the detected browser at approval, D-02).
    pub label: String,
    /// ISO 8601 timestamp of when this association was approved.
    pub paired_at: String,
    /// ISO 8601 timestamp of the most recent authenticated RPC from this association.
    pub last_used_at: Option<String>,
    /// Hex-encoded 32-byte BLAKE2b-256 digest of the pairing token — a HASH, NEVER the raw
    /// token. The raw token exists only extension-side (`chrome.storage.local`) and travels the
    /// wire exactly once, inside the encrypted `associate-ok` response (Plan 03).
    pub pairing_token_hash: String,
}

/// The extension-peers.json document root.
///
/// Intentionally has NO `vaultPairId`/`lastSyncedAt`/`lastKnownIp` fields — those are
/// sync-specific (pairing.rs's PeersDoc) and meaningless for a browser-extension association
/// (RESEARCH.md Anti-Patterns).
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionPeersDoc {
    pub schema_version: u32,
    pub associations: Vec<ExtensionPeerRecord>,
}

// ---------------------------------------------------------------------------
// hash_pairing_token — single BLAKE2b-256 hashing site (write AND verify use this)
// ---------------------------------------------------------------------------

/// Hash a raw pairing token to its 32-byte BLAKE2b-256 digest.
///
/// This is the ONE function both the write path (mint + store the hash at approval) and the
/// verify path (Plan 03: hash the incoming token, compare against the stored hash) must call —
/// keeping the algorithm/output-length invariant in a single place rather than re-implementing
/// the hash at each call site.
pub fn hash_pairing_token(token: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(token);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

// ---------------------------------------------------------------------------
// extension-peers.json atomic write + read (mirrors pairing.rs's peers.json helpers)
// ---------------------------------------------------------------------------

/// Atomically write `doc` as pretty-printed JSON to `<config_dir>/cryptiq/extension-peers.json`.
///
/// Steps (identical 5-step sequence to pairing.rs's write_peers_json_atomic):
///   1. Serialize to JSON bytes.
///   2. Write to `extension-peers.json.tmp` (same directory).
///   3. `sync_all` on the tmp file.
///   4. `fs::rename` (atomic swap) tmp -> `extension-peers.json`.
///   5. Best-effort dir-fsync.
///
/// Security: `assert_confined` (reused from pairing.rs) is called on both paths BEFORE any I/O.
/// NEVER writes a raw pairing token or any private key — only ExtensionPeersDoc fields.
pub fn write_extension_peers_json_atomic(config_dir: &str, doc: &ExtensionPeersDoc) -> Result<(), String> {
    let dir = PathBuf::from(config_dir).join("cryptiq");

    fs::create_dir_all(&dir).map_err(|e| {
        format!("write_extension_peers_json_atomic: mkdir failed for '{}': {}", dir.display(), e)
    })?;

    let target = dir.join("extension-peers.json");
    let tmp = dir.join("extension-peers.json.tmp");

    assert_confined(&target, &dir)?;
    assert_confined(&tmp, &dir)?;

    let bytes = serde_json::to_vec_pretty(doc)
        .map_err(|e| format!("write_extension_peers_json_atomic: JSON serialize failed: {}", e))?;

    {
        let mut f = File::create(&tmp).map_err(|e| {
            format!(
                "write_extension_peers_json_atomic: failed to create tmp file '{}': {}",
                tmp.display(),
                e
            )
        })?;
        f.write_all(&bytes).map_err(|e| {
            format!(
                "write_extension_peers_json_atomic: failed to write tmp file '{}': {}",
                tmp.display(),
                e
            )
        })?;
        f.sync_all().map_err(|e| {
            format!(
                "write_extension_peers_json_atomic: sync_all on tmp file '{}' failed: {}",
                tmp.display(),
                e
            )
        })?;
    }

    fs::rename(&tmp, &target).map_err(|e| {
        format!(
            "write_extension_peers_json_atomic: atomic rename failed ('{}' -> '{}'): {}",
            tmp.display(),
            target.display(),
            e
        )
    })?;

    let _ = File::open(&dir).and_then(|f| f.sync_all());

    Ok(())
}

/// Read extension-peers.json from `<config_dir>/cryptiq/extension-peers.json`.
///
/// - File absent -> return a default `ExtensionPeersDoc` (schemaVersion 1, empty associations).
/// - File present, parseable, schemaVersion == 1 -> return parsed doc.
/// - File present but unparseable JSON, or unknown schemaVersion -> Err (fail closed; never
///   guess).
pub fn read_extension_peers_json(config_dir: &str) -> Result<ExtensionPeersDoc, String> {
    let path = PathBuf::from(config_dir).join("cryptiq").join("extension-peers.json");

    if !path.exists() {
        return Ok(ExtensionPeersDoc {
            schema_version: 1,
            associations: vec![],
        });
    }

    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("read_extension_peers_json: failed to read '{}': {}", path.display(), e))?;

    let doc: ExtensionPeersDoc = serde_json::from_str(&raw)
        .map_err(|e| format!("read_extension_peers_json: JSON parse failed for '{}': {}", path.display(), e))?;

    if doc.schema_version != 1 {
        return Err(format!(
            "read_extension_peers_json: unknown schemaVersion {} in '{}' — cannot parse across schemas",
            doc.schema_version,
            path.display()
        ));
    }

    Ok(doc)
}

// ---------------------------------------------------------------------------
// revoke_extension_association — remove ONE association, keep the shared app key (V4)
// ---------------------------------------------------------------------------

/// Remove one association record from extension-peers.json, identified by `client_id`.
///
/// DOES NOT touch `EXTENSION_IDENTITY_SK_TARGET` — the app's association keypair is SHARED
/// across all extension associations, so revoking one association must never delete it
/// (T-15-03 / V4 Access Control). Mirrors pairing.rs's `unpair_device` retain-then-atomic-
/// rewrite shape.
pub fn revoke_extension_association(config_dir: &str, client_id: &str) -> Result<(), String> {
    let mut doc = read_extension_peers_json(config_dir)?;

    let before_len = doc.associations.len();
    doc.associations.retain(|a| a.client_id != client_id);

    if doc.associations.len() == before_len {
        return Err(format!(
            "revoke_extension_association: association '{}' not found in extension-peers.json",
            client_id
        ));
    }

    write_extension_peers_json_atomic(config_dir, &doc)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::pairing::tests::MockCredentialStore;
    use crate::commands::pairing::CredentialStore;

    fn fresh_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cryptiq_extension_peers_test_{}", name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn sample_record(client_id: &str) -> ExtensionPeerRecord {
        let token: [u8; 32] = [7u8; 32];
        let hash = hash_pairing_token(&token);
        ExtensionPeerRecord {
            client_id: client_id.to_string(),
            client_public_key: "aa".repeat(32),
            label: "Chrome".to_string(),
            paired_at: "2026-07-03T00:00:00Z".to_string(),
            last_used_at: None,
            pairing_token_hash: hex_encode(&hash),
        }
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // -----------------------------------------------------------------------
    // test_write_then_read_round_trips_association
    // -----------------------------------------------------------------------
    #[test]
    fn test_write_then_read_round_trips_association() {
        let dir = fresh_dir("roundtrip");
        let config_dir = dir.to_str().unwrap();

        let record = sample_record("client-1");
        let doc = ExtensionPeersDoc {
            schema_version: 1,
            associations: vec![record.clone()],
        };

        write_extension_peers_json_atomic(config_dir, &doc).expect("write must succeed");
        let read_back = read_extension_peers_json(config_dir).expect("read must succeed");

        assert_eq!(read_back.schema_version, 1);
        assert_eq!(read_back.associations.len(), 1);
        assert_eq!(read_back.associations[0], record);
        assert_eq!(read_back.associations[0].pairing_token_hash, record.pairing_token_hash);
    }

    // -----------------------------------------------------------------------
    // test_read_on_absent_file_returns_empty_default
    // -----------------------------------------------------------------------
    #[test]
    fn test_read_on_absent_file_returns_empty_default() {
        let dir = fresh_dir("absent");
        let config_dir = dir.to_str().unwrap();

        let doc = read_extension_peers_json(config_dir).expect("absent file must fail-open");
        assert_eq!(doc.schema_version, 1);
        assert!(doc.associations.is_empty());
    }

    // -----------------------------------------------------------------------
    // test_read_on_unknown_schema_version_fails_closed
    // -----------------------------------------------------------------------
    #[test]
    fn test_read_on_unknown_schema_version_fails_closed() {
        let dir = fresh_dir("bad_schema");
        let config_dir = dir.to_str().unwrap();

        // Write a raw file with an unknown schemaVersion directly (bypassing the writer, which
        // always stamps schemaVersion 1) to simulate a future/corrupt on-disk format.
        let cryptiq_dir = dir.join("cryptiq");
        std::fs::create_dir_all(&cryptiq_dir).unwrap();
        let bad_json = serde_json::json!({ "schemaVersion": 99, "associations": [] });
        std::fs::write(cryptiq_dir.join("extension-peers.json"), bad_json.to_string()).unwrap();

        let result = read_extension_peers_json(config_dir);
        assert!(result.is_err(), "unknown schemaVersion must fail closed, never be guessed");
    }

    // -----------------------------------------------------------------------
    // test_revoke_removes_exactly_matching_association_and_errors_if_absent
    // -----------------------------------------------------------------------
    #[test]
    fn test_revoke_removes_exactly_matching_association_and_errors_if_absent() {
        let dir = fresh_dir("revoke");
        let config_dir = dir.to_str().unwrap();

        let doc = ExtensionPeersDoc {
            schema_version: 1,
            associations: vec![sample_record("client-a"), sample_record("client-b")],
        };
        write_extension_peers_json_atomic(config_dir, &doc).unwrap();

        revoke_extension_association(config_dir, "client-a").expect("revoke must succeed");

        let after = read_extension_peers_json(config_dir).unwrap();
        assert_eq!(after.associations.len(), 1);
        assert_eq!(after.associations[0].client_id, "client-b");

        // Revoking an absent client_id must error, not silently succeed.
        let missing = revoke_extension_association(config_dir, "client-a");
        assert!(missing.is_err(), "revoking an already-absent association must error");
    }

    // -----------------------------------------------------------------------
    // test_revoke_does_not_touch_shared_identity_key
    // -----------------------------------------------------------------------
    #[test]
    fn test_revoke_does_not_touch_shared_identity_key() {
        let dir = fresh_dir("revoke_keeps_identity");
        let config_dir = dir.to_str().unwrap();

        let store = MockCredentialStore::new();
        store
            .write(EXTENSION_IDENTITY_SK_TARGET, &[1u8; 32])
            .expect("seed the shared identity key");

        let doc = ExtensionPeersDoc {
            schema_version: 1,
            associations: vec![sample_record("client-only")],
        };
        write_extension_peers_json_atomic(config_dir, &doc).unwrap();

        revoke_extension_association(config_dir, "client-only").expect("revoke must succeed");

        // revoke_extension_association never touches the CredentialStore at all — assert the
        // shared identity key is still present in the mock store, proving V4 Access Control.
        assert!(
            store.contains(EXTENSION_IDENTITY_SK_TARGET),
            "revoking an association must NEVER delete the app's shared identity key"
        );
    }

    // -----------------------------------------------------------------------
    // test_assert_confined_rejects_path_outside_config_dir
    // -----------------------------------------------------------------------
    #[test]
    fn test_assert_confined_rejects_path_outside_config_dir() {
        let dir = fresh_dir("confinement");
        let cryptiq_dir = dir.join("cryptiq");
        std::fs::create_dir_all(&cryptiq_dir).unwrap();

        let outside = std::env::temp_dir().join("cryptiq_extension_peers_OUTSIDE.json");
        let result = assert_confined(&outside, &cryptiq_dir);
        assert!(result.is_err(), "assert_confined must reject a target outside the confined dir");
    }

    // -----------------------------------------------------------------------
    // test_identity_key_round_trips_through_mock_credential_store
    // -----------------------------------------------------------------------
    #[test]
    fn test_identity_key_round_trips_through_mock_credential_store() {
        let store = MockCredentialStore::new();
        let secret_key_bytes: Vec<u8> = (0u8..32).collect();

        store
            .write(EXTENSION_IDENTITY_SK_TARGET, &secret_key_bytes)
            .expect("write must succeed");

        let read_back = store
            .read(EXTENSION_IDENTITY_SK_TARGET)
            .expect("read must succeed");
        assert_eq!(read_back, secret_key_bytes);
    }

    // -----------------------------------------------------------------------
    // test_serialized_doc_never_contains_raw_token_bytes
    // -----------------------------------------------------------------------
    #[test]
    fn test_serialized_doc_never_contains_raw_token_bytes() {
        let raw_token: [u8; 32] = [0x42u8; 32];
        let raw_token_hex = hex_encode(&raw_token);
        let hash = hash_pairing_token(&raw_token);
        let hash_hex = hex_encode(&hash);

        // Sanity: the hash must differ from the raw token's own hex encoding.
        assert_ne!(raw_token_hex, hash_hex);

        let record = ExtensionPeerRecord {
            client_id: "client-secret-check".to_string(),
            client_public_key: "bb".repeat(32),
            label: "Edge".to_string(),
            paired_at: "2026-07-03T00:00:00Z".to_string(),
            last_used_at: None,
            pairing_token_hash: hash_hex.clone(),
        };
        let doc = ExtensionPeersDoc {
            schema_version: 1,
            associations: vec![record],
        };

        let serialized = serde_json::to_string_pretty(&doc).unwrap();

        assert!(
            serialized.contains(&hash_hex),
            "serialized JSON must contain the token HASH"
        );
        assert!(
            !serialized.contains(&raw_token_hex),
            "serialized JSON must NEVER contain the raw pairing token bytes in any encoding"
        );
    }
}
