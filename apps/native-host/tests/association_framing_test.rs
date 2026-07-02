//! Phase 15 Plan 01, Task 3 — pin the NEW Phase-15 envelope shapes (`associate`, `associate-ok`,
//! and the opaque `{nonce, box}` `rpc` payload) through the sidecar's OWN stdio framing, in
//! isolation, BEFORE any browser or crypto wiring exists (mirrors the v2.0 Noise
//! `#[tokio::test]` "pin the protocol before wiring the browser" discipline — 15-RESEARCH.md
//! Validation Architecture / Wave 0 Gaps, Discretion Q7).
//!
//! The sidecar is byte-transparent (crypto lives app-side, Plan 03) — this test needs NO
//! `crypto_box` dependency. The `rpc` envelope's `box`/`nonce` fields are constructed here as
//! OPAQUE base64 strings; framing.rs neither knows nor cares what's inside them.
//!
//! `apps/native-host/Cargo.toml` gained NO new dependency for this test (T-14-SC) — the
//! `#[path]` attribute below reuses `src/framing.rs`'s ACTUAL source directly, so this is a true
//! pin against the real reader/writer, not a reimplementation.

#[path = "../src/framing.rs"]
mod framing;

use std::io::Cursor;

/// The Phase-15 wire envelope shape — identical field layout to `extension_bridge.rs`'s
/// `BridgeEnvelope` (D-01, unreshaped) and `main.rs`'s local `BridgeEnvelope` struct. Declared
/// again here (test-local) rather than imported, since `main.rs` is a binary target with no
/// `[lib]` — this mirrors main.rs's own struct verbatim.
#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
struct BridgeEnvelope {
    #[serde(rename = "protocolVersion")]
    protocol_version: u32,
    #[serde(rename = "type")]
    msg_type: String,
    id: Option<String>,
    payload: serde_json::Value,
}

const CURRENT_PROTOCOL_VERSION: u32 = 1;

/// Round-trip an envelope through `framing::write_message`/`framing::read_message` and assert
/// it comes back structurally identical.
fn round_trip(envelope: &BridgeEnvelope) -> BridgeEnvelope {
    let original_bytes = serde_json::to_vec(envelope).expect("serialize envelope");

    let mut buf = Vec::new();
    framing::write_message(&mut buf, &original_bytes).expect("write_message must succeed");

    let mut cursor = Cursor::new(buf);
    let round_tripped_bytes =
        framing::read_message(&mut cursor).expect("read_message must succeed on our own output");

    assert_eq!(
        round_tripped_bytes, original_bytes,
        "framing round-trip must reproduce the envelope byte-for-byte"
    );

    serde_json::from_slice(&round_tripped_bytes).expect("round-tripped bytes must still be valid JSON")
}

// -----------------------------------------------------------------------------------
// test_associate_envelope_round_trips
//
// The one-time, plaintext `associate` handshake request (TOFU — no shared secret exists yet,
// so this is NOT boxed) must survive the sidecar's framing unchanged.
// -----------------------------------------------------------------------------------
#[test]
fn test_associate_envelope_round_trips() {
    let original = BridgeEnvelope {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        msg_type: "associate".to_string(),
        id: Some("req-1".to_string()),
        payload: serde_json::json!({
            "clientPublicKey": "YmFzZTY0LWVuY29kZWQtcHVibGljLWtleS1ieXRlcw==",
            "label": "Chrome"
        }),
    };

    let round_tripped = round_trip(&original);

    assert_eq!(round_tripped, original);
    assert_eq!(round_tripped.msg_type, "associate");
    assert_eq!(
        round_tripped.payload["clientPublicKey"],
        original.payload["clientPublicKey"]
    );
    assert_eq!(round_tripped.payload["label"], "Chrome");
}

// -----------------------------------------------------------------------------------
// test_associate_ok_envelope_round_trips
//
// The plaintext `associate-ok` response (also TOFU-plaintext per Anti-Patterns — encrypting the
// handshake itself would require ANOTHER bootstrap secret) must survive unchanged.
// -----------------------------------------------------------------------------------
#[test]
fn test_associate_ok_envelope_round_trips() {
    let original = BridgeEnvelope {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        msg_type: "associate-ok".to_string(),
        id: Some("req-1".to_string()),
        payload: serde_json::json!({
            "hostPublicKey": "aG9zdC1wdWJsaWMta2V5LWJhc2U2NA==",
            "pairingToken": "cGFpcmluZy10b2tlbi1iYXNlNjQ="
        }),
    };

    let round_tripped = round_trip(&original);

    assert_eq!(round_tripped, original);
    assert_eq!(round_tripped.msg_type, "associate-ok");
    assert_eq!(
        round_tripped.payload["hostPublicKey"],
        original.payload["hostPublicKey"]
    );
    assert_eq!(
        round_tripped.payload["pairingToken"],
        original.payload["pairingToken"]
    );
}

// -----------------------------------------------------------------------------------
// test_rpc_envelope_with_opaque_box_round_trips_byte_identical
//
// Every message AFTER the one-time handshake carries an OPAQUE `{ nonce, box }` payload (the
// box's plaintext, before encryption, is `{ pairingToken, ...innerPayload }` — but the sidecar
// never sees that; it only relays bytes). This test constructs a REALISTIC-shaped base64 blob
// (not real ciphertext — no crypto_box dependency needed here, Plan 03's job) and asserts the
// base64 body survives framing byte-for-byte, proving the sidecar is truly transparent.
// -----------------------------------------------------------------------------------
#[test]
fn test_rpc_envelope_with_opaque_box_round_trips_byte_identical() {
    // A 24-byte nonce and an arbitrary-length "ciphertext" blob, both base64-encoded — opaque
    // to this test and to the sidecar alike. Correctness of the ENCODING (not framing) is
    // irrelevant here; what matters is that framing does not mutate a single byte of it.
    let nonce_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBk="; // 24 arbitrary bytes, base64
    let box_b64 = "dGhpcy1pcy1hbi1vcGFxdWUtY2lwaGVydGV4dC1ibG9iLW5vdC1yZWFsLWNyeXB0bw==";

    let original = BridgeEnvelope {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        msg_type: "rpc".to_string(),
        id: Some("req-2".to_string()),
        payload: serde_json::json!({
            "nonce": nonce_b64,
            "box": box_b64,
        }),
    };

    let round_tripped = round_trip(&original);

    assert_eq!(round_tripped, original);
    assert_eq!(
        round_tripped.payload["nonce"].as_str().unwrap(),
        nonce_b64,
        "the base64 nonce body must be byte-identical after round-trip (framing is transparent)"
    );
    assert_eq!(
        round_tripped.payload["box"].as_str().unwrap(),
        box_b64,
        "the base64 box body must be byte-identical after round-trip (framing is transparent)"
    );
}

// -----------------------------------------------------------------------------------
// test_oversize_frame_rejected_before_body_allocated
//
// A length prefix declaring more than `framing::MAX_NATIVE_MESSAGE_LEN` MUST be rejected before
// any large allocation is attempted — mirrors framing.rs's own
// `test_read_message_rejects_oversize_before_buffering` (same underlying function; re-asserted
// here at the Phase-15 envelope-pinning layer per the plan's acceptance criteria).
// -----------------------------------------------------------------------------------
#[test]
fn test_oversize_frame_rejected_before_body_allocated() {
    use std::io::Read;

    /// Yields only an oversized 4-byte length prefix, then panics if `read_message` ever tries
    /// to read further bytes — proving no allocation/second-read happened before the cap check.
    struct PrefixOnlyThenPanic {
        prefix: [u8; 4],
        served: bool,
    }
    impl Read for PrefixOnlyThenPanic {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.served {
                self.served = true;
                let n = buf.len().min(4);
                buf[..n].copy_from_slice(&self.prefix[..n]);
                return Ok(n);
            }
            panic!(
                "read_message attempted a second read after an oversized length prefix — \
                 implies a buffer was allocated for the attacker-claimed size before the \
                 size-cap check fired"
            );
        }
    }

    let oversized_len: u32 = framing::MAX_NATIVE_MESSAGE_LEN + 1;
    let oversized = PrefixOnlyThenPanic {
        prefix: oversized_len.to_ne_bytes(),
        served: false,
    };

    let result = framing::read_message(oversized);

    assert!(
        result.is_err(),
        "an oversize frame must be rejected, not silently accepted"
    );
    assert_eq!(
        result.unwrap_err().kind(),
        std::io::ErrorKind::InvalidData,
        "oversized frame must be reported as InvalidData BEFORE any body allocation"
    );
}
