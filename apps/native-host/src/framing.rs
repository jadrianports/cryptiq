//! Chrome native-messaging stdio framing (hand-rolled, per D-05/D-08 decisions).
//!
//! Chrome's native-messaging protocol prefixes every message on stdin/stdout with a 4-byte
//! length in **native byte order** (little-endian on Windows — Cryptiq is Windows-first),
//! followed by that many bytes of UTF-8 JSON
//! [CITED: developer.chrome.com/docs/extensions/develop/concepts/native-messaging].
//!
//! This is a near-exact analog of `recv_framed_large`/`send_framed_large` already in
//! `apps/desktop/src-tauri/src/commands/sync.rs` (4-byte length-prefix, bounded-before-buffer
//! discipline) — same discipline, DELIBERATELY DIFFERENT byte order: native-messaging mandates
//! native endianness (`from_ne_bytes`/`to_ne_bytes`), while `sync.rs`'s pipe-facing analog uses
//! big-endian (`from_be_bytes`/`to_be_bytes`). Do not conflate the two conventions — this module
//! is STDIO-only (Chrome <-> sidecar); the sidecar<->app named-pipe side in `main.rs` uses
//! big-endian to match `sync.rs`.
//!
//! This module is synchronous `std::io` (not tokio async) because it talks directly to
//! `std::io::stdin()`/`stdout()`, which are blocking, thread-based handles under the hood.

use std::io::{self, Read, Write};

/// Chrome's hard cap on a single browser->host message (1 MiB). Anything claiming to be
/// larger is rejected BEFORE any buffer is allocated (D-05 bounded-before-buffer discipline —
/// mirrors `MAX_SYNC_FRAME` in `sync.rs`). Without this check, a malicious or corrupted 4-byte
/// prefix (up to 4 GiB) could trigger a huge allocation before a single payload byte is read,
/// giving a local attacker a cheap memory-exhaustion DoS against the sidecar process.
pub const MAX_NATIVE_MESSAGE_LEN: u32 = 1024 * 1024;

/// Read one length-prefixed JSON message from a Chrome-native-messaging stdio stream.
///
/// SECURITY (D-05): the claimed length is checked against `MAX_NATIVE_MESSAGE_LEN` BEFORE
/// `vec![0u8; len]` is ever allocated, so an attacker-controlled 4-byte prefix cannot force
/// an oversized allocation. The error is generic ("frame too large") and returned via
/// `io::ErrorKind::InvalidData` — the caller (`main.rs`) turns this into a typed
/// `protocol-error` envelope and exits (no silent retry, no hang).
pub fn read_message<R: Read>(mut r: R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_ne_bytes(len_buf);
    if len > MAX_NATIVE_MESSAGE_LEN {
        // D-05: reject BEFORE buffering — no allocation for the oversized claim.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "protocol-error: frame too large",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Validate that `len` (a payload byte count) fits in the u32 length prefix, returning the
/// cast value. Extracted from `write_message` so the u32::MAX boundary can be unit-tested
/// without materializing a multi-gigabyte payload.
fn checked_prefix_len(len: usize) -> io::Result<u32> {
    u32::try_from(len).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message too large"))
}

/// Write one length-prefixed JSON message to a Chrome-native-messaging stdio stream.
///
/// Rejects payloads that exceed `u32::MAX` with an `InvalidInput` io::Error rather than
/// silently truncating or panicking.
pub fn write_message<W: Write>(mut w: W, payload: &[u8]) -> io::Result<()> {
    let len = checked_prefix_len(payload.len())?;
    w.write_all(&len.to_ne_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // -----------------------------------------------------------------------------------
    // test_read_message_returns_exact_bytes
    //
    // A valid u32-LE (native) length prefix + N bytes must round-trip to exactly those N
    // bytes — no off-by-one, no trailing garbage picked up.
    // -----------------------------------------------------------------------------------
    #[test]
    fn test_read_message_returns_exact_bytes() {
        let payload = b"hello cryptiq bridge";
        let mut framed = Vec::new();
        framed.extend_from_slice(&(payload.len() as u32).to_ne_bytes());
        framed.extend_from_slice(payload);
        // Trailing garbage that must NOT be consumed by this single read_message call.
        framed.extend_from_slice(b"TRAILING-GARBAGE-NOT-PART-OF-FRAME");

        let mut cursor = Cursor::new(framed);
        let result = read_message(&mut cursor).expect("valid frame must read successfully");

        assert_eq!(
            result, payload,
            "read_message must return exactly the N bytes declared by the length prefix"
        );
    }

    // -----------------------------------------------------------------------------------
    // test_write_then_read_round_trips_arbitrary_json
    //
    // write_message followed by read_message must reproduce an arbitrary JSON byte payload
    // unchanged.
    // -----------------------------------------------------------------------------------
    #[test]
    fn test_write_then_read_round_trips_arbitrary_json() {
        let original = serde_json::json!({
            "protocolVersion": 1,
            "type": "echo",
            "id": "abc-123",
            "payload": { "nested": [1, 2, 3], "text": "quotes \" and \\ backslashes" }
        });
        let original_bytes = serde_json::to_vec(&original).expect("serialize test payload");

        let mut buf = Vec::new();
        write_message(&mut buf, &original_bytes).expect("write_message must succeed");

        let mut cursor = Cursor::new(buf);
        let round_tripped =
            read_message(&mut cursor).expect("read_message must succeed on our own output");

        assert_eq!(
            round_tripped, original_bytes,
            "write_message/read_message round-trip must reproduce the payload byte-for-byte"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&round_tripped).expect("round-tripped bytes must still be valid JSON");
        assert_eq!(parsed, original, "round-tripped JSON must be structurally identical");
    }

    // -----------------------------------------------------------------------------------
    // test_read_message_rejects_oversize_before_buffering — D-05 / mirrors
    // sync.rs::test_recv_framed_large_rejects_oversize (FIX 2 / review HIGH-2 pattern).
    //
    // A length prefix claiming more than MAX_NATIVE_MESSAGE_LEN (here, u32::MAX — a ~4 GiB
    // claim) must be rejected WITHOUT ever allocating a buffer of that size. We prove "no
    // allocation" by supplying ONLY the 4-byte prefix and nothing else: if read_message
    // allocated first and then tried to read the (nonexistent) body, it would return an
    // UnexpectedEof error instead of InvalidData. Getting InvalidData proves the size check
    // fired before any attempt to fill a payload buffer.
    // -----------------------------------------------------------------------------------
    #[test]
    fn test_read_message_rejects_oversize_before_buffering() {
        // Reader that yields only the oversize 4-byte prefix, then panics if asked to read
        // any further bytes — a hard runtime assertion that no post-prefix read (which would
        // only happen after an oversized allocation) was attempted.
        struct PrefixOnlyThenPanic {
            prefix: [u8; 4],
            served: bool,
        }
        impl Read for PrefixOnlyThenPanic {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if !self.served {
                    self.served = true;
                    let n = buf.len().min(4);
                    buf[..n].copy_from_slice(&self.prefix[..n]);
                    return Ok(n);
                }
                panic!(
                    "read_message attempted a second read after an oversized length prefix — \
                     this implies a buffer was allocated for the attacker-claimed size before \
                     the D-05 cap check fired"
                );
            }
        }

        let oversized = PrefixOnlyThenPanic {
            prefix: 0xFFFF_FFFFu32.to_ne_bytes(),
            served: false,
        };

        let result = read_message(oversized);

        assert!(
            result.is_err(),
            "read_message must reject a length prefix above MAX_NATIVE_MESSAGE_LEN"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "oversized frame must be reported as InvalidData, not a downstream read failure"
        );
    }

    // -----------------------------------------------------------------------------------
    // test_write_message_rejects_payload_larger_than_u32_max
    //
    // write_message must reject any payload whose length cannot fit in a u32 length prefix
    // rather than truncating it or panicking on the cast.
    // -----------------------------------------------------------------------------------
    #[test]
    fn test_write_message_rejects_payload_larger_than_u32_max() {
        // A real (u32::MAX + 1)-byte allocation is infeasible (and unnecessary) in a unit
        // test. `write_message` delegates its length check to `checked_prefix_len`, which
        // operates on the `usize` length alone — exercising it directly at the u32::MAX
        // boundary proves write_message's InvalidInput branch fires correctly without
        // materializing gigabytes of payload.
        let over_u32_len: usize = u32::MAX as usize + 1;

        let result = checked_prefix_len(over_u32_len);

        assert!(
            result.is_err(),
            "checked_prefix_len (used by write_message) must reject lengths above u32::MAX"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::InvalidInput,
            "oversized payload length must be reported as InvalidInput"
        );

        // Also confirm the in-range boundary (exactly u32::MAX) is accepted, so the rejection
        // above is a genuine boundary check and not an overly broad failure.
        assert!(
            checked_prefix_len(u32::MAX as usize).is_ok(),
            "checked_prefix_len must accept a length exactly at u32::MAX"
        );
    }
}
