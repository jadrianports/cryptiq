// apps/desktop/src/lib/bridge/bridgeFingerprint.ts
//
// Pure pubkey-bytes -> grouped short-hex fingerprint formatter (D-01, BRIDGE-05).
//
// Used by ExtensionApprovalModal.svelte to render a human-eyeball-able fingerprint
// of the extension's Curve25519 public key alongside the Allow/Deny prompt, e.g.
// "4F2A·8C11·B071·D9F3".
//
// SECURITY NOTE (15-RESEARCH.md Pattern 3 / Assumption A3):
//   This fingerprint is a DISPLAY-ONLY human-eyeball aid for re-approval after an
//   extension reinstall — it is NEVER used as a security check itself. The actual
//   security boundary is the persisted public key + crypto_box + pairing token
//   (Rust-side, extension_bridge.rs). No hand-rolled crypto here — this is a plain
//   hex/grouping transform of already-public key bytes, not a cryptographic primitive.
//
// Core purity note: pure TS, no Svelte/Tauri/node:fs import — testable standalone.

/**
 * Format the first 8 bytes of a Curve25519 public key as a grouped, uppercase,
 * middle-dot-separated hex string for human display.
 *
 * Example: bytes [0x4f, 0x2a, 0x8c, 0x11, 0xb0, 0x71, 0xd9, 0xf3, ...] ->
 *          "4F2A·8C11·B071·D9F3"
 *
 * @param publicKeyBytes The extension's Curve25519 public key (32 bytes; only the
 *                        first 8 are used for the fingerprint).
 * @returns A grouped uppercase hex string joined by U+00B7 MIDDLE DOT.
 */
export function formatFingerprint(publicKeyBytes: Uint8Array): string {
  const hex = Array.from(publicKeyBytes.slice(0, 8))
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join('');
  return hex.match(/.{1,4}/g)!.join('·');
}
