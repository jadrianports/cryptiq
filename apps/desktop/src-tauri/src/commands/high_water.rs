// apps/desktop/src-tauri/src/commands/high_water.rs
//
// Phase 36 Plan 09 — D-11's rollback mitigation: a monotonic high-water version plus a
// signature-covered SHA-256 binding. This is Cryptiq's OWN answer to UPD-03 (36-02-SUMMARY.md,
// CONFIRMED): minisign signs the ARTIFACT bytes, but `version` lives in the UNSIGNED
// `latest.json` — so a GitHub-account compromise with NO key access can serve a real, old,
// validly-signed artifact under a false high version claim ("99.0.0") and every existing check
// (including UPD-02's strictly-greater comparator) passes, because the comparator only ever sees
// the untrusted claim.
//
// BINDING MECHANISM DECISION (36-RESEARCH.md Open Question 3 — explicitly flagged as "a genuine
// design decision for the plan, not a research gap ... resolve it explicitly rather than
// defaulting silently"):
//
// CHOSEN: Option A — a small minisign-signed sub-manifest binding `{version, sha256}` together.
// The release ceremony signs this tiny document with the SAME key that signs the artifact;
// `verify_sub_manifest` below verifies that signature against the SAME pubkey BEFORE trusting the
// version claim at all, then the caller compares the downloaded artifact's SHA-256 against the
// bound value. This makes the version claim itself KEY-COVERED — precisely the property UPD-03
// found missing. Reasoning this beats a high-water-only design: the rollback attack's version
// claim (e.g. "99.0.0") is deliberately ABOVE any plausible high-water mark, so a high-water
// check alone, applied to the UNSIGNED claim, would not refuse it — only binding the claim to the
// key does. D-11's literal language ("signature-covered SHA-256 binding") requires this half; an
// unsigned high-water check alone would not satisfy it.
//
// REJECTED: Option B (high-water version only, no signed binding). Cheaper — no new crypto
// surface — but strictly weaker: it stops only a claim AT OR BELOW a recorded mark, doing nothing
// against a same-or-higher false claim over old bytes (T-36-50). Not selected because Option A
// fit this plan's budget (the crypto primitives — minisign-verify, sha2 — are already pinned in
// this workspace; no new crate was needed) and D-11's language is explicit about the binding.
//
// FOLLOW-ON FLAGGED TO THE ORCHESTRATOR: `scripts/release/sign.mjs` (Plan 08 — DEFERRED at the
// time this plan executed) must be extended to actually PRODUCE and upload this signed
// sub-manifest during a real release ceremony. This plan builds and tests the Rust-side VERIFIER
// only; until Plan 08 lands that follow-on task, no real release can produce a sub-manifest Rust
// can verify. Recorded here, not silently left implicit — see 36-09-SUMMARY.md.
//
// D-12 — WHY THIS IS NOT IN config.json: `packages/core/src/config/config.ts`'s `parseConfig`
// reconstructs an EXPLICIT object literal on every parse (read directly this plan, lines ~74-82)
// — any key not named in that literal is silently DROPPED the next time `serializeConfig` writes
// the file back. An absent high-water mark would silently RE-OPEN the exact rollback this plan
// exists to close (a missing mark reads as "no floor recorded", which is the pre-mitigation
// state). Never put anything in config.json whose ABSENCE is dangerous. Storage here instead: a
// dedicated Rust-side JSON sidecar at `$APPCONFIG/cryptiq/update-highwater.json`, written
// atomically following `vault_write_atomic` / `pairing.rs`'s `write_peers_json_atomic` discipline
// (temp file in the same directory -> `sync_all` -> atomic rename -> best-effort dir-fsync).
//
// Responsibilities:
//   HighWaterState           — three-state read result: Known(version) | Absent | Unreadable.
//                               NOT an Option<Version> — "never recorded" and "cannot read" are
//                               different facts and must be distinguishable at the call site.
//   read_high_water            — reads the sidecar; every failure mode collapses to Unreadable.
//   record_high_water          — MONOTONIC write: refuses (silently, Ok) to record a
//                               non-strictly-greater value; refuses (Err) to write at all when
//                               the current state is Unreadable (see `should_record_high_water`).
//   should_record_high_water — the pure decision core factored out of `record_high_water` so it
//                               can be pinned by a #[test] with zero AppHandle/filesystem I/O —
//                               required because this machine cannot construct a live
//                               `tauri::App`/`AppHandle` inside a `cargo test` binary at all
//                               (36-02-SUMMARY.md's exhaustively-diagnosed environment blocker;
//                               `record_high_water` itself is therefore untestable directly here,
//                               exactly like `config_guard::config_bool_field` and
//                               `extension_bridge::extension_bridge_enabled` are never tested
//                               directly either — only their pure cores are).
//   passes_high_water          — the pure anti-rollback decision, zero I/O.
//   SubManifestBinding         — the verified {version, sha256} pair extracted from a
//                               signature-checked sub-manifest.
//   verify_sub_manifest        — minisign-verifies a sub-manifest's signature against a pubkey
//                               (same outer-base64-then-inner-minisign-decode convention as
//                               `update.rs`'s own reproduction of the plugin's
//                               `verify_signature()` call), then parses `{version, sha256}` JSON.
//                               Runs from PRODUCTION code (not merely #[cfg(test)]) — this is why
//                               `minisign-verify` moved from [dev-dependencies] to [dependencies]
//                               in Cargo.toml this plan.
//   sha256_hex                 — SHA-256 of arbitrary bytes as lowercase hex (the `sha2` crate;
//                               D-11 / 36-RESEARCH.md's "Don't Hand-Roll" table — reuse an
//                               already-audited primitive, never hand-roll hashing).
//
// Security invariants:
//   - This module NEVER reads or writes config.json (D-12) — grep-asserted in the plan's
//     acceptance criteria; every `config.json` mention above is inside a `//` comment.
//   - `passes_high_water`: `Unreadable` -> `false` (FAIL CLOSED — a corrupt/deleted sidecar must
//     never regain the rollback). `Absent` -> falls back to the running app's OWN version as a
//     floor (the SAFE fallback: a fresh install has no mark yet, and the app's own compiled-in
//     version is a floor the attacker cannot lower) — this is NOT permit-by-default.
//   - `verify_sub_manifest` never trusts a version claim that is not inside a
//     signature-verified sub-manifest — the unsigned `latest.json` `version` field is NEVER an
//     input to this module.
//   - `should_record_high_water` refuses to advance the mark when the current read is
//     `Unreadable` (returns `None`, meaning "do not write"): if we cannot verify what the prior
//     high value was, silently accepting any new value risks lowering an unknown existing mark.
//     In practice this call is never reached while `Unreadable`, because `passes_high_water`
//     already refuses every apply in that state — but refusing here too is the safer default if
//     this function is ever invoked out of band.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use minisign_verify::{PublicKey, Signature};
use tauri::Manager;

/// Three-state high-water read result. "Never recorded" (`Absent`) and "cannot read"
/// (`Unreadable`) are different facts with different safe responses and must never be collapsed
/// into a single `Option<Version>`.
///
/// Not yet constructed by any live path this plan (mirrors `update.rs`'s own
/// `with_explicit_comparator` `#[allow(dead_code)]` precedent): `update_check`/`update_apply`'s
/// real runtime call into this module lands in Phase 37; this plan's own tests (both here and in
/// `update.rs`'s `check_rollback_mitigation` tests) exercise every variant directly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum HighWaterState {
    /// A high-water mark was successfully read from the sidecar.
    Known(semver::Version),
    /// The sidecar does not exist yet — a fresh install, or one that has never recorded a mark.
    Absent,
    /// The sidecar exists but could not be read/parsed (missing config dir, unreadable file,
    /// corrupt JSON, or an unparseable version string). Distinguished from `Absent` because the
    /// safe response differs: `Absent` falls back to a floor, `Unreadable` fails closed entirely.
    Unreadable,
}

#[derive(serde::Serialize)]
#[allow(dead_code)]
struct HighWaterFileWrite<'a> {
    version: &'a str,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct HighWaterFileRead {
    version: String,
}

/// Reads `$APPCONFIG/cryptiq/update-highwater.json`. Every failure mode (unresolvable config
/// dir, missing file, unreadable file, corrupt JSON, unparseable version string) collapses to
/// `Unreadable` — a missing FILE specifically (not merely a missing FIELD) is `Absent`, per the
/// three-state contract above.
///
/// Not yet called by any live path this plan — Phase 37 wires the real `update_check` runtime
/// that calls this. `#[allow(dead_code)]` matches `update.rs`'s `with_explicit_comparator`
/// forward-declared-for-a-later-plan precedent.
#[allow(dead_code)]
pub fn read_high_water(app: &tauri::AppHandle) -> HighWaterState {
    let config_dir = match app.path().app_config_dir() {
        Ok(p) => p,
        Err(_) => return HighWaterState::Unreadable, // cannot resolve config dir at all
    };
    let path = config_dir.join("cryptiq").join("update-highwater.json");
    if !path.exists() {
        return HighWaterState::Absent;
    }
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => return HighWaterState::Unreadable, // exists but unreadable (permissions, race)
    };
    let parsed: HighWaterFileRead = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return HighWaterState::Unreadable, // corrupt JSON
    };
    match semver::Version::parse(&parsed.version) {
        Ok(v) => HighWaterState::Known(v),
        Err(_) => HighWaterState::Unreadable, // unparseable version string
    }
}

/// The pure decision core of `record_high_water`, factored out so it is testable with zero
/// `AppHandle`/filesystem I/O (see the module header's `should_record_high_water` entry for why).
/// Returns `Some(new_value)` when a write should proceed, `None` when it should not (a silent
/// no-op — never an error the caller need report — for a non-strictly-greater candidate, or a
/// refusal when the current state is `Unreadable`, per the module header's security invariant).
#[allow(dead_code)]
pub(crate) fn should_record_high_water(
    current: &HighWaterState,
    candidate: &semver::Version,
) -> Option<semver::Version> {
    match current {
        HighWaterState::Known(existing) => {
            if candidate > existing {
                Some(candidate.clone())
            } else {
                None // monotonic: a non-strictly-greater candidate is a silent no-op
            }
        }
        HighWaterState::Absent => Some(candidate.clone()), // first-ever recording
        HighWaterState::Unreadable => None, // refuse to write over an unknown prior value
    }
}

/// Records a new high-water mark. MONOTONIC: reads the current value first (`read_high_water`)
/// and only writes when `should_record_high_water` says to. A non-strictly-greater candidate is
/// an idempotent no-op returning `Ok(())`, never an error. Written atomically via the
/// project's standard temp-file -> `sync_all` -> atomic rename -> best-effort dir-fsync
/// discipline (mirrors `vault_write_atomic` / `pairing.rs`'s `write_peers_json_atomic`).
///
/// Not yet called by any live path this plan — per the module header, "recording the mark is
/// Phase 37's job" (it happens on a successful update, which no runtime path exists for yet).
#[allow(dead_code)]
pub fn record_high_water(app: &tauri::AppHandle, v: &semver::Version) -> Result<(), String> {
    let current = read_high_water(app);
    let new_value = match should_record_high_water(&current, v) {
        Some(v) => v,
        None => return Ok(()), // no-op: either non-strictly-greater, or current is Unreadable
    };

    let config_dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("record_high_water: could not resolve app config dir: {}", e))?;
    let dir = config_dir.join("cryptiq");
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("record_high_water: mkdir failed for '{}': {}", dir.display(), e))?;

    let target = dir.join("update-highwater.json");
    let tmp = dir.join("update-highwater.json.tmp");

    let version_string = new_value.to_string();
    let bytes = serde_json::to_vec_pretty(&HighWaterFileWrite { version: &version_string })
        .map_err(|e| format!("record_high_water: JSON serialize failed: {}", e))?;

    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp).map_err(|e| {
            format!("record_high_water: failed to create tmp file '{}': {}", tmp.display(), e)
        })?;
        f.write_all(&bytes).map_err(|e| {
            format!("record_high_water: failed to write tmp file '{}': {}", tmp.display(), e)
        })?;
        f.sync_all().map_err(|e| {
            format!("record_high_water: sync_all on tmp file '{}' failed: {}", tmp.display(), e)
        })?;
    }

    std::fs::rename(&tmp, &target).map_err(|e| {
        format!(
            "record_high_water: atomic rename failed ('{}' -> '{}'): {}",
            tmp.display(),
            target.display(),
            e
        )
    })?;

    // Best-effort dir-fsync (no-op on Windows; durability on Linux/macOS) — matches
    // write_peers_json_atomic's exact same step.
    let _ = std::fs::File::open(&dir).and_then(|f| f.sync_all());

    Ok(())
}

/// The pure anti-rollback decision — no `AppHandle`, no Tauri, no I/O.
///
///   - `Known(hw)`   -> `candidate > hw`
///   - `Absent`      -> falls back to `candidate > current_app`. This is the SAFE fallback: on a
///     fresh install no mark exists yet, and the running app's OWN version is a floor the
///     attacker cannot lower (they don't control what binary is already installed). It is NOT a
///     permit-by-default — a candidate at or below the app's own version is still refused.
///   - `Unreadable`  -> `false`. FAIL CLOSED. A corrupt store must never permit — an attacker who
///     can corrupt the sidecar must not thereby regain the rollback.
///
/// Called from `update.rs`'s `check_rollback_mitigation` (also `#[allow(dead_code)]` this plan —
/// Phase 37 wires its real runtime caller) and directly by this module's own tests.
#[allow(dead_code)]
pub(crate) fn passes_high_water(
    state: &HighWaterState,
    candidate: &semver::Version,
    current_app: &semver::Version,
) -> bool {
    match state {
        HighWaterState::Known(hw) => candidate > hw,
        HighWaterState::Absent => candidate > current_app,
        HighWaterState::Unreadable => false,
    }
}

// ---------------------------------------------------------------------------
// Option A — the signed sub-manifest binding.
// ---------------------------------------------------------------------------

/// The verified `{version, sha256}` pair extracted from a signature-checked sub-manifest.
/// `sha256_hex` is lower-cased on parse so comparison against `sha256_hex()`'s own output
/// (always lowercase) is a plain string equality, never case-sensitive by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct SubManifestBinding {
    pub(crate) version: semver::Version,
    pub(crate) sha256_hex: String,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct SubManifestJson {
    version: String,
    sha256: String,
}

/// Typed reasons `verify_sub_manifest` can fail — every failure surfaces a distinguishable
/// reason, never a bare `Err(())`, matching the project's fail-closed typed-error contract.
#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum BindingError {
    /// The outer base64 wrapper, the minisign signature, or the minisign verification itself
    /// failed — the sub-manifest's authenticity cannot be established.
    SignatureInvalid,
    /// The signature verified, but the signed bytes are not the expected `{version, sha256}`
    /// JSON shape.
    MalformedJson,
    /// The signature and JSON shape both verified, but the `version` field is not a valid semver
    /// string.
    MalformedVersion,
}

/// Verifies a minisign-signed sub-manifest (Option A's key-covered `{version, sha256}` binding)
/// against `pubkey_b64` — the SAME outer-base64-wrapped minisign public key that sits at
/// `tauri.conf.json`'s `plugins.updater.pubkey`. Mirrors `update.rs`'s own
/// `upd03_rollback_experiment` reproduction of the plugin's private `verify_signature()` call:
/// both the pubkey and the signature are OUTER base64 blobs wrapping the inner minisign text,
/// decoded here exactly as the plugin itself decodes them — this function runs the SAME
/// verification the real artifact signature undergoes, applied to the sub-manifest instead.
///
/// LOAD-BEARING ORDERING: this function must be called, and must succeed, BEFORE the caller
/// trusts `sub_manifest_bytes`' `version` field for anything (including a high-water comparison)
/// — that ordering IS Option A's entire value. Verifying a version claim after already having
/// acted on it is not a gate.
#[allow(dead_code)]
pub(crate) fn verify_sub_manifest(
    sub_manifest_bytes: &[u8],
    signature_b64: &str,
    pubkey_b64: &str,
) -> Result<SubManifestBinding, BindingError> {
    let decode_outer_b64 = |raw: &str| -> Result<String, BindingError> {
        let bytes = STANDARD.decode(raw.trim()).map_err(|_| BindingError::SignatureInvalid)?;
        String::from_utf8(bytes).map_err(|_| BindingError::SignatureInvalid)
    };
    let pubkey_text = decode_outer_b64(pubkey_b64)?;
    let signature_text = decode_outer_b64(signature_b64)?;

    let public_key = PublicKey::decode(&pubkey_text).map_err(|_| BindingError::SignatureInvalid)?;
    let signature =
        Signature::decode(&signature_text).map_err(|_| BindingError::SignatureInvalid)?;
    public_key
        .verify(sub_manifest_bytes, &signature, true)
        .map_err(|_| BindingError::SignatureInvalid)?;

    let parsed: SubManifestJson =
        serde_json::from_slice(sub_manifest_bytes).map_err(|_| BindingError::MalformedJson)?;
    let version =
        semver::Version::parse(&parsed.version).map_err(|_| BindingError::MalformedVersion)?;

    Ok(SubManifestBinding { version, sha256_hex: parsed.sha256.to_lowercase() })
}

/// SHA-256 of arbitrary bytes as lowercase hex. D-11 / 36-RESEARCH.md's "Don't Hand-Roll" table:
/// reuse an already-audited primitive (the `sha2` crate) rather than hand-rolling a hash.
///
/// Not yet called by any live path this plan — Phase 37's real update path will hash the
/// downloaded artifact and compare it against `SubManifestBinding::sha256_hex`.
#[allow(dead_code)]
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> semver::Version {
        semver::Version::parse(s).unwrap()
    }

    // -----------------------------------------------------------------------
    // passes_high_water — the pure anti-rollback decision (all 6 plan-named tests below).
    // -----------------------------------------------------------------------

    #[test]
    fn high_water_refuses_equal_version() {
        let state = HighWaterState::Known(v("3.2.0"));
        assert!(
            !passes_high_water(&state, &v("3.2.0"), &v("3.2.0")),
            "ANTI-ROLLBACK: a candidate equal to the recorded high-water mark must be refused"
        );
    }

    #[test]
    fn high_water_refuses_lower_version() {
        let state = HighWaterState::Known(v("3.2.0"));
        assert!(
            !passes_high_water(&state, &v("3.1.9"), &v("3.2.0")),
            "ANTI-ROLLBACK: a candidate below the recorded high-water mark must be refused — \
             this is the exact property UPD-03's rollback attack tries to defeat"
        );
    }

    #[test]
    fn high_water_permits_strictly_greater() {
        let state = HighWaterState::Known(v("3.2.0"));
        assert!(
            passes_high_water(&state, &v("3.2.1"), &v("3.2.0")),
            "a genuinely strictly-greater candidate must be permitted — a gate that refuses \
             everything would also pass the two refusal tests above"
        );
    }

    #[test]
    fn absent_high_water_falls_back_to_app_version_floor() {
        let state = HighWaterState::Absent;
        // A fresh install (no mark recorded yet): the running app's own version is the floor.
        assert!(
            passes_high_water(&state, &v("3.2.1"), &v("3.2.0")),
            "Absent must permit a candidate strictly greater than the app's OWN version"
        );
        assert!(
            !passes_high_water(&state, &v("3.2.0"), &v("3.2.0")),
            "Absent must NOT be permit-by-default — a candidate equal to the app's own version \
             must still be refused"
        );
        assert!(
            !passes_high_water(&state, &v("3.1.0"), &v("3.2.0")),
            "Absent must NOT be permit-by-default — a candidate below the app's own version \
             must still be refused"
        );
    }

    #[test]
    fn unreadable_high_water_fails_closed() {
        let state = HighWaterState::Unreadable;
        // Even a candidate that is obviously "newer" must be refused — a corrupt/deleted
        // sidecar must never regain the rollback (T-36-48).
        assert!(
            !passes_high_water(&state, &v("99.0.0"), &v("3.2.0")),
            "Unreadable must fail CLOSED regardless of how high the candidate claims to be"
        );
    }

    #[test]
    fn record_high_water_is_monotonic() {
        // record_high_water(app, ..) itself cannot be driven directly by a #[test] on this
        // machine — constructing a live tauri::AppHandle inside a cargo-test binary crashes at
        // load (STATUS_ENTRYPOINT_NOT_FOUND), the same exhaustively-diagnosed environment
        // blocker documented in update.rs's upd03_rollback_experiment / 36-02-SUMMARY.md. This
        // test instead drives the PURE decision core `record_high_water` delegates to,
        // simulating the exact sequence the acceptance criterion describes: "recording 3.2.0
        // then 3.1.0 leaves the mark at 3.2.0".
        let after_first = should_record_high_water(&HighWaterState::Absent, &v("3.2.0"));
        assert_eq!(after_first, Some(v("3.2.0")), "the first-ever recording must be accepted");

        // Simulate having actually recorded 3.2.0: the state read back is now Known(3.2.0).
        let simulated_state_after_first = HighWaterState::Known(v("3.2.0"));
        let after_second = should_record_high_water(&simulated_state_after_first, &v("3.1.0"));
        assert_eq!(
            after_second, None,
            "recording a LOWER version after 3.2.0 must be a silent no-op — the mark stays at \
             3.2.0, never regresses to 3.1.0"
        );
    }

    // -----------------------------------------------------------------------
    // should_record_high_water — the Unreadable-refuses-to-write invariant (not itself one of
    // the plan's 6 named tests, but load-bearing for the module header's security invariant).
    // -----------------------------------------------------------------------
    #[test]
    fn should_record_high_water_refuses_when_unreadable() {
        assert_eq!(
            should_record_high_water(&HighWaterState::Unreadable, &v("99.0.0")),
            None,
            "must refuse to write over an unknown prior value, even for an ostensibly-high \
             candidate — silently accepting here could lower an unknown existing mark"
        );
    }

    // -----------------------------------------------------------------------
    // sha256_hex — known NIST test vectors (no hand-rolled hashing; the sha2 crate's own
    // correctness is trusted, this test pins Cryptiq's call-site usage: lowercase hex, full
    // 64-character digest).
    // -----------------------------------------------------------------------
    #[test]
    fn sha256_hex_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA-256 of the empty string is a fixed, universally-known value"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA-256(\"abc\") is the canonical NIST FIPS 180-4 test vector"
        );
    }

    // -----------------------------------------------------------------------
    // verify_sub_manifest — Option A's signed {version, sha256} binding. Fixtures below are a
    // FRESH throwaway keypair (D-09-style: generated this plan via `npx tauri signer generate`,
    // private key discarded after use, never committed) signing two small sub-manifest JSON
    // documents via `npx tauri signer sign`. Both the pubkey and each `.sig` are OUTER base64
    // blobs wrapping the inner minisign text, exactly as `tauri-plugin-updater`'s own
    // `verify_signature()` expects (confirmed this session identically to update.rs's own
    // fixture-loading convention) — decoded here via the SAME `decode_outer_b64` step
    // `verify_sub_manifest` itself performs.
    // -----------------------------------------------------------------------

    /// Throwaway public key generated for THIS plan's sub-manifest fixtures only (distinct from
    /// update.rs's Plan 02 THROWAWAY_PUBKEY — that plan's private key was never persisted past
    /// its own session, so a fresh keypair was generated here rather than reused). The private
    /// key was written to an OS-temp scratch path outside the repo and is not needed again; only
    /// the resulting public key + signatures below are committed, mirroring D-09's "never commit
    /// the private half" discipline.
    const SUBMANIFEST_PUBKEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IEYwMTUwQzU2RDRBQkQ1N0UKUldSKzFhdlVWZ3dWOEpqTGtxNnBIVW4wM0hyQjY2ZGN5bjB2NlVMYmZIbXJEZGRSV0ttRXY5ejcK";

    /// A genuine sub-manifest for version 3.2.0, binding it to the REAL SHA-256 of the Plan 02
    /// fixture artifact (`Cryptiq_3.2.0_x64-setup.exe`, recorded in 36-02-SUMMARY.md) — the exact
    /// bytes that were signed (no trailing newline).
    const SUBMANIFEST_320_JSON: &str = r#"{"version":"3.2.0","sha256":"bdf80aacae51a333c134af15e1e7602f4adca9f062466770d0fae86e8fcbcb21"}"#;
    const SUBMANIFEST_320_SIG: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVSKzFhdlVWZ3dWOEJHZGxGb3ArVG1vMU50ZXBMZ3FnaVFxZG5SWlAwaGhTWWxSRllydllCMEN0cFFuc0pBOG9mZTV5WHhxZFcxSnRSY2ZYNDlBb0xDcWNhRTY4T2RkdHdFPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzg0MzAyMTk3CWZpbGU6c3VibWFuaWZlc3QtMzIwLmpzb24KZnlPZ3ArY1U3UFJmdk8vd2hLVGlMUnpKV1VWN0ZnejU1RWZTdHdnY0Y1aXI2b2VHSFlKcVlqVktHc0gzRUdyai9NTmt0dURJL2pzeWJQMTl6d3o5Qnc9PQo=";

    /// A genuine (but semantically OLD) sub-manifest for version 3.1.0 — used by update.rs's
    /// Plan 09 Task 2 tests to prove `update_refused_rollback` fires against a validly-signed
    /// REPLAY of an old release (T-36-50: a false OR genuinely-old version claim at/above the
    /// high-water mark is a distinct threat from a missing/invalid binding). The sha256 value is
    /// a placeholder (all-zero) — this fixture's `version` field is what these tests exercise,
    /// not artifact-hash matching.
    #[allow(dead_code)]
    const SUBMANIFEST_310_JSON: &str = r#"{"version":"3.1.0","sha256":"0000000000000000000000000000000000000000000000000000000000000000"}"#;
    #[allow(dead_code)]
    const SUBMANIFEST_310_SIG: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVSKzFhdlVWZ3dWOEN0bmVNVFMwSjdjeXRYaVh5ektKM2dIRWJSeFZYU0diNjd4NE9SMThVWkpoWk5wTkpnMUlmTVBncU42M21rczV6MVFUS240N01NVlp0WVFUSDNkL1FVPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzg0MzAyMjAxCWZpbGU6c3VibWFuaWZlc3QtMzEwLmpzb24Kdm52MHBnWU4rdnlPeG5VVmZMbDhBMTJYL2FmRHBTUG8zS0d2OUdoV0RlRWNhZ0gxMWJ6aEZ1SFBjMU9kdWpJR0xMTldJVFZKYi8wc0tnaVd4Yk9qRHc9PQo=";

    #[test]
    fn verify_sub_manifest_accepts_genuine_signature() {
        let binding =
            verify_sub_manifest(SUBMANIFEST_320_JSON.as_bytes(), SUBMANIFEST_320_SIG, SUBMANIFEST_PUBKEY)
                .expect("a genuinely-signed sub-manifest must verify");
        assert_eq!(binding.version, v("3.2.0"));
        assert_eq!(
            binding.sha256_hex,
            "bdf80aacae51a333c134af15e1e7602f4adca9f062466770d0fae86e8fcbcb21"
        );
    }

    #[test]
    fn verify_sub_manifest_rejects_tampered_json() {
        // Flip one byte in the signed JSON — the signature must no longer verify.
        let mut tampered = SUBMANIFEST_320_JSON.as_bytes().to_vec();
        tampered[20] ^= 0x01;
        let result = verify_sub_manifest(&tampered, SUBMANIFEST_320_SIG, SUBMANIFEST_PUBKEY);
        assert_eq!(
            result,
            Err(BindingError::SignatureInvalid),
            "a tampered sub-manifest must fail signature verification, not silently parse"
        );
    }

    #[test]
    fn verify_sub_manifest_rejects_missing_binding() {
        // The UPD-03 rollback attack's hand-built latest.json (36-02-SUMMARY.md) carries NO
        // sub-manifest at all — simulated here by empty bytes / an empty signature, which must
        // fail closed rather than default to "no binding required".
        let result = verify_sub_manifest(b"", "", SUBMANIFEST_PUBKEY);
        assert_eq!(result, Err(BindingError::SignatureInvalid));
    }

    #[test]
    fn high_water_check_precedes_binding_use() {
        // Composition check (mirrors update.rs's own ordering test, at the high_water layer):
        // verify_sub_manifest's returned version must be what passes_high_water is evaluated
        // against, never the caller's own untrusted claim. This test proves the verified binding
        // and the high-water check compose correctly for a genuinely-signed, above-mark version.
        let binding =
            verify_sub_manifest(SUBMANIFEST_320_JSON.as_bytes(), SUBMANIFEST_320_SIG, SUBMANIFEST_PUBKEY)
                .expect("fixture must verify");
        let state = HighWaterState::Known(v("3.1.0"));
        assert!(
            passes_high_water(&state, &binding.version, &v("3.1.0")),
            "a genuinely-signed, strictly-greater version must pass once bound"
        );
    }
}
