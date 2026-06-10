// apps/desktop/src-tauri/src/commands/vault.rs
//
// Custom Tauri commands for vault file operations.
//
// Responsibilities:
//   vault_write_atomic  — tmp → fsync → rotate backups → atomic rename → dir-fsync (VAULT-05/06)
//   vault_write_named   — fsync + atomic rename to an explicitly-named path; no backup rotation
//                         (used by TauriVaultStorageAdapter.savePreMigrationBackup, P3-13)
//   vault_lock_acquire  — write {pid, hostname, startedAt} advisory lockfile with P3-08/09/10 logic
//   vault_lock_check    — re-verify lock ownership before each write (P3-08)
//   vault_lock_release  — remove the advisory lockfile on session end
//
// Security:
//   - Lockfile carries ONLY {pid, hostname, startedAt} — never any secret, key, or password.
//   - Backups are byte-copies of the already-encrypted vault; no plaintext ever touches Rust.
//   - Every command that accepts a path canonicalizes and confines it before any I/O.
//   - Backup paths are built by appending ".bak.N" to the FULL vault path string (Pitfall 2 defense).

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Lockfile shape — NEVER add password/key fields here (T-03-15)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone)]
struct LockFile {
    pid: u32,
    hostname: String,
    #[serde(rename = "startedAt")]
    started_at: String, // ISO 8601
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Derive the advisory lockfile path from the vault path.
///
/// `vault.cryptiq` → `vault.cryptiq.lock`
fn lock_path(vault_path: &str) -> PathBuf {
    PathBuf::from(format!("{}.lock", vault_path))
}

/// Get the machine hostname using environment variables (zero-dependency fallback).
///
/// Task-1 decision: Option A — no `hostname` crate. Reads `COMPUTERNAME` on Windows
/// (the primary dev platform) and `HOSTNAME` on Unix/macOS. Falls back to "unknown",
/// which still allows stale-detection via the timestamp alone (acceptable degradation).
fn get_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

// NOTE: a per-PID liveness probe (`pid_is_alive`) was removed (UAT T5 fix). It was only
// used by vault_lock_acquire's SAME-HOST branch, where it caused an intermittent-unlock bug:
// it false-positived on OS PID reuse after a relaunch (a dead prior instance's PID gets
// reused → looked "alive" → spurious VAULT_LOCKED) and never recognised our OWN PID. The
// single-instance plugin (decision 13) already guarantees at most one live Cryptiq process
// per host, so a same-host lock can only be our own or a dead prior instance — never a live
// peer. Same-host locks are therefore ALWAYS safe to take over; no PID liveness check needed.

/// Return `true` if the ISO 8601 `started_at` timestamp is more than 30 minutes old.
///
/// If the timestamp is unparseable, returns `false` (treat as fresh — conservative).
fn is_older_than_30_min(started_at: &str) -> bool {
    // Parse using only `std` — parse the ISO 8601 string via `chrono` is unavailable,
    // so we rely on the system time. We compare RFC 3339 strings by converting to epoch.
    // Use a simple approach: parse year/month/day/hour/min/sec from a canonical ISO string.
    // If parsing fails, treat as fresh (not stale) — conservative.
    match parse_iso8601_epoch_secs(started_at) {
        Some(lock_epoch) => {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            now_secs.saturating_sub(lock_epoch) > 30 * 60
        }
        None => false,
    }
}

/// Parse a subset of ISO 8601 / RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ` or with offset)
/// into a Unix epoch in seconds. Sufficient for the 30-minute staleness check.
///
/// Returns `None` if the string cannot be parsed.
fn parse_iso8601_epoch_secs(s: &str) -> Option<u64> {
    // Expected format: "2026-05-30T12:34:56Z" or "2026-05-30T12:34:56.123Z"
    let s = s.trim();
    // Accept: YYYY-MM-DDTHH:MM:SS[.frac][Z|+00:00]
    let date_time = s.get(..19)?; // "YYYY-MM-DDTHH:MM:SS"
    if date_time.as_bytes().get(4) != Some(&b'-')
        || date_time.as_bytes().get(7) != Some(&b'-')
        || date_time.as_bytes().get(10) != Some(&b'T')
        || date_time.as_bytes().get(13) != Some(&b':')
        || date_time.as_bytes().get(16) != Some(&b':')
    {
        return None;
    }
    let year: u64 = date_time[0..4].parse().ok()?;
    let month: u64 = date_time[5..7].parse().ok()?;
    let day: u64 = date_time[8..10].parse().ok()?;
    let hour: u64 = date_time[11..13].parse().ok()?;
    let min: u64 = date_time[14..16].parse().ok()?;
    let sec: u64 = date_time[17..19].parse().ok()?;

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || min > 59
        || sec > 59
    {
        return None;
    }

    // Compute days since Unix epoch (1970-01-01) using Julian Day Number arithmetic.
    // This handles leap years correctly for the range we care about (2020–2100).
    let epoch_jdn = julian_day(1970, 1, 1)?;
    let lock_jdn = julian_day(year, month, day)?;
    let days_since_epoch = lock_jdn.checked_sub(epoch_jdn)?;
    let epoch_secs = days_since_epoch * 86400 + hour * 3600 + min * 60 + sec;
    Some(epoch_secs)
}

/// Compute the proleptic Julian Day Number for a (year, month, day) in the Gregorian calendar.
///
/// Uses i64 throughout so intermediate values can go negative without overflow
/// (fixes CR-03: the old u64 `b` was ~2^64-13 and the final addition overflowed
/// in Rust debug builds, causing a panic on every staleness check in `cargo tauri dev`).
fn julian_day(year: u64, month: u64, day: u64) -> Option<u64> {
    // Algorithm: https://en.wikipedia.org/wiki/Julian_day#Converting_Gregorian_calendar_date_to_Julian_Day_Number
    // Only valid for years > 0. We operate in the range 2000–2100; this is safe.
    if year == 0 {
        return None;
    }
    let (y, m) = if month <= 2 {
        (year - 1, month + 12)
    } else {
        (year, month)
    };
    // All arithmetic in i64 so that intermediate values can be negative.
    let y = y as i64;
    let m = m as i64;
    let d = day as i64;
    let a = y / 100;
    let b = 2 - a + a / 4; // can be negative for years before ~200 AD; fine for 2000-2100
    let jdn = (365.25 * (y as f64 + 4716.0)) as i64
        + (30.6001 * (m as f64 + 1.0)) as i64
        + d
        + b
        - 1524;
    if jdn < 0 {
        return None;
    }
    Some(jdn as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known JDN for 2000-01-01 is 2451545 (verified against
    /// https://en.wikipedia.org/wiki/Julian_day#Epochs).
    #[test]
    fn julian_day_known_date_2000_01_01() {
        assert_eq!(julian_day(2000, 1, 1), Some(2451545));
    }

    /// Spot-check a more recent date: 2026-05-30.
    /// JDN = 2461191 (cross-checked: 2451545 + 9646 days from 2000-01-01).
    #[test]
    fn julian_day_known_date_2026_05_30() {
        assert_eq!(julian_day(2026, 5, 30), Some(2461191));
    }

    /// Year 0 is rejected.
    #[test]
    fn julian_day_rejects_year_zero() {
        assert_eq!(julian_day(0, 1, 1), None);
    }

    /// Staleness check does not panic for a fresh (now) timestamp.
    #[test]
    fn is_older_than_30_min_fresh_timestamp_does_not_panic() {
        // A timestamp far in the future is definitely not stale.
        assert!(!is_older_than_30_min("2099-12-31T23:59:59Z"));
    }

    /// Staleness check returns true for a clearly-old timestamp.
    #[test]
    fn is_older_than_30_min_old_timestamp_returns_true() {
        // 2000-01-01 is well over 30 minutes ago.
        assert!(is_older_than_30_min("2000-01-01T00:00:00Z"));
    }

    // -----------------------------------------------------------------------
    // Phase-3 HUMAN-UAT backend coverage (closes 03-HUMAN-UAT.md tests 1–3
    // at the filesystem/command layer without a live Tauri window — the click
    // -through round-trip stays for Phase-4 UI + tauri-driver).
    //
    // Each test uses its own uniquely-named temp dir so the default parallel
    // cargo runner has no cross-test contention.
    // -----------------------------------------------------------------------

    /// Create a clean temp directory for a test (removes any prior run's dir).
    fn fresh_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cryptiq_uat_{}", name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// Path string for `vault.cryptiq` inside `dir`.
    fn vault_in(dir: &Path) -> String {
        dir.join("vault.cryptiq").to_str().unwrap().to_string()
    }

    /// Hand-write an advisory lockfile next to the vault (simulates another session).
    fn write_lock(vault_path: &str, pid: u32, hostname: &str, started_at: &str) {
        let json = format!(
            "{{\"pid\":{},\"hostname\":{:?},\"startedAt\":{:?}}}",
            pid, hostname, started_at
        );
        fs::write(format!("{}.lock", vault_path), json).expect("write lock");
    }

    // --- UAT Test 1: live vault creation round-trip (backend) ---------------

    #[test]
    fn write_atomic_creates_exact_bytes_and_leaves_no_tmp() {
        let dir = fresh_dir("write_basic");
        let vp = vault_in(&dir);
        let bytes = vec![1u8, 2, 3, 4, 5];

        vault_write_atomic(vp.clone(), bytes.clone(), 0).expect("write");

        assert_eq!(fs::read(&vp).unwrap(), bytes, "primary holds exact bytes");
        assert!(!PathBuf::from(format!("{}.tmp", vp)).exists(), "no .tmp left behind");
        assert!(!PathBuf::from(format!("{}.bak.1", vp)).exists(), "max_backups=0 => no backup");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_file_carries_only_pid_host_startedat_and_no_secrets() {
        // T-03-15: the advisory lock must never contain a key/password/vault data.
        let dir = fresh_dir("lock_shape");
        let vp = vault_in(&dir);

        vault_lock_acquire(vp.clone(), "2099-01-01T00:00:00Z".to_string()).expect("acquire");

        let raw = fs::read_to_string(format!("{}.lock", vp)).expect("read lock");
        let obj = serde_json::from_str::<serde_json::Value>(&raw)
            .expect("lock is JSON")
            .as_object()
            .expect("lock is a JSON object")
            .clone();

        assert_eq!(obj.len(), 3, "lock has exactly 3 fields");
        assert!(obj.contains_key("pid"));
        assert!(obj.contains_key("hostname"));
        assert!(obj.contains_key("startedAt"));
        for forbidden in ["key", "password", "secret", "data", "entries"] {
            assert!(!obj.contains_key(forbidden), "lock must not contain '{}'", forbidden);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    // --- UAT Test 2: backup rotation ordering + content-hash dedup ----------

    #[test]
    fn write_atomic_rotates_newest_first_and_caps_at_five() {
        let dir = fresh_dir("rotation");
        let vp = vault_in(&dir);

        // Six writes with distinct contents. Write #1 has no prior primary => no backup.
        let versions: Vec<Vec<u8>> = (1u8..=6).map(|n| vec![n; 8]).collect();
        for v in &versions {
            vault_write_atomic(vp.clone(), v.clone(), 5).expect("write");
            // Crash-safety invariant: the primary is present after every write.
            assert!(PathBuf::from(&vp).exists(), "primary always present");
        }

        // primary == v6; bak.1 == v5 (NEWEST backup) ... bak.5 == v1 (oldest).
        assert_eq!(fs::read(&vp).unwrap(), versions[5], "primary is newest (v6)");
        assert_eq!(fs::read(format!("{}.bak.1", vp)).unwrap(), versions[4], "bak.1 is newest backup (v5)");
        assert_eq!(fs::read(format!("{}.bak.2", vp)).unwrap(), versions[3]);
        assert_eq!(fs::read(format!("{}.bak.3", vp)).unwrap(), versions[2]);
        assert_eq!(fs::read(format!("{}.bak.4", vp)).unwrap(), versions[1]);
        assert_eq!(fs::read(format!("{}.bak.5", vp)).unwrap(), versions[0], "bak.5 is oldest (v1)");
        assert!(!PathBuf::from(format!("{}.bak.6", vp)).exists(), "capped at 5 slots");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_max_backups_zero_is_dedup_no_op() {
        // P3-11: when the content hash is unchanged the adapter passes maxBackups=0,
        // which must update the primary but create NO new backup slot.
        let dir = fresh_dir("dedup");
        let vp = vault_in(&dir);

        vault_write_atomic(vp.clone(), vec![1u8; 4], 5).expect("seed (no prior primary => no backup)");
        vault_write_atomic(vp.clone(), vec![2u8; 4], 5).expect("second write => bak.1");
        let bak1_before = fs::read(format!("{}.bak.1", vp)).expect("bak.1 exists after 2nd write");

        vault_write_atomic(vp.clone(), vec![3u8; 4], 0).expect("dedup write");

        assert_eq!(fs::read(&vp).unwrap(), vec![3u8; 4], "primary updated");
        assert_eq!(fs::read(format!("{}.bak.1", vp)).unwrap(), bak1_before, "bak.1 untouched by dedup write");
        assert!(!PathBuf::from(format!("{}.bak.2", vp)).exists(), "dedup write created no new slot");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_named_writes_inside_vault_dir_without_rotation() {
        // P3-13 pre-migration backup path.
        let dir = fresh_dir("write_named");
        let vp = vault_in(&dir);
        vault_write_atomic(vp.clone(), vec![9u8; 4], 0).expect("seed primary");

        let backup = dir.join("pre-v2-backup.cryptiq").to_str().unwrap().to_string();
        let bytes = vec![7u8; 16];
        vault_write_named(vp.clone(), backup.clone(), bytes.clone()).expect("named write");

        assert_eq!(fs::read(&backup).unwrap(), bytes, "named backup has exact bytes");
        assert!(!PathBuf::from(format!("{}.tmp", backup)).exists(), "no .tmp left behind");
        assert!(!PathBuf::from(format!("{}.bak.1", backup)).exists(), "named write does not rotate");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_named_rejects_target_outside_vault_dir() {
        // WR-04 / T-03-16 path-confinement hardening: a target outside the vault
        // directory must be rejected and NOTHING written — even though the target
        // file does not yet exist (the case the old constructed-path check missed).
        let dir = fresh_dir("write_named_confine");
        let vp = vault_in(&dir);
        vault_write_atomic(vp.clone(), vec![9u8; 4], 0).expect("seed primary");

        let outside = std::env::temp_dir().join("cryptiq_uat_outside");
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&outside).expect("create outside dir");
        let evil = outside.join("evil.cryptiq").to_str().unwrap().to_string();

        let res = vault_write_named(vp.clone(), evil.clone(), vec![1u8; 4]);
        assert!(res.is_err(), "target outside the vault dir must be rejected");
        assert!(!PathBuf::from(&evil).exists(), "nothing written outside confinement");
        assert!(
            !PathBuf::from(format!("{}.tmp", evil)).exists(),
            "no .tmp written outside confinement either"
        );

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
    }

    // --- UAT Test 3: advisory-lock multi-process decisions ------------------

    #[test]
    fn lock_acquire_takes_over_fresh_live_same_host_lock() {
        // P3-09, REVISED by Phase-4 UAT T5: same machine, fresh timestamp, even our own
        // live PID => TAKE OVER, not block. The single-instance plugin (decision 13)
        // guarantees at most one live Cryptiq process per host, so a same-host lock can
        // only be self or a dead prior instance — never a live peer. The old "block on
        // fresh same-host" behaviour false-positived on PID reuse after relaunch and
        // wedged unlock with a spurious VAULT_LOCKED. This test now pins the corrected
        // takeover behaviour implemented in vault_lock_acquire (same-host => fall through).
        let dir = fresh_dir("lock_live");
        let vp = vault_in(&dir);
        write_lock(&vp, std::process::id(), &get_hostname(), "2099-01-01T00:00:00Z");

        vault_lock_acquire(vp.clone(), "2099-01-01T00:00:00Z".to_string())
            .expect("fresh same-host lock is taken over (single-instance guarantees no live peer)");
        vault_lock_check(vp.clone()).expect("we own the lock after take-over");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_acquire_takes_over_stale_same_host_lock() {
        // P3-09: same host but >30min old => stale => silent take-over.
        let dir = fresh_dir("lock_stale");
        let vp = vault_in(&dir);
        write_lock(&vp, std::process::id(), &get_hostname(), "2000-01-01T00:00:00Z");

        vault_lock_acquire(vp.clone(), "2099-01-01T00:00:00Z".to_string())
            .expect("stale same-host lock is taken over");
        vault_lock_check(vp.clone()).expect("we own the lock after take-over");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_acquire_warns_cross_host_fresh_but_still_writes_our_lock() {
        // P3-10: different hostname, fresh => warn, but our lock IS written and owned.
        let dir = fresh_dir("lock_xhost");
        let vp = vault_in(&dir);
        write_lock(&vp, 4242, "some-other-machine-xyz", "2099-01-01T00:00:00Z");

        let err = vault_lock_acquire(vp.clone(), "2099-01-01T00:00:00Z".to_string())
            .expect_err("cross-host fresh returns a warn signal");
        assert!(err.starts_with("VAULT_LOCK_WARN:"), "got: {}", err);
        vault_lock_check(vp.clone()).expect("our lock was written despite the warn");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_check_and_release_lifecycle() {
        let dir = fresh_dir("lock_lifecycle");
        let vp = vault_in(&dir);

        vault_lock_acquire(vp.clone(), "2099-01-01T00:00:00Z".to_string()).expect("acquire");
        vault_lock_check(vp.clone()).expect("owned right after acquire");

        // Another process steals the lock (different PID, same host).
        write_lock(&vp, std::process::id().wrapping_add(1), &get_hostname(), "2099-01-01T00:00:00Z");
        let stolen = vault_lock_check(vp.clone()).expect_err("different pid => stolen");
        assert!(stolen.starts_with("VAULT_LOCK_STOLEN:"), "got: {}", stolen);

        // Release removes the lock; a follow-up check reports it lost; release is idempotent.
        vault_lock_release(vp.clone()).expect("release");
        assert_eq!(
            vault_lock_check(vp.clone()).expect_err("missing lock => lost"),
            "VAULT_LOCK_LOST"
        );
        vault_lock_release(vp.clone()).expect("release is idempotent");

        let _ = fs::remove_dir_all(&dir);
    }

    // ---------------------------------------------------------------------------
    // test_vault_sweep_tmp — D-09 / T-11-12 / T-11-13 / SC-1
    //
    // 1. Create a real vault dir with a `vault.cryptiq` primary + a stale `vault.cryptiq.tmp`.
    // 2. Call vault_sweep_tmp — assert the .tmp is gone and the primary is intact.
    // 3. Call vault_sweep_tmp again — assert it is idempotent (Ok when no .tmp).
    // 4. Confinement test: build a .tmp path whose parent escapes the vault dir and assert
    //    assert_confined returns an error (path confinement violation — T-11-12).
    // ---------------------------------------------------------------------------

    #[test]
    fn test_vault_sweep_tmp() {
        let dir = fresh_dir("sweep_tmp");
        let vault_path_buf = dir.join("vault.cryptiq");
        let tmp_path_buf = dir.join("vault.cryptiq.tmp");
        let vault_path_str = vault_path_buf.to_str().unwrap().to_string();

        // Write primary vault file (simulated — just some bytes).
        {
            let mut f = File::create(&vault_path_buf).expect("create primary vault");
            f.write_all(b"fake-vault-bytes").expect("write primary");
        }

        // Write stale .tmp file (simulated crash residue).
        {
            let mut f = File::create(&tmp_path_buf).expect("create stale .tmp");
            f.write_all(b"stale-tmp-bytes").expect("write stale tmp");
        }

        assert!(tmp_path_buf.exists(), "stale .tmp must exist before sweep");
        assert!(vault_path_buf.exists(), "primary must exist before sweep");

        // Call vault_sweep_tmp — should delete the .tmp.
        let result = vault_sweep_tmp(vault_path_str.clone());
        assert!(result.is_ok(), "vault_sweep_tmp should return Ok: {:?}", result);

        assert!(!tmp_path_buf.exists(), "stale .tmp must be gone after sweep");
        assert!(vault_path_buf.exists(), "primary must survive the sweep — SC-1");

        // Idempotent: calling again with no .tmp must still return Ok.
        let result2 = vault_sweep_tmp(vault_path_str.clone());
        assert!(
            result2.is_ok(),
            "vault_sweep_tmp must be idempotent (Ok when no .tmp): {:?}",
            result2
        );

        // Confinement test: create a sibling dir and verify assert_confined rejects
        // a .tmp in sibling_dir when the parent is the vault dir (T-11-12).
        let sibling_dir = fresh_dir("sweep_tmp_sibling");
        let real_parent = dir.clone();
        let out_of_parent_tmp = sibling_dir.join("vault.cryptiq.tmp");
        // Create the out-of-parent tmp so assert_confined can canonicalize its parent.
        {
            let mut f = File::create(&out_of_parent_tmp).expect("create out-of-parent tmp");
            f.write_all(b"evil-tmp").expect("write evil tmp");
        }
        // assert_confined must reject a tmp in sibling_dir when parent is the vault dir.
        let confine_result = assert_confined(&out_of_parent_tmp, &real_parent);
        assert!(
            confine_result.is_err(),
            "assert_confined must reject a .tmp outside the vault parent dir (T-11-12)"
        );
        let confine_err = confine_result.unwrap_err();
        assert!(
            confine_err.contains("confinement") || confine_err.contains("not inside"),
            "confinement error message should mention 'confinement' or 'not inside', got: {}",
            confine_err
        );

        // Cleanup.
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&sibling_dir);
    }
}

// ---------------------------------------------------------------------------
// Path confinement helpers
// ---------------------------------------------------------------------------

/// Verify that `target` resolves to a path inside `expected_parent` after
/// canonicalization. Returns `Err` with an explanatory message if the check
/// fails, if a directory cannot be canonicalized, or if `target` has no parent.
///
/// For writes the target file itself may not yet exist, so we resolve the
/// target's *own* parent directory (which must exist for any write) and append
/// the filename. We must NOT construct the candidate path from `expected_parent`
/// — doing so would discard the target's real location and let an out-of-tree
/// absolute path (e.g. `C:\elsewhere\evil.cryptiq`) pass the check while the
/// subsequent write still lands outside the vault directory (WR-04 / T-03-16).
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
        // Existing file: canonicalize directly (resolves symlinks and `..`).
        target
            .canonicalize()
            .map_err(|e| format!("Path confinement: could not canonicalize '{}': {}", target.display(), e))?
    } else {
        // Non-existent file: canonicalize the target's OWN parent dir (which must
        // exist for a write) and append the filename. Never trust a path rooted at
        // `expected_parent` here.
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

/// Extract and canonicalize the parent directory from a vault path string.
/// Returns `(parent_dir, vault_path_buf)` or an error string.
fn resolve_vault_parent(vault_path_str: &str) -> Result<(PathBuf, PathBuf), String> {
    let vault_path = PathBuf::from(vault_path_str);
    let parent = vault_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| format!("Invalid vault path '{}': no parent directory", vault_path_str))?;

    // Require the parent directory to exist.
    if !parent.exists() {
        return Err(format!(
            "Vault directory does not exist: '{}'",
            parent.display()
        ));
    }

    Ok((parent.to_path_buf(), vault_path))
}

// ---------------------------------------------------------------------------
// vault_write_atomic  (VAULT-05 / VAULT-06)
// ---------------------------------------------------------------------------

/// Atomically write `bytes` to `path`:
///
/// 1. Write to `<path>.tmp` in the SAME directory.
/// 2. `File::sync_all()` on the tmp file (FlushFileBuffers on Windows).
/// 3. Rotate backup slots without ever removing the primary (crash-safe ordering):
///    shift `bak.(n-1)` → `bak.n` … `bak.1` → `bak.2`, then COPY (not rename/move)
///    the current primary `vault.cryptiq` → `bak.1`. Copying leaves the primary intact,
///    so on a crash the primary is always present on disk (either the old or new file).
///    Skipped entirely when `max_backups == 0` (content-hash dedup path, no rotation).
/// 4. `std::fs::rename(tmp → live)` — this is the single atomic swap. On crash, either
///    the old primary or the new primary is present; both are valid encrypted vaults.
/// 5. Best-effort dir-fsync (`File::open(parent).and_then(sync_all)` — no-op on Windows).
///
/// Backup paths are built by appending `.bak.N` to the FULL `path` string (Pitfall 2 defense
/// — avoids `with_extension` which strips the last extension segment and can clobber `.cryptiq`).
///
/// The `bytes` parameter arrives as a plain JS number array (`Array.from(uint8array)`) that
/// serde_json deserializes correctly as `Vec<u8>` (Tauri v2 IPC — Pitfall 1 in RESEARCH.md).
///
/// The JS invoke call is:
///   `invoke('vault_write_atomic', { path, bytes: Array.from(bytes), maxBackups })`
/// Tauri v2 maps camelCase JS key `maxBackups` → snake_case Rust param `max_backups`.
#[tauri::command]
pub fn vault_write_atomic(path: String, bytes: Vec<u8>, max_backups: u8) -> Result<(), String> {
    let (parent, vault_path) = resolve_vault_parent(&path)?;
    assert_confined(&vault_path, &parent)?;

    // Step 1: write to .tmp in the SAME directory.
    let tmp_path = PathBuf::from(format!("{}.tmp", path));
    assert_confined(&tmp_path, &parent)?;

    {
        let mut f = File::create(&tmp_path).map_err(|e| {
            format!("vault_write_atomic: failed to create tmp file '{}': {}", tmp_path.display(), e)
        })?;
        f.write_all(&bytes).map_err(|e| {
            format!("vault_write_atomic: failed to write tmp file '{}': {}", tmp_path.display(), e)
        })?;
        // Step 2: fsync the tmp file (FlushFileBuffers on Windows).
        f.sync_all().map_err(|e| {
            format!("vault_write_atomic: sync_all on tmp file '{}' failed: {}", tmp_path.display(), e)
        })?;
    }

    // Step 3 (CR-01 crash-safe rotation): rotate backups WITHOUT removing the primary.
    //
    // Crash-safety invariant: the primary vault file must NEVER be absent on disk.
    // The old code used rename(primary → bak.1) BEFORE the tmp rename, leaving a window
    // where a crash would destroy the only good copy. The fix: COPY primary → bak.1 so
    // the primary stays intact until the atomic step-4 rename replaces it. On any crash
    // between step 3 and step 4, the original primary is still present and valid.
    //
    // max_backups == 0 means "no rotation" (used by the content-hash dedup path) — skip
    // step 3 entirely in that case.
    if max_backups > 0 && vault_path.exists() {
        // Shift bak.{n-1} → bak.{n} from the oldest slot downward.
        // E.g. max_backups=5: shift bak.4→bak.5, bak.3→bak.4, ..., bak.1→bak.2.
        for slot in (1..max_backups).rev() {
            let from = PathBuf::from(format!("{}.bak.{}", path, slot));
            let to = PathBuf::from(format!("{}.bak.{}", path, slot + 1));
            if from.exists() {
                // Best-effort — if the rename fails (e.g. permissions), continue.
                let _ = fs::rename(&from, &to);
            }
        }
        // COPY (not rename) live → bak.1: primary stays on disk through the atomic rename.
        let bak1 = PathBuf::from(format!("{}.bak.1", path));
        fs::copy(&vault_path, &bak1).map_err(|e| {
            format!(
                "vault_write_atomic: failed to copy live→bak.1 ('{}' → '{}'): {}",
                vault_path.display(),
                bak1.display(),
                e
            )
        })?;
    }

    // Step 4: atomic rename tmp → live (MoveFileExW REPLACE_EXISTING on Windows).
    // Primary is ALWAYS present before and after this rename (crash-safety: old or new, both valid).
    fs::rename(&tmp_path, &vault_path).map_err(|e| {
        format!(
            "vault_write_atomic: atomic rename failed ('{}' → '{}'): {}",
            tmp_path.display(),
            vault_path.display(),
            e
        )
    })?;

    // Step 5: best-effort dir-fsync (no-op on Windows; durability on Linux/macOS).
    let _ = File::open(&parent).and_then(|f| f.sync_all());

    Ok(())
}

// ---------------------------------------------------------------------------
// vault_write_named  (P3-13 pre-migration backup)
// ---------------------------------------------------------------------------

/// Write `bytes` atomically to the explicitly-named `path` (no backup rotation).
///
/// Used by `TauriVaultStorageAdapter.savePreMigrationBackup()` to write a
/// never-rotated named backup alongside the vault directory. Uses the same
/// tmp → fsync → rename semantics as `vault_write_atomic` for durability.
///
/// Path confinement (WR-04): both `path` and its `.tmp` sibling are verified to reside
/// inside the vault directory (the same `assert_confined` guard used by `vault_write_atomic`).
/// This prevents a crafted `path` argument from writing outside the intended directory.
/// `vault_path` is the canonical vault file path; its parent is used as the confinement root.
///
/// The JS invoke call is:
///   `invoke('vault_write_named', { vaultPath, path, bytes: Array.from(bytes) })`
/// Tauri v2 maps camelCase `vaultPath` → `vault_path`.
#[tauri::command]
pub fn vault_write_named(vault_path: String, path: String, bytes: Vec<u8>) -> Result<(), String> {
    // Resolve and canonicalize the vault directory — this is the confinement root.
    let (vault_parent, _) = resolve_vault_parent(&vault_path)?;

    let (parent, target_path) = resolve_vault_parent(&path)?;

    // WR-04: verify the target is inside the vault directory, not just its own parent.
    assert_confined(&target_path, &vault_parent)?;
    // Also verify the target's own declared parent matches (defense-in-depth).
    assert_confined(&target_path, &parent)?;

    // Write to .tmp sibling, then rename.
    let tmp_path = PathBuf::from(format!("{}.tmp", path));
    assert_confined(&tmp_path, &vault_parent)?;
    assert_confined(&tmp_path, &parent)?;

    {
        let mut f = File::create(&tmp_path).map_err(|e| {
            format!("vault_write_named: failed to create tmp '{}': {}", tmp_path.display(), e)
        })?;
        f.write_all(&bytes).map_err(|e| {
            format!("vault_write_named: write to tmp '{}' failed: {}", tmp_path.display(), e)
        })?;
        f.sync_all().map_err(|e| {
            format!("vault_write_named: sync_all on tmp '{}' failed: {}", tmp_path.display(), e)
        })?;
    }

    fs::rename(&tmp_path, &target_path).map_err(|e| {
        format!(
            "vault_write_named: rename '{}' → '{}' failed: {}",
            tmp_path.display(),
            target_path.display(),
            e
        )
    })?;

    let _ = File::open(&parent).and_then(|f| f.sync_all());
    Ok(())
}

// ---------------------------------------------------------------------------
// vault_lock_acquire  (VAULT-09, P3-08/09/10)
// ---------------------------------------------------------------------------

/// Acquire the advisory lockfile for the vault at `vault_path`.
///
/// Decision logic (mirrors `lockLogic.ts` pure seam for consistency):
///
/// - No existing lock → write our lock, return `Ok(())`.
/// - Existing lock, same host, fresh + live PID → `Err("VAULT_LOCKED:<pid>:<host>")`.
/// - Existing lock, same host, stale (dead PID OR >30min) → take over, return `Ok(())`.
/// - Existing lock, cross-host, fresh → write our lock, return `Err("VAULT_LOCK_WARN:<pid>:<host>")`.
///   The caller surfaces a warning but proceeds.
/// - Existing lock, cross-host, stale (>30min) → take over, return `Ok(())`.
///
/// The JS invoke call is:
///   `invoke('vault_lock_acquire', { vaultPath, startedAt })`
/// Tauri v2 maps camelCase `vaultPath` → `vault_path`, `startedAt` → `started_at`.
#[tauri::command]
pub fn vault_lock_acquire(vault_path: String, started_at: String) -> Result<(), String> {
    let lock = lock_path(&vault_path);
    let my_pid = std::process::id();
    let my_host = get_hostname();

    if lock.exists() {
        let content = fs::read_to_string(&lock).map_err(|e| e.to_string())?;
        // If the lock file is malformed/unparseable, treat as absent (take over).
        if let Ok(existing) = serde_json::from_str::<LockFile>(&content) {
            let stale = is_older_than_30_min(&existing.started_at);

            if existing.hostname == my_host {
                // P3-09: Same machine. The single-instance plugin (decision 13) guarantees at
                // most ONE live Cryptiq process per host, so a same-host lock can only be our own
                // (self) or a DEAD prior instance — never a live peer. Always take over (fall
                // through to overwrite). This is the robust fix for the intermittent-unlock bug
                // (UAT T5): the old PID-liveness gate false-positived on PID reuse after relaunch
                // and didn't recognise our own PID, wedging unlock with a spurious VAULT_LOCKED.
            } else {
                // P3-10: Different hostname.
                if !stale {
                    // Fresh cross-host lock → warn, but write our lock and allow.
                    // The Err return causes TauriVaultStorageAdapter to surface a UI warning;
                    // the caller still proceeds (the lock IS written below before returning).
                    let warn_pid = existing.pid;
                    let warn_host = existing.hostname.clone();
                    let lock_data = LockFile {
                        pid: my_pid,
                        hostname: my_host,
                        started_at,
                    };
                    let json = serde_json::to_string(&lock_data).map_err(|e| e.to_string())?;
                    fs::write(&lock, json).map_err(|e| e.to_string())?;
                    return Err(format!("VAULT_LOCK_WARN:{}:{}", warn_pid, warn_host));
                }
                // Cross-host stale → take over (fall through).
            }
        }
        // Unparseable or stale → fall through and overwrite.
    }

    // Write our lock.
    let lock_data = LockFile {
        pid: my_pid,
        hostname: my_host,
        started_at,
    };
    let json = serde_json::to_string(&lock_data).map_err(|e| e.to_string())?;
    fs::write(&lock, json).map_err(|e| e.to_string())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// vault_lock_check  (P3-08 re-verify before each write)
// ---------------------------------------------------------------------------

/// Re-verify that the current process still holds the advisory lock before a write.
///
/// Returns:
///   `Ok(())`                              — lock is valid and owned by us.
///   `Err("VAULT_LOCK_LOST")`             — lock file is gone.
///   `Err("VAULT_LOCK_STOLEN:<pid>:<host>")` — another process took the lock.
///
/// The JS invoke call is:
///   `invoke('vault_lock_check', { vaultPath })`
/// Tauri v2 maps camelCase `vaultPath` → `vault_path`.
#[tauri::command]
pub fn vault_lock_check(vault_path: String) -> Result<(), String> {
    let lock = lock_path(&vault_path);
    let my_pid = std::process::id();
    let my_host = get_hostname();

    if !lock.exists() {
        return Err("VAULT_LOCK_LOST".to_string());
    }

    let content = fs::read_to_string(&lock).map_err(|e| {
        format!("vault_lock_check: failed to read lock file: {}", e)
    })?;

    let existing: LockFile = serde_json::from_str(&content).map_err(|_| {
        // Malformed lock file — treat as lost.
        "VAULT_LOCK_LOST".to_string()
    })?;

    if existing.pid != my_pid || existing.hostname != my_host {
        return Err(format!(
            "VAULT_LOCK_STOLEN:{}:{}",
            existing.pid, existing.hostname
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// vault_lock_release  (P3-08 session end)
// ---------------------------------------------------------------------------

/// Remove the advisory lockfile if it exists.
///
/// Best-effort: a missing lockfile is not an error (lock may have already been
/// released or taken over by a stale-detection path).
///
/// The JS invoke call is:
///   `invoke('vault_lock_release', { vaultPath })`
/// Tauri v2 maps camelCase `vaultPath` → `vault_path`.
#[tauri::command]
pub fn vault_lock_release(vault_path: String) -> Result<(), String> {
    let lock = lock_path(&vault_path);
    if lock.exists() {
        fs::remove_file(&lock).map_err(|e| {
            format!("vault_lock_release: failed to remove lock file '{}': {}", lock.display(), e)
        })?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// vault_export_copy  (EXPORT-01, Phase 6 / P6-10)
// ---------------------------------------------------------------------------

/// Copy the canonical vault file to a user-chosen destination path.
///
/// Called after:
///   1. The user re-authenticated via the ConfirmMasterPassword gate (P6-09 / AUTH-11).
///   2. Any in-flight save has completed (save-mutex flushed in JS — P6-10).
///   3. The native save dialog returned a destination path.
///
/// Uses `std::fs::copy` — a simple byte copy; no new crypto, no temp file.
/// The exported bytes are identical to the already-encrypted `.cryptiq` on disk
/// (EXPORT-01: "just a file copy, no new crypto").
///
/// Security notes:
///   - Source is the canonical `.cryptiq` file (always-encrypted bytes — T-06-17).
///   - Destination is OUTSIDE the literal vault scopes by design (the user chose it
///     via the OS save dialog). `assert_confined` is deliberately NOT applied to the
///     destination (T-06-18 analysis: write is performed by this Rust command, not by
///     JS plugin-fs; dialog:allow-save already scopes the write; no single-`*` glob added).
///   - Error strings contain only paths, never secrets (T-06-19).
///
/// The JS invoke call is:
///   `invoke('vault_export_copy', { sourcePath, destinationPath })`
/// Tauri v2 maps camelCase keys → snake_case Rust params.
#[tauri::command]
pub fn vault_export_copy(source_path: String, destination_path: String) -> Result<(), String> {
    let src = std::path::PathBuf::from(&source_path);
    let dst = std::path::PathBuf::from(&destination_path);

    if !src.exists() {
        return Err(format!(
            "vault_export_copy: source '{}' does not exist",
            src.display()
        ));
    }

    std::fs::copy(&src, &dst).map_err(|e| {
        format!(
            "vault_export_copy: copy '{}' → '{}' failed: {}",
            src.display(),
            dst.display(),
            e
        )
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// vault_sweep_tmp  (D-09 stale-.tmp sweep — SC-1 crash residue cleanup)
// ---------------------------------------------------------------------------

/// Delete a stale `<vault_path>.tmp` if one exists in the same directory.
///
/// Called by JS on vault unlock to sweep any orphaned `.tmp` from a prior crash
/// (D-09 / SC-1). An orphaned `.tmp` means the atomic rename never completed, so
/// the primary vault file is intact; the `.tmp` is safe residue to delete.
///
/// **Idempotent:** returns `Ok(())` even if no `.tmp` file is found.
///
/// **Path confinement (T-11-12):** `assert_confined` is called on the `.tmp` path BEFORE
/// any `remove_file` — a crafted `vault_path` that resolves to a `.tmp` outside the
/// vault directory is rejected with no delete attempted.
///
/// Non-async: mirroring `vault_write_atomic` (`pub fn`, not `pub async fn`).
///
/// The JS invoke call is:
///   `invoke('vault_sweep_tmp', { vaultPath })`
/// Tauri v2 maps camelCase `vaultPath` → snake_case `vault_path`.
#[tauri::command]
pub fn vault_sweep_tmp(vault_path: String) -> Result<(), String> {
    let (parent, _vault_pb) = resolve_vault_parent(&vault_path)?;

    let tmp_path = PathBuf::from(format!("{}.tmp", vault_path));

    // T-11-12: confine the tmp path before any delete.
    assert_confined(&tmp_path, &parent)?;

    if tmp_path.exists() {
        // Best-effort delete: ignore the error (idempotent — the primary is always intact).
        let _ = fs::remove_file(&tmp_path);
    }

    Ok(())
}

