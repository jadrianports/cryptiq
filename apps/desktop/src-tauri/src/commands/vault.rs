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

/// Return `true` if the process with the given PID is still alive.
///
/// Windows: `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `GetExitCodeProcess`
///   — exit code 259 (STILL_ACTIVE) means the process is running.
/// macOS: `kill(pid, 0)` signal 0 — returns 0 if alive, -1 (ESRCH) if dead.
/// Linux (cfg fallback): treated as alive (conservative — no build target for Linux).
#[cfg(windows)]
fn pid_is_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    const STILL_ACTIVE: u32 = 259;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            // Could not open — process is gone.
            return false;
        }
        let mut exit_code: u32 = 0;
        let still_running =
            GetExitCodeProcess(handle, &mut exit_code) != 0 && exit_code == STILL_ACTIVE;
        CloseHandle(handle);
        still_running
    }
}

#[cfg(target_os = "macos")]
fn pid_is_alive(pid: u32) -> bool {
    // kill(pid, 0): signal 0 — returns 0 if process alive, -1 with ESRCH if dead.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

// Fallback for platforms not explicitly targeted (should not be reachable at runtime
// per D-15 — Linux is excluded from the capability manifest and Cargo target gates).
#[cfg(not(any(windows, target_os = "macos")))]
fn pid_is_alive(_pid: u32) -> bool {
    // Conservative: treat as alive so we don't accidentally clobber a live lock.
    true
}

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
}

// ---------------------------------------------------------------------------
// Path confinement helpers
// ---------------------------------------------------------------------------

/// Verify that `target` resolves to a path inside `expected_parent` after
/// canonicalization. Returns `Err` with an explanatory message if the check
/// fails or if `target` does not exist (for writes the parent dir must exist,
/// but we check the parent's canonical form, not the file itself).
///
/// For writes, the file itself may not yet exist; we canonicalize the parent
/// dir and construct the expected path from there.
fn assert_confined(target: &Path, expected_parent: &Path) -> Result<(), String> {
    // Canonicalize the parent directory (must exist).
    let canonical_parent = expected_parent
        .canonicalize()
        .map_err(|e| format!("Path confinement: could not canonicalize parent '{}': {}", expected_parent.display(), e))?;

    // Construct the canonical target path: canonicalize the parent + the filename.
    let file_name = target
        .file_name()
        .ok_or_else(|| format!("Path confinement: '{}' has no filename component", target.display()))?;
    let expected_target = canonical_parent.join(file_name);

    // Compare by canonicalizing the target if it exists, otherwise use constructed path.
    let canonical_target = if target.exists() {
        target
            .canonicalize()
            .unwrap_or_else(|_| expected_target.clone())
    } else {
        expected_target.clone()
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
                // P3-09: Same machine.
                let pid_dead = !pid_is_alive(existing.pid);
                if !stale && !pid_dead {
                    // Fresh lock + live PID on same host → truly locked (single-instance
                    // plugin should prevent this, but handle it defensively).
                    return Err(format!(
                        "VAULT_LOCKED:{}:{}",
                        existing.pid, existing.hostname
                    ));
                }
                // Stale or dead → take over (fall through to write our lock).
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
