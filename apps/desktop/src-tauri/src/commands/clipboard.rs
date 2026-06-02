// apps/desktop/src-tauri/src/commands/clipboard.rs
//
// Custom Tauri commands for the sensitive-copy clipboard path (LOCK-02 / LOCK-06).
//
// Responsibilities:
//   clipboard_write_sensitive — write the value to the OS clipboard and set the platform
//                               transient/sensitive markers, then stash a HASH of the value
//                               (P5-09 — never the plaintext). On Windows the text AND the three
//                               exclusion-format markers are written in ONE owned clipboard
//                               transaction (the markers require clipboard ownership via
//                               EmptyClipboard — see write_windows_sensitive). On macOS arboard
//                               writes the text and we add the concealed + transient pasteboard
//                               types on top via addTypes:owner:.
//   clipboard_clear_if_ours   — re-read the current clipboard, re-hash it, and clear ONLY if the
//                               re-hash equals the stashed hash (the value is "still ours"); the
//                               stash is wiped to None regardless (timer fired / lock / done).
//
// Security (P5-09 — LOCKED, and the non-negotiable invariants for this module):
//   - The stash holds ONLY a `copied_hash: u64` (std DefaultHasher / SipHash). It NEVER holds the
//     plaintext value. There is deliberately no plaintext-value field on the stash struct — no
//     plaintext secret is retained in Rust memory across the 25s clipboard window.
//   - The plaintext `value` is dropped at the end of `clipboard_write_sensitive` (it is hashed,
//     then goes out of scope — it is never moved into the stash).
//   - No secret/plaintext ever appears in any `format!` / `println!` / `eprintln!` / log / error
//     string. Error strings carry only the originating API's error, never the clipboard contents.
//   - The webview is permanently denied `clipboard-manager:allow-read-text`; the still-ours read
//     + compare lives here in Rust, and the value never crosses back to JS (both commands return
//     `Result<(), String>` with no payload).
//
// Hashing choice (CLAUDE.md "deps pinned and minimized" → PREFER zero new dependency):
//   std::collections::hash_map::DefaultHasher (SipHash) — sufficient for the non-adversarial
//   "is the clipboard still ours?" liveness check (the threat model excludes a local attacker
//   crafting a SipHash collision in the 25s window) and adds NO Cargo dependency.
//
// Platform-marker dependency path (A3, resolved in Task 1):
//   arboard 3.6.1 pulls objc2 0.6.4 / objc2-app-kit 0.3.2 transitively. The plan's drafted
//   `objc2-app-kit = "0.2"` (Approach B) is a duplicate-major conflict against that 0.6.4 stack,
//   so per the documented contingency we use the raw libc / Objective-C FFI fallback
//   (RESEARCH §macOS Approach A) — no new macOS Cargo dep, no version negotiation.
//
// NOTE (verification reality): this is a Windows-first dev machine. `cargo build`/`clippy` on
// Windows compile ONLY the `#[cfg(windows)]` paths. The `#[cfg(target_os = "macos")]` marker code
// below is written under its cfg guard and is compiled ONLY by macOS CI — it is unverified on
// this Windows machine.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;

use arboard::Clipboard;
use tauri::State;

// ---------------------------------------------------------------------------
// In-memory stash — a HASH only (P5-09). NEVER add a plaintext-value field here.
// ---------------------------------------------------------------------------

/// The only thing Cryptiq retains about a copied secret: a hash of its bytes.
///
/// Per the LOCKED P5-09 decision this holds a `copied_hash: u64`, NOT the plaintext.
/// There is intentionally no plaintext-value field — the plaintext is dropped immediately
/// after `clipboard_write_sensitive` hashes it.
pub struct ClipboardState {
    /// SipHash (std `DefaultHasher`) of the most-recently copied secret. Never logged,
    /// never serialized, never sent to the webview.
    pub copied_hash: u64,
}

/// Tauri-managed state holding the at-most-one current stash.
pub type ClipboardStore = Mutex<Option<ClipboardState>>;

// ---------------------------------------------------------------------------
// Pure helpers (factored so write + clear hash and compare identically)
// ---------------------------------------------------------------------------

/// Hash a clipboard value's bytes with the std `DefaultHasher` (SipHash) → `u64`.
///
/// The write path and the clear path BOTH call this so the comparison is apples-to-apples.
/// The input is never logged; only the resulting `u64` is retained.
fn hash_value(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.as_bytes().hash(&mut hasher);
    hasher.finish()
}

/// The pure still-ours decision: given an optional stashed hash and the re-hashed current
/// clipboard contents, should we clear?
///
/// - `None` stash → `false` (nothing was ours; never clear).
/// - `Some(h)` and `h == current_hash` → `true` (still ours; clear).
/// - `Some(h)` and `h != current_hash` → `false` (user copied something else; no-op).
///
/// Factored out so it can be unit-tested without a Tauri runtime or a real OS clipboard.
fn should_clear(stashed: Option<u64>, current_hash: u64) -> bool {
    matches!(stashed, Some(h) if h == current_hash)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Write `value` to the OS clipboard, set the platform transient/sensitive markers, and stash
/// a HASH of the value for the later still-ours clear (P5-09 / LOCK-02 / LOCK-06).
///
/// Returns `Ok(())` with no payload — the secret never crosses back to the webview.
///
/// The JS invoke call is: `invoke('clipboard_write_sensitive', { value })`.
#[tauri::command]
pub fn clipboard_write_sensitive(value: String, state: State<ClipboardStore>) -> Result<(), String> {
    // 1. Write the text AND set the platform sensitive/transient markers.
    //
    //    Windows (BUG-3 fix): the text write and the three LOCK-06 exclusion markers MUST happen
    //    in ONE owned clipboard transaction. `SetClipboardData` only succeeds for the task that
    //    OWNS the clipboard, and ownership is granted ONLY by `EmptyClipboard`. arboard's
    //    `set_text` runs its own open→EmptyClipboard→SetClipboardData→close cycle and leaves
    //    arboard's hidden window as the owner — so a SECOND transaction that skips EmptyClipboard
    //    (to avoid wiping the text) is NOT the owner and every exclusion-marker SetClipboardData
    //    silently fails. We therefore do the whole sensitive write ourselves on Windows (do NOT
    //    use arboard for this path) so the markers actually apply.
    #[cfg(windows)]
    write_windows_sensitive(&value)?;

    //    macOS: arboard writes the text in its own transaction, then we add the concealed +
    //    transient pasteboard types on top via `addTypes:owner:` (best-effort markers).
    #[cfg(target_os = "macos")]
    {
        let mut cb = Clipboard::new().map_err(|e| format!("clipboard init failed: {e}"))?;
        cb.set_text(&value)
            .map_err(|e| format!("clipboard write failed: {e}"))?;
        set_macos_clipboard_markers();
    }

    //    Any other platform (none ship in v1 — Linux is structurally excluded): fall back to a
    //    plain arboard text write so the still-ours machinery still has a value to compare.
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let mut cb = Clipboard::new().map_err(|e| format!("clipboard init failed: {e}"))?;
        cb.set_text(&value)
            .map_err(|e| format!("clipboard write failed: {e}"))?;
    }

    // 2. Stash ONLY the hash (P5-09). `value` is hashed here and then dropped at end of scope —
    //    it is never moved into the stash, so no plaintext is retained in Rust memory.
    let h = hash_value(&value);
    let mut guard = state
        .lock()
        .map_err(|_| "clipboard state lock poisoned".to_string())?;
    *guard = Some(ClipboardState { copied_hash: h });
    Ok(())
    // `value` (the plaintext secret) is dropped here.
}

/// Clear the OS clipboard ONLY if its current contents still hash-match what Cryptiq stashed
/// (LOCK-02). If the user copied something else in the meantime, this is a no-op so their later
/// copy is never wiped. The stash is wiped to `None` regardless (the timer/lock fired — done).
///
/// The JS invoke call is: `invoke('clipboard_clear_if_ours')` (no args).
#[tauri::command]
pub fn clipboard_clear_if_ours(state: State<ClipboardStore>) -> Result<(), String> {
    // Read the stashed hash (if any), then release the lock before touching the OS clipboard.
    let stashed: Option<u64> = {
        let guard = state
            .lock()
            .map_err(|_| "clipboard state lock poisoned".to_string())?;
        guard.as_ref().map(|s| s.copied_hash)
    };

    // Nothing was ever stashed → nothing to clear.
    if stashed.is_none() {
        return Ok(());
    }

    // Re-read the current clipboard, re-hash it, and decide by HASH.
    let mut cb = Clipboard::new().map_err(|e| format!("clipboard init failed: {e}"))?;
    let current = cb.get_text().unwrap_or_default();
    let current_hash = hash_value(&current);
    // Drop the re-read plaintext as soon as it is hashed (it never leaves this function).
    drop(current);

    if should_clear(stashed, current_hash) {
        cb.clear().map_err(|e| format!("clipboard clear failed: {e}"))?;
    }

    // Wipe the stash regardless — the timer/lock fired, so we are done with this copy.
    let mut guard = state
        .lock()
        .map_err(|_| "clipboard state lock poisoned".to_string())?;
    *guard = None;
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows sensitive write — text + exclusion markers in ONE owned transaction (#[cfg(windows)])
// ---------------------------------------------------------------------------

/// Write `value` to the Windows clipboard AND set the THREE LOCK-06 exclusion-format markers in a
/// SINGLE owned clipboard transaction so Windows Clipboard History (Win+V) and Cloud Clipboard
/// skip the just-written secret (BUG-3 fix).
///
/// Why a single owned transaction (the bug this replaces):
///   `SetClipboardData` only succeeds for the task that OWNS the clipboard, and ownership is
///   granted ONLY by calling `EmptyClipboard` after `OpenClipboard`. An earlier design let
///   arboard write the text in its OWN open/empty/set/close cycle (leaving arboard's hidden window
///   as the owner), then opened a SECOND transaction WITHOUT `EmptyClipboard` to "just add" the
///   marker formats — but without ownership every marker `SetClipboardData` failed silently, so
///   the exclusion markers never applied and secrets could land in Win+V / Cloud Clipboard.
///
/// A subsequent fix put the markers inside this single owned transaction but set them with a NULL
/// handle (`SetClipboardData(fmt_id, NULL)`). That is ALSO wrong: NULL means delayed rendering
/// (the owner promises to serve `WM_RENDERFORMAT` later — which this app never does), and the two
/// value-driven formats get NO serialized DWORD for the OS to read, so history/cloud exclusion
/// still did not take effect. Per Microsoft's Clipboard Formats contract each marker must carry a
/// serialized 4-byte DWORD payload — see step 4.
///
/// Correct flow (per the Win32 clipboard contract):
///   1. `OpenClipboard(NULL)` (3-try / 50ms backoff — another process's watcher can hold it).
///   2. `EmptyClipboard()` — THIS makes us the owner; required for every `SetClipboardData` below.
///   3. Write the text ourselves: UTF-16 + trailing NUL into a `GMEM_MOVEABLE` HGLOBAL, then
///      `SetClipboardData(CF_UNICODETEXT, hglobal)`. Win32 ownership transfer rule: once
///      `SetClipboardData` SUCCEEDS the SYSTEM owns the HGLOBAL — we must NOT `GlobalFree` it. If
///      it FAILS we still own the HGLOBAL and must `GlobalFree` it (and surface an error).
///   4. For EACH of the three exclusion formats allocate its OWN `GMEM_MOVEABLE` HGLOBAL holding a
///      serialized little-endian 4-byte DWORD (`set_clipboard_dword`) and `SetClipboardData(fmt_id,
///      hglobal)`: Exclude…MonitorProcessing = 1 (presence excludes), CanIncludeInClipboardHistory
///      = 0, CanUploadToCloudClipboard = 0. These succeed because we own the clipboard; on success
///      the system owns each handle (no `GlobalFree`), on failure we free our own handle. Marker
///      failure is best-effort (the 25s auto-clear is the hard guarantee); we log a generic
///      warning that NEVER contains `value`.
///   5. `CloseClipboard()`.
///
/// Reference for the three Win10 v1809+ format names: KeePassXC `src/gui/Clipboard.cpp`. The
/// legacy `CLIPBOARD_VIEWER_IGNORE` is NOT honored by Clipboard History — these three are.
///
/// Returns `Err(..)` only if the text itself could not be placed on the clipboard (open/empty/
/// alloc/SetClipboardData(CF_UNICODETEXT) failure). Error strings carry only the API failure,
/// NEVER the clipboard value.
#[cfg(windows)]
fn write_windows_sensitive(value: &str) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{GlobalFree, HANDLE};
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

    // CF_UNICODETEXT (= 13) is the standard UTF-16 text clipboard format. We use the literal value
    // (rather than pulling the whole `Win32_System_Ole` feature for a single stable constant) and
    // cast to the u32 that `SetClipboardData`'s `uformat` parameter expects.
    const CF_UNICODETEXT: u32 = 13;

    // Win10 v1809+ exclusion formats (history + cloud), each paired with the serialized 4-byte
    // DWORD value Microsoft's contract requires for it (the name is a NUL-terminated UTF-16 string):
    //   - ExcludeClipboardContentFromMonitorProcessing: presence excludes — value 1 (matches KeePassXC).
    //   - CanIncludeInClipboardHistory:                 DWORD 0 forbids Win+V clipboard history.
    //   - CanUploadToCloudClipboard:                    DWORD 0 forbids Cloud Clipboard sync.
    const FORMATS: [(&str, u32); 3] = [
        ("ExcludeClipboardContentFromMonitorProcessing\0", 1u32),
        ("CanIncludeInClipboardHistory\0", 0u32),
        ("CanUploadToCloudClipboard\0", 0u32),
    ];

    // Set a single exclusion-marker format to a serialized 4-byte DWORD `value`.
    //
    // Must be called while we already OWN the clipboard (inside the open/EmptyClipboard
    // transaction). Allocates this format's OWN `GMEM_MOVEABLE` HGLOBAL — handles are owned
    // per-format by the system, so we never share one handle across formats. Ownership rule
    // (identical to the CF_UNICODETEXT write): on a SUCCESSFUL `SetClipboardData` the system owns
    // the HGLOBAL (do NOT `GlobalFree`); on FAILURE (GlobalLock or SetClipboardData returns NULL)
    // we still own it and must `GlobalFree` it. Returns `true` only on a real SetClipboardData
    // success — best-effort, so a `false` is counted, never aborts the already-written text.
    //
    // # Safety
    // Caller must own the clipboard (post-EmptyClipboard) and pass a registered `fmt_id`.
    unsafe fn set_clipboard_dword(fmt_id: u32, value: u32) -> bool {
        let hglobal = GlobalAlloc(GMEM_MOVEABLE, std::mem::size_of::<u32>());
        if hglobal.is_null() {
            return false;
        }
        let locked = GlobalLock(hglobal);
        if locked.is_null() {
            // Never handed to the system — we still own it, so free it.
            GlobalFree(hglobal);
            return false;
        }
        // Serialize the DWORD as little-endian (Win32 DWORD wire order).
        std::ptr::copy_nonoverlapping(
            value.to_le_bytes().as_ptr(),
            locked as *mut u8,
            std::mem::size_of::<u32>(),
        );
        GlobalUnlock(hglobal);

        if SetClipboardData(fmt_id, hglobal as HANDLE).is_null() {
            // SetClipboardData failed — ownership did NOT transfer; free our handle.
            GlobalFree(hglobal);
            false
        } else {
            // Success: the system now owns the HGLOBAL — do NOT GlobalFree it.
            true
        }
    }

    // Pre-encode the text as UTF-16 + a trailing NUL terminator (CF_UNICODETEXT contract).
    let mut wide: Vec<u16> = value.encode_utf16().collect();
    wide.push(0);
    let byte_len = wide.len() * std::mem::size_of::<u16>();

    // Open the clipboard, retrying if another process's watcher transiently holds it (Pitfall 2).
    let mut opened = false;
    for attempt in 0..3 {
        if unsafe { OpenClipboard(std::ptr::null_mut()) } != 0 {
            opened = true;
            break;
        }
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    if !opened {
        return Err("clipboard write failed: could not open clipboard after 3 tries".to_string());
    }

    // From here on, CloseClipboard MUST run on every exit path. We funnel all returns through
    // the closing block below by computing a result first.
    let result: Result<(), String> = (|| {
        // EmptyClipboard makes the calling task the OWNER — required for SetClipboardData.
        if unsafe { EmptyClipboard() } == 0 {
            return Err("clipboard write failed: EmptyClipboard returned FALSE".to_string());
        }

        // Allocate a movable global buffer for the UTF-16 text and copy the bytes in.
        let hglobal = unsafe { GlobalAlloc(GMEM_MOVEABLE, byte_len) };
        if hglobal.is_null() {
            return Err("clipboard write failed: GlobalAlloc returned NULL".to_string());
        }
        let locked = unsafe { GlobalLock(hglobal) };
        if locked.is_null() {
            // We still own the HGLOBAL (never handed to the system) — free it.
            unsafe { GlobalFree(hglobal) };
            return Err("clipboard write failed: GlobalLock returned NULL".to_string());
        }
        unsafe {
            std::ptr::copy_nonoverlapping(wide.as_ptr() as *const u8, locked as *mut u8, byte_len);
            GlobalUnlock(hglobal);
        }

        // Hand the buffer to the clipboard. On SUCCESS the SYSTEM takes ownership of the HGLOBAL —
        // we must NOT GlobalFree it. On FAILURE we still own it and must free it.
        let set = unsafe { SetClipboardData(CF_UNICODETEXT, hglobal as HANDLE) };
        if set.is_null() {
            unsafe { GlobalFree(hglobal) };
            return Err("clipboard write failed: SetClipboardData(CF_UNICODETEXT) returned NULL"
                .to_string());
        }

        // Text is now on the clipboard and we own the clipboard, so the exclusion markers below
        // will succeed. These are best-effort: a marker failure does NOT fail the write (the 25s
        // auto-clear is the hard guarantee), so we only count REAL successes for a generic warning.
        //
        // Per Microsoft's Clipboard Formats contract each marker carries a serialized 4-byte DWORD
        // payload (NOT a NULL handle — NULL means delayed rendering, which we never service, and
        // gives the OS no DWORD to read for the two value-driven formats):
        //   - ExcludeClipboardContentFromMonitorProcessing → presence excludes; we set value 1.
        //   - CanIncludeInClipboardHistory                 → DWORD 0 to forbid Win+V history.
        //   - CanUploadToCloudClipboard                    → DWORD 0 to forbid Cloud Clipboard.
        let mut markers_set = 0u32;
        for (fmt, value) in FORMATS.iter() {
            let fmt_w: Vec<u16> = fmt.encode_utf16().collect();
            let fmt_id = unsafe { RegisterClipboardFormatW(fmt_w.as_ptr()) };
            if fmt_id != 0 && unsafe { set_clipboard_dword(fmt_id, *value) } {
                markers_set += 1;
            }
        }
        if markers_set < FORMATS.len() as u32 {
            // Best-effort markers — NEVER log the value, only the count.
            eprintln!(
                "clipboard markers: only {markers_set}/{} exclusion formats applied; relying on \
                 the 25s auto-clear (no secret logged)",
                FORMATS.len()
            );
        }
        Ok(())
    })();

    unsafe {
        CloseClipboard();
    }
    result
}

// ---------------------------------------------------------------------------
// macOS sensitive markers (#[cfg(target_os = "macos")]) — raw libc/objc FFI fallback (A3)
// ---------------------------------------------------------------------------

/// Add the two `org.nspasteboard.*` marker types to the general pasteboard so macOS clipboard
/// managers treat the just-written secret as concealed + transient (LOCK-06).
///
/// Marker identifiers (nspasteboard.org community standard — `NSPasteboardTypeTransient` is NOT a
/// real Apple SDK constant). The two UTIs set below (see the byte-strings in the FFI body):
///   - the Concealed type — treat as confidential; obfuscate if displayed
///   - the Transient type  — do not record in clipboard history
///
/// Implementation: raw Objective-C FFI via `libc`'s `objc_msgSend` (A3 fallback — arboard's
/// transitive objc2 0.6.4 / objc2-app-kit 0.3.2 conflicts with the plan's drafted
/// `objc2-app-kit = "0.2"`, so we avoid adding a duplicate-major objc2 stack). arboard already
/// wrote the text to `[NSPasteboard generalPasteboard]`; we call `addTypes:owner:` on top of it,
/// which registers the marker UTIs without clearing the existing string data.
///
/// UNVERIFIED ON WINDOWS: this path is compiled only by macOS CI.
#[cfg(target_os = "macos")]
fn set_macos_clipboard_markers() {
    use std::ffi::c_void;
    use std::os::raw::c_char;

    // Objective-C runtime + AppKit/Foundation C entry points.
    #[link(name = "objc", kind = "dylib")]
    extern "C" {
        fn objc_getClass(name: *const c_char) -> *mut c_void;
        fn sel_registerName(name: *const c_char) -> *mut c_void;
    }

    // `objc_msgSend` is variadic at the C level; declare typed shims for the exact call shapes
    // we need so the calling convention is correct (the standard pattern for raw objc FFI).
    extern "C" {
        // [Class selector] / [obj selector] returning an id (*mut c_void).
        fn objc_msgSend(receiver: *mut c_void, sel: *mut c_void) -> *mut c_void;
    }

    // Typed re-decl of objc_msgSend for the calls that take arguments. Each distinct argument
    // signature needs its own transmuted function pointer (objc_msgSend itself is the same symbol).
    unsafe fn send0(receiver: *mut c_void, sel: *mut c_void) -> *mut c_void {
        objc_msgSend(receiver, sel)
    }

    // [NSString stringWithUTF8String: cstr]
    unsafe fn nsstring(cls_nsstring: *mut c_void, sel_with_utf8: *mut c_void, cstr: *const c_char) -> *mut c_void {
        let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_char) -> *mut c_void =
            std::mem::transmute(objc_msgSend as *const c_void);
        f(cls_nsstring, sel_with_utf8, cstr)
    }

    // [NSArray arrayWithObjects: a, b, count: 2]  (via arrayWithObjects:count: + a C array)
    unsafe fn nsarray_with(
        cls_nsarray: *mut c_void,
        sel_arr: *mut c_void,
        objs: *const *mut c_void,
        count: usize,
    ) -> *mut c_void {
        let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *const *mut c_void, usize) -> *mut c_void =
            std::mem::transmute(objc_msgSend as *const c_void);
        f(cls_nsarray, sel_arr, objs, count)
    }

    // [pasteboard addTypes: array owner: nil]
    unsafe fn add_types(pb: *mut c_void, sel_add: *mut c_void, types: *mut c_void, owner: *mut c_void) {
        let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) =
            std::mem::transmute(objc_msgSend as *const c_void);
        f(pb, sel_add, types, owner);
    }

    unsafe {
        // Selectors / classes.
        let cls_pasteboard = objc_getClass(b"NSPasteboard\0".as_ptr() as *const c_char);
        let cls_string = objc_getClass(b"NSString\0".as_ptr() as *const c_char);
        let cls_array = objc_getClass(b"NSArray\0".as_ptr() as *const c_char);
        if cls_pasteboard.is_null() || cls_string.is_null() || cls_array.is_null() {
            // AppKit not available — markers are best-effort; the 25s auto-clear still applies.
            return;
        }

        let sel_general = sel_registerName(b"generalPasteboard\0".as_ptr() as *const c_char);
        let sel_with_utf8 =
            sel_registerName(b"stringWithUTF8String:\0".as_ptr() as *const c_char);
        let sel_array =
            sel_registerName(b"arrayWithObjects:count:\0".as_ptr() as *const c_char);
        let sel_add_types =
            sel_registerName(b"addTypes:owner:\0".as_ptr() as *const c_char);

        // pasteboard = [NSPasteboard generalPasteboard]
        let pasteboard = send0(cls_pasteboard, sel_general);
        if pasteboard.is_null() {
            return;
        }

        // The two community-standard marker UTIs (nspasteboard.org).
        let concealed =
            nsstring(cls_string, sel_with_utf8, b"org.nspasteboard.ConcealedType\0".as_ptr() as *const c_char);
        let transient =
            nsstring(cls_string, sel_with_utf8, b"org.nspasteboard.TransientType\0".as_ptr() as *const c_char);
        if concealed.is_null() || transient.is_null() {
            return;
        }

        // types = [NSArray arrayWithObjects:&[concealed, transient] count:2]
        let objs: [*mut c_void; 2] = [concealed, transient];
        let types = nsarray_with(cls_array, sel_array, objs.as_ptr(), 2);
        if types.is_null() {
            return;
        }

        // [pasteboard addTypes:types owner:nil] — registers the marker types on top of the
        // existing string data arboard already wrote.
        add_types(pasteboard, sel_add_types, types, std::ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// Tests — the still-ours decision, arranged BY HASH (no Tauri runtime / no real OS clipboard)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// LOCK-02 / P5-09: the still-ours decision is made BY HASH —
    ///   - stashed hash == hash(current == "secret")  → clear
    ///   - stashed hash != hash(current == "other")   → no clear
    ///   - stash == None                              → no-op
    ///
    /// This exercises the pure `hash_value` + `should_clear` seam directly (VALIDATION seam 3),
    /// so it needs no Tauri runtime and never touches a real OS clipboard.
    #[test]
    fn clipboard_clear_only_fires_on_match() {
        // Arrange: Cryptiq copied "secret" → it stashes hash("secret").
        let stashed = hash_value("secret");

        // Case 1 — the clipboard still holds "secret": re-hash matches → CLEAR.
        let current_same = hash_value("secret");
        assert!(
            should_clear(Some(stashed), current_same),
            "match → must clear: stashed hash equals re-hash of unchanged clipboard"
        );

        // Case 2 — the user copied "other": re-hash differs → NO clear (don't wipe their copy).
        let current_other = hash_value("other");
        assert!(
            !should_clear(Some(stashed), current_other),
            "mismatch → must NOT clear: a different value is on the clipboard"
        );

        // Case 3 — nothing was ever stashed: no-op regardless of the current clipboard.
        assert!(
            !should_clear(None, current_same),
            "None stash → no-op: nothing was ours to clear"
        );
        assert!(
            !should_clear(None, current_other),
            "None stash → no-op even if some value is present"
        );
    }

    /// Sanity: equal inputs hash equal; different inputs (overwhelmingly) hash unequal.
    /// This pins the "hash identically on both paths" contract `should_clear` relies on.
    #[test]
    fn hash_value_is_deterministic_and_discriminating() {
        assert_eq!(hash_value("secret"), hash_value("secret"));
        assert_ne!(hash_value("secret"), hash_value("other"));
        assert_ne!(hash_value(""), hash_value("secret"));
    }
}
