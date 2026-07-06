mod commands;

use tauri::{Emitter, Manager};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default();

    // SEC-16: single-instance MUST be registered FIRST so it runs before
    // other plugins can interfere — per v2.tauri.app/plugin/single-instance/.
    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // Focus the main window when a second launch is attempted.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_focus();
                let _ = window.unminimize();
            }
        }));
    }

    // fs plugin MUST be registered BEFORE persisted-scope per
    // v2.tauri.app/plugin/persisted-scope/.
    builder = builder.plugin(tauri_plugin_fs::init());

    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_persisted_scope::init());
    }

    // opener plugin — desktop only (macOS + Windows, per D-15).
    // Registered AFTER the locked three (single-instance → fs → persisted-scope) per FLAG-4.
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        builder = builder.plugin(tauri_plugin_opener::init());
    }

    // DEV/TEST INFRA (PERMANENT, dev-only) — hypothesi MCP bridge for driving the app during
    // UAT (e.g. the v2.0 single-device sync checks). Gated to debug builds: the WebSocket
    // server NEVER starts in a release build. Bound to 127.0.0.1 (loopback only) instead of the
    // plugin default 0.0.0.0 so it is not reachable off-box. Registered AFTER the locked three
    // (single-instance → fs → persisted-scope) and after opener, so it does NOT disturb plugin
    // order. Pairs with the `mcp-bridge:default` capability + `withGlobalTauri` supplied ONLY by
    // the dev-only merge config `tauri.mcp-bridge.conf.json` (via `tauri dev --config` /
    // `pnpm dev:bridge`) — never in the production capabilities. Kept permanently (no churn).
    #[cfg(debug_assertions)]
    {
        builder = builder.plugin(
            tauri_plugin_mcp_bridge::Builder::new()
                .bind_address("127.0.0.1")
                .build(),
        );
    }

    builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        // Tauri-managed in-memory clipboard stash (a HASH only, per P5-09). Registered before
        // invoke_handler so the two clipboard commands can inject `State<ClipboardStore>`.
        .manage(commands::clipboard::ClipboardStore::default())
        // Tauri-managed pairing session map (Plan 09-05). Registered before invoke_handler
        // so the async pairing commands can inject `State<PairingSessionMap>`.
        .manage(commands::pairing::PairingSessionMap::new())
        // Phase 10 Plan 02 — sync listener lifecycle state (D-06 listen-while-unlocked).
        // Holds only a cancel channel; the TransportState lives on the task stack (Pitfall 6).
        .manage(commands::sync::SyncListenerState::new())
        // Phase 11 Plan 03 — B-side merged-blob oneshot (listener waits for JS confirm-save).
        .manage(commands::sync::SyncMergedBlobPending::new())
        // Phase 11 Plan 03 — D-08 single-sync busy guard (cleared on all exits via RAII drop).
        .manage(commands::sync::SyncBusyGuard::new())
        // Phase 11 Plan 03 — A-side merged-blob oneshot (sync_now parks; JS resolves via sync_provide_merged_blob).
        .manage(commands::sync::SyncProvideBlobPending::new())
        // Phase 14 Plan 02 — always-on extension-bridge listener state (BRIDGE-02; kill-switch stub for Phase 20 UX-05)
        .manage(commands::extension_bridge::ExtensionBridgeState::new())
        // Phase 15 Plan 03 — bounded (60s) TOFU approval wait, a SEPARATE lock from the
        // steady-state peer-lookup cache below (Pitfall 4). Resolved by Plan 04's
        // bridge_approve/bridge_deny commands.
        .manage(commands::extension_bridge::PendingAssociationMap::new())
        // Phase 15 Plan 03 — steady-state clientPublicKey -> pairing_token_hash lookup,
        // populated at association time and consulted on every `rpc`; evicted immediately by
        // Plan 04's revoke_extension_association_cmd (T-15-03).
        .manage(commands::extension_bridge::ExtensionPeerCache::new())
        // Phase 16 — non-human-gated pending-RPC map (~3s timeout) mediating the
        // match-origin/fill-entry emit+oneshot round trip into the renderer. A THIRD,
        // independent lock from PendingAssociationMap and ExtensionPeerCache (Pitfall 1/4).
        .manage(commands::extension_bridge::PendingRpcMap::new())
        // Native half of LOCK-01: start the system-sleep watcher once the app is built.
        // Gated to (windows, macOS) per D-15; emits "cryptiq-sleep-lock" on system sleep.
        .setup(|app| {
            #[cfg(any(target_os = "windows", target_os = "macos"))]
            {
                start_sleep_watcher(app.handle().clone());
            }
            // Phase 14 Plan 02 — local named-pipe listener (BRIDGE-02), production.
            // Explicitly NOT #[cfg(debug_assertions)]-gated (unlike the dev MCP bridge above) and
            // NOT gated by vault-unlock state — the echo endpoint carries zero vault data (D-04).
            // Phase 20 UX-05/D-04: gated on the device-local `extensionBridgeEnabled` kill-switch
            // read from config.json, so an explicit OFF persists across an app restart. Fail-open:
            // absent/missing/corrupt config spawns as before.
            if commands::extension_bridge::extension_bridge_enabled(app.handle()) {
                commands::extension_bridge::spawn_extension_bridge_listener(app.handle().clone());
            }
            // Touch `app` on platforms where the watcher is compiled out (Linux excluded from v1).
            let _ = app;
            Ok(())
        })
        // LOCK-01 native half: blur/minimize and close emit named events; the JS lock policy
        // (idle.svelte / App.svelte) decides whether/how to lock. We do NOT prevent_close —
        // the app quits on close (no system tray in v1, P5-05); JS lock() runs first.
        .on_window_event(|window, event| match event {
            tauri::WindowEvent::CloseRequested { .. } => {
                let _ = window.emit("cryptiq-window-close", ());
            }
            // Tauri v2 has no WindowEvent::Minimized — minimize loses focus, so Focused(false)
            // is the correct minimize/blur proxy (tauri-apps discussion #11826).
            tauri::WindowEvent::Focused(false) => {
                let _ = window.emit("cryptiq-window-blur", ());
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault::vault_write_atomic,
            commands::vault::vault_write_named,
            commands::vault::vault_lock_acquire,
            commands::vault::vault_lock_check,
            commands::vault::vault_lock_release,
            commands::vault::vault_export_copy,   // Phase 6 — EXPORT-01 / P6-10
            commands::clipboard::clipboard_write_sensitive,
            commands::clipboard::clipboard_clear_if_ours,
            // Phase 9 — device identity + pairing commands (Plan 09-05)
            commands::pairing::get_local_device_info,
            commands::pairing::device_key_write,
            commands::pairing::device_key_read,
            commands::pairing::device_key_delete,
            commands::pairing::generate_qr_svg,
            commands::pairing::get_lan_ip,
            commands::pairing::pairing_initiate,
            commands::pairing::pairing_connect,
            commands::pairing::pairing_confirm,
            commands::pairing::pairing_finalize,
            commands::pairing::unpair_device,
            commands::pairing::peers_json_read,
            commands::pairing::pairing_get_sas,  // Phase 12 Plan 12-01 — read-only SAS poll fallback
            // Phase 10 — sync transport commands (D-05 initiator + D-06 listen lifecycle)
            commands::sync::sync_now,           // Phase 10 Plan 03 — IK sync initiator
            commands::sync::sync_listener_start,
            commands::sync::sync_listener_stop,
            // Phase 11 Plan 03 — D-01 wire protocol: merged-blob + ack legs
            commands::sync::sync_confirm_save,       // B-side JS→Rust confirm (plan 04 calls this)
            commands::sync::sync_provide_merged_blob, // A-side oneshot resolver (plan 04 calls this)
            commands::vault::vault_sweep_tmp,         // D-09 stale .tmp sweep on vault open
            // Phase 15 Plan 04 — association lifecycle command surface (BRIDGE-05/BRIDGE-09)
            commands::extension_bridge::bridge_approve,
            commands::extension_bridge::bridge_deny,
            commands::extension_bridge::extension_peers_list,
            commands::extension_bridge::rename_extension_association,
            commands::extension_bridge::revoke_extension_association_cmd,
            // Phase 16 — RPC dispatch commands (BRIDGE-08/XSEC-05)
            commands::extension_bridge::bridge_rpc_response,
            commands::extension_bridge::focus_app,
            // Phase 20 — UX-05 extension-bridge kill-switch start/stop (D-01/D-04)
            commands::extension_bridge::start_extension_bridge_listener,
            commands::extension_bridge::stop_extension_bridge_listener,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Cryptiq");
}

// ---------------------------------------------------------------------------
// System-sleep watcher (LOCK-01 / P5-05 — system sleep ALWAYS locks).
//
// Windows: Tauri/tao does NOT fire `tauri://suspended` on system sleep
// (tauri-apps/tauri#7466, closed "not planned"), so we run a dedicated thread with a
// message-only window that handles WM_POWERBROADCAST / PBT_APMSUSPEND and emits
// "cryptiq-sleep-lock" to the webview.
//
// macOS: `tauri://suspended` covers app-hide/background but NOT system sleep, so we register an
// NSWorkspaceWillSleepNotification observer (raw libc/objc FFI fallback — A3) that emits the same
// event. A supplemental tauri://suspended listener MAY be added on the JS side for app-hide; it
// never replaces this observer for the system-sleep guarantee.
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn start_sleep_watcher(app_handle: tauri::AppHandle) {
    #[cfg(target_os = "windows")]
    start_sleep_watcher_windows(app_handle);

    #[cfg(target_os = "macos")]
    start_sleep_watcher_macos(app_handle);
}

// --- Windows: WM_POWERBROADCAST / PBT_APMSUSPEND on a message-only window ----------------------

#[cfg(target_os = "windows")]
fn start_sleep_watcher_windows(app_handle: tauri::AppHandle) {
    use std::sync::OnceLock;

    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    // In windows-sys 0.59 the power-broadcast message + suspend subcode both live under
    // Win32_UI_WindowsAndMessaging (not Win32_System_Power, which carries the
    // RegisterPowerSettingNotification family). Both feature flags are declared in Cargo.toml.
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
        TranslateMessage, HWND_MESSAGE, MSG, PBT_APMSUSPEND, WINDOW_EX_STYLE, WM_POWERBROADCAST,
        WNDCLASSW, WS_OVERLAPPED,
    };

    // The emit target. The wndproc is a plain `extern "system" fn` (no captured environment),
    // so the AppHandle is shared via a process-global OnceLock. There is exactly one sleep
    // watcher thread for the app's lifetime, so a single global slot is sufficient.
    static APP: OnceLock<tauri::AppHandle> = OnceLock::new();
    let _ = APP.set(app_handle);

    unsafe extern "system" fn wndproc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if msg == WM_POWERBROADCAST && wparam as u32 == PBT_APMSUSPEND {
            if let Some(app) = APP.get() {
                // Emit to the webview; JS (App.svelte) runs vaultSession.lock() + go('unlock').
                let _ = app.emit("cryptiq-sleep-lock", ());
            }
            // Per Win32 docs, return TRUE (1) to grant the power request.
            return 1;
        }
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }

    std::thread::spawn(move || {
        unsafe {
            let class_name: Vec<u16> = "CryptiqSleepWatcher\0".encode_utf16().collect();
            let hinstance = GetModuleHandleW(std::ptr::null());

            let mut wc: WNDCLASSW = std::mem::zeroed();
            wc.lpfnWndProc = Some(wndproc);
            wc.hInstance = hinstance;
            wc.lpszClassName = class_name.as_ptr();
            // Registering the same class twice across restarts is harmless here (one process,
            // one watcher thread); ignore the return value.
            RegisterClassW(&wc);

            // Message-only window (HWND_MESSAGE parent) — invisible, receives WM_POWERBROADCAST.
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                class_name.as_ptr(),
                class_name.as_ptr(),
                WS_OVERLAPPED,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                std::ptr::null_mut(),
                hinstance,
                std::ptr::null(),
            );
            if hwnd.is_null() {
                // Could not create the watcher window — sleep-lock via WM_POWERBROADCAST is
                // unavailable. Idle/blur/close locking still works; no secret is involved.
                eprintln!("sleep watcher: failed to create message-only window (no secret logged)");
                return;
            }

            // Standard Win32 message pump for this thread's message-only window.
            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    });
}

// --- macOS: NSWorkspaceWillSleepNotification observer (raw libc/objc FFI fallback, A3) ----------

#[cfg(target_os = "macos")]
fn start_sleep_watcher_macos(app_handle: tauri::AppHandle) {
    use std::ffi::c_void;
    use std::os::raw::c_char;
    use std::sync::OnceLock;

    // One AppHandle for the process-lifetime observer callback.
    static APP: OnceLock<tauri::AppHandle> = OnceLock::new();
    let _ = APP.set(app_handle);

    #[link(name = "objc", kind = "dylib")]
    extern "C" {
        fn objc_getClass(name: *const c_char) -> *mut c_void;
        fn sel_registerName(name: *const c_char) -> *mut c_void;
        fn objc_msgSend(receiver: *mut c_void, sel: *mut c_void) -> *mut c_void;
    }

    // C callback invoked by the notification center when the system is about to sleep.
    // Signature matches `addObserver:selector:name:object:` style is awkward from pure C FFI,
    // so we use the block-based `addObserverForName:object:queue:usingBlock:` API instead and
    // pass a C function pointer wrapped as a stack-block is non-trivial; for v1 we use the
    // simpler `addObserver:selector:` against a tiny dynamically-created class. To keep the FFI
    // footprint minimal and dependency-free, we instead poll-free register via a C-trampoline
    // exposed through a small Objective-C associated target object.
    //
    // NOTE (UNVERIFIED ON WINDOWS — macOS CI compiles this): the cleanest dependency-free route
    // is the block-based observer. We construct a global-block literal that calls `emit_sleep`.
    extern "C" fn emit_sleep(_block: *mut c_void, _notification: *mut c_void) {
        if let Some(app) = APP.get() {
            let _ = app.emit("cryptiq-sleep-lock", ());
        }
    }

    // Minimal NSConcreteGlobalBlock layout so we can pass a C function as an Objective-C block to
    // `addObserverForName:object:queue:usingBlock:`. The block ABI is stable on macOS.
    #[repr(C)]
    struct BlockDescriptor {
        reserved: usize,
        size: usize,
    }
    #[repr(C)]
    struct Block {
        isa: *const c_void,
        flags: i32,
        reserved: i32,
        invoke: extern "C" fn(*mut c_void, *mut c_void),
        descriptor: *const BlockDescriptor,
    }

    #[link(name = "System", kind = "dylib")]
    extern "C" {
        static _NSConcreteGlobalBlock: c_void;
    }

    unsafe {
        let cls_workspace = objc_getClass(b"NSWorkspace\0".as_ptr() as *const c_char);
        if cls_workspace.is_null() {
            return;
        }
        let sel_shared = sel_registerName(b"sharedWorkspace\0".as_ptr() as *const c_char);
        let sel_nc = sel_registerName(b"notificationCenter\0".as_ptr() as *const c_char);

        let workspace = objc_msgSend(cls_workspace, sel_shared);
        if workspace.is_null() {
            return;
        }
        let center = objc_msgSend(workspace, sel_nc);
        if center.is_null() {
            return;
        }

        // Build the notification-name NSString.
        let cls_string = objc_getClass(b"NSString\0".as_ptr() as *const c_char);
        let sel_with_utf8 = sel_registerName(b"stringWithUTF8String:\0".as_ptr() as *const c_char);
        let make_nsstring: unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_char) -> *mut c_void =
            std::mem::transmute(objc_msgSend as *const c_void);
        let name = make_nsstring(
            cls_string,
            sel_with_utf8,
            b"NSWorkspaceWillSleepNotification\0".as_ptr() as *const c_char,
        );
        if name.is_null() {
            return;
        }

        // Assemble the global block wrapping our C trampoline.
        static DESCRIPTOR: BlockDescriptor = BlockDescriptor {
            reserved: 0,
            size: std::mem::size_of::<Block>(),
        };

        // BUG-4 fix: the block MUST have storage that genuinely outlives this function. The
        // notification center retains the OBSERVER for the process lifetime, but with a
        // `_NSConcreteGlobalBlock` isa the runtime ELIDES the heap copy it would otherwise make,
        // so it keeps using whatever pointer we hand it. A stack-local `let block = Block { .. }`
        // + `std::mem::forget(block)` does NOT keep the stack slot alive (forget only suppresses
        // Drop) — the slot is reclaimed on return and the observer fires through freed memory on
        // sleep (use-after-free). Instead we heap-allocate and `Box::leak` to get a genuinely
        // `'static` pointer that lives for the entire process lifetime (matching the
        // intentionally-leaked-for-the-process-lifetime intent of the observer).
        let block: &'static Block = Box::leak(Box::new(Block {
            isa: &_NSConcreteGlobalBlock as *const c_void,
            flags: 0,
            reserved: 0,
            invoke: emit_sleep,
            descriptor: &DESCRIPTOR,
        }));

        // [center addObserverForName:name object:nil queue:nil usingBlock:block]
        let sel_add = sel_registerName(
            b"addObserverForName:object:queue:usingBlock:\0".as_ptr() as *const c_char,
        );
        let add: unsafe extern "C" fn(
            *mut c_void,
            *mut c_void,
            *mut c_void,
            *mut c_void,
            *mut c_void,
            *const Block,
        ) -> *mut c_void = std::mem::transmute(objc_msgSend as *const c_void);
        // Pass the stable leaked pointer (NOT a stack address). The observer token returned here
        // is intentionally discarded — we observe sleep for the whole process lifetime and never
        // remove it; the leaked block backing it lives just as long.
        let _observer = add(
            center,
            sel_add,
            name,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            block as *const Block,
        );
    }
}
