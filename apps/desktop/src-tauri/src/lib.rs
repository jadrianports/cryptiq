mod commands;

use tauri::Manager;

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

    builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(tauri::generate_handler![
            commands::vault::vault_write_atomic,
            commands::vault::vault_write_named,
            commands::vault::vault_lock_acquire,
            commands::vault::vault_lock_check,
            commands::vault::vault_lock_release,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Cryptiq");
}
