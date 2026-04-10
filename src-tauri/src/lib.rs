#![allow(unexpected_cfgs)]

// ═══════════════════════════════════════════════════════════
//  LexFlow — Modular architecture (v4 vault)
// ═══════════════════════════════════════════════════════════

mod audit;
mod backup;
mod bio;
mod constants;
mod crypto;
mod csv_export;
mod doc_tools;
mod error;
mod files;
mod import_export;
mod io;
mod license;
mod lockout;
mod notifications;
mod platform;
mod search;
mod security;
mod settings;
mod setup;
mod state;
mod validation;
mod vault;
pub(crate) mod vault_engine;
mod vault_engine_tests;
mod window;

use state::AppState;
use std::fs;
#[allow(unused_imports)] // needed for get_webview_window in run() event handler
use tauri::Manager;

#[cfg(mobile)]
#[tauri::mobile_entry_point]
pub fn mobile_entry() {
    run();
}

pub fn run() {
    // NOTE: do NOT init tracing-subscriber here — tauri-plugin-log handles it.
    // Double-init causes panic: "attempted to set a logger after already initialized"

    // ── SECURITY: disable core dumps (prevents DEK/plaintext in crash dumps)
    security::disable_core_dumps();

    // ── Panic Logger ────────────────────────────────────────────
    #[cfg(not(target_os = "android"))]
    {
        let crash_dir = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join("com.pietrolongo.lexflow");
        let _ = fs::create_dir_all(&crash_dir);
        let crash_log = crash_dir.join("crash.log");

        std::panic::set_hook(Box::new(move |info| {
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            let location = info
                .location()
                .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                .unwrap_or_else(|| "unknown location".to_string());
            let message = if let Some(s) = info.payload().downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = info.payload().downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic payload".to_string()
            };

            let entry = format!(
                "\n═══ CRASH {} ═══\nLocation: {}\nMessage: {}\nThread: {:?}\n",
                timestamp,
                location,
                message,
                std::thread::current().name().unwrap_or("unnamed"),
            );

            if crash_log.exists() {
                if let Ok(meta) = crash_log.metadata() {
                    if meta.len() > 1_048_576 {
                        let backup = crash_log.with_extension("log.old");
                        let _ = fs::rename(&crash_log, &backup);
                    }
                }
            }
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&crash_log)
                .and_then(|mut f| {
                    use std::io::Write;
                    f.write_all(entry.as_bytes())
                });
            eprintln!("{}", entry);
        }));
    }

    // ── Windows: Single Instance Mutex ──────────────────────────
    #[cfg(target_os = "windows")]
    {
        if !setup::acquire_single_instance_mutex() {
            eprintln!("[LexFlow] Exiting: another instance is already running");
            std::process::exit(0);
        }
    }

    #[cfg(not(target_os = "android"))]
    let data_dir = dirs::data_dir()
        .expect("FATAL: could not determine system data directory (dirs::data_dir)")
        .join("com.pietrolongo.lexflow")
        .join("lexflow-vault");

    #[cfg(not(target_os = "android"))]
    let security_dir = dirs::data_dir()
        .expect("FATAL: could not determine system data directory (dirs::data_dir)")
        .join("com.pietrolongo.lexflow");

    #[cfg(target_os = "android")]
    let data_dir = std::env::temp_dir().join("lexflow-android-pending");
    #[cfg(target_os = "android")]
    let security_dir = std::env::temp_dir().join("lexflow-android-pending");

    let _ = fs::create_dir_all(&data_dir);
    let _ = fs::create_dir_all(&security_dir);

    #[cfg(not(target_os = "android"))]
    setup::migrate_old_identifier(&data_dir, &security_dir);

    setup::migrate_security_files(&data_dir, &security_dir);

    #[cfg(not(target_os = "android"))]
    let data_dir_for_scheduler = data_dir.clone();

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_log::Builder::default().build())
        .plugin(tauri_plugin_shell::init());

    #[cfg(not(target_os = "android"))]
    let builder = builder.plugin(tauri_plugin_window_state::Builder::new().build());

    builder
        .manage(AppState::new(data_dir, security_dir))
        .setup(move |app| {
            setup::verify_binary_integrity();

            #[cfg(not(target_os = "android"))]
            {
                let id = platform::init_machine_id()
                    .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
                platform::MACHINE_ID_CACHE.set(id).ok();
            }
            #[cfg(target_os = "android")]
            {
                let id = platform::init_android_device_id()
                    .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
                platform::ANDROID_DEVICE_ID_CACHE.set(id).ok();
            }

            #[cfg(not(target_os = "android"))]
            notifications::setup_notification_permissions(app, &data_dir_for_scheduler);
            #[cfg(target_os = "android")]
            notifications::setup_notification_permissions(app, std::path::Path::new(""));

            #[cfg(not(target_os = "android"))]
            setup::setup_desktop(app, &data_dir_for_scheduler)?;

            #[cfg(target_os = "android")]
            setup::setup_android(app);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Vault
            vault::vault_exists,
            vault::unlock_vault,
            vault::lock_vault,
            vault::reset_vault,
            vault::change_password,
            vault::verify_vault_password,
            vault::get_vault_health,
            vault::generate_recovery_key,
            vault::unlock_with_recovery,
            audit::get_audit_log,
            // Data
            vault::load_practices,
            vault::save_practices,
            vault::load_agenda,
            vault::save_agenda,
            vault::get_summary,
            // Index-only reads (v4 perf)
            vault::get_vault_index,
            vault::load_record_detail,
            vault::load_record_history,
            // Search (trigram + BM25)
            search::search_vault,
            search::rebuild_search_index,
            // Conflict Check
            vault::check_conflict,
            // Time Tracking
            vault::load_time_logs,
            vault::save_time_logs,
            // Invoices
            vault::load_invoices,
            // CSV Export
            csv_export::export_time_logs_csv,
            csv_export::export_invoices_csv,
            // Backup
            backup::trigger_backup,
            backup::get_backup_list,
            vault::save_invoices,
            // Contacts
            vault::load_contacts,
            vault::save_contacts,
            // Settings
            settings::get_settings,
            settings::save_settings,
            // Biometrics
            bio::check_bio,
            bio::has_bio_saved,
            bio::save_bio,
            bio::bio_login,
            bio::clear_bio,
            // Files
            files::select_file,
            files::select_files,
            files::select_folder,
            files::open_path,
            files::select_pdf_save_path,
            files::write_pdf_to_path,
            files::generate_typst_pdf,
            files::list_folder_contents,
            files::warm_swift,
            // Notifications
            notifications::send_notification,
            notifications::send_urgent_notification,
            notifications::send_actionable_notification,
            notifications::sync_notification_schedule,
            notifications::test_notification,
            // License
            license::check_license,
            license::verify_license,
            license::activate_license,
            license::get_machine_fingerprint,
            // Document Tools
            doc_tools::pdf_info,
            doc_tools::merge_pdfs,
            doc_tools::split_pdf,
            doc_tools::remove_pages,
            doc_tools::extract_pages,
            doc_tools::compress_pdf,
            doc_tools::add_watermark,
            doc_tools::pdf_to_text,
            doc_tools::images_to_pdf,
            doc_tools::protect_pdf,
            doc_tools::rotate_pdf,
            doc_tools::reorder_pages,
            doc_tools::add_page_numbers,
            doc_tools::redact_pdf,
            doc_tools::secure_pdf,
            doc_tools::unsecure_pdf,
            // Import / Export
            import_export::export_vault,
            import_export::import_vault,
            // Platform
            files::is_mac,
            files::get_app_version,
            files::get_platform,
            // Security & Content Protection
            window::set_content_protection,
            window::ping_activity,
            window::set_autolock_minutes,
            window::get_autolock_minutes,
            // Window
            window::window_minimize,
            window::window_maximize,
            files::window_close,
            window::show_main_window,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|#[allow(unused)] app, event| {
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = event {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            if let tauri::RunEvent::ExitRequested { api, .. } = &event {
                api.prevent_exit();
            }
        });
}
