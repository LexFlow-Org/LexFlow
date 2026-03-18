// ═══════════════════════════════════════════════════════════
//  WINDOW — Window controls, content protection, autolock
// ═══════════════════════════════════════════════════════════

use crate::state::{notify_autolock_condvar, AppState};
use std::time::{Duration, Instant};
#[allow(unused_imports)] // Manager needed for get_webview_window on desktop
use tauri::{AppHandle, Manager, State};

#[tauri::command]
pub(crate) fn set_content_protection(app: AppHandle, enabled: bool) -> bool {
    #[cfg(not(target_os = "android"))]
    {
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.set_content_protected(enabled);
            true
        } else {
            false
        }
    }
    #[cfg(target_os = "android")]
    {
        // Su Android FLAG_SECURE è gestito via tauri mobile — sempre attivo per sicurezza
        let _ = (app, enabled);
        true
    }
}

#[tauri::command]
pub(crate) fn ping_activity(state: State<AppState>) {
    // SECURITY FIX (Audit 2026-03-11 L5): single lock scope to prevent TOCTOU race.
    // Previously two consecutive locks on last_activity allowed another thread to
    // modify the value between the read and the write.
    let now = Instant::now();
    let mut guard = state
        .last_activity
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if now.duration_since(*guard) > Duration::from_secs(1) {
        *guard = now;
        drop(guard);
        // PERF: wake autolock thread to recalculate sleep duration from new activity time
        notify_autolock_condvar(&state);
    }
}

#[tauri::command]
pub(crate) fn set_autolock_minutes(state: State<AppState>, minutes: u32) {
    // SECURITY FIX (Gemini Audit Chunk 15): log mutex poisoning
    match state.autolock_minutes.lock() {
        Ok(mut guard) => *guard = minutes,
        Err(e) => {
            eprintln!("[SECURITY] autolock_minutes mutex poisoned: {}", e);
            *e.into_inner() = minutes;
        }
    }
    // PERF: wake autolock thread to recalculate with new timeout
    notify_autolock_condvar(&state);
}

#[tauri::command]
pub(crate) fn get_autolock_minutes(state: State<AppState>) -> u32 {
    *state
        .autolock_minutes
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

// ═══════════════════════════════════════════════════════════
//  WINDOW CONTROLS — solo desktop
// ═══════════════════════════════════════════════════════════

#[tauri::command]
pub(crate) fn window_minimize(app: AppHandle) {
    #[cfg(not(target_os = "android"))]
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.minimize();
    }
    #[cfg(target_os = "android")]
    {
        let _ = app;
    }
}

#[tauri::command]
pub(crate) fn window_maximize(app: AppHandle) {
    #[cfg(not(target_os = "android"))]
    if let Some(w) = app.get_webview_window("main") {
        if w.is_maximized().unwrap_or(false) {
            let _ = w.unmaximize();
        } else {
            let _ = w.maximize();
        }
    }
    #[cfg(target_os = "android")]
    {
        let _ = app;
    }
}

#[tauri::command]
pub(crate) fn show_main_window(app: AppHandle) {
    #[cfg(not(target_os = "android"))]
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }
    #[cfg(target_os = "android")]
    {
        let _ = app;
    }
}
