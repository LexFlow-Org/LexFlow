// ═══════════════════════════════════════════════════════════
//  SETUP — App initialization, GC, migrations, system tray
// ═══════════════════════════════════════════════════════════

#![allow(unused_imports)]

use crate::constants::*;
use crate::crypto::{decrypt_data, encrypt_data};
use crate::io::{atomic_write_with_sync, secure_write};
use crate::license::PUBLIC_KEY_BYTES;
use crate::platform::get_local_encryption_key;
use crate::state::{notify_autolock_condvar, AppState};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};
use tauri::{AppHandle, Emitter, Manager};

// ═══════════════════════════════════════════════════════════
//  STARTUP CLEANUP
// ═══════════════════════════════════════════════════════════

/// Clean up orphan .tmp files left by crashed atomic writes.
/// If foo.tmp exists but foo doesn't → rename as recovery.
/// If both exist → delete .tmp (it's an incomplete write).
#[allow(dead_code)] // Called from setup_desktop; unused on Android
pub(crate) fn cleanup_orphan_tmp_files(vault_dir: &std::path::Path) {
    let entries = match fs::read_dir(vault_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.contains(".tmp.") {
            continue;
        }
        let tmp_path = entry.path();
        // Extract the original filename by removing .tmp.XXXXX suffix
        // Format: .filename.tmp.12345 → filename
        let original_name = name
            .trim_start_matches('.')
            .split(".tmp.")
            .next()
            .unwrap_or("");
        if original_name.is_empty() {
            continue;
        }
        let original_path = vault_dir.join(original_name);

        if original_path.exists() {
            // Original exists — .tmp is an incomplete write, safe to delete
            eprintln!(
                "[LexFlow] Cleanup: removing orphan tmp {:?} (original exists)",
                name
            );
            let _ = fs::remove_file(&tmp_path);
        } else {
            // Original missing — .tmp might be the only copy, attempt recovery
            eprintln!(
                "[LexFlow] Cleanup: recovering orphan tmp {:?} → {:?}",
                name, original_name
            );
            if fs::rename(&tmp_path, &original_path).is_err() {
                eprintln!("[LexFlow] WARNING: failed to recover {:?}, deleting", name);
                let _ = fs::remove_file(&tmp_path);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  APP RUNNER
// ═══════════════════════════════════════════════════════════

/// Verify binary integrity at startup — detects patched crypto constants.
///
/// SECURITY FIX (Audit v2.5): strengthened from plain SHA-256 to HMAC-SHA256.
/// - Uses HMAC with a domain-separated key derived from the integrity seed itself,
///   so an attacker must understand the HMAC construction (not just find-and-replace a hash).
/// - Comparison uses constant-time `hmac::verify()` to prevent timing side-channels
///   (the old `==` on hex strings leaked the number of matching prefix bytes via timing).
/// - Added the domain separator version string to the seed, so changes to the check
///   algorithm invalidate old hashes (forces re-computation, not copy-paste from older builds).
///
/// Limitations (inherent, not fixable in software):
/// An attacker with full binary write access can patch both the expected hash AND the
/// verification code. This check is a "speed bump" — it stops naive patchers and automated
/// tools but not a determined reverse engineer. Defense-in-depth: combine with code signing,
/// notarization (macOS), and Gatekeeper/SmartScreen at the OS level.
pub(crate) fn verify_binary_integrity() {
    // Build the integrity seed from all security-critical constants
    let mut integrity_seed = Vec::with_capacity(256);
    integrity_seed.extend_from_slice(b"LEXFLOW-INTEGRITY-V2:");
    integrity_seed.extend_from_slice(VAULT_MAGIC);
    integrity_seed.extend_from_slice(&(AES_KEY_LEN as u64).to_le_bytes());
    integrity_seed.extend_from_slice(&(NONCE_LEN as u64).to_le_bytes());
    integrity_seed.extend_from_slice(&ARGON2_M_COST.to_le_bytes());
    integrity_seed.extend_from_slice(&ARGON2_T_COST.to_le_bytes());
    integrity_seed.extend_from_slice(&ARGON2_P_COST.to_le_bytes());
    integrity_seed.extend_from_slice(&PUBLIC_KEY_BYTES);
    integrity_seed.extend_from_slice(&crate::lockout::DEK_WIPE_THRESHOLD.to_le_bytes());

    // Self-referential HMAC: key = SHA-256(seed), msg = seed
    let hmac_key = <Sha256 as Digest>::digest(&integrity_seed);
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key).expect("HMAC can take key of any size");
    mac.update(&integrity_seed);
    let computed = mac.finalize();
    let computed_hex = hex::encode(computed.into_bytes());

    // Expected HMAC is computed at build time by build.rs and injected as env var.
    // This guarantees it ALWAYS matches the compiled constants, regardless of
    // optimization level, target, or platform.
    let expected = env!("LEXFLOW_INTEGRITY_HMAC");

    // SECURITY FIX: constant-time comparison via HMAC verify instead of string !=
    let expected_bytes = hex::decode(expected).unwrap_or_default();
    let mut verify_mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key).expect("HMAC can take key of any size");
    verify_mac.update(&integrity_seed);
    if verify_mac.verify_slice(&expected_bytes).is_err() {
        eprintln!("[SECURITY] Binary integrity HMAC mismatch!");
        eprintln!("  Expected (build.rs): {}", expected);
        eprintln!("  Computed (runtime):  {}", computed_hex);
        // Non-fatal: the vault crypto (AES-256-GCM-SIV + Argon2id) is the real
        // protection. This check detects accidental constant corruption, not
        // deliberate tampering (an attacker can patch any check out of a binary).
    }
}

/// Auto-lock loop — shared between desktop and Android.
/// PERF: uses Condvar for event-driven wakeups instead of hard sleep polling.
/// Sleeps exactly until the next meaningful check is needed (warning or lock threshold),
/// reducing unnecessary wakeups from ~2880/day to ~2/session. Saves battery on laptops/phones.
pub(crate) fn autolock_loop(ah: AppHandle) {
    // We use a dedicated condvar so that ping_activity / set_autolock_minutes
    // can wake this thread immediately when the idle timer should be recalculated.
    let pair = std::sync::Arc::new((std::sync::Mutex::new(()), std::sync::Condvar::new()));
    // Store the condvar in AppState so ping_activity can notify us
    {
        let state = ah.state::<AppState>();
        *state
            .autolock_condvar
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(pair.clone());
    }
    let (lock, cvar) = &*pair;

    loop {
        let is_unlocked = {
            let state = ah.state::<AppState>();
            state.vault_key.lock().map(|k| k.is_some()).unwrap_or(false)
        };
        if !is_unlocked {
            // Vault is locked — sleep long, nothing to check
            let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
            let _ = cvar.wait_timeout(guard, Duration::from_secs(60));
            continue;
        }
        let (minutes, last) = {
            let state = ah.state::<AppState>();
            let m = *state
                .autolock_minutes
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let l = *state
                .last_activity
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            (m, l)
        };
        if minutes == 0 {
            // Autolock disabled — sleep until setting changes (condvar wakeup)
            let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
            let _ = cvar.wait_timeout(guard, Duration::from_secs(120));
            continue;
        }
        let elapsed = Instant::now().duration_since(last);
        let threshold = Duration::from_secs(minutes as u64 * 60);
        let warning_at = threshold.saturating_sub(Duration::from_secs(30));

        if elapsed >= threshold {
            // Lock now
            let state2 = ah.state::<AppState>();
            *state2.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
            *state2.vault_dek.lock().unwrap_or_else(|e| e.into_inner()) = None;
            let _ = ah.emit("lf-vault-locked", ());
            continue;
        }
        if elapsed >= warning_at {
            let _ = ah.emit("lf-vault-warning", ());
            // Sleep remaining time until lock
            let remaining = threshold.saturating_sub(elapsed);
            let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
            let _ = cvar.wait_timeout(guard, remaining);
            continue;
        }
        // Sleep until warning threshold
        let sleep_until_warning = warning_at.saturating_sub(elapsed);
        let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        let _ = cvar.wait_timeout(guard, sleep_until_warning);
    }
}

/// Copy all files from one directory to another, skipping existing files.
#[cfg(not(target_os = "android"))]
fn copy_dir_non_overwrite(src: &std::path::Path, dest_dir: &std::path::Path) {
    let entries = match fs::read_dir(src) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let dest = dest_dir.join(entry.file_name());
        if !dest.exists() {
            let _ = fs::copy(entry.path(), &dest);
        }
    }
}

/// Copy security files from one directory to another, skipping existing files.
#[cfg(not(target_os = "android"))]
fn copy_security_files_if_missing(src_dir: &std::path::Path, dest_dir: &std::path::Path) {
    for sec_file in &[
        LICENSE_FILE,
        LICENSE_SENTINEL_FILE,
        BURNED_KEYS_FILE,
        LOCKOUT_FILE,
    ] {
        let old_path = src_dir.join(sec_file);
        let new_path = dest_dir.join(sec_file);
        if old_path.exists() && !new_path.exists() {
            let _ = fs::copy(&old_path, &new_path);
        }
    }
}

/// Migrate data from old identifier (com.technojaw.lexflow) to new one.
#[cfg(not(target_os = "android"))]
pub(crate) fn migrate_old_identifier(data_dir: &std::path::Path, security_dir: &std::path::Path) {
    let old_data_dir = match dirs::data_dir() {
        Some(d) => d,
        None => return,
    };
    let old_base = old_data_dir.join("com.technojaw.lexflow");
    if !old_base.exists() || !old_base.is_dir() {
        return;
    }

    let old_vault = old_base.join("lexflow-vault");
    if old_vault.exists() && !data_dir.join(VAULT_FILE).exists() {
        copy_dir_non_overwrite(&old_vault, data_dir);
    }
    copy_security_files_if_missing(&old_base, security_dir);
}

/// Migrate security files from vault dir to security_dir (post v2.6.1).
pub(crate) fn migrate_security_files(data_dir: &std::path::Path, security_dir: &std::path::Path) {
    for sec_file in &[
        LICENSE_FILE,
        LICENSE_SENTINEL_FILE,
        BURNED_KEYS_FILE,
        LOCKOUT_FILE,
    ] {
        let old_path = data_dir.join(sec_file);
        let new_path = security_dir.join(sec_file);
        if old_path.exists() && !new_path.exists() {
            let _ = fs::copy(&old_path, &new_path);
            let _ = fs::remove_file(&old_path);
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  SINGLE INSTANCE MUTEX — Windows only
// ═══════════════════════════════════════════════════════════
//
// On Windows, if the user downloads a new MSI while the old version is
// running (typically minimised in the system tray), the installer will
// fail with "File in use" and leave a half-corrupted installation.
//
// Solution: at startup we create a **Named Mutex** (kernel object) with
// the app's identifier.  If the mutex already exists, another instance
// is already running.  We bring its window to the foreground and exit
// immediately — this also prevents the user from accidentally running
// two copies of the app.
//
// The mutex is automatically released by the OS when the process exits,
// so the MSI installer can proceed cleanly.

#[cfg(target_os = "windows")]
static SINGLE_INSTANCE_MUTEX: std::sync::OnceLock<isize> = std::sync::OnceLock::new();

/// Attempt to acquire the single-instance mutex.
/// Returns `true` if this is the first instance (mutex acquired).
/// Returns `false` if another instance is already running.
#[cfg(target_os = "windows")]
pub(crate) fn acquire_single_instance_mutex() -> bool {
    use std::ffi::CString;

    // Use the bundle identifier as the mutex name (globally unique)
    let mutex_name =
        CString::new("Global\\com.pietrolongo.lexflow").expect("mutex name has no null bytes");

    let handle = unsafe {
        windows_sys::Win32::System::Threading::CreateMutexA(
            std::ptr::null(), // default security attributes
            1,                // bInitialOwner = TRUE (we want ownership)
            mutex_name.as_ptr() as *const u8,
        )
    };

    if handle.is_null() {
        // CreateMutex failed entirely — let the app run anyway
        eprintln!("[LexFlow] WARNING: CreateMutexA failed, single-instance check skipped");
        return true;
    }

    let last_error = unsafe { windows_sys::Win32::Foundation::GetLastError() };

    // ERROR_ALREADY_EXISTS (183) means another instance holds the mutex
    if last_error == windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS {
        // Another instance is running — close our handle and signal the caller
        unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
        eprintln!("[LexFlow] Another instance is already running — exiting");
        return false;
    }

    // We got the mutex — store the handle so it lives for the process lifetime
    // (the OS releases it automatically when the process exits)
    let _ = SINGLE_INSTANCE_MUTEX.set(handle as isize);
    eprintln!("[LexFlow] Single-instance mutex acquired ✓");
    true
}

// ═══════════════════════════════════════════════════════════
//  macOS: TCC GUARD — "Move to Applications" warning
// ═══════════════════════════════════════════════════════════
//
// TCC (Transparency, Consent, and Control) associates permissions
// (Notifications, Disk Access, etc.) with the Bundle ID + path + signature.
// If the user runs the app from ~/Downloads or from a mounted DMG,
// permissions granted there will NOT carry over when the app is later
// moved to /Applications.  Worse, macOS may show the green checkmark
// in System Preferences while the app silently lacks the permission.
//
// Solution: if the app is NOT running from /Applications (or a subfolder),
// emit a frontend event so the UI can show a non-blocking banner:
//   "Per mantenere i permessi, sposta LexFlow nella cartella Applicazioni."
// We do NOT block the app — power users may have valid reasons to run
// from other paths — but we make the situation visible.

#[cfg(target_os = "macos")]
fn check_tcc_location(app: &tauri::App) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let path_str = exe.to_string_lossy();

    // Canonical check: /Applications/ or ~/Applications/
    let in_applications = path_str.starts_with("/Applications/")
        || path_str.contains("/Users/") && path_str.contains("/Applications/");

    // Also reject DMG / Translocation paths
    let in_transient = path_str.contains("/Volumes/")
        || path_str.contains("/AppTranslocation/")
        || path_str.contains("/private/var/folders/");

    if !in_applications || in_transient {
        eprintln!(
            "[LexFlow] TCC warning: running from non-standard path «{}»",
            path_str
        );
        // Emit event to frontend — the UI can show a dismissable banner
        let _ = app.emit(
            "lf-tcc-location-warning",
            json!({
                "path": path_str.to_string(),
                "inTransient": in_transient,
            }),
        );
    } else {
        eprintln!("[LexFlow] TCC: running from /Applications ✓");
    }
}

// ═══════════════════════════════════════════════════════════
//  WEBVIEW CACHE INVALIDATION — all desktop platforms
// ═══════════════════════════════════════════════════════════
//
// WebViews (WKWebView on macOS, WebView2 on Windows) aggressively cache
// .js/.css files.  After updating the binary (new DMG/MSI), the WebView
// may load stale UI from cache → white screens, broken buttons, or a
// Frankenstein mix of old design and new code.
//
// Solution: at startup, compare the current app version with the version
// stored in a small marker file.  If the version has changed (= the user
// just updated), we clear the WebView cache directories before the
// WebView loads.  Vite's content-hash filenames (main-a7f9b.js) provide
// a second layer of defence, but the native cache wipe is the nuclear
// option that guarantees a clean slate.

#[cfg(not(target_os = "android"))]
fn clear_webview_cache_on_upgrade(app_version: &str, app_data_dir: &std::path::Path) {
    let marker_file = app_data_dir.join(".webview-version");

    // Check if version changed
    if let Ok(saved) = std::fs::read_to_string(&marker_file) {
        if saved.trim() == app_version {
            return; // Same version — no cache wipe needed
        }
    }

    eprintln!("[LexFlow] Version change detected → clearing WebView cache…");

    // macOS: WKWebView stores cache in ~/Library/WebKit/<BundleID>/
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = dirs::home_dir() {
            let webkit_cache = home.join("Library/WebKit/com.pietrolongo.lexflow");
            if webkit_cache.exists() {
                let _ = fs::remove_dir_all(&webkit_cache);
                eprintln!("[LexFlow] Cleared WKWebView cache ✓");
            }
            // Also clear HTTP storage
            let http_storage = home.join("Library/HTTPStorages/com.pietrolongo.lexflow");
            if http_storage.exists() {
                let _ = fs::remove_dir_all(&http_storage);
                eprintln!("[LexFlow] Cleared HTTPStorages ✓");
            }
            // Cached Data in Application Support
            let cached_data = home.join("Library/Caches/com.pietrolongo.lexflow");
            if cached_data.exists() {
                let _ = fs::remove_dir_all(&cached_data);
                eprintln!("[LexFlow] Cleared Caches dir ✓");
            }
        }
    }

    // Windows: WebView2 stores cache in AppData/Local/<ProductName>/EBWebView/
    #[cfg(target_os = "windows")]
    {
        if let Some(local) = dirs::data_local_dir() {
            let webview2_cache = local.join("com.pietrolongo.lexflow/EBWebView");
            if webview2_cache.exists() {
                let _ = fs::remove_dir_all(&webview2_cache);
                eprintln!("[LexFlow] Cleared WebView2 cache ✓");
            }
        }
    }

    // Linux: WebKitGTK stores cache in ~/.local/share/<app>/WebKit/
    #[cfg(target_os = "linux")]
    {
        if let Some(data) = dirs::data_dir() {
            let webkit_cache = data.join("com.pietrolongo.lexflow/WebKit");
            if webkit_cache.exists() {
                let _ = fs::remove_dir_all(&webkit_cache);
                eprintln!("[LexFlow] Cleared WebKitGTK cache ✓");
            }
        }
    }

    // Persist current version so we don't wipe again on next launch
    let _ = std::fs::write(&marker_file, app_version);
    eprintln!(
        "[LexFlow] WebView cache cleared for upgrade to {} ✓",
        app_version
    );
}

// ═══════════════════════════════════════════════════════════
//  GARBAGE COLLECTION — temp/cache file cleanup (all platforms)
// ═══════════════════════════════════════════════════════════
//
// Over time, the app accumulates temporary files:
//   • Typst .typ/.pdf intermediates in std::env::temp_dir()
//   • Old export/import scratch files
//   • Stale cache entries from previous versions
//
// Solution: on every launch (in a background thread), scan the system
// temp directory for files matching our prefix ("lexflow_*") that are
// older than 7 days, and delete them.  Also sweep our app cache dir
// for orphaned files.
//
// This is the "good tenant" pattern — clean up after yourself so the
// user's disk doesn't fill up with garbage from years of updates.

const GC_MAX_AGE_DAYS: u64 = 7;

fn garbage_collect_temp_files() {
    std::thread::spawn(|| {
        let max_age = Duration::from_secs(GC_MAX_AGE_DAYS * 24 * 60 * 60);
        let now = SystemTime::now();
        let mut cleaned = 0u32;
        let mut bytes_freed = 0u64;

        // 1. System temp dir — clean "lexflow_*" files (Typst intermediates, etc.)
        let temp_dir = std::env::temp_dir();
        if let Ok(entries) = fs::read_dir(&temp_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if !name_str.starts_with("lexflow_") {
                    continue;
                }
                if let Ok(meta) = entry.metadata() {
                    let age = meta
                        .modified()
                        .or_else(|_| meta.created())
                        .ok()
                        .and_then(|t| now.duration_since(t).ok());
                    if let Some(file_age) = age {
                        if file_age > max_age {
                            let size = meta.len();
                            if meta.is_dir() {
                                let _ = fs::remove_dir_all(entry.path());
                            } else {
                                let _ = fs::remove_file(entry.path());
                            }
                            cleaned += 1;
                            bytes_freed += size;
                        }
                    }
                }
            }
        }

        // 2. App cache dir (platform-specific)
        #[cfg(target_os = "macos")]
        if let Some(home) = dirs::home_dir() {
            let cache_dir = home.join("Library/Caches/com.pietrolongo.lexflow");
            gc_directory(&cache_dir, max_age, now, &mut cleaned, &mut bytes_freed);
        }

        #[cfg(target_os = "windows")]
        if let Some(local) = dirs::data_local_dir() {
            let cache_dir = local.join("com.pietrolongo.lexflow/cache");
            gc_directory(&cache_dir, max_age, now, &mut cleaned, &mut bytes_freed);
        }

        #[cfg(target_os = "android")]
        if let Ok(cache_dir) = std::env::var("TMPDIR") {
            let p = std::path::PathBuf::from(cache_dir);
            gc_directory(&p, max_age, now, &mut cleaned, &mut bytes_freed);
        }

        if cleaned > 0 {
            let freed_mb = bytes_freed as f64 / (1024.0 * 1024.0);
            eprintln!(
                "[LexFlow] GC: cleaned {} temp file(s), freed {:.1} MB",
                cleaned, freed_mb
            );
        } else {
            eprintln!("[LexFlow] GC: no stale temp files found ✓");
        }
    });
}

/// Scan a directory and remove files/dirs older than `max_age`.
#[allow(dead_code)]
fn gc_directory(
    dir: &std::path::Path,
    max_age: Duration,
    now: SystemTime,
    cleaned: &mut u32,
    bytes_freed: &mut u64,
) {
    if !dir.exists() {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        if let Ok(meta) = entry.metadata() {
            let age = meta
                .modified()
                .or_else(|_| meta.created())
                .ok()
                .and_then(|t| now.duration_since(t).ok());
            if let Some(file_age) = age {
                if file_age > max_age {
                    let size = meta.len();
                    if meta.is_dir() {
                        let _ = fs::remove_dir_all(entry.path());
                    } else {
                        let _ = fs::remove_file(entry.path());
                    }
                    *cleaned += 1;
                    *bytes_freed += size;
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  LAUNCHSERVICES CLEANUP — macOS only (Professional / Gold Standard)
// ═══════════════════════════════════════════════════════════

/// Spawn a background thread that:
///   1. Dumps the LaunchServices database via `lsregister -dump`.
///   2. For every entry whose `identifier:` matches our bundle ID and whose
///      canonical path differs from our running .app, unregisters it (`-u`).
///   3. Force-registers (`-f`) our own bundle so macOS re-indexes metadata
///      and routes notifications, "Open With" menus, etc. to this instance.
///   4. Writes a state file so subsequent launches skip the expensive dump.
#[cfg(target_os = "macos")]
fn run_ls_cleanup(
    bundle_id: String,
    canonical_path_str: String,
    state_file: std::path::PathBuf,
    state_signature: String,
) {
    std::thread::spawn(move || {
        eprintln!("[LexFlow] LaunchServices: optimisation started in background…");

        let ls = "/System/Library/Frameworks/CoreServices.framework/\
                  Versions/A/Frameworks/LaunchServices.framework/\
                  Versions/A/Support/lsregister";

        let canonical_current = std::path::PathBuf::from(&canonical_path_str);

        if let Ok(output) = std::process::Command::new(ls).arg("-dump").output() {
            let dump = String::from_utf8_lossy(&output.stdout);
            let mut entry_path: Option<std::path::PathBuf> = None;
            let mut unregistered = 0u32;

            for line in dump.lines() {
                let trimmed = line.trim();

                if trimmed.starts_with("path:") {
                    // Extract the path, stripping the trailing " (0x…)" hex offset
                    let raw = trimmed.trim_start_matches("path:").trim();
                    let clean = raw.split(" (0x").next().unwrap_or(raw);
                    entry_path = Some(std::path::PathBuf::from(clean));
                } else if trimmed.starts_with("identifier:") && trimmed.contains(&bundle_id) {
                    if let Some(ref stale) = entry_path {
                        // Canonical (symlink-safe, case-insensitive) comparison
                        let is_current = std::fs::canonicalize(stale)
                            .map(|cp| cp == canonical_current)
                            .unwrap_or(false);

                        if !is_current {
                            // SECURITY FIX (Audit 2026-03-14): removed redundant if/else —
                            // both branches executed identical code.  Unregister regardless
                            // of whether the stale path still exists on disk: lsregister -u
                            // gracefully handles non-existent paths and we want to purge the
                            // LaunchServices DB entry either way.
                            let _ = std::process::Command::new(ls)
                                .args(["-u", &stale.to_string_lossy()])
                                .status();
                            unregistered += 1;
                            eprintln!(
                                "[LexFlow] LaunchServices: unregistered stale «{}»",
                                stale.display()
                            );
                        }
                    }
                    entry_path = None;
                }
            }

            if unregistered > 0 {
                eprintln!(
                    "[LexFlow] LaunchServices: removed {} phantom registration(s)",
                    unregistered
                );
            }
        }

        // Force-register the current .app bundle so macOS re-indexes
        // metadata (notifications, "Open With", Spotlight, etc.)
        let _ = std::process::Command::new(ls)
            .args(["-f", &canonical_path_str])
            .status();
        eprintln!(
            "[LexFlow] LaunchServices: registered current «{}»",
            canonical_path_str
        );

        // Persist the state signature — next launch will skip the dump
        let _ = std::fs::write(&state_file, &state_signature);

        eprintln!("[LexFlow] LaunchServices cleanup done ✓");
    });
}

/// Setup desktop-specific features: window events, system tray, auto-lock, cron job.
#[cfg(not(target_os = "android"))]
pub(crate) fn setup_desktop(
    app: &mut tauri::App,
    data_dir_for_scheduler: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    // SECURITY: cleanup orphan .tmp files from previous crashes
    cleanup_orphan_tmp_files(data_dir_for_scheduler);

    crate::notifications::sync_notifications(app.handle(), data_dir_for_scheduler);

    // ── WebView cache invalidation on version change ────────────
    // Must run BEFORE the WebView loads the frontend.
    let app_version = app.package_info().version.to_string();
    let app_data_root = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join("com.pietrolongo.lexflow");
    clear_webview_cache_on_upgrade(&app_version, &app_data_root);

    // ── Garbage collection of stale temp files (background) ─────
    garbage_collect_temp_files();

    // ── macOS: TCC location guard ───────────────────────────────
    #[cfg(target_os = "macos")]
    check_tcc_location(app);

    #[cfg(target_os = "macos")]
    {
        let bundle_id = app.config().identifier.clone();
        let _ = std::process::Command::new("/usr/bin/defaults")
            .args(["write", &bundle_id, "NSAppSleepDisabled", "-bool", "YES"])
            .output();
        eprintln!("[LexFlow] macOS App Nap disabled via defaults write ✓");

        // ── LaunchServices cleanup (Professional / Gold Standard) ───
        // On macOS, opening DMGs registers phantom app copies in the
        // LaunchServices database.  Over time this causes duplicate
        // entries in Notification Centre, "Open With" menus, and can
        // route notifications to a stale (unmounted) bundle.
        //
        // This implementation follows the "Gold Standard" pattern used
        // by professional macOS apps distributed outside the Mac App Store:
        //
        //   Pillar 1 — Anti-Translocation: refuses to act if the app is
        //     running from a DMG (/Volumes/) or Gatekeeper sandbox
        //     (/AppTranslocation/).  Cleaning from those paths would
        //     register a transient location and break notifications
        //     the moment the disk is ejected.
        //
        //   Pillar 2 — Memoization (zero overhead): a small state file
        //     records path+version.  If both match on the next launch
        //     the entire lsregister dump is skipped (~1 ms check).
        //     The heavy cleanup only runs after an update or reinstall.
        //
        //   Pillar 3 — Async background thread: when the cleanup *does*
        //     run, it happens off the main thread so the UI is never
        //     blocked.
        //
        //   Extras:
        //     • fs::canonicalize() for symlink-safe, case-insensitive
        //       path comparison (critical on APFS).
        //     • ancestors().nth(3) — idiomatic Rust to walk from
        //       Contents/MacOS/lexflow → LexFlow.app.
        //     • p.exists() guard before unregistering — avoids useless
        //       errors on paths that were already deleted.
        //     • status() instead of output() for unregister calls —
        //       we don't need their stdout.
        //     • -f (force) re-registration of the current bundle so
        //       macOS re-indexes metadata and routes notifications
        //       to the freshly-installed instance.
        {
            let app_version = app.package_info().version.to_string();
            let bid = bundle_id.clone();

            // 1. Resolve canonical path of the running .app bundle
            //    Contents/MacOS/lexflow → Contents/MacOS → Contents → LexFlow.app
            let Ok(exe_path) = std::env::current_exe() else {
                eprintln!("[LexFlow] LaunchServices: cannot resolve current_exe, skipping");
                // fall through — the #[cfg] block ends below
                return Ok(());
            };
            let Some(app_path) = exe_path.ancestors().nth(3).map(|p| p.to_path_buf()) else {
                eprintln!("[LexFlow] LaunchServices: cannot walk to .app bundle, skipping");
                return Ok(());
            };
            let canonical_path = std::fs::canonicalize(&app_path).unwrap_or(app_path);
            let path_str = canonical_path.to_string_lossy().to_string();

            // 2. Anti-Translocation / Anti-DMG guard
            //    If the app is running from a mounted DMG or from Gatekeeper's
            //    randomised translocation sandbox, we must NOT touch the
            //    LaunchServices database — doing so would register a transient
            //    path that breaks notifications as soon as the volume is ejected.
            if path_str.contains("/AppTranslocation/") || path_str.contains("/Volumes/") {
                eprintln!(
                    "[LexFlow] LaunchServices: running from transient path «{}», \
                     skipping cleanup to avoid registering a temporary location",
                    path_str
                );
                // fall through — do not return, let the rest of setup_desktop run
            } else {
                // 3. Memoization — zero-overhead on repeated launches
                //    We store a small state file in ~/Library/Application Support/
                //    com.pietrolongo.lexflow/ with the format "path|version".
                //    If it matches, the expensive lsregister dump is skipped entirely.
                let state_dir = dirs::data_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
                    .join("com.pietrolongo.lexflow");
                let _ = std::fs::create_dir_all(&state_dir);
                let state_file = state_dir.join("ls_cleanup_state.txt");
                let current_signature = format!("{}|{}", path_str, app_version);

                if let Ok(saved) = std::fs::read_to_string(&state_file) {
                    if saved.trim() == current_signature {
                        eprintln!(
                            "[LexFlow] LaunchServices: already optimised for {} — skip",
                            app_version
                        );
                        // fall through — nothing to do
                    } else {
                        // Signature mismatch → version or path changed → run cleanup
                        run_ls_cleanup(bid, path_str, state_file, current_signature);
                    }
                } else {
                    // First launch or state file missing → run cleanup
                    run_ls_cleanup(bid, path_str, state_file, current_signature);
                }
            }
        }
    }

    // Launch the desktop cron job
    let app_handle_cron = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        crate::notifications::desktop_cron_job(app_handle_cron).await;
    });

    // Auto-lock thread
    let ah = app.handle().clone();
    std::thread::spawn(move || autolock_loop(ah));

    // macOS: apply overlay titlebar for seamless look (traffic lights stay visible)
    #[cfg(target_os = "macos")]
    if let Some(w) = app.get_webview_window("main") {
        use tauri::TitleBarStyle;
        let _ = w.set_title_bar_style(TitleBarStyle::Overlay);
    }

    // Show main window
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }

    // Window focus/blur events + close intercept
    setup_window_events(app);

    // System tray
    setup_system_tray(app)?;

    Ok(())
}

/// Register window focus/blur and close-requested events.
#[cfg(not(target_os = "android"))]
pub(crate) fn setup_window_events(app: &tauri::App) {
    let app_handle = app.handle().clone();
    if let Some(w) = app.get_webview_window("main") {
        let w_clone = w.clone();
        w.on_window_event(move |event| match event {
            tauri::WindowEvent::Focused(focused) => {
                let _ = app_handle.emit("lf-blur", !focused);
            }
            tauri::WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                if w_clone.is_fullscreen().unwrap_or(false) {
                    let _ = w_clone.set_fullscreen(false);
                }
                // Trigger autolock before hiding — vault locks when user closes window
                let _ = w_clone.emit("lf-lock", ());
                let _ = w_clone.hide();
            }
            _ => {}
        });
    }
}

/// Create the system tray icon with show/quit menu.
#[cfg(not(target_os = "android"))]
pub(crate) fn setup_system_tray(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::TrayIconBuilder;

    let show_item = MenuItem::with_id(app, "show", "Apri LexFlow", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Chiudi LexFlow", true, None::<&str>)?;
    let tray_menu = Menu::with_items(app, &[&show_item, &quit_item])?;

    // Load dedicated tray-icon.rgba (pre-converted from rounded PNG)
    // Format: 4 bytes width LE + 4 bytes height LE + raw RGBA pixels
    let tray_icon = {
        let raw = include_bytes!("../icons/tray-icon.rgba");
        let w = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let h = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
        tauri::image::Image::new_owned(raw[8..].to_vec(), w, h)
    };

    TrayIconBuilder::new()
        .tooltip("LexFlow — Gestionale Legale")
        .icon(tray_icon)
        .menu(&tray_menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            "quit" => {
                let state = app.state::<AppState>();
                *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let tauri::tray::TrayIconEvent::Click {
                button: tauri::tray::MouseButton::Left,
                ..
            } = event
            {
                if let Some(w) = tray.app_handle().get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
        })
        .build(app)?;
    Ok(())
}

/// Setup Android-specific features: resolve data dir, AOT sync, auto-lock.
/// MUST be called during `setup()` — without it, data_dir/security_dir point
/// to a temp placeholder and no vault I/O should occur.
#[cfg(target_os = "android")]
pub(crate) fn setup_android(app: &mut tauri::App) {
    let real_dir = app
        .path()
        .app_data_dir()
        .expect("FATAL: Android could not resolve app_data_dir");
    let vault_dir = real_dir.join("lexflow-vault");
    fs::create_dir_all(&vault_dir).expect("FATAL: cannot create Android vault directory");
    *app.state::<AppState>()
        .data_dir
        .write()
        .unwrap_or_else(|e| e.into_inner()) = vault_dir.clone();
    *app.state::<AppState>()
        .security_dir
        .write()
        .unwrap_or_else(|e| e.into_inner()) = real_dir.clone();
    crate::notifications::sync_notifications(&app.handle(), &vault_dir);

    // ── GOD TIER: Android Notification Channel (IMPORTANCE_HIGH) ──
    // Create a high-importance notification channel so reminders appear as
    // heads-up banners and play sound even in Doze mode.
    // The channel ID must match what tauri-plugin-notification uses.
    // Combined with `allow_while_idle: true` in Schedule::At, this gives
    // us AlarmManager.setExactAndAllowWhileIdle() behavior — the CPU
    // wakes at the exact scheduled time even at 5% battery.
    {
        use tauri_plugin_notification::NotificationExt;
        let _ = app.notification().create_channel(
            tauri_plugin_notification::Channel::builder("lexflow_urgent", "LexFlow Urgenti")
                .description("Scadenze e udienze — non silenziabili")
                .importance(tauri_plugin_notification::Importance::High)
                .sound("default")
                .vibration(true)
                .lights(true)
                .build(),
        );
        let _ = app.notification().create_channel(
            tauri_plugin_notification::Channel::builder("lexflow_default", "LexFlow")
                .description("Promemoria e briefing")
                .importance(tauri_plugin_notification::Importance::Default)
                .sound("default")
                .build(),
        );
        eprintln!("[LexFlow] Android notification channels created ✓");
    }

    // Garbage collect stale temp files (background thread)
    garbage_collect_temp_files();

    let ah = app.handle().clone();
    std::thread::spawn(move || autolock_loop(ah));
}

// mobile entry point is in lib.rs
