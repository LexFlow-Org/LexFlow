// ═══════════════════════════════════════════════════════════
//  LOCKOUT — Brute-force protection with exponential backoff
// ═══════════════════════════════════════════════════════════
//
//  v4 upgrade: exponential delays instead of flat 5min lockout.
//  After 10 failed attempts: wipe DEK from keystore.
//  Delays: [0, 0, 0, 5s, 15s, 30s, 60s, 300s, 900s, ...]

use crate::constants::*;
use crate::io::atomic_write_with_sync;
use crate::platform::get_local_encryption_key;
use crate::state::AppState;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::fs;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::State;

/// Exponential backoff delays in seconds, indexed by (attempts - 3).
/// First 3 attempts have no delay. After 10 total: DEK wiped from keystore.
const BACKOFF_DELAYS: &[u64] = &[5, 15, 30, 60, 300, 900];

/// After this many failed attempts, wipe DEK from native keystore.
const DEK_WIPE_THRESHOLD: u32 = 10;

fn lockout_hmac(data: &str) -> String {
    let key = get_local_encryption_key();
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("HMAC can take key of any size");
    mac.update(b"LOCKOUT-INTEGRITY:");
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub(crate) fn lockout_load(data_dir: &std::path::Path) -> (u32, Option<SystemTime>) {
    let path = data_dir.join(LOCKOUT_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return (0, None),
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return (0, None);
    }
    let parts: Vec<&str> = trimmed.splitn(3, ':').collect();
    if parts.len() != 3 {
        eprintln!("[SECURITY] Lockout file format invalid — fail-closed (enforcing max attempts)");
        return (DEK_WIPE_THRESHOLD, None);
    }
    let data_part = format!("{}:{}", parts[0], parts[1]);
    let stored_hmac = parts[2];
    let hmac_valid = hex::decode(stored_hmac)
        .ok()
        .map(|stored_bytes| {
            let key = get_local_encryption_key();
            let mut verify_mac =
                <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("HMAC can take key of any size");
            verify_mac.update(b"LOCKOUT-INTEGRITY:");
            verify_mac.update(data_part.as_bytes());
            verify_mac.verify_slice(&stored_bytes).is_ok()
        })
        .unwrap_or(false);
    if !hmac_valid {
        eprintln!("[SECURITY] Lockout file HMAC mismatch — possible tampering. Fail-closed.");
        return (DEK_WIPE_THRESHOLD, None);
    }
    let attempts = parts[0].parse::<u32>().unwrap_or(DEK_WIPE_THRESHOLD);
    let lockout_end_secs = parts[1].parse::<u64>().unwrap_or(0);
    if lockout_end_secs == 0 {
        return (attempts, None);
    }
    let end = UNIX_EPOCH + Duration::from_secs(lockout_end_secs);
    (attempts, Some(end))
}

pub(crate) fn lockout_save(
    data_dir: &std::path::Path,
    attempts: u32,
    locked_until: Option<SystemTime>,
) {
    let secs = locked_until
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let data_part = format!("{}:{}", attempts, secs);
    let hmac = lockout_hmac(&data_part);
    let content = format!("{}:{}", data_part, hmac);
    let _ = atomic_write_with_sync(&data_dir.join(LOCKOUT_FILE), content.as_bytes());
}

pub(crate) fn lockout_clear(data_dir: &std::path::Path) {
    let _ = fs::remove_file(data_dir.join(LOCKOUT_FILE));
}

/// Compute the lockout duration for a given attempt count.
/// Returns None if no lockout needed, Some(seconds) otherwise.
fn compute_backoff_duration(attempts: u32) -> Option<u64> {
    if attempts < 3 {
        return None;
    }
    let idx = ((attempts - 3) as usize).min(BACKOFF_DELAYS.len() - 1);
    Some(BACKOFF_DELAYS[idx])
}

pub(crate) fn check_lockout(
    state: &State<AppState>,
    sec_dir: &std::path::Path,
) -> Result<(), Value> {
    let (disk_attempts, disk_locked_until) = lockout_load(sec_dir);
    {
        let mut att = state
            .failed_attempts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if disk_attempts > *att {
            *att = disk_attempts;
        }
    }
    // Check disk-based lockout (persists across restarts)
    if let Some(end_time) = disk_locked_until {
        let now = SystemTime::now();
        if now < end_time {
            let remaining = end_time
                .duration_since(now)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let att = *state
                .failed_attempts
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            return Err(json!({
                "success": false, "valid": false, "locked": true,
                "remaining": remaining,
                "attempts": att,
                "maxAttempts": DEK_WIPE_THRESHOLD,
            }));
        }
    }
    // Check in-memory lockout (Instant-based, within-session)
    if let Some(until) = *state.locked_until.lock().unwrap_or_else(|e| e.into_inner()) {
        if Instant::now() < until {
            let att = *state
                .failed_attempts
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            return Err(json!({
                "success": false, "valid": false, "locked": true,
                "remaining": (until - Instant::now()).as_secs(),
                "attempts": att,
                "maxAttempts": DEK_WIPE_THRESHOLD,
            }));
        }
    }
    Ok(())
}

pub(crate) fn record_failed_attempt(state: &State<AppState>, sec_dir: &std::path::Path) {
    let mut att = state
        .failed_attempts
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *att += 1;

    // Compute exponential backoff
    let lockout_secs = compute_backoff_duration(*att);
    let locked_sys = lockout_secs.map(|secs| {
        let t = SystemTime::now() + Duration::from_secs(secs);
        *state.locked_until.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Instant::now() + Duration::from_secs(secs));
        t
    });

    lockout_save(sec_dir, *att, locked_sys);

    eprintln!(
        "[SECURITY] Failed auth attempt #{}/{} at {}{}{}",
        *att,
        DEK_WIPE_THRESHOLD,
        chrono::Local::now().to_rfc3339(),
        if let Some(secs) = lockout_secs {
            format!(" → LOCKOUT {}s", secs)
        } else {
            String::new()
        },
        if *att >= DEK_WIPE_THRESHOLD {
            " → DEK WIPE TRIGGERED"
        } else {
            ""
        }
    );

    // After DEK_WIPE_THRESHOLD: wipe DEK from native keystore
    if *att >= DEK_WIPE_THRESHOLD {
        wipe_dek_from_keystore();
    }
}

/// Wipe cached DEK from the native keystore (biometric credentials).
/// After this, the user must re-enter their password — biometric unlock is disabled.
fn wipe_dek_from_keystore() {
    #[cfg(not(target_os = "android"))]
    {
        let user = whoami::username();
        if let Ok(entry) = keyring::Entry::new(BIO_SERVICE, &user) {
            let _ = entry.delete_credential();
        }
        eprintln!(
            "[SECURITY] DEK wiped from keystore after {} failed attempts",
            DEK_WIPE_THRESHOLD
        );
    }
}

pub(crate) fn clear_lockout(state: &State<AppState>, sec_dir: &std::path::Path) {
    *state
        .failed_attempts
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = 0;
    *state.locked_until.lock().unwrap_or_else(|e| e.into_inner()) = None;
    lockout_clear(sec_dir);
}
