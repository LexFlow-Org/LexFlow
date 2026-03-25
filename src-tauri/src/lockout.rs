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
pub(crate) const DEK_WIPE_THRESHOLD: u32 = 10;

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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (0, None),
        Err(_) => {
            // SECURITY FIX: non-NotFound error = fail-closed (don't reset counter)
            eprintln!("[SECURITY] Lockout file read error (not NotFound) — fail-closed");
            return (DEK_WIPE_THRESHOLD, None);
        }
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
    // FIX: reuse key instead of deriving twice
    let verify_key = get_local_encryption_key();
    let hmac_valid = hex::decode(stored_hmac)
        .ok()
        .map(|stored_bytes| {
            let mut verify_mac = <Hmac<Sha256> as Mac>::new_from_slice(&verify_key)
                .expect("HMAC can take key of any size");
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
    // FIX: log write error instead of silently ignoring
    if let Err(e) = atomic_write_with_sync(&data_dir.join(LOCKOUT_FILE), content.as_bytes()) {
        eprintln!(
            "[SECURITY] WARNING: lockout file write failed: {}. In-memory lockout still active.",
            e
        );
    }
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
                "remaining": until.checked_duration_since(Instant::now()).unwrap_or(Duration::ZERO).as_secs(),
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
            if let Err(e) = entry.delete_credential() {
                eprintln!("[SECURITY] WARNING: failed to wipe DEK from keystore: {:?}. Biometric bypass may remain active!", e);
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("lexflow_lockout_test_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn ensure_machine_id() {
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
        {
            let _ = crate::platform::MACHINE_ID_CACHE.set("test_machine_id_for_lockout".to_string());
        }
    }

    #[test]
    fn test_lockout_save_load_roundtrip() {
        ensure_machine_id();
        let dir = test_dir();
        lockout_save(&dir, 5, None);
        let (attempts, locked_until) = lockout_load(&dir);
        assert_eq!(attempts, 5);
        assert!(locked_until.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_lockout_save_load_with_time() {
        ensure_machine_id();
        let dir = test_dir();
        let future = SystemTime::now() + Duration::from_secs(300);
        lockout_save(&dir, 7, Some(future));
        let (attempts, locked_until) = lockout_load(&dir);
        assert_eq!(attempts, 7);
        assert!(locked_until.is_some());
        // Locked until should be roughly 300s from now
        let remaining = locked_until
            .unwrap()
            .duration_since(SystemTime::now())
            .unwrap()
            .as_secs();
        assert!(remaining > 290 && remaining <= 300);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_lockout_load_missing_file() {
        ensure_machine_id();
        let dir = test_dir();
        let (attempts, locked_until) = lockout_load(&dir);
        assert_eq!(attempts, 0);
        assert!(locked_until.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_lockout_load_tampered_hmac() {
        ensure_machine_id();
        let dir = test_dir();
        lockout_save(&dir, 3, None);
        // Tamper the file
        let path = dir.join(LOCKOUT_FILE);
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = format!("{}TAMPERED", content);
        std::fs::write(&path, tampered).unwrap();
        let (attempts, _) = lockout_load(&dir);
        assert_eq!(attempts, DEK_WIPE_THRESHOLD, "Tampered HMAC → fail-closed");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_lockout_load_invalid_format() {
        ensure_machine_id();
        let dir = test_dir();
        let path = dir.join(LOCKOUT_FILE);
        std::fs::write(&path, "garbage data without colons").unwrap();
        let (attempts, _) = lockout_load(&dir);
        assert_eq!(attempts, DEK_WIPE_THRESHOLD, "Invalid format → fail-closed");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_lockout_load_empty_file() {
        ensure_machine_id();
        let dir = test_dir();
        let path = dir.join(LOCKOUT_FILE);
        std::fs::write(&path, "").unwrap();
        let (attempts, _) = lockout_load(&dir);
        assert_eq!(attempts, 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_lockout_clear() {
        ensure_machine_id();
        let dir = test_dir();
        lockout_save(&dir, 5, None);
        assert!(dir.join(LOCKOUT_FILE).exists());
        lockout_clear(&dir);
        assert!(!dir.join(LOCKOUT_FILE).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_compute_backoff_no_delay_first_3() {
        assert!(compute_backoff_duration(0).is_none());
        assert!(compute_backoff_duration(1).is_none());
        assert!(compute_backoff_duration(2).is_none());
    }

    #[test]
    fn test_compute_backoff_exponential() {
        assert_eq!(compute_backoff_duration(3), Some(5));
        assert_eq!(compute_backoff_duration(4), Some(15));
        assert_eq!(compute_backoff_duration(5), Some(30));
        assert_eq!(compute_backoff_duration(6), Some(60));
        assert_eq!(compute_backoff_duration(7), Some(300));
        assert_eq!(compute_backoff_duration(8), Some(900));
    }

    #[test]
    fn test_compute_backoff_saturates() {
        // Beyond BACKOFF_DELAYS length → stays at last value
        assert_eq!(compute_backoff_duration(100), Some(900));
        assert_eq!(compute_backoff_duration(255), Some(900));
    }

    #[test]
    fn test_lockout_hmac_deterministic() {
        ensure_machine_id();
        let h1 = lockout_hmac("5:0");
        let h2 = lockout_hmac("5:0");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_lockout_hmac_different_data() {
        ensure_machine_id();
        let h1 = lockout_hmac("5:0");
        let h2 = lockout_hmac("6:0");
        assert_ne!(h1, h2);
    }

    // ─── Attacker simulation: file replacement ───────────────

    #[test]
    fn test_attacker_resets_counter_to_zero() {
        ensure_machine_id();
        let dir = test_dir();
        lockout_save(&dir, 9, None);
        // Attacker writes a fake lockout file with 0 attempts
        let path = dir.join(LOCKOUT_FILE);
        std::fs::write(&path, "0:0:fakehash").unwrap();
        let (attempts, _) = lockout_load(&dir);
        // HMAC mismatch → fail-closed at max
        assert_eq!(attempts, DEK_WIPE_THRESHOLD);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_attacker_deletes_lockout_file() {
        ensure_machine_id();
        let dir = test_dir();
        lockout_save(&dir, 8, Some(SystemTime::now() + Duration::from_secs(900)));
        // Attacker deletes the file
        std::fs::remove_file(dir.join(LOCKOUT_FILE)).unwrap();
        let (attempts, _) = lockout_load(&dir);
        // File missing → resets to 0 (attacker wins this one, but in-memory state persists)
        assert_eq!(attempts, 0);
        std::fs::remove_dir_all(&dir).ok();
    }
}
