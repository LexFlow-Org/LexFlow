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

/// Exponential backoff delays in seconds, indexed by (attempts - 3).
/// First 3 attempts have no delay. After 10 total: DEK wiped from keystore.
const BACKOFF_DELAYS: &[u64] = &[5, 15, 30, 60, 300, 900];

/// After this many failed attempts, wipe DEK from native keystore.
pub(crate) const DEK_WIPE_THRESHOLD: u32 = 10;

/// CONC-LO-2 (audit): every poisoning recovery now logs a `[lockout] WARN` line via
/// inline `unwrap_or_else` blocks, so a thread that panicked while holding a
/// lockout-related lock leaves a visible breadcrumb in stderr.
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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // SECURITY FIX: lockout_clear now writes a signed zero file instead of
            // deleting. A missing file means either fresh install or manual deletion.
            // Treat cautiously: return half the wipe threshold so the user still gets
            // a few attempts but an attacker can't fully reset the counter.
            eprintln!("[SECURITY] Lockout file missing — treating as suspicious (half-threshold)");
            return (DEK_WIPE_THRESHOLD / 2, None);
        }
        Err(_) => {
            // SECURITY FIX: non-NotFound error = fail-closed (don't reset counter)
            eprintln!("[SECURITY] Lockout file read error (not NotFound) — fail-closed");
            return (DEK_WIPE_THRESHOLD, None);
        }
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        // SECURITY FIX: empty file is suspicious (lockout_clear writes a signed zero file)
        eprintln!("[SECURITY] Lockout file empty — treating as suspicious (half-threshold)");
        return (DEK_WIPE_THRESHOLD / 2, None);
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
) -> Result<(), String> {
    // SEC-LO-4 (audit): lockout file inherits 0600 from `atomic_write_with_sync`
    // (which writes via secure_write) and the parent security dir is hardened to
    // 0700 by setup.rs (`harden_dir_0700` on app_data_root, state_dir, vault_dir).
    // We do NOT recreate or chmod the directory from here — that would race with
    // other components and silently undo a tighter mode an admin might have set.
    // TODO(audit:CONC-LO-1): add fs2 file lock to serialize concurrent
    // record_failed_attempt across processes. With a single-instance mutex on
    // Windows and the practical assumption of one user-process on macOS/Linux
    // we already get serial behaviour, but two child processes (e.g. a CLI
    // helper running while the GUI is open) could race-write the lockout file
    // and lose increments. Use `fs2::FileExt::lock_exclusive` here.
    let secs = locked_until
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let data_part = format!("{}:{}", attempts, secs);
    let hmac = lockout_hmac(&data_part);
    let content = format!("{}:{}", data_part, hmac);
    let path = data_dir.join(LOCKOUT_FILE);
    // BUG-LO-2 (audit): retry once on transient I/O errors instead of failing closed
    // permanently — a momentarily-locked AV / antivirus scan should not lock the user
    // out of the lockout file itself.
    match atomic_write_with_sync(&path, content.as_bytes()) {
        Ok(()) => Ok(()),
        Err(e1) => {
            std::thread::sleep(Duration::from_millis(50));
            match atomic_write_with_sync(&path, content.as_bytes()) {
                Ok(()) => Ok(()),
                Err(e2) => {
                    let msg = format!(
                        "[SECURITY] WARNING: lockout file write failed (retry): {} (initial: {}). In-memory lockout still active.",
                        e2, e1
                    );
                    eprintln!("{}", msg);
                    Err(msg)
                }
            }
        }
    }
}

pub(crate) fn lockout_clear(data_dir: &std::path::Path) {
    // Write a zeroed-and-signed file instead of deleting.
    // This way, a missing file is suspicious (manual deletion) and can be
    // treated more cautiously in lockout_load.
    if let Err(e) = lockout_save(data_dir, 0, None) {
        eprintln!("[SECURITY] lockout_clear failed to write zero file: {}", e);
    }
}

/// Compute the lockout duration for a given attempt count.
/// Returns None if no lockout needed, Some(seconds) otherwise.
///
/// BUG-LO-3 (audit): if BACKOFF_DELAYS is ever shrunk to empty (e.g. by mistake
/// in a refactor), `BACKOFF_DELAYS.len() - 1` would underflow on `usize` and
/// the indexing would panic. Use `last().copied().unwrap_or(60)` so we degrade
/// to a sane 60s lockout instead of crashing.
fn compute_backoff_duration(attempts: u32) -> Option<u64> {
    if attempts < 3 {
        return None;
    }
    if BACKOFF_DELAYS.is_empty() {
        return Some(BACKOFF_DELAYS.last().copied().unwrap_or(60));
    }
    let idx = ((attempts - 3) as usize).min(BACKOFF_DELAYS.len() - 1);
    Some(BACKOFF_DELAYS[idx])
}

/// L15: SECURITY NOTE — Two-tier lockout design:
/// 1. In-memory lockout uses `Instant` (monotonic clock) — this is the PRIMARY defense
///    within a session and cannot be bypassed by clock manipulation.
/// 2. Disk-based lockout uses `SystemTime` — this is a SECONDARY measure that survives
///    app restarts but IS susceptible to clock manipulation (setting the system clock
///    forward to expire the lockout). The HMAC-signed lockout file prevents counter
///    reset, so an attacker can at most skip the wait period, not the attempt count.
pub(crate) fn check_lockout(state: &AppState, sec_dir: &std::path::Path) -> Result<(), Value> {
    let (disk_attempts, disk_locked_until) = lockout_load(sec_dir);
    {
        let mut att = state.failed_attempts.lock().unwrap_or_else(|e| {
            eprintln!("[lockout] WARN: mutex poisoned, recovering: {}", e);
            e.into_inner()
        });
        if disk_attempts > *att {
            *att = disk_attempts;
        }
    }
    // Check disk-based lockout (persists across restarts, but susceptible to clock manipulation)
    if let Some(end_time) = disk_locked_until {
        let now = SystemTime::now();

        // SEC-LO-2 (audit): system-clock rollback defence. Persist a high-water
        // mark of the latest SystemTime we've ever observed. If `now` is more
        // than HIGH_WATER_GRACE_SECS *behind* that mark, the user has rolled
        // the clock backwards (or DST/timezone artefact). Treat the lockout
        // as still active rather than letting the rollback skip the wait.
        const HIGH_WATER_GRACE_SECS: u64 = 30;
        let high_water_path = sec_dir.join(".lockout_hwm");
        let current_secs = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let stored_hwm = std::fs::read_to_string(&high_water_path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let mut clock_rollback = false;
        if stored_hwm > 0 && current_secs + HIGH_WATER_GRACE_SECS < stored_hwm {
            eprintln!(
                "[SECURITY] clock rollback detected (now={} hwm={}) — keeping lockout active",
                current_secs, stored_hwm
            );
            clock_rollback = true;
        }
        // Refresh the high-water mark forward (best-effort).
        if current_secs > stored_hwm {
            let _ = atomic_write_with_sync(&high_water_path, current_secs.to_string().as_bytes());
        }

        if clock_rollback || now < end_time {
            let remaining = if clock_rollback {
                // Show the full original remaining window — we don't trust `now`.
                end_time
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs().saturating_sub(stored_hwm))
                    .unwrap_or(0)
            } else {
                end_time
                    .duration_since(now)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            };
            let att = *state.failed_attempts.lock().unwrap_or_else(|e| {
                eprintln!("[lockout] WARN: mutex poisoned, recovering: {}", e);
                e.into_inner()
            });
            return Err(json!({
                "success": false, "valid": false, "locked": true,
                "remaining": remaining,
                "attempts": att,
                "maxAttempts": DEK_WIPE_THRESHOLD,
            }));
        }
    }
    check_memory_lockout(state)
}

fn check_memory_lockout(state: &AppState) -> Result<(), Value> {
    // Release the deadline mutex before acquiring failed_attempts. An if-let
    // scrutinee guard lives through its body and inverted the writer's order.
    let deadline = *state.locked_until.lock().unwrap_or_else(|e| {
        eprintln!("[lockout] WARN: mutex poisoned, recovering: {}", e);
        e.into_inner()
    });
    if let Some(until) = deadline {
        if Instant::now() < until {
            let att = *state.failed_attempts.lock().unwrap_or_else(|e| {
                eprintln!("[lockout] WARN: mutex poisoned, recovering: {}", e);
                e.into_inner()
            });
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

/// Caller holds write_mutex throughout credential verification and failure.
pub(crate) fn record_failed_attempt_locked(state: &AppState, sec_dir: &std::path::Path) {
    record_failed_attempt_with_cleanup(state, sec_dir, wipe_dek_from_keystore);
}

fn record_failed_attempt_with_cleanup(
    state: &AppState,
    sec_dir: &std::path::Path,
    cleanup_keystore: impl FnOnce(),
) {
    let mut att = state.failed_attempts.lock().unwrap_or_else(|e| {
        eprintln!("[lockout] WARN: mutex poisoned, recovering: {}", e);
        e.into_inner()
    });
    *att = att.saturating_add(1);

    // Compute exponential backoff
    let lockout_secs = compute_backoff_duration(*att);
    // BUG-LO-1 (audit): when no lockout is needed (lockout_secs.is_none()), explicitly
    // clear `state.locked_until` so we don't leak a stale Instant from a prior attempt.
    if lockout_secs.is_none() {
        *state.locked_until.lock().unwrap_or_else(|e| {
            eprintln!(
                "[lockout] WARN: locked_until mutex poisoned, recovering: {}",
                e
            );
            e.into_inner()
        }) = None;
    }
    let locked_sys = lockout_secs.map(|secs| {
        // SEC-LO-5 (audit): sanity-check the persisted end_time. If `now + secs` somehow
        // already lies in the past (system clock skew, integer wrap), refuse to persist
        // a useless past-date and reset to a fresh future window instead.
        let now = SystemTime::now();
        let mut end = now + Duration::from_secs(secs);
        if end <= now {
            eprintln!(
                "[SECURITY] WARN: computed lockout_end is not in the future ({}s); resetting to now+{}s",
                secs, secs
            );
            end = SystemTime::now() + Duration::from_secs(secs);
        }
        *state.locked_until.lock().unwrap_or_else(|e| {
            eprintln!("[lockout] WARN: mutex poisoned, recovering: {}", e);
            e.into_inner()
        }) =
            Some(Instant::now() + Duration::from_secs(secs));
        end
    });

    if let Err(e) = lockout_save(sec_dir, *att, locked_sys) {
        eprintln!(
            "[SECURITY] record_failed_attempt: lockout persist failed: {}",
            e
        );
    }

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

    // After DEK_WIPE_THRESHOLD: wipe DEK from native keystore AND from memory.
    // SEC-LO-1 (audit): the previous TODO note shifted in-memory wipe responsibility
    // to every caller. Centralise it via wipe_dek_full so we can never forget.
    if *att >= DEK_WIPE_THRESHOLD {
        // Drop the failed_attempts mutex before reaching into other AppState slots
        // to avoid lock-ordering surprises.
        drop(att);
        // Same transaction as the failure count: a concurrent read cannot
        // restore plaintext cache between key revocation and cache scrubbing.
        state.lock_vault_locked();
        cleanup_keystore();
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
    // TODO(audit:SEC-LO-6): implement keystore wipe for Android (currently no-op).
    // The Android Keystore biometric DEK is rooted in the platform StrongBox/TEE; we
    // need a JNI bridge here to call KeyStore.deleteEntry() with the right alias.
}

pub(crate) fn clear_lockout(state: &AppState, sec_dir: &std::path::Path) {
    *state.failed_attempts.lock().unwrap_or_else(|e| {
        eprintln!("[lockout] WARN: mutex poisoned, recovering: {}", e);
        e.into_inner()
    }) = 0;
    *state.locked_until.lock().unwrap_or_else(|e| {
        eprintln!("[lockout] WARN: mutex poisoned, recovering: {}", e);
        e.into_inner()
    }) = None;
    lockout_clear(sec_dir);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir() -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("lexflow_lockout_test_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn ensure_machine_id() {
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
        {
            let _ =
                crate::platform::MACHINE_ID_CACHE.set("test_machine_id_for_lockout".to_string());
        }
    }

    #[test]
    fn lockout_threshold_clears_keys_cache_version_before_fake_keystore_cleanup() {
        ensure_machine_id();
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::new(dir.path().join("vault"), dir.path().to_path_buf());
        *state.vault_key.lock().unwrap() = Some(crate::state::SecureKey::new(
            zeroize::Zeroizing::new(vec![1; 32]),
        ));
        *state.vault_dek.lock().unwrap() = Some(crate::state::SecureKey::new(
            zeroize::Zeroizing::new(vec![2; 32]),
        ));
        *state.vault_version.write().unwrap() = 8;
        *state.vault_cache.write().unwrap() = Some(json!({"client": "Synthetic private record"}));
        let session = state.document_session().unwrap();
        *state.failed_attempts.lock().unwrap() = DEK_WIPE_THRESHOLD - 1;
        let _transaction = state.write_mutex.lock().unwrap();
        let mut cleanup_called = false;
        record_failed_attempt_with_cleanup(&state, dir.path(), || {
            cleanup_called = true;
            assert!(state.vault_key.lock().unwrap().is_none());
            assert!(state.vault_dek.lock().unwrap().is_none());
            assert!(state.vault_cache.read().unwrap().is_none());
            assert_eq!(*state.vault_version.read().unwrap(), 0);
            assert!(state.validate_document_session(session).is_err());
        });
        assert!(cleanup_called);
        assert_eq!(lockout_load(dir.path()).0, DEK_WIPE_THRESHOLD);
    }

    #[test]
    fn exhausted_attempt_counter_saturates_and_still_revokes_session() {
        ensure_machine_id();
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::new(dir.path().join("vault"), dir.path().to_path_buf());
        *state.failed_attempts.lock().unwrap() = u32::MAX;
        *state.vault_cache.write().unwrap() = Some(json!({"client": "Synthetic"}));
        let _transaction = state.write_mutex.lock().unwrap();
        record_failed_attempt_with_cleanup(&state, dir.path(), || {});
        assert_eq!(*state.failed_attempts.lock().unwrap(), u32::MAX);
        assert_eq!(lockout_load(dir.path()).0, u32::MAX);
        assert!(state.vault_cache.read().unwrap().is_none());
    }

    #[test]
    fn memory_lockout_check_cannot_deadlock_with_attempt_updates() {
        use std::sync::{mpsc, Arc, Barrier};
        let state = Arc::new(AppState::new(Default::default(), Default::default()));
        *state.locked_until.lock().unwrap() = Some(Instant::now() + Duration::from_secs(60));
        let barrier = Arc::new(Barrier::new(2));
        let (done, received) = mpsc::channel();
        for writer in [false, true] {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            let done = done.clone();
            std::thread::spawn(move || {
                for _ in 0..2_000 {
                    barrier.wait();
                    if writer {
                        let mut attempts = state.failed_attempts.lock().unwrap();
                        std::thread::yield_now();
                        let _deadline = state.locked_until.lock().unwrap();
                        *attempts += 1;
                    } else {
                        assert!(check_memory_lockout(&state).is_err());
                    }
                }
                done.send(()).unwrap();
            });
        }
        // Bound completion so a regression fails instead of hanging the suite.
        for _ in 0..2 {
            received
                .recv_timeout(Duration::from_secs(10))
                .expect("lockout mutex order deadlocked");
        }
    }

    #[test]
    fn test_lockout_save_load_roundtrip() {
        ensure_machine_id();
        let dir = test_dir();
        lockout_save(&dir, 5, None).unwrap();
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
        lockout_save(&dir, 7, Some(future)).unwrap();
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
        // Missing file is now suspicious → half-threshold
        assert_eq!(attempts, DEK_WIPE_THRESHOLD / 2);
        assert!(locked_until.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_lockout_load_tampered_hmac() {
        ensure_machine_id();
        let dir = test_dir();
        lockout_save(&dir, 3, None).unwrap();
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
        // SECURITY FIX: empty file is now suspicious → half-threshold
        assert_eq!(attempts, DEK_WIPE_THRESHOLD / 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_lockout_clear() {
        ensure_machine_id();
        let dir = test_dir();
        lockout_save(&dir, 5, None).unwrap();
        assert!(dir.join(LOCKOUT_FILE).exists());
        lockout_clear(&dir);
        // File should still exist (now written as signed zero instead of deleted)
        assert!(dir.join(LOCKOUT_FILE).exists());
        let (attempts, locked_until) = lockout_load(&dir);
        assert_eq!(attempts, 0);
        assert!(locked_until.is_none());
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
        lockout_save(&dir, 9, None).unwrap();
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
        lockout_save(&dir, 8, Some(SystemTime::now() + Duration::from_secs(900))).unwrap();
        // Attacker deletes the file
        std::fs::remove_file(dir.join(LOCKOUT_FILE)).unwrap();
        let (attempts, _) = lockout_load(&dir);
        // SECURITY FIX: missing file now treated as suspicious → half-threshold
        assert_eq!(attempts, DEK_WIPE_THRESHOLD / 2);
        std::fs::remove_dir_all(&dir).ok();
    }
}
