// ═══════════════════════════════════════════════════════════
//  AUDIT — Encrypted audit log with HMAC tamper-evident chain
// ═══════════════════════════════════════════════════════════

use crate::constants::*;
use crate::crypto::{decrypt_data, encrypt_data};
use crate::io::{atomic_write_with_sync, safe_bounded_read};
use crate::state::{get_vault_key, with_vault_dek, AppState};
use serde_json::{json, Map, Value};
use std::sync::{Mutex, OnceLock};
use tauri::State;
use zeroize::Zeroizing;

/// Max audit log file size: 10 MB (prevents OOM from inflated/tampered file)
const MAX_AUDIT_SIZE: u64 = 10 * 1024 * 1024;

/// Genesis prev_hash placeholder (64 hex chars of zero) for the first chain entry.
const GENESIS_PREV_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Hard error state — once tripped, no further audit appends are accepted until
/// the user acknowledges the corruption. This is a tamper-evident posture.
static AUDIT_HARD_ERROR: OnceLock<Mutex<bool>> = OnceLock::new();

fn audit_hard_error_flag() -> &'static Mutex<bool> {
    AUDIT_HARD_ERROR.get_or_init(|| Mutex::new(false))
}

fn is_audit_locked() -> bool {
    *audit_hard_error_flag()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn set_audit_locked(v: bool) {
    *audit_hard_error_flag()
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = v;
}

/// One-time warning latch for legacy (pre-chain) audit logs.
static LEGACY_LOG_WARNED: OnceLock<Mutex<bool>> = OnceLock::new();

fn warn_legacy_log_once() {
    let cell = LEGACY_LOG_WARNED.get_or_init(|| Mutex::new(false));
    let mut warned = cell.lock().unwrap_or_else(|e| e.into_inner());
    if !*warned {
        eprintln!(
            "[LexFlow] NOTICE: legacy audit log detected (no HMAC chain). Chain will start \
             from genesis on the next append. Existing entries cannot be retroactively verified."
        );
        *warned = true;
    }
}

/// Lock-time audit queue: when the vault is locked we cannot encrypt, so we
/// buffer events here and flush on next unlock via [`flush_pending_audit_events`].
static PENDING_AUDIT: OnceLock<Mutex<Vec<Value>>> = OnceLock::new();

fn pending_audit_queue() -> &'static Mutex<Vec<Value>> {
    PENDING_AUDIT.get_or_init(|| Mutex::new(Vec::new()))
}

/// Drain & flush queued lock-time audit events. Call right after a successful unlock.
#[allow(dead_code)]
pub(crate) fn flush_pending_audit_events(state: &State<AppState>) {
    let drained: Vec<Value> = {
        let mut q = pending_audit_queue()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *q)
    };
    for ev in drained {
        let name = ev
            .get("event")
            .and_then(|v| v.as_str())
            .unwrap_or("PENDING_EVENT")
            .to_string();
        let _ = append_audit_log(state, &name);
    }
}

/// Canonical JSON serialization of an entry for HMAC computation.
///
/// `serde_json::Map` is backed by `BTreeMap` (no `preserve_order` feature in this
/// project), which means `serde_json::to_vec` already produces output with
/// alphabetically-sorted keys and no whitespace — i.e. canonical form. This is
/// the property the HMAC chain relies on for cross-process verification.
fn canonical_json(v: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(v).map_err(|e| format!("canonical_json failed: {}", e))
}

/// Compute HMAC-SHA256 over `prev_canonical || new_canonical`, keyed by the DEK.
fn compute_chain_hmac(key: &[u8], prev_canonical: &[u8], new_canonical: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(prev_canonical);
    mac.update(new_canonical);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Verify a stored hex `prev_hash` against the freshly-computed HMAC, in
/// constant time.
fn verify_chain_hmac(
    key: &[u8],
    prev_canonical: &[u8],
    new_canonical: &[u8],
    expected_hex: &str,
) -> bool {
    use hmac::{Hmac, Mac};
    let expected = match hex::decode(expected_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    let mut mac = match Hmac::<sha2::Sha256>::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(prev_canonical);
    mac.update(new_canonical);
    mac.verify_slice(&expected).is_ok()
}

/// True if the entry is part of the HMAC chain (has both `prev_hash` and `seq`).
fn entry_is_chained(entry: &Value) -> bool {
    entry.get("prev_hash").and_then(|v| v.as_str()).is_some()
        && entry.get("seq").and_then(|v| v.as_u64()).is_some()
}

/// Strip `prev_hash` and `seq` from an entry, returning a new Value used as the
/// HMAC input for the entry itself.
fn entry_without_chain_fields(entry: &Value) -> Value {
    match entry {
        Value::Object(map) => {
            let mut clone: Map<String, Value> = map.clone();
            clone.remove("prev_hash");
            clone.remove("seq");
            Value::Object(clone)
        }
        other => other.clone(),
    }
}

/// Verify the HMAC chain across the loaded log. Returns `Ok(())` if the log is
/// either fully chained and valid, or fully legacy (no chain fields anywhere —
/// in which case a one-time warning is emitted), or starts with legacy entries
/// followed by a contiguous chain that begins at a `audit.chain.genesis` marker
/// (the post-migration shape). On a partial/broken chain it returns `Err` and
/// the caller is expected to set the hard error state.
fn verify_chain(key: &[u8], logs: &[Value]) -> Result<(), String> {
    if logs.is_empty() {
        return Ok(());
    }

    let any_chained = logs.iter().any(entry_is_chained);
    if !any_chained {
        // Pure legacy log — predates the HMAC chain. Don't verify, warn once.
        warn_legacy_log_once();
        return Ok(());
    }

    // Locate the start of the chain: the first chained entry. Everything before
    // it must be legacy (no chain fields). Everything from it onward must be
    // chained, with seq starting at 0 and incrementing by 1.
    let chain_start = logs
        .iter()
        .position(entry_is_chained)
        .expect("any_chained == true implies a position");

    // Pre-chain prefix must be entirely legacy (no chain fields).
    for (idx, entry) in logs[..chain_start].iter().enumerate() {
        if entry_is_chained(entry) {
            return Err(format!(
                "audit log chain broken: chained entry {} appears before chain start",
                idx
            ));
        }
    }
    if chain_start > 0 {
        // Legacy entries precede the chain — same one-time warning.
        warn_legacy_log_once();
    }

    // From `chain_start` onward, every entry must be chained and contiguous.
    let mut prev_canonical: Vec<u8> = Vec::new(); // empty before the genesis link
    let mut expected_seq: u64 = 0;
    for (offset, entry) in logs[chain_start..].iter().enumerate() {
        if !entry_is_chained(entry) {
            return Err(format!(
                "audit log chain broken: legacy entry mixed into chain at offset {}",
                offset
            ));
        }
        let stored_prev_hash =
            entry
                .get("prev_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    format!(
                        "audit log chain broken at chain offset {}: missing prev_hash",
                        offset
                    )
                })?;
        let stored_seq = entry.get("seq").and_then(|v| v.as_u64()).ok_or_else(|| {
            format!(
                "audit log chain broken at chain offset {}: missing seq",
                offset
            )
        })?;

        if stored_seq != expected_seq {
            return Err(format!(
                "audit log chain broken at entry {}: seq {} (expected {})",
                stored_seq, stored_seq, expected_seq
            ));
        }

        let entry_for_hash = entry_without_chain_fields(entry);
        let new_canonical = canonical_json(&entry_for_hash)
            .map_err(|e| format!("audit log chain broken at entry {}: {}", stored_seq, e))?;

        if offset == 0 {
            // Genesis link: prev_hash must equal the all-zero placeholder.
            if stored_prev_hash != GENESIS_PREV_HASH {
                return Err(format!(
                    "audit log chain broken at entry {}: non-genesis prev_hash on first chained entry",
                    stored_seq
                ));
            }
        } else if !verify_chain_hmac(key, &prev_canonical, &new_canonical, stored_prev_hash) {
            return Err(format!("audit log chain broken at entry {}", stored_seq));
        }

        prev_canonical = new_canonical;
        expected_seq = expected_seq.saturating_add(1);
    }
    Ok(())
}

pub(crate) fn append_audit_log(state: &State<AppState>, event_name: &str) -> Result<(), String> {
    if is_audit_locked() {
        eprintln!(
            "[LexFlow] Audit append refused: hard error state (tampering suspected): {}",
            event_name
        );
        return Err("audit log locked due to suspected tampering".into());
    }
    let key = match get_vault_key(state) {
        Ok(k) => k,
        Err(_) => {
            // Vault locked — buffer event in memory and flush on next unlock.
            // SEC-AUDIT-2: do not just print to stderr; preserve the event.
            let mut q = pending_audit_queue()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            // Bound the queue to avoid runaway memory if an attacker spams events.
            const MAX_PENDING: usize = 1024;
            if q.len() < MAX_PENDING {
                q.push(json!({
                    "event": event_name,
                    "time": chrono::Local::now().to_rfc3339(),
                    "queued_while_locked": true,
                }));
            }
            eprintln!(
                "[LexFlow] Audit event buffered (vault locked): {}",
                event_name
            );
            return Ok(());
        }
    };
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let path = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .join(AUDIT_LOG_FILE);
    let mut logs: Vec<Value> = if path.exists() {
        // SECURITY FIX: bounded read prevents OOM from inflated audit file
        let enc = safe_bounded_read(&path, MAX_AUDIT_SIZE).unwrap_or_default();
        match decrypt_data(&key, &enc) {
            Ok(dec) => serde_json::from_slice(&dec).unwrap_or_default(),
            Err(_) => {
                // SEC-AUDIT-1: do NOT silently reset to empty on decrypt failure
                // (that would let an attacker erase history by corrupting the file).
                // Instead: quarantine the corrupt file, set hard error state,
                // refuse new appends until user acknowledges.
                let ts = chrono::Local::now().format("%Y%m%d%H%M%S").to_string();
                let corrupt_backup = path.with_extension(format!("log.corrupt.{}", ts));
                let _ = std::fs::rename(&path, &corrupt_backup);
                eprintln!(
                    "[LexFlow] SECURITY: Audit log decryption failed — tampering suspected. Quarantined to {:?}. New appends BLOCKED until user acknowledges.",
                    corrupt_backup
                );
                set_audit_locked(true);
                return Err(
                    "audit log corrupted/tampered — quarantined; user must acknowledge".into(),
                );
            }
        }
    } else {
        vec![]
    };

    // SEC-AUDIT-1 (HMAC chain): verify the chain on the existing log before
    // appending. If verification fails, set hard error state and refuse the
    // append — an attacker with KEK could otherwise rewrite history coherently.
    //
    // Key selection: prefer the v4 DEK via `with_vault_dek` (mlock'd, no
    // clone). If unavailable (v2 legacy vault), fall back to the same key we
    // used to decrypt the file. The chain HMAC is keyed by whichever key was
    // in effect when the chain was created, so consistency across vault formats
    // requires that the user not switch keys mid-chain. (Re-keying flows
    // outside this file are responsible for re-anchoring the chain genesis.)
    let chain_verify = with_vault_dek(state, |dek| (verify_chain(dek, &logs), dek.to_vec()));
    let (verify_outcome, chain_key) = match chain_verify {
        Ok((outcome, dek_bytes)) => (outcome, dek_bytes),
        Err(_) => {
            // No DEK available — fall back to the v2 vault_key.
            (verify_chain(&key, &logs), key.to_vec())
        }
    };
    if let Err(chain_err) = verify_outcome {
        // Chain broken — quarantine and set hard error.
        let ts = chrono::Local::now().format("%Y%m%d%H%M%S").to_string();
        let corrupt_backup = path.with_extension(format!("log.corrupt.{}", ts));
        let _ = std::fs::rename(&path, &corrupt_backup);
        eprintln!(
            "[LexFlow] SECURITY: {} — quarantined to {:?}. Appends BLOCKED.",
            chain_err, corrupt_backup
        );
        set_audit_locked(true);
        // Best-effort wipe of the chain key copy before returning.
        {
            let mut k = chain_key;
            zeroize::Zeroize::zeroize(&mut k);
        }
        return Err(format!(
            "{} — quarantined; user must acknowledge",
            chain_err
        ));
    }
    // Decide whether we still need to insert a chain genesis marker. We do iff
    // (a) at least one legacy (non-chained) entry exists AND (b) no chained
    // entry exists yet — i.e. this is the first append after the upgrade.
    let needs_genesis_marker =
        logs.iter().any(|e| !entry_is_chained(e)) && !logs.iter().any(entry_is_chained);
    // Also handle the pristine case: a brand-new file with no entries at all
    // does NOT need a genesis marker — the first appended event becomes the
    // genesis itself (seq=0, prev_hash=GENESIS_PREV_HASH) via the normal path.
    let legacy_present = needs_genesis_marker;

    // If the loaded log is legacy (no chain), drop it and restart from genesis
    // on this append. The historical entries remain in the file ONLY in the
    // sense that they were just verified to decrypt — but going forward the
    // chain starts fresh. We keep the legacy entries appended below the new
    // chain header so the user can still read history; however, they will not
    // be re-verified by future appends because the chain header marks the
    // chain start.
    //
    // Strategy: if legacy_present, mark the chain genesis with a synthetic
    // header entry (`event = "audit.chain.genesis"`) and treat all prior
    // legacy entries as "before the chain". On future reads we still warn-once
    // about legacy entries that precede the genesis marker.
    if legacy_present {
        // Insert a chain genesis marker as the first chained entry. All legacy
        // entries already in `logs` remain in place (untouched, unverifiable).
        // The new genesis marker has seq = 0 relative to the chain and
        // prev_hash = GENESIS_PREV_HASH (the all-zero placeholder).
        let now = chrono::Local::now().to_rfc3339();
        let mut genesis = Map::new();
        genesis.insert("event".into(), json!("audit.chain.genesis"));
        genesis.insert("time".into(), json!(now.clone()));
        genesis.insert("chain_genesis_ts".into(), json!(now));
        genesis.insert("prev_hash".into(), json!(GENESIS_PREV_HASH));
        genesis.insert("seq".into(), json!(0u64));
        logs.push(Value::Object(genesis));
    }

    // Determine the previous chained entry (if any) and the next seq.
    let (prev_canonical, next_seq) = {
        let last_chained = logs.iter().rev().find(|e| entry_is_chained(e));
        match last_chained {
            Some(prev) => {
                let prev_for_hash = entry_without_chain_fields(prev);
                let prev_canonical = canonical_json(&prev_for_hash)?;
                let prev_seq = prev.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
                (prev_canonical, prev_seq.saturating_add(1))
            }
            None => (Vec::new(), 0u64),
        }
    };

    // Build the new entry without chain fields, compute its HMAC, then attach
    // prev_hash + seq.
    let mut new_entry_map = Map::new();
    new_entry_map.insert("event".into(), json!(event_name));
    new_entry_map.insert("time".into(), json!(chrono::Local::now().to_rfc3339()));
    let new_entry_for_hash = Value::Object(new_entry_map.clone());
    let new_canonical = canonical_json(&new_entry_for_hash)?;

    let prev_hash_hex = if prev_canonical.is_empty() {
        // Genesis of the chain — no previous entry.
        GENESIS_PREV_HASH.to_string()
    } else {
        let mac = compute_chain_hmac(&chain_key, &prev_canonical, &new_canonical);
        hex::encode(mac)
    };

    new_entry_map.insert("prev_hash".into(), json!(prev_hash_hex));
    new_entry_map.insert("seq".into(), json!(next_seq));
    logs.push(Value::Object(new_entry_map));

    // Best-effort: zeroize the temporary chain key copy.
    {
        let mut k = chain_key;
        zeroize::Zeroize::zeroize(&mut k);
    }

    if logs.len() > 10000 {
        let excess = logs.len() - 10000;
        logs.drain(0..excess);
    }
    // SECURITY FIX: propagate serialization error instead of unwrap_or_default
    // (which would encrypt an empty blob, destroying the entire log)
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&logs).map_err(|e| format!("Audit serialization failed: {}", e))?,
    );
    let enc = encrypt_data(&key, &plaintext)?;
    atomic_write_with_sync(&path, &enc)?;
    Ok(())
}

#[tauri::command]
pub(crate) fn get_audit_log(
    state: State<AppState>,
    offset: Option<usize>,
    limit: Option<usize>,
) -> Result<Value, String> {
    if is_audit_locked() {
        return Err("audit log locked due to suspected tampering".into());
    }
    let key = get_vault_key(&state)?;
    let path = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .join(AUDIT_LOG_FILE);
    if !path.exists() {
        return Ok(json!([]));
    }
    // SECURITY FIX: bounded read
    let enc = safe_bounded_read(&path, MAX_AUDIT_SIZE).map_err(|e| e.to_string())?;
    let dec = decrypt_data(&key, &enc)?;
    let all: Vec<Value> = serde_json::from_slice(&dec).map_err(|e| e.to_string())?;

    // SEC-AUDIT-1 (HMAC chain): verify the full chain on read. Any mismatch =>
    // hard error state, refuse further appends, return Err. Legacy logs (no
    // chain fields anywhere) are accepted with a one-time warning.
    let verify_result = with_vault_dek(&state, |dek| verify_chain(dek, &all));
    match verify_result {
        Ok(Ok(())) => {}
        Ok(Err(chain_err)) => {
            set_audit_locked(true);
            eprintln!(
                "[LexFlow] SECURITY: {} — locking audit subsystem.",
                chain_err
            );
            return Err(chain_err);
        }
        Err(_) => {
            // No DEK available (v2 vault). Verify with the same key we used to
            // decrypt the file — that's the only key material we have.
            if let Err(chain_err) = verify_chain(&key, &all) {
                set_audit_locked(true);
                eprintln!(
                    "[LexFlow] SECURITY: {} — locking audit subsystem.",
                    chain_err
                );
                return Err(chain_err);
            }
        }
    }

    // SEC-AUDIT-3: pagination — cap limit, default to a sane window.
    const MAX_LIMIT: usize = 1000;
    let off = offset.unwrap_or(0);
    let lim = limit.unwrap_or(MAX_LIMIT).min(MAX_LIMIT);
    let end = off.saturating_add(lim).min(all.len());
    if off >= all.len() {
        return Ok(json!([]));
    }
    let slice: Vec<Value> = all[off..end].to_vec();
    Ok(Value::Array(slice))
}
