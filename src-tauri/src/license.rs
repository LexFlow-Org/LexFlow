// ═══════════════════════════════════════════════════════════
//  LICENSE — Ed25519 verification, activation, burned keys
// ═══════════════════════════════════════════════════════════

use crate::constants::*;
use crate::crypto::{decrypt_data, encrypt_data};
use crate::io::{atomic_write_with_sync, safe_now_ms};
use crate::lockout::{check_lockout, clear_lockout, record_failed_attempt};
use crate::platform::{
    compute_machine_fingerprint, decrypt_local_with_migration, get_local_encryption_key,
};
use crate::state::AppState;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::fs;
use tauri::State;

const LAST_CHECK_TS_FILE: &str = ".last-license-check";

pub(crate) const PUBLIC_KEY_BYTES: [u8; 32] = [
    165u8, 168u8, 18u8, 242u8, 77u8, 185u8, 21u8, 57u8, 73u8, 63u8, 24u8, 223u8, 51u8, 205u8,
    205u8, 147u8, 14u8, 52u8, 150u8, 216u8, 125u8, 219u8, 73u8, 154u8, 80u8, 107u8, 177u8, 59u8,
    40u8, 183u8, 104u8, 171u8,
];

// ─── Burned-key registry ────────────────────────────────────

fn compute_burn_hash(token: &str) -> String {
    use sha2::Digest as _;
    let seed = format!("BURN-GLOBAL-V2:{}", token);
    let hash = Sha256::digest(seed.as_bytes());
    hex::encode(hash)
}

fn compute_burn_hash_legacy(token: &str, fingerprint: &str) -> String {
    use sha2::Digest as _;
    let seed = format!("BURN:{}:{}", fingerprint, token);
    let hash = Sha256::digest(seed.as_bytes());
    hex::encode(hash)
}

fn load_burned_keys(dir: &std::path::Path) -> Result<Vec<String>, String> {
    let path = dir.join(BURNED_KEYS_FILE);
    if !path.exists() {
        return Ok(vec![]);
    }
    let dec = decrypt_local_with_migration(&path).ok_or_else(|| {
        "CRITICAL: Impossibile decifrare il registro delle chiavi bruciate. Possibile manomissione."
            .to_string()
    })?;
    let text = String::from_utf8_lossy(&dec);
    Ok(text
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect())
}

fn burn_key(dir: &std::path::Path, burn_hash: &str) -> Result<(), String> {
    let mut hashes = load_burned_keys(dir)?;
    if hashes.contains(&burn_hash.to_string()) {
        return Ok(());
    }
    hashes.push(burn_hash.to_string());
    let content = hashes.join("\n");
    let enc_key = get_local_encryption_key();
    let encrypted = encrypt_data(&enc_key, content.as_bytes())
        .map_err(|e| format!("Errore cifratura registro: {}", e))?;
    atomic_write_with_sync(&dir.join(BURNED_KEYS_FILE), &encrypted).map_err(|e| {
        format!(
            "FATAL: Impossibile salvare il registro aggiornato su disco: {}",
            e
        )
    })?;
    Ok(())
}

fn is_key_burned(dir: &std::path::Path, token: &str, fingerprint: &str) -> Result<bool, String> {
    let burn_hash_v2 = compute_burn_hash(token);
    let burn_hash_legacy = compute_burn_hash_legacy(token, fingerprint);
    let hashes = load_burned_keys(dir)?;
    Ok(hashes.contains(&burn_hash_v2) || hashes.contains(&burn_hash_legacy))
}

// ─── Monotonic clock check ──────────────────────────────────

fn monotonic_clock_check(sec_dir: &std::path::Path) -> Result<(), String> {
    let ts_path = sec_dir.join(LAST_CHECK_TS_FILE);
    let now_ms = safe_now_ms();

    if let Ok(raw) = fs::read_to_string(&ts_path) {
        let parts: Vec<&str> = raw.trim().splitn(2, ':').collect();
        if parts.len() == 2 {
            let stored_ts = parts[0].parse::<u64>().unwrap_or(0);
            let stored_hmac = parts[1];
            let enc_key = get_local_encryption_key();
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&enc_key)
                .expect("HMAC can take key of any size");
            mac.update(b"CLOCK-CHECK:");
            mac.update(parts[0].as_bytes());
            let hmac_valid = hex::decode(stored_hmac)
                .ok()
                .map(|bytes| mac.verify_slice(&bytes).is_ok())
                .unwrap_or(false);
            if hmac_valid && now_ms < stored_ts.saturating_sub(300_000) {
                return Err("SECURITY: System clock appears to have been set backwards. License check refused.".into());
            }
        }
    }

    let ts_str = now_ms.to_string();
    let enc_key = get_local_encryption_key();
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&enc_key).expect("HMAC can take key of any size");
    mac.update(b"CLOCK-CHECK:");
    mac.update(ts_str.as_bytes());
    let hmac_hex = hex::encode(mac.finalize().into_bytes());
    let _ = atomic_write_with_sync(&ts_path, format!("{}:{}", ts_str, hmac_hex).as_bytes());
    Ok(())
}

// ─── License types ──────────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub(crate) struct LicensePayload {
    pub c: String,
    pub e: u64,
    pub id: String,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub h: Option<String>,
    #[serde(default)]
    pub g: Option<u64>,
    #[serde(default)]
    pub a: Option<String>,
    #[serde(default)]
    pub s: Option<String>,
    #[serde(default)]
    pub t: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct VerificationResult {
    pub valid: bool,
    pub client: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_grace_period: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_days: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_locked: Option<bool>,
}

// ─── Helpers ────────────────────────────────────────────────

fn parse_lxfw_payload(token: &str) -> Option<LicensePayload> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts[0] != "LXFW" {
        return None;
    }
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    serde_json::from_slice(&payload_bytes).ok()
}

fn extract_key_id(token: &str) -> Option<String> {
    parse_lxfw_payload(token).map(|p| p.id)
}

fn extract_expiry_ms(token: &str) -> Option<u64> {
    parse_lxfw_payload(token).map(|p| p.e)
}

fn recover_sentinel_key_id(sentinel_path: &std::path::Path) -> Option<String> {
    let sentinel_content = fs::read_to_string(sentinel_path).ok()?;
    let stored_key_id_enc = sentinel_content.lines().nth(1).filter(|s| !s.is_empty())?;
    let enc_bytes = hex::decode(stored_key_id_enc).ok()?;
    let enc_key = get_local_encryption_key();
    let dec = decrypt_data(&enc_key, &enc_bytes).ok()?;
    String::from_utf8(dec).ok()
}

fn check_existing_license_blocks(path: &std::path::Path, new_key: &str) -> Option<Value> {
    if !path.exists() {
        return None;
    }
    let dec = decrypt_local_with_migration(path)?;
    let existing: Value = serde_json::from_slice(&dec).ok()?;
    let existing_version = existing
        .get("keyVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let new_id = extract_key_id(new_key);

    if existing_version == "ed25519-burned" {
        let expiry = existing
            .get("expiryMs")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let now_ms = safe_now_ms();
        if now_ms <= expiry {
            let existing_id = existing
                .get("keyId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            if existing_id != new_id {
                return Some(
                    json!({"success": false, "error": "Una licenza valida è già attiva. Non è possibile sostituirla."}),
                );
            }
        }
    } else {
        let existing_key = existing.get("key").and_then(|k| k.as_str()).unwrap_or("");
        if !existing_key.is_empty()
            && verify_license(existing_key.to_string()).valid
            && extract_key_id(existing_key) != new_id
        {
            return Some(
                json!({"success": false, "error": "Una licenza valida è già attiva. Non è possibile sostituirla."}),
            );
        }
    }
    None
}

fn silent_upgrade_fingerprint(data: &Value, key: &[u8], path: &std::path::Path, fp: &str) {
    let mut upgraded = data.clone();
    if let Some(obj) = upgraded.as_object_mut() {
        obj.insert("machineFingerprint".to_string(), json!(fp));
    }
    if let Ok(bytes) = serde_json::to_vec(&upgraded) {
        if let Ok(encrypted) = encrypt_data(key, &bytes) {
            if let Err(e) = atomic_write_with_sync(path, &encrypted) {
                eprintln!("[SECURITY] license fingerprint upgrade write failed: {}", e);
            }
        }
    }
}

fn write_license_sentinel(
    sentinel_path: &std::path::Path,
    fingerprint: &str,
    key_id: &str,
    now: &str,
) {
    let enc_key = get_local_encryption_key();
    let sentinel_data = format!("LEXFLOW-SENTINEL:{}:{}:{}", fingerprint, key_id, now);
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&enc_key).expect("HMAC can take key of any size");
    mac.update(sentinel_data.as_bytes());
    let sentinel_hmac = hex::encode(mac.finalize().into_bytes());
    let encrypted_key_id = encrypt_data(&enc_key, key_id.as_bytes())
        .map(hex::encode)
        .unwrap_or_default();
    let sentinel_content = format!("{}\n{}", sentinel_hmac, encrypted_key_id);
    let _ = atomic_write_with_sync(sentinel_path, sentinel_content.as_bytes());
}

fn check_burned_key_registry(
    sec_dir: &std::path::Path,
    key: &str,
    fingerprint: &str,
) -> Result<(), Value> {
    match is_key_burned(sec_dir, key, fingerprint) {
        Ok(true) => Err(
            json!({"success": false, "error": "Questa chiave è già stata utilizzata e non può essere riattivata."}),
        ),
        Err(e) => {
            eprintln!("[SECURITY] burned-keys registry unreadable: {}", e);
            Err(
                json!({"success": false, "error": "Registro chiavi non leggibile. Contattare il supporto."}),
            )
        }
        Ok(false) => Ok(()),
    }
}

fn check_license_burned(
    data: &Value,
    key: &[u8],
    path: &std::path::Path,
    current_fp: &str,
    needs_fp_upgrade: bool,
) -> Value {
    let token_hmac = data.get("tokenHmac").and_then(|v| v.as_str()).unwrap_or("");
    let expiry_ms = data.get("expiryMs").and_then(|v| v.as_u64()).unwrap_or(0);
    let grace_days = data.get("graceDays").and_then(|v| v.as_u64()).unwrap_or(0);
    let client = data
        .get("client")
        .and_then(|v| v.as_str())
        .unwrap_or("Studio Legale")
        .to_string();
    let lawyer_name = data
        .get("lawyerName")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let studio_name = data
        .get("studioName")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let lawyer_title = data
        .get("lawyerTitle")
        .and_then(|v| v.as_str())
        .unwrap_or("Avv.")
        .to_string();

    if token_hmac.is_empty() {
        return json!({"activated": false, "reason": "Dati licenza corrotti."});
    }
    let now_ms = safe_now_ms();
    let grace_ms = grace_days * 86_400 * 1000;

    if now_ms > expiry_ms {
        if grace_ms > 0 && now_ms <= (expiry_ms + grace_ms) {
            if needs_fp_upgrade {
                silent_upgrade_fingerprint(data, key, path, current_fp);
            }
            return json!({
                "activated": true,
                "activatedAt": data.get("activatedAt").cloned().unwrap_or(Value::Null),
                "client": client,
                "lawyerName": lawyer_name,
                "lawyerTitle": lawyer_title,
                "studioName": studio_name,
                "inGracePeriod": true,
                "graceDays": grace_days,
            });
        }
        return json!({"activated": false, "expired": true, "reason": "Licenza scaduta."});
    }
    if needs_fp_upgrade {
        silent_upgrade_fingerprint(data, key, path, current_fp);
    }
    json!({
        "activated": true,
        "activatedAt": data.get("activatedAt").cloned().unwrap_or(Value::Null),
        "client": client,
        "lawyerName": lawyer_name,
        "lawyerTitle": lawyer_title,
        "studioName": studio_name,
    })
}

fn check_license_legacy(
    data: &Value,
    license_key: &str,
    key: &[u8],
    path: &std::path::Path,
    sec_dir: &std::path::Path,
    current_fp: &str,
) -> Value {
    let verification = verify_license(license_key.to_string());
    if !verification.valid {
        return json!({"activated": false, "expired": true, "reason": verification.message});
    }

    let mut token_mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC can take key of any size");
    token_mac.update(license_key.as_bytes());
    let token_hmac = hex::encode(token_mac.finalize().into_bytes());

    let expiry_ms: u64 = extract_expiry_ms(license_key).unwrap_or(0);
    let client = verification
        .client
        .unwrap_or_else(|| "Studio Legale".to_string());
    let key_id = extract_key_id(license_key).unwrap_or_else(|| "legacy".to_string());

    let upgraded = json!({
        "tokenHmac": token_hmac,
        "activatedAt": data.get("activatedAt").cloned().unwrap_or(Value::Null),
        "client": client,
        "keyVersion": "ed25519-burned",
        "machineFingerprint": current_fp,
        "keyId": key_id,
        "expiryMs": expiry_ms,
    });

    if let Ok(bytes) = serde_json::to_vec(&upgraded) {
        if let Ok(encrypted) = encrypt_data(key, &bytes) {
            if let Err(e) = atomic_write_with_sync(path, &encrypted) {
                eprintln!("[SECURITY] license upgrade write failed: {}", e);
            }
        }
    }
    if let Err(e) = burn_key(sec_dir, &compute_burn_hash(license_key)) {
        eprintln!(
            "[SECURITY] CRITICAL: burn_key failed during legacy upgrade: {}",
            e
        );
    }

    json!({
        "activated": true,
        "activatedAt": data.get("activatedAt").cloned().unwrap_or(Value::Null),
        "client": client,
        "lawyerName": "",
        "studioName": "",
    })
}

fn perform_license_activation(
    sec_dir: &std::path::Path,
    path: &std::path::Path,
    sentinel_path: &std::path::Path,
    key: &str,
    client: &str,
    fingerprint: &str,
) -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    let key_id = extract_key_id(key).unwrap_or_else(|| "unknown".to_string());
    let enc_key = get_local_encryption_key();

    let mut token_mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&enc_key).expect("HMAC can take key of any size");
    token_mac.update(key.as_bytes());
    let token_hmac = hex::encode(token_mac.finalize().into_bytes());

    let parsed_payload = parse_lxfw_payload(key);
    let expiry_ms = parsed_payload.as_ref().map(|p| p.e).unwrap_or(0);
    let grace_days = parsed_payload.as_ref().and_then(|p| p.g).unwrap_or(0);
    let hardware_locked = parsed_payload.as_ref().and_then(|p| p.h.as_ref()).is_some();
    let lawyer_name = parsed_payload
        .as_ref()
        .and_then(|p| p.a.clone())
        .unwrap_or_default();
    let studio_name = parsed_payload
        .as_ref()
        .and_then(|p| p.s.clone())
        .unwrap_or_default();
    let lawyer_title = parsed_payload
        .as_ref()
        .and_then(|p| p.t.clone())
        .unwrap_or_else(|| "Avv.".to_string());

    let record = json!({
        "tokenHmac": token_hmac,
        "activatedAt": now,
        "client": client,
        "lawyerName": lawyer_name,
        "lawyerTitle": lawyer_title,
        "studioName": studio_name,
        "keyVersion": "ed25519-burned",
        "machineFingerprint": fingerprint,
        "keyId": key_id,
        "expiryMs": expiry_ms,
        "graceDays": grace_days,
        "hardwareLocked": hardware_locked,
    });

    let encrypted = match encrypt_data(&enc_key, &serde_json::to_vec(&record).unwrap_or_default()) {
        Ok(enc) => enc,
        Err(e) => return json!({"success": false, "error": format!("Errore cifratura: {}", e)}),
    };
    if let Err(e) = atomic_write_with_sync(path, &encrypted) {
        return json!({"success": false, "error": format!("Errore salvataggio: {}", e)});
    }

    write_license_sentinel(sentinel_path, fingerprint, &key_id, &now);

    if let Err(e) = burn_key(sec_dir, &compute_burn_hash(key)) {
        eprintln!(
            "[SECURITY] CRITICAL: burn_key failed after activation: {}",
            e
        );
    }

    json!({"success": true, "client": client, "lawyerName": lawyer_name, "lawyerTitle": lawyer_title})
}

// ─── Tauri commands ─────────────────────────────────────────

#[tauri::command]
pub(crate) fn get_machine_fingerprint() -> String {
    compute_machine_fingerprint()
}

#[tauri::command]
pub(crate) fn verify_license(key_string: String) -> VerificationResult {
    let parts: Vec<&str> = key_string.split('.').collect();
    if parts.len() != 3 || parts[0] != "LXFW" {
        return VerificationResult {
            valid: false,
            client: None,
            message: "Formato chiave non valido.".into(),
            in_grace_period: None,
            grace_days: None,
            hardware_locked: None,
        };
    }

    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    let payload_bytes = match URL_SAFE_NO_PAD.decode(payload_b64) {
        Ok(b) => b,
        Err(_) => {
            return VerificationResult {
                valid: false,
                client: None,
                message: "Errore decodifica payload.".into(),
                in_grace_period: None,
                grace_days: None,
                hardware_locked: None,
            }
        }
    };

    let signature_bytes = match URL_SAFE_NO_PAD.decode(signature_b64) {
        Ok(b) => b,
        Err(_) => {
            return VerificationResult {
                valid: false,
                client: None,
                message: "Errore decodifica firma.".into(),
                in_grace_period: None,
                grace_days: None,
                hardware_locked: None,
            }
        }
    };

    let public_key = match VerifyingKey::from_bytes(&PUBLIC_KEY_BYTES) {
        Ok(k) => k,
        Err(_) => {
            return VerificationResult {
                valid: false,
                client: None,
                message: "Errore chiave pubblica interna.".into(),
                in_grace_period: None,
                grace_days: None,
                hardware_locked: None,
            }
        }
    };

    let signature = match Signature::from_slice(&signature_bytes) {
        Ok(s) => s,
        Err(_) => {
            return VerificationResult {
                valid: false,
                client: None,
                message: "Firma corrotta.".into(),
                in_grace_period: None,
                grace_days: None,
                hardware_locked: None,
            }
        }
    };

    if public_key
        .verify(payload_b64.as_bytes(), &signature)
        .is_err()
    {
        return VerificationResult {
            valid: false,
            client: None,
            message: "Firma non valida o licenza manomessa!".into(),
            in_grace_period: None,
            grace_days: None,
            hardware_locked: None,
        };
    }

    let payload: LicensePayload = match serde_json::from_slice(&payload_bytes) {
        Ok(p) => p,
        Err(_) => {
            return VerificationResult {
                valid: false,
                client: None,
                message: "Dati licenza corrotti.".into(),
                in_grace_period: None,
                grace_days: None,
                hardware_locked: None,
            }
        }
    };

    let hardware_locked = payload.h.is_some();
    if let Some(ref required_hwid) = payload.h {
        let current_fp = compute_machine_fingerprint();
        if *required_hwid != current_fp {
            return VerificationResult {
                valid: false,
                client: Some(payload.c),
                message: "Licenza bloccata su un altro dispositivo (Hardware ID mismatch).".into(),
                in_grace_period: None,
                grace_days: payload.g,
                hardware_locked: Some(true),
            };
        }
    }

    let now = safe_now_ms();
    let grace_days = payload.g.unwrap_or(0);
    let grace_ms = grace_days * 86_400 * 1000;

    if now > payload.e {
        if grace_ms > 0 && now <= (payload.e + grace_ms) {
            return VerificationResult {
                valid: true,
                client: Some(payload.c),
                message: "Licenza in Grace Period — rinnovo necessario!".into(),
                in_grace_period: Some(true),
                grace_days: Some(grace_days),
                hardware_locked: if hardware_locked { Some(true) } else { None },
            };
        }
        return VerificationResult {
            valid: false,
            client: Some(payload.c),
            message: "Licenza scaduta.".into(),
            in_grace_period: Some(false),
            grace_days: if grace_days > 0 {
                Some(grace_days)
            } else {
                None
            },
            hardware_locked: if hardware_locked { Some(true) } else { None },
        };
    }

    VerificationResult {
        valid: true,
        client: Some(payload.c),
        message: "Licenza attivata con successo!".into(),
        in_grace_period: Some(false),
        grace_days: if grace_days > 0 {
            Some(grace_days)
        } else {
            None
        },
        hardware_locked: if hardware_locked { Some(true) } else { None },
    }
}

#[tauri::command]
pub(crate) fn check_license(state: State<AppState>) -> Value {
    let sec_dir = state
        .security_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let path = sec_dir.join(LICENSE_FILE);
    let sentinel_path = sec_dir.join(LICENSE_SENTINEL_FILE);

    if let Err(e) = monotonic_clock_check(&sec_dir) {
        eprintln!("[SECURITY] {}", e);
        return json!({"activated": false, "reason": "Anomalia orologio di sistema rilevata. Verificare data/ora e riprovare."});
    }

    if !path.exists() {
        if sentinel_path.exists() {
            return json!({"activated": false, "tampered": true, "reason": "File di licenza rimosso o manomesso. Contattare il supporto."});
        }
        return json!({"activated": false});
    }

    let key = get_local_encryption_key();
    let data: Value = if let Some(dec) = decrypt_local_with_migration(&path) {
        serde_json::from_slice(&dec).unwrap_or(json!({}))
    } else {
        return json!({"activated": false, "reason": "File licenza corrotto o non valido per questo dispositivo."});
    };

    let current_fp = compute_machine_fingerprint();
    if let Some(stored_fp) = data.get("machineFingerprint").and_then(|v| v.as_str()) {
        if stored_fp != current_fp {
            return json!({"activated": false, "reason": "Licenza attivata su un altro dispositivo."});
        }
    }
    let needs_fp_upgrade = data.get("machineFingerprint").is_none();
    let key_version = data
        .get("keyVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if key_version == "ed25519-burned" {
        return check_license_burned(&data, &key, &path, &current_fp, needs_fp_upgrade);
    }

    let license_key = data.get("key").and_then(|k| k.as_str()).unwrap_or("");
    if !license_key.is_empty() {
        return check_license_legacy(&data, license_key, &key, &path, &sec_dir, &current_fp);
    }

    json!({"activated": false})
}

#[tauri::command]
pub(crate) fn activate_license(state: State<AppState>, key: String) -> Value {
    let sec_dir = state
        .security_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());

    if let Err(locked_json) = check_lockout(&state, &sec_dir) {
        return locked_json;
    }

    let key = key.trim().to_string();
    let path = sec_dir.join(LICENSE_FILE);
    let sentinel_path = sec_dir.join(LICENSE_SENTINEL_FILE);

    if !path.exists() && sentinel_path.exists() {
        let stored_key_id = recover_sentinel_key_id(&sentinel_path);
        let new_key_id = extract_key_id(&key);
        match (stored_key_id.as_deref(), new_key_id.as_deref()) {
            (Some(old), Some(new_id)) if old == new_id => {}
            _ => {
                return json!({"success": false, "error": "Questa installazione ha già una licenza registrata. Contattare il supporto per assistenza."})
            }
        }
    }

    if let Some(blocked) = check_existing_license_blocks(&path, &key) {
        return blocked;
    }

    let verification = verify_license(key.clone());
    if !verification.valid {
        record_failed_attempt(&state, &sec_dir);
        return json!({"success": false, "error": verification.message});
    }

    let fingerprint = compute_machine_fingerprint();

    if let Err(msg) = check_burned_key_registry(&sec_dir, &key, &fingerprint) {
        record_failed_attempt(&state, &sec_dir);
        return msg;
    }

    if sentinel_path.exists() && !sec_dir.join(BURNED_KEYS_FILE).exists() {
        record_failed_attempt(&state, &sec_dir);
        return json!({"success": false, "error": "Registro chiavi compromesso. Contattare il supporto per assistenza."});
    }

    let client = verification
        .client
        .unwrap_or_else(|| "Studio Legale".to_string());
    let result =
        perform_license_activation(&sec_dir, &path, &sentinel_path, &key, &client, &fingerprint);

    if result
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        clear_lockout(&state, &sec_dir);
    } else {
        record_failed_attempt(&state, &sec_dir);
    }

    result
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_license_verification_full_cycle() {
        let valid_token = "LXFW.eyJjIjoicGlldHJvX3Rlc3QiLCJlIjoxODAzOTE4MTIxMzczLCJpZCI6IjQzMWQxYzU5LThjZWQtNDNiMy04MTRmLTk4YjhlYzUyNzJmZiJ9.CjPgp0RCKAHd7fNY3dFrYKS7dGuktI0SyLrk_E6Te70J1K2HJpI9u1O2epkUcNsWFgggAvOd8yCqLVFqrCvtDg";

        let token_expiry_ms: u64 = 1_803_918_121_373;
        let now_ms = safe_now_ms();
        if now_ms > token_expiry_ms {
            eprintln!(
                "⚠️  TEST SKIPPED: The hardcoded test token expired on 2027-02-12.\n\
                 Generate a new token with: python3 generate_license_v2.py generate\n\
                 Then update this test with the new token."
            );
            let result = verify_license(valid_token.to_string());
            assert!(!result.valid, "Expired token should be rejected");
            assert_eq!(
                result.client.unwrap(),
                "pietro_test",
                "Client should still be parseable from expired token"
            );
            assert!(
                result.message.contains("scaduta") || result.message.contains("expired"),
                "Message should indicate expiry, got: {}",
                result.message
            );
            return;
        }

        let result = verify_license(valid_token.to_string());
        assert!(
            result.valid,
            "La licenza valida è stata respinta! Errore: {}",
            result.message
        );
        assert_eq!(result.client.unwrap(), "pietro_test");

        let mut tampered_token = valid_token.to_string();
        tampered_token.replace_range(tampered_token.len() - 5..tampered_token.len() - 4, "Z");
        let tamper_result = verify_license(tampered_token);
        assert!(
            !tamper_result.valid,
            "Sicurezza fallita: la licenza manomessa è stata accettata!"
        );
        assert_eq!(
            tamper_result.message,
            "Firma non valida o licenza manomessa!"
        );

        let invalid_format = "TOKEN_SENZA_PUNTI";
        let format_result = verify_license(invalid_format.to_string());
        assert!(!format_result.valid);
        assert_eq!(format_result.message, "Formato chiave non valido.");
    }
}
