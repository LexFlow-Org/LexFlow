// ═══════════════════════════════════════════════════════════
//  DATA VALIDATION — validate records before saving
// ═══════════════════════════════════════════════════════════

use serde_json::Value;

const MAX_STRING_LEN: usize = 50_000;
const MAX_ARRAY_LEN: usize = 10_000;

// ─── shared low-level helpers ─────────────────────────────────────────────

/// Reject NUL bytes, ASCII control characters (except tab/CR/LF), the BIDI
/// override RTLO (U+202E) which can be used to spoof filenames in the FE,
/// and the related LRO/PDF override marks. Whitelisted characters: tab (\t),
/// newline (\n), and carriage return (\r) — these are required for legitimate
/// notes / multi-line free text fields.
#[allow(dead_code)]
pub(crate) fn validate_no_control_chars(s: &str, field: &str) -> Result<(), String> {
    for ch in s.chars() {
        if ch == '\u{0000}' {
            return Err(format!("Campo '{}': contiene NUL", field));
        }
        if ch.is_control() && ch != '\t' && ch != '\n' && ch != '\r' {
            return Err(format!(
                "Campo '{}': contiene caratteri di controllo non consentiti",
                field
            ));
        }
        // RTLO / LRO / PDF / LRE / RLE / FSI / PDI — bidi spoofing
        if matches!(
            ch,
            '\u{202A}'
                | '\u{202B}'
                | '\u{202C}'
                | '\u{202D}'
                | '\u{202E}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
        ) {
            return Err(format!(
                "Campo '{}': contiene marcatori di direzione bidirezionale",
                field
            ));
        }
    }
    Ok(())
}

/// Validate an ID: ASCII alphanumeric, dash, underscore. 1..=64 chars.
#[allow(dead_code)]
pub(crate) fn validate_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 64 {
        return Err("id length out of range (1..=64)".into());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("id contains invalid characters".into());
    }
    Ok(())
}

/// Validate a filename: no path separators, no traversal, no NUL/control,
/// length 1..=255. Caller is expected to use only the leaf name.
#[allow(dead_code)]
pub(crate) fn validate_filename(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > 255 {
        return Err("filename length out of range (1..=255)".into());
    }
    if s.contains('/') || s.contains('\\') {
        return Err("filename must not contain path separators".into());
    }
    if s == "." || s == ".." || s.contains("..") {
        return Err("filename must not contain traversal".into());
    }
    if s.contains('\0') {
        return Err("filename must not contain NUL".into());
    }
    for ch in s.chars() {
        if ch.is_control() {
            return Err("filename must not contain control chars".into());
        }
    }
    Ok(())
}

/// Validate a path: no traversal, no NUL. Caller should canonicalize and
/// re-check that the result remains under an expected base directory.
#[allow(dead_code)]
pub(crate) fn validate_path(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("path is empty".into());
    }
    if s.contains('\0') {
        return Err("path must not contain NUL".into());
    }
    // Reject any explicit traversal segment.
    for seg in s.split(['/', '\\']) {
        if seg == ".." {
            return Err("path must not contain traversal segments".into());
        }
    }
    Ok(())
}

/// SEC-VAL-1: validate the shape of a settings document at the IPC boundary
/// (mirror of settings::is_valid_settings_schema). Permissive on unknown keys
/// but rejects scalars/arrays as the document root.
#[allow(dead_code)]
pub(crate) fn validate_settings_value(v: &Value) -> Result<(), String> {
    let obj = v
        .as_object()
        .ok_or("settings deve essere un oggetto JSON")?;
    if let Some(am) = obj.get("autolockMinutes") {
        let n = am.as_u64().ok_or("autolockMinutes deve essere un numero")?;
        if n == 0 || n > 1440 {
            return Err("autolockMinutes fuori intervallo (1..=1440)".into());
        }
    }
    if let Some(ne) = obj.get("notifyEnabled") {
        if !ne.is_boolean() {
            return Err("notifyEnabled deve essere booleano".into());
        }
    }
    if let Some(hd) = obj.get("hide_notification_details") {
        if !hd.is_boolean() {
            return Err("hide_notification_details deve essere booleano".into());
        }
    }
    Ok(())
}

/// SEC-VAL-1: validate a notification schedule payload coming from the FE.
#[allow(dead_code)]
pub(crate) fn validate_notification_schedule(v: &Value) -> Result<(), String> {
    let obj = v
        .as_object()
        .ok_or("schedule deve essere un oggetto JSON")?;
    if let Some(bt) = obj.get("briefingTimes") {
        let arr = bt.as_array().ok_or("briefingTimes deve essere un array")?;
        if arr.len() > 32 {
            return Err("briefingTimes troppo lungo (max 32)".into());
        }
        for t in arr {
            let s = t
                .as_str()
                .ok_or("briefingTimes contiene un valore non stringa")?;
            if s.len() != 5 || s.as_bytes().get(2) != Some(&b':') {
                return Err(format!("briefingTimes: formato non valido '{}'", s));
            }
        }
    }
    if let Some(items) = obj.get("items") {
        let arr = items.as_array().ok_or("items deve essere un array")?;
        if arr.len() > MAX_ARRAY_LEN {
            return Err(format!(
                "items troppo lunghi: {} (max {})",
                arr.len(),
                MAX_ARRAY_LEN
            ));
        }
    }
    Ok(())
}

/// Validate a practices array before saving.
pub(crate) fn validate_practices(data: &Value) -> Result<(), String> {
    let arr = data.as_array().ok_or("practices deve essere un array")?;
    if arr.len() > MAX_ARRAY_LEN {
        return Err(format!(
            "Troppi fascicoli: {} (max {})",
            arr.len(),
            MAX_ARRAY_LEN
        ));
    }
    for (i, item) in arr.iter().enumerate() {
        let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if id.is_empty() {
            return Err(format!("Fascicolo #{}: campo 'id' mancante", i + 1));
        }
        if id.len() > 200 {
            return Err(format!("Fascicolo #{}: id troppo lungo", i + 1));
        }
        // Validate string fields don't exceed limits
        for field in &["client", "counterparty", "object", "description", "court"] {
            if let Some(s) = item.get(*field).and_then(|v| v.as_str()) {
                if s.len() > MAX_STRING_LEN {
                    return Err(format!(
                        "Fascicolo '{}': campo '{}' troppo lungo ({} caratteri, max {})",
                        id,
                        field,
                        s.len(),
                        MAX_STRING_LEN
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Validate contacts array.
pub(crate) fn validate_contacts(data: &Value) -> Result<(), String> {
    let arr = data.as_array().ok_or("contacts deve essere un array")?;
    if arr.len() > MAX_ARRAY_LEN {
        return Err(format!(
            "Troppi contatti: {} (max {})",
            arr.len(),
            MAX_ARRAY_LEN
        ));
    }
    for (i, item) in arr.iter().enumerate() {
        let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if id.is_empty() {
            return Err(format!("Contatto #{}: campo 'id' mancante", i + 1));
        }
        for field in &["name", "email", "pec", "phone", "notes"] {
            if let Some(s) = item.get(*field).and_then(|v| v.as_str()) {
                if s.len() > MAX_STRING_LEN {
                    return Err(format!("Contatto '{}': campo '{}' troppo lungo", id, field));
                }
            }
        }
    }
    Ok(())
}

/// Check string fields don't exceed MAX_STRING_LEN.
fn check_record_strings(item: &Value, fields: &[&str]) -> Result<(), String> {
    for &f in fields {
        if let Some(s) = item.get(f).and_then(|v| v.as_str()) {
            if s.len() > MAX_STRING_LEN {
                return Err(format!(
                    "Campo '{}' troppo lungo ({} > {})",
                    f,
                    s.len(),
                    MAX_STRING_LEN
                ));
            }
        }
    }
    Ok(())
}

/// Validate agenda array — per-record field checks.
pub(crate) fn validate_agenda(data: &Value) -> Result<(), String> {
    let arr = data.as_array().ok_or("agenda deve essere un array")?;
    if arr.len() > MAX_ARRAY_LEN {
        return Err(format!(
            "Troppi eventi: {} (max {})",
            arr.len(),
            MAX_ARRAY_LEN
        ));
    }
    for (i, item) in arr.iter().enumerate() {
        if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
            if id.len() > 200 {
                return Err(format!("Evento {}: id troppo lungo", i));
            }
        }
        check_record_strings(
            item,
            &[
                "title",
                "text",
                "notes",
                "location",
                "category",
                "practiceId",
            ],
        )?;
    }
    Ok(())
}

/// Validate time logs array — per-record field checks.
pub(crate) fn validate_time_logs(data: &Value) -> Result<(), String> {
    let arr = data.as_array().ok_or("timeLogs deve essere un array")?;
    if arr.len() > MAX_ARRAY_LEN {
        return Err(format!("Troppi log: {} (max {})", arr.len(), MAX_ARRAY_LEN));
    }
    for (i, item) in arr.iter().enumerate() {
        if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
            if id.len() > 200 {
                return Err(format!("Log {}: id troppo lungo", i));
            }
        }
        check_record_strings(item, &["description", "practiceId", "date"])?;
    }
    Ok(())
}

/// Validate invoices array — per-record field checks.
pub(crate) fn validate_invoices(data: &Value) -> Result<(), String> {
    let arr = data.as_array().ok_or("invoices deve essere un array")?;
    if arr.len() > MAX_ARRAY_LEN {
        return Err(format!(
            "Troppe fatture: {} (max {})",
            arr.len(),
            MAX_ARRAY_LEN
        ));
    }
    for (i, item) in arr.iter().enumerate() {
        if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
            if id.len() > 200 {
                return Err(format!("Fattura {}: id troppo lungo", i));
            }
        }
        check_record_strings(
            item,
            &["number", "client", "description", "status", "notes"],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ─── validate_practices ──────────────────────────────────

    #[test]
    fn test_practices_valid() {
        let data = json!([
            {"id": "p1", "client": "Mario Rossi", "object": "Causa civile"},
            {"id": "p2", "client": "Anna Bianchi", "counterparty": "Carlo Verdi"},
        ]);
        assert!(validate_practices(&data).is_ok());
    }

    #[test]
    fn test_practices_not_array() {
        assert!(validate_practices(&json!({"id": "p1"})).is_err());
        assert!(validate_practices(&json!("string")).is_err());
        assert!(validate_practices(&json!(42)).is_err());
        assert!(validate_practices(&json!(null)).is_err());
    }

    #[test]
    fn test_practices_missing_id() {
        let data = json!([{"client": "Mario Rossi"}]);
        let err = validate_practices(&data).unwrap_err();
        assert!(err.contains("id"));
    }

    #[test]
    fn test_practices_empty_id() {
        let data = json!([{"id": "", "client": "Mario"}]);
        let err = validate_practices(&data).unwrap_err();
        assert!(err.contains("id"));
    }

    #[test]
    fn test_practices_id_too_long() {
        let long_id = "x".repeat(201);
        let data = json!([{"id": long_id, "client": "Mario"}]);
        let err = validate_practices(&data).unwrap_err();
        assert!(err.contains("troppo lungo"));
    }

    #[test]
    fn test_practices_field_too_long() {
        let long_str = "a".repeat(MAX_STRING_LEN + 1);
        let data = json!([{"id": "p1", "client": long_str}]);
        let err = validate_practices(&data).unwrap_err();
        assert!(err.contains("client"));
        assert!(err.contains("troppo lungo"));
    }

    #[test]
    fn test_practices_too_many() {
        let arr: Vec<Value> = (0..MAX_ARRAY_LEN + 1)
            .map(|i| json!({"id": format!("p{}", i), "client": "Test"}))
            .collect();
        let err = validate_practices(&Value::Array(arr)).unwrap_err();
        assert!(err.contains("Troppi"));
    }

    #[test]
    fn test_practices_empty_array_ok() {
        assert!(validate_practices(&json!([])).is_ok());
    }

    #[test]
    fn test_practices_max_length_field_ok() {
        let exact = "a".repeat(MAX_STRING_LEN);
        let data = json!([{"id": "p1", "client": exact}]);
        assert!(validate_practices(&data).is_ok());
    }

    // ─── validate_contacts ──────────────────────────────────

    #[test]
    fn test_contacts_valid() {
        let data = json!([
            {"id": "c1", "name": "Avv. Rossi", "email": "rossi@pec.it"},
        ]);
        assert!(validate_contacts(&data).is_ok());
    }

    #[test]
    fn test_contacts_not_array() {
        assert!(validate_contacts(&json!("not array")).is_err());
    }

    #[test]
    fn test_contacts_missing_id() {
        let data = json!([{"name": "Mario"}]);
        assert!(validate_contacts(&data).unwrap_err().contains("id"));
    }

    #[test]
    fn test_contacts_field_too_long() {
        let long = "b".repeat(MAX_STRING_LEN + 1);
        let data = json!([{"id": "c1", "notes": long}]);
        assert!(validate_contacts(&data)
            .unwrap_err()
            .contains("troppo lungo"));
    }

    // ─── validate_agenda ─────────────────────────────────────

    #[test]
    fn test_agenda_valid() {
        let data = json!([
            {"id": "a1", "title": "Udienza Tribunale di Roma", "date": "2026-04-15", "time": "09:30"},
        ]);
        assert!(validate_agenda(&data).is_ok());
    }

    #[test]
    fn test_agenda_not_array() {
        assert!(validate_agenda(&json!(42)).is_err());
    }

    #[test]
    fn test_agenda_id_too_long() {
        let long_id = "x".repeat(201);
        let data = json!([{"id": long_id, "title": "Test"}]);
        assert!(validate_agenda(&data).unwrap_err().contains("troppo lungo"));
    }

    #[test]
    fn test_agenda_field_too_long() {
        let long = "c".repeat(MAX_STRING_LEN + 1);
        let data = json!([{"id": "a1", "title": long}]);
        assert!(validate_agenda(&data).is_err());
    }

    // ─── validate_time_logs ──────────────────────────────────

    #[test]
    fn test_time_logs_valid() {
        let data = json!([
            {"id": "tl1", "description": "Studio atti causa Rossi", "date": "2026-03-25", "practiceId": "p1"},
        ]);
        assert!(validate_time_logs(&data).is_ok());
    }

    #[test]
    fn test_time_logs_not_array() {
        assert!(validate_time_logs(&json!(null)).is_err());
    }

    // ─── validate_invoices ───────────────────────────────────

    #[test]
    fn test_invoices_valid() {
        let data = json!([
            {"id": "inv1", "number": "2026/001", "client": "Mario Rossi", "status": "emessa"},
        ]);
        assert!(validate_invoices(&data).is_ok());
    }

    #[test]
    fn test_invoices_too_many() {
        let arr: Vec<Value> = (0..MAX_ARRAY_LEN + 1)
            .map(|i| json!({"id": format!("inv{}", i)}))
            .collect();
        assert!(validate_invoices(&Value::Array(arr)).is_err());
    }

    // ─── Stress: all validators on realistic data ────────────

    #[test]
    fn test_realistic_studio_legale_data() {
        let practices = json!([
            {"id": "p001", "client": "Mario Rossi S.r.l.", "counterparty": "Bianchi & Associati",
             "object": "Risarcimento danni da inadempimento contrattuale art. 1218 c.c.",
             "description": "Il cliente lamenta danni per €150.000 derivanti da mancata consegna merce...",
             "court": "Tribunale Civile di Milano — Sez. IX"},
            {"id": "p002", "client": "Anna Verdi", "counterparty": "INPS",
             "object": "Ricorso avverso diniego pensione di invalidità",
             "court": "Tribunale del Lavoro di Roma"},
        ]);
        assert!(validate_practices(&practices).is_ok());

        let agenda = json!([
            {"id": "a001", "title": "Udienza di trattazione Rossi vs Bianchi",
             "date": "2026-04-20", "time": "09:30", "location": "Tribunale di Milano, Aula 7",
             "category": "udienza", "practiceId": "p001"},
            {"id": "a002", "title": "Scadenza deposito memoria ex art. 183 c.p.c.",
             "date": "2026-04-10", "category": "scadenza", "practiceId": "p001"},
        ]);
        assert!(validate_agenda(&agenda).is_ok());

        let contacts = json!([
            {"id": "c001", "name": "Avv. Giuseppe Neri", "email": "neri@ordineavvocati.mi.it",
             "pec": "giuseppe.neri@pec.ordineavvocatimilano.it", "phone": "+39 02 1234567",
             "fiscalCode": "NRSGPP80A01F205X", "notes": "Controparte causa Rossi"},
        ]);
        assert!(validate_contacts(&contacts).is_ok());

        let time_logs = json!([
            {"id": "tl001", "description": "Studio fascicolo e atti di causa",
             "date": "2026-03-20", "practiceId": "p001"},
            {"id": "tl002", "description": "Redazione comparsa di costituzione e risposta",
             "date": "2026-03-22", "practiceId": "p001"},
        ]);
        assert!(validate_time_logs(&time_logs).is_ok());

        let invoices = json!([
            {"id": "inv001", "number": "2026/001", "client": "Mario Rossi S.r.l.",
             "description": "Competenze legali — Causa civile Rossi vs Bianchi",
             "status": "emessa", "notes": "Scadenza pagamento 30gg"},
        ]);
        assert!(validate_invoices(&invoices).is_ok());
    }
}
