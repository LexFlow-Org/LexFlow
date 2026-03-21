// ═══════════════════════════════════════════════════════════
//  DATA VALIDATION — validate records before saving
// ═══════════════════════════════════════════════════════════

use serde_json::Value;

const MAX_STRING_LEN: usize = 50_000;
const MAX_ARRAY_LEN: usize = 10_000;

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

/// Validate agenda array.
pub(crate) fn validate_agenda(data: &Value) -> Result<(), String> {
    let arr = data.as_array().ok_or("agenda deve essere un array")?;
    if arr.len() > MAX_ARRAY_LEN {
        return Err(format!(
            "Troppi eventi: {} (max {})",
            arr.len(),
            MAX_ARRAY_LEN
        ));
    }
    Ok(())
}

/// Validate time logs array.
pub(crate) fn validate_time_logs(data: &Value) -> Result<(), String> {
    let arr = data.as_array().ok_or("timeLogs deve essere un array")?;
    if arr.len() > MAX_ARRAY_LEN {
        return Err(format!("Troppi log: {} (max {})", arr.len(), MAX_ARRAY_LEN));
    }
    Ok(())
}

/// Validate invoices array.
pub(crate) fn validate_invoices(data: &Value) -> Result<(), String> {
    let arr = data.as_array().ok_or("invoices deve essere un array")?;
    if arr.len() > MAX_ARRAY_LEN {
        return Err(format!(
            "Troppe fatture: {} (max {})",
            arr.len(),
            MAX_ARRAY_LEN
        ));
    }
    Ok(())
}
