// ═══════════════════════════════════════════════════════════
//  CSV EXPORT — time logs and invoices
// ═══════════════════════════════════════════════════════════

use crate::state::AppState;
use crate::vault::read_vault_internal;
use serde_json::Value;
use tauri::State;

pub(crate) fn escape_csv(s: &str) -> String {
    // SECURITY: prefix dangerous characters to prevent CSV formula injection
    // when opened in Excel/LibreOffice. Characters =, +, -, @, \t, \0 at the
    // start of a cell are interpreted as formulas.
    let trimmed = s.trim_start();
    let sanitized = if trimmed.starts_with('=')
        || trimmed.starts_with('+')
        || trimmed.starts_with('-')
        || trimmed.starts_with('@')
        || trimmed.starts_with('\t')
        || trimmed.starts_with('\0')
    {
        format!("'{}", s) // single-quote prefix neutralizes formula
    } else {
        s.to_string()
    };
    if sanitized.contains(',')
        || sanitized.contains('"')
        || sanitized.contains('\n')
        || sanitized.contains('\r')
    {
        format!("\"{}\"", sanitized.replace('"', "\"\""))
    } else {
        sanitized
    }
}

fn value_to_str(v: &Value, field: &str) -> String {
    v.get(field)
        .and_then(|f| f.as_str())
        .unwrap_or("")
        .to_string()
}

fn value_to_num(v: &Value, field: &str) -> String {
    v.get(field)
        .and_then(|f| f.as_f64())
        .map(|n| format!("{:.2}", n))
        .unwrap_or_default()
}

#[tauri::command]
pub(crate) fn export_time_logs_csv(state: State<AppState>) -> Result<String, String> {
    let vault = read_vault_internal(&state)?;
    let logs = vault
        .get("timeLogs")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut csv = String::from("Data,Fascicolo,Descrizione,Ore,Tariffa,Totale\n");
    for log in &logs {
        csv.push_str(&format!(
            "{},{},{},{},{},{}\n",
            escape_csv(&value_to_str(log, "date")),
            escape_csv(&value_to_str(log, "practiceId")),
            escape_csv(&value_to_str(log, "description")),
            value_to_num(log, "hours"),
            value_to_num(log, "rate"),
            value_to_num(log, "total"),
        ));
    }
    Ok(csv)
}

#[tauri::command]
pub(crate) fn export_invoices_csv(state: State<AppState>) -> Result<String, String> {
    let vault = read_vault_internal(&state)?;
    let invoices = vault
        .get("invoices")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut csv = String::from("Numero,Data,Cliente,Importo,Stato\n");
    for inv in &invoices {
        csv.push_str(&format!(
            "{},{},{},{},{}\n",
            escape_csv(&value_to_str(inv, "number")),
            escape_csv(&value_to_str(inv, "date")),
            escape_csv(&value_to_str(inv, "client")),
            value_to_num(inv, "amount"),
            escape_csv(&value_to_str(inv, "status")),
        ));
    }
    Ok(csv)
}
