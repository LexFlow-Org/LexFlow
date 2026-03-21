// ═══════════════════════════════════════════════════════════
//  CSV EXPORT — time logs and invoices
// ═══════════════════════════════════════════════════════════

use crate::state::AppState;
use crate::vault::read_vault_internal;
use serde_json::Value;
use tauri::State;

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
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
