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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_csv_simple() {
        assert_eq!(escape_csv("hello"), "hello");
        assert_eq!(escape_csv("Mario Rossi"), "Mario Rossi");
    }

    #[test]
    fn test_escape_csv_comma() {
        assert_eq!(escape_csv("Rossi, Mario"), "\"Rossi, Mario\"");
    }

    #[test]
    fn test_escape_csv_quotes() {
        assert_eq!(escape_csv("Detto \"il capo\""), "\"Detto \"\"il capo\"\"\"");
    }

    #[test]
    fn test_escape_csv_newline() {
        assert_eq!(escape_csv("line1\nline2"), "\"line1\nline2\"");
    }

    #[test]
    fn test_escape_csv_carriage_return() {
        assert_eq!(escape_csv("a\rb"), "\"a\rb\"");
    }

    #[test]
    fn test_escape_csv_formula_injection_equals() {
        let result = escape_csv("=CMD(\"calc\")");
        // Result is quoted because of inner ", but the ' prefix neutralizes the formula
        assert!(result.contains("'=CMD"), "Formula starting with = must contain ' prefix: got {}", result);
    }

    #[test]
    fn test_escape_csv_formula_injection_plus() {
        let result = escape_csv("+1+1");
        assert!(result.starts_with("'"), "got: {}", result);
    }

    #[test]
    fn test_escape_csv_formula_injection_minus() {
        let result = escape_csv("-1-1");
        assert!(result.starts_with("'"), "got: {}", result);
    }

    #[test]
    fn test_escape_csv_formula_injection_at() {
        let result = escape_csv("@SUM(A1:A10)");
        assert!(result.starts_with("'"), "got: {}", result);
    }

    #[test]
    fn test_escape_csv_formula_injection_tab() {
        let result = escape_csv("\t=evil");
        assert!(result.starts_with("'"), "got: {}", result);
    }

    #[test]
    fn test_escape_csv_formula_injection_null() {
        let result = escape_csv("\0=evil");
        assert!(result.starts_with("'"), "got: {}", result);
    }

    #[test]
    fn test_escape_csv_formula_with_leading_spaces() {
        // trim_start is used, so "  =CMD" should still be caught
        let result = escape_csv("  =CMD(\"calc\")");
        // Contains ' prefix for formula neutralization (may also be quoted due to ")
        assert!(result.contains("'"), "Formula with spaces must contain ' prefix: got {}", result);
    }

    #[test]
    fn test_escape_csv_empty() {
        assert_eq!(escape_csv(""), "");
    }

    #[test]
    fn test_escape_csv_formula_plus_comma() {
        // Formula injection + comma → both prefix and quoting
        let result = escape_csv("+1,2");
        assert!(result.contains("'"), "Must contain ' prefix: got {}", result);
        assert!(result.contains("\""), "Must be quoted due to comma: got {}", result);
    }

    #[test]
    fn test_escape_csv_realistic_legal_text() {
        let text = "Avv. Mario Rossi — Studio Legale \"Rossi & Partners\", Via Roma 42";
        let escaped = escape_csv(text);
        // Should be quoted (contains comma and quotes)
        assert!(escaped.starts_with("\""));
        assert!(escaped.ends_with("\""));
        // Inner quotes should be doubled
        assert!(escaped.contains("\"\"Rossi"));
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
