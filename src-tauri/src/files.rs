// ═══════════════════════════════════════════════════════════
//  FILES — File selection, PDF, Typst, system utilities
// ═══════════════════════════════════════════════════════════

use crate::state::AppState;
use serde_json::{json, Value};
use std::fs;
use tauri::{AppHandle, Manager, State};

// ─── Open path (with security sanitization) ─────────────────

#[tauri::command]
pub(crate) fn open_path(app: AppHandle, path: String) {
    #[cfg(not(target_os = "android"))]
    {
        let p = std::path::Path::new(&path);
        if !p.exists() || !p.is_absolute() {
            eprintln!(
                "[LexFlow] SECURITY: open_path refused non-existent/relative path: {:?}",
                path
            );
            return;
        }
        let canonical = match p.canonicalize() {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "[LexFlow] SECURITY: open_path failed to canonicalize {:?}: {}",
                    path, e
                );
                return;
            }
        };
        let is_dir = canonical.is_dir();
        let ext = canonical
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        const ALLOWED_EXTENSIONS: &[&str] = &[
            "pdf", "docx", "doc", "xlsx", "xls", "pptx", "ppt", "txt", "rtf", "odt", "ods", "odp",
            "csv", "png", "jpg", "jpeg", "gif", "bmp", "svg", "webp", "lex",
        ];
        if !is_dir && !ALLOWED_EXTENSIONS.contains(&ext.as_str()) {
            eprintln!(
                "[LexFlow] SECURITY: open_path refused non-allowed extension (after canonicalize): {:?} → {:?}",
                path, canonical
            );
            return;
        }
        use tauri_plugin_opener::OpenerExt;
        let canonical_str = canonical.to_string_lossy().to_string();
        if let Err(e) = app.opener().open_path(&canonical_str, None::<&str>) {
            eprintln!("[LexFlow] Failed to open path: {:?}", e);
        }
    }
    #[cfg(target_os = "android")]
    {
        let _ = (app, path);
    }
}

// ─── File/folder selection dialogs ──────────────────────────

#[tauri::command]
pub(crate) async fn select_file(app: AppHandle) -> Result<Option<Value>, String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .add_filter("Documenti", &["pdf", "docx", "doc"])
        .pick_file(move |file_path| {
            let _ = tx.send(file_path);
        });
    let file = rx.await.map_err(|e| format!("Dialog error: {}", e))?;
    Ok(file.and_then(|f| {
        let path = f.into_path().ok()?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        Some(json!({"name": name, "path": path.to_string_lossy()}))
    }))
}

#[tauri::command]
pub(crate) async fn select_folder(app: AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel();
    #[cfg(not(target_os = "android"))]
    app.dialog().file().pick_folder(move |folder_path| {
        let _ = tx.send(folder_path);
    });
    #[cfg(target_os = "android")]
    app.dialog().file().pick_file(move |folder_path| {
        let _ = tx.send(folder_path);
    });
    let folder = rx.await.map_err(|e| format!("Dialog error: {}", e))?;
    Ok(folder.and_then(|f| f.into_path().ok().map(|p| p.to_string_lossy().to_string())))
}

// ─── PDF save/write ─────────────────────────────────────────

#[tauri::command]
pub(crate) async fn select_pdf_save_path(
    app: AppHandle,
    default_name: String,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .add_filter("PDF", &["pdf"])
        .set_file_name(&default_name)
        .save_file(move |file_path| {
            let _ = tx.send(file_path);
        });
    let file_path = rx.await.map_err(|e| format!("Dialog error: {}", e))?;
    match file_path {
        Some(fp) => {
            let path = fp.into_path().map_err(|e| format!("Path error: {:?}", e))?;
            Ok(Some(path.to_string_lossy().into_owned()))
        }
        None => Ok(None),
    }
}

#[tauri::command]
pub(crate) async fn write_pdf_to_path(path: String, data: Vec<u8>) -> Result<bool, String> {
    if data.is_empty() {
        return Err("Cannot write empty PDF data".to_string());
    }
    let p = std::path::PathBuf::from(&path);
    if !p.is_absolute() {
        return Err("Percorso relativo non consentito".to_string());
    }
    let ext = p
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    if ext != "pdf" {
        return Err("Solo file .pdf consentiti".to_string());
    }
    let parent = p
        .parent()
        .ok_or_else(|| "Percorso senza directory padre".to_string())?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|_| "Directory di destinazione non valida o non accessibile".to_string())?;
    let allowed_prefixes: Vec<std::path::PathBuf> = [
        dirs::home_dir(),
        dirs::document_dir(),
        dirs::desktop_dir(),
        dirs::download_dir(),
        dirs::data_dir(),
    ]
    .iter()
    .filter_map(|d| d.as_ref().and_then(|p| p.canonicalize().ok()))
    .collect();
    let is_allowed = allowed_prefixes
        .iter()
        .any(|prefix| canonical_parent.starts_with(prefix));
    if !is_allowed {
        eprintln!(
            "[LexFlow] SECURITY: write_pdf_to_path refused path outside allowed dirs: {:?}",
            path
        );
        return Err(
            "Percorso non consentito: la destinazione deve essere all'interno delle directory dell'utente."
                .to_string(),
        );
    }
    {
        use std::io::Write;
        let mut file = fs::File::create(&path).map_err(|e| format!("Create failed: {}", e))?;
        file.write_all(&data)
            .map_err(|e| format!("Write failed: {}", e))?;
        file.sync_all().map_err(|e| format!("Sync failed: {}", e))?;
    }
    Ok(true)
}

// ─── List folder contents ───────────────────────────────────

#[tauri::command]
pub(crate) fn list_folder_contents(path: String) -> Result<Value, String> {
    let p = std::path::PathBuf::from(&path);
    if !p.is_absolute() {
        return Err("Percorso relativo non consentito".into());
    }
    let canonical = p
        .canonicalize()
        .map_err(|_| "Percorso non valido o non accessibile".to_string())?;
    let allowed_prefixes: Vec<std::path::PathBuf> = [
        dirs::home_dir(),
        dirs::document_dir(),
        dirs::desktop_dir(),
        dirs::download_dir(),
        dirs::data_dir(),
    ]
    .iter()
    .filter_map(|d| d.as_ref().and_then(|p| p.canonicalize().ok()))
    .collect();
    let is_allowed = allowed_prefixes
        .iter()
        .any(|prefix| canonical.starts_with(prefix));
    if !is_allowed {
        eprintln!(
            "[LexFlow] SECURITY: list_folder_contents refused path outside allowed dirs: {:?}",
            canonical
        );
        return Err("Percorso non consentito: accesso limitato alle directory dell'utente.".into());
    }
    if !canonical.exists() {
        return Err("Percorso non esiste".into());
    }
    let mut items: Vec<Value> = Vec::new();
    match std::fs::read_dir(&canonical) {
        Ok(rd) => {
            for entry in rd.flatten() {
                let md = entry.metadata().ok();
                let is_dir = md.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let modified = md.and_then(|m| m.modified().ok()).map(|t| {
                    let dt: chrono::DateTime<chrono::Utc> = t.into();
                    dt.to_rfc3339()
                });
                items.push(json!({
                    "name": entry.file_name().to_string_lossy(),
                    "path": entry.path().to_string_lossy(),
                    "is_dir": is_dir,
                    "modified": modified,
                }));
            }
            items.sort_by(|a, b| {
                let da = a.get("is_dir").and_then(|v| v.as_bool()).unwrap_or(false);
                let db = b.get("is_dir").and_then(|v| v.as_bool()).unwrap_or(false);
                if da != db {
                    return db.cmp(&da);
                }
                let na = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let nb = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
                na.to_lowercase().cmp(&nb.to_lowercase())
            });
            Ok(Value::Array(items))
        }
        Err(e) => {
            use std::io::ErrorKind;
            if e.kind() == ErrorKind::PermissionDenied {
                Err("Permesso negato".into())
            } else {
                Err(e.to_string())
            }
        }
    }
}

// ─── Warm Swift (macOS biometric) ───────────────────────────

#[tauri::command]
pub(crate) fn warm_swift() -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        match Command::new("/usr/bin/swift").arg("-version").output() {
            Ok(_) => Ok(true),
            Err(e) => Err(e.to_string()),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(false)
    }
}

// ─── Typst PDF generation ───────────────────────────────────

fn escape_typst(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for ch in input.chars() {
        match ch {
            '#' | '$' | '*' | '@' | '[' | ']' | '\\' | '_' | '~' | '<' | '>' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

#[derive(serde::Deserialize)]
struct TypstDeadline {
    date: String,
    label: String,
}

#[derive(serde::Deserialize)]
struct TypstDiaryEntry {
    date: String,
    text: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub(crate) struct TypstPracticeData {
    client: String,
    object: Option<String>,
    #[serde(rename = "type")]
    practice_type: String,
    type_label: String,
    status_label: String,
    counterparty: Option<String>,
    court: Option<String>,
    code: Option<String>,
    description: Option<String>,
    counterparty_label: String,
    court_label: String,
    code_label: String,
    lawyer_name: Option<String>,
    lawyer_title: Option<String>,
    studio_name: Option<String>,
    deadlines: Option<Vec<TypstDeadline>>,
    diary: Option<Vec<TypstDiaryEntry>>,
}

#[tauri::command]
pub(crate) async fn generate_typst_pdf(
    app: AppHandle,
    data: TypstPracticeData,
) -> Result<Vec<u8>, String> {
    use tauri_plugin_shell::process::CommandEvent;
    use tauri_plugin_shell::ShellExt;

    let template_path = app
        .path()
        .resource_dir()
        .map_err(|e| format!("Cannot resolve resource dir: {}", e))?
        .join("templates")
        .join("fascicolo.typ");

    let template = std::fs::read_to_string(&template_path)
        .map_err(|e| format!("Cannot read template: {} (path: {:?})", e, template_path))?;

    let deadlines_content = match &data.deadlines {
        Some(dls) if !dls.is_empty() => {
            let mut s = String::new();
            s.push_str("#pagebreak(weak: true)\n");
            s.push_str("#text(size: 13pt, weight: \"bold\", fill: slate-900, tracking: 0.3pt)[Prossime Scadenze]\n");
            s.push_str("#v(0.2cm)\n");
            s.push_str("#line(length: 100%, stroke: 0.5pt + slate-300)\n");
            s.push_str("#v(0.4cm)\n\n");
            s.push_str("#table(\n");
            s.push_str("  columns: (25%, 75%),\n");
            s.push_str("  stroke: (x, y) => if y == 0 { (bottom: 1pt + slate-300) } else { (bottom: 0.5pt + divider) },\n");
            s.push_str("  inset: 8pt,\n");
            s.push_str("  block(fill: slate-100, width: 100%, inset: 8pt)[#text(size: 8.5pt, weight: \"bold\", fill: slate-500, tracking: 1pt)[DATA]],\n");
            s.push_str("  block(fill: slate-100, width: 100%, inset: 8pt)[#text(size: 8.5pt, weight: \"bold\", fill: slate-500, tracking: 1pt)[SCADENZA]],\n");
            for dl in dls {
                let date_safe = escape_typst(&dl.date);
                let label_safe = escape_typst(&dl.label);
                s.push_str(&format!(
                    "  block(inset: 8pt)[#text(fill: slate-700, weight: \"bold\")[{}]], block(inset: 8pt)[#text(fill: slate-900)[{}]],\n",
                    date_safe, label_safe
                ));
            }
            s.push_str(")\n");
            s
        }
        _ => String::new(),
    };

    let diary_content = match &data.diary {
        Some(entries) if !entries.is_empty() => {
            let mut s = String::new();
            s.push_str("#pagebreak(weak: true)\n");
            s.push_str("#text(size: 13pt, weight: \"bold\", fill: slate-900, tracking: 0.3pt)[Diario Attività]\n");
            s.push_str("#v(0.2cm)\n");
            s.push_str("#line(length: 100%, stroke: 0.5pt + slate-300)\n");
            s.push_str("#v(0.4cm)\n\n");
            s.push_str("#table(\n");
            s.push_str("  columns: (20%, 80%),\n");
            s.push_str("  stroke: (x, y) => if y == 0 { (bottom: 1pt + slate-300) } else { (bottom: 0.5pt + divider) },\n");
            s.push_str("  inset: 8pt,\n");
            s.push_str("  block(fill: slate-100, width: 100%, inset: 8pt)[#text(size: 8.5pt, weight: \"bold\", fill: slate-500, tracking: 1pt)[DATA]],\n");
            s.push_str("  block(fill: slate-100, width: 100%, inset: 8pt)[#text(size: 8.5pt, weight: \"bold\", fill: slate-500, tracking: 1pt)[ANNOTAZIONE]],\n");
            for entry in entries {
                let date_safe = escape_typst(&entry.date);
                let text_safe = escape_typst(&entry.text);
                s.push_str(&format!(
                    "  block(inset: 8pt)[#text(fill: slate-700, weight: \"bold\")[{}]], block(inset: 8pt)[#text(fill: slate-900)[{}]],\n",
                    date_safe, text_safe
                ));
            }
            s.push_str(")\n");
            s
        }
        _ => String::new(),
    };

    let client_safe = escape_typst(&data.client);
    let type_label_safe = escape_typst(&data.type_label);
    let status_label_safe = escape_typst(&data.status_label);
    let object_safe = escape_typst(data.object.as_deref().unwrap_or("—"));
    let counterparty_safe = escape_typst(data.counterparty.as_deref().unwrap_or("—"));
    let court_safe = escape_typst(data.court.as_deref().unwrap_or("—"));
    let code_safe = escape_typst(data.code.as_deref().unwrap_or("—"));
    let description_safe = escape_typst(data.description.as_deref().unwrap_or(""));
    let counterparty_label_safe = escape_typst(&data.counterparty_label);
    let court_label_safe = escape_typst(&data.court_label);
    let code_label_safe = escape_typst(&data.code_label);
    let studio_safe = escape_typst(data.studio_name.as_deref().unwrap_or(""));
    let lawyer_safe = escape_typst(data.lawyer_name.as_deref().unwrap_or(""));
    let lawyer_title_safe = escape_typst(data.lawyer_title.as_deref().unwrap_or("Avv."));

    let now = chrono::Local::now().format("%d/%m/%Y").to_string();
    let document = template
        .replace("__STUDIO_NAME__", &studio_safe)
        .replace("__LAWYER_NAME__", &lawyer_safe)
        .replace("__LAWYER_TITLE__", &lawyer_title_safe)
        .replace("__TYPE_LABEL__", &type_label_safe)
        .replace("__STATUS_LABEL__", &status_label_safe)
        .replace("__CLIENT__", &client_safe)
        .replace("__OBJECT__", &object_safe)
        .replace("__COUNTERPARTY__", &counterparty_safe)
        .replace("__COURT__", &court_safe)
        .replace("__CODE__", &code_safe)
        .replace("__DESCRIPTION__", &description_safe)
        .replace("__COUNTERPARTY_LABEL__", &counterparty_label_safe)
        .replace("__COURT_LABEL__", &court_label_safe)
        .replace("__CODE_LABEL__", &code_label_safe)
        .replace("__DATE_GENERATED__", &now)
        .replace("__DEADLINES_CONTENT__", &deadlines_content)
        .replace("__DIARY_CONTENT__", &diary_content);

    let temp_dir = std::env::temp_dir();
    let run_id = format!("{:016x}", rand::random::<u64>());
    let file_typst = temp_dir.join(format!("lexflow_{}.typ", run_id));
    let file_pdf = temp_dir.join(format!("lexflow_{}.pdf", run_id));

    std::fs::write(&file_typst, &document).map_err(|e| format!("Cannot write temp .typ: {}", e))?;

    let font_path = app
        .path()
        .resource_dir()
        .map_err(|e| format!("Cannot resolve resource dir: {}", e))?
        .join("fonts");

    let sidecar_command = app
        .shell()
        .sidecar("typst")
        .map_err(|e| format!("Sidecar typst non trovato: {}", e))?
        .args([
            "compile",
            &file_typst.to_string_lossy(),
            &file_pdf.to_string_lossy(),
            "--font-path",
            &font_path.to_string_lossy(),
        ]);

    let (mut rx, _child) = sidecar_command
        .spawn()
        .map_err(|e| format!("Impossibile avviare Typst: {}", e))?;

    let mut stderr_output = String::new();
    while let Some(event) = rx.recv().await {
        match event {
            CommandEvent::Stderr(line) => {
                stderr_output.push_str(&String::from_utf8_lossy(&line));
            }
            CommandEvent::Terminated(payload) => {
                if payload.code != Some(0) {
                    let _ = crate::security::secure_delete_file(&file_typst);
                    let _ = crate::security::secure_delete_file(&file_pdf);
                    return Err(format!(
                        "Typst compilation failed (exit {}): {}",
                        payload.code.unwrap_or(-1),
                        stderr_output
                    ));
                }
            }
            _ => {}
        }
    }

    let pdf_bytes =
        std::fs::read(&file_pdf).map_err(|e| format!("Cannot read generated PDF: {}", e))?;
    let _ = crate::security::secure_delete_file(&file_typst);
    let _ = crate::security::secure_delete_file(&file_pdf);

    Ok(pdf_bytes)
}

// ─── Platform info commands ─────────────────────────────────

#[tauri::command]
pub(crate) fn window_close(app: AppHandle, state: State<AppState>) {
    *state.vault_key.lock().unwrap_or_else(|e| e.into_inner()) = None;
    #[cfg(not(target_os = "android"))]
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.hide();
    }
    #[cfg(target_os = "android")]
    {
        let _ = app;
    }
}

#[tauri::command]
pub(crate) fn get_app_version(app: AppHandle) -> String {
    app.package_info().version.to_string()
}

#[tauri::command]
pub(crate) fn is_mac() -> bool {
    cfg!(target_os = "macos")
}

#[tauri::command]
pub(crate) fn get_platform() -> String {
    #[cfg(target_os = "android")]
    {
        "android".to_string()
    }
    #[cfg(target_os = "ios")]
    {
        "ios".to_string()
    }
    #[cfg(target_os = "macos")]
    {
        "macos".to_string()
    }
    #[cfg(target_os = "windows")]
    {
        "windows".to_string()
    }
    #[cfg(target_os = "linux")]
    {
        "linux".to_string()
    }
    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "macos",
        target_os = "windows",
        target_os = "linux"
    )))]
    {
        "unknown".to_string()
    }
}
