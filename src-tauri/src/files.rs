// ═══════════════════════════════════════════════════════════
//  FILES — File selection, PDF, Typst, system utilities
// ═══════════════════════════════════════════════════════════

use crate::state::AppState;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, State};

// ─── Constants ──────────────────────────────────────────────

/// Max bytes allowed by `read_file_base64` (50 MiB).
const READ_FILE_MAX_BYTES: u64 = 50 * 1024 * 1024;

/// Allowlist of extensions for `read_file_base64` (FE-driven PDF render etc.).
const READ_ALLOWED_EXT: &[&str] = &["pdf", "png", "jpg", "jpeg", "txt", "csv"];

/// Max payload size for `write_pdf_to_path` (100 MiB).
const WRITE_PDF_MAX_BYTES: usize = 100 * 1024 * 1024;

/// Max number of entries returned by `list_folder_contents`.
const LIST_FOLDER_MAX_ENTRIES: usize = 10_000;

/// Max length per Typst text field (64 KiB) before truncation.
const TYPST_FIELD_MAX_BYTES: usize = 64 * 1024;

// ─── Open path (with security sanitization) ─────────────────

fn open_path_impl(app: AppHandle, path: String) {
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
        // L14: SVG removed — SVGs can contain embedded JavaScript and are a
        // cross-site scripting vector when opened in a browser/webview context.
        const ALLOWED_EXTENSIONS: &[&str] = &[
            "pdf", "docx", "doc", "xlsx", "xls", "pptx", "ppt", "txt", "rtf", "odt", "ods", "odp",
            "csv", "png", "jpg", "jpeg", "gif", "bmp", "webp", "lex",
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

async fn select_file_impl(
    app: AppHandle,
    extensions: Option<Vec<String>>,
) -> Result<Option<Value>, String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let exts = extensions.unwrap_or_else(|| vec!["pdf".into(), "docx".into(), "doc".into()]);
    let ext_refs: Vec<&str> = exts.iter().map(|s| s.as_str()).collect();
    app.dialog()
        .file()
        .add_filter("Documenti", &ext_refs)
        .pick_file(move |file_path| {
            let _ = tx.send(file_path);
        });
    let file = rx.await.map_err(|e| format!("Dialog error: {}", e))?;
    // FIX-S5: canonicalize the OS-provided path before returning so downstream
    // consumers always work on a fully resolved, symlink-free path.
    Ok(file.and_then(|f| {
        let path = f.into_path().ok()?;
        let canonical = path.canonicalize().unwrap_or(path);
        let name = canonical
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());
        Some(json!({"name": name, "path": canonical.to_string_lossy()}))
    }))
}

/// Build the allowlist of directory prefixes accepted by `read_file_base64`.
/// Mirrors `write_pdf_to_path`'s allowlist plus the LexFlow data_dir (for vault
/// read-back) and the system temp dir (for in-flight Typst PDFs).
fn allowed_read_prefixes(app: &AppHandle) -> Vec<std::path::PathBuf> {
    let mut v: Vec<std::path::PathBuf> = Vec::new();
    if let Some(home) = dirs::home_dir() {
        if let Ok(c) = home.canonicalize() {
            v.push(c);
        }
    }
    if let Some(d) = dirs::document_dir().and_then(|p| p.canonicalize().ok()) {
        v.push(d);
    }
    if let Some(d) = dirs::desktop_dir().and_then(|p| p.canonicalize().ok()) {
        v.push(d);
    }
    if let Some(d) = dirs::download_dir().and_then(|p| p.canonicalize().ok()) {
        v.push(d);
    }
    if let Ok(data_dir) = app.path().app_data_dir() {
        if let Ok(c) = data_dir.canonicalize() {
            v.push(c);
        }
    }
    if let Ok(t) = std::env::temp_dir().canonicalize() {
        v.push(t);
    }
    v
}

/// Read a file and return its contents as base64 (for PDF rendering in frontend).
///
/// SECURITY (CRIT-3, BE-11 S4):
/// - Canonicalizes the input path and rejects symlinks.
/// - Restricts to an extension allowlist (pdf/png/jpg/jpeg/txt/csv).
/// - Restricts to an allowlist of directory prefixes (Documents, Desktop,
///   Downloads, app data_dir, temp_dir).
/// - Caps the file size at `READ_FILE_MAX_BYTES` via `safe_bounded_read`.
fn read_file_base64_impl(app: AppHandle, path: String) -> Result<String, String> {
    let p = std::path::PathBuf::from(&path);
    if !p.is_absolute() {
        return Err("percorso relativo non consentito".into());
    }
    // Reject any explicit `..` component; canonicalize will then resolve symlinks.
    if p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("percorso non consentito (contiene '..')".into());
    }

    // Reject symlinks before canonicalizing (canonicalize would follow them).
    let meta = std::fs::symlink_metadata(&p)
        .map_err(|_| "path non valido o file inesistente".to_string())?;
    if meta.file_type().is_symlink() {
        return Err("symlink rifiutati".into());
    }
    if !meta.is_file() {
        return Err("non è un file regolare".into());
    }

    let canonical = p
        .canonicalize()
        .map_err(|_| "path non valido o file inesistente".to_string())?;

    // Re-check after canonicalization in case of TOCTOU.
    let canon_meta =
        std::fs::symlink_metadata(&canonical).map_err(|_| "path non valido".to_string())?;
    if canon_meta.file_type().is_symlink() {
        return Err("symlink rifiutati".into());
    }

    // Extension allowlist (re-checked on the canonical path).
    let ext = canonical
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    if !READ_ALLOWED_EXT.contains(&ext.as_str()) {
        return Err(format!("estensione non consentita: {}", ext));
    }

    // Prefix allowlist mirroring write_pdf_to_path.
    let allowed = allowed_read_prefixes(&app);
    if !allowed.iter().any(|prefix| canonical.starts_with(prefix)) {
        eprintln!(
            "[LexFlow] SECURITY: read_file_base64 refused path outside allowed dirs: {:?}",
            canonical
        );
        return Err("path non consentito (fuori dalle directory permesse)".into());
    }

    let bytes = crate::io::safe_bounded_read(&canonical, READ_FILE_MAX_BYTES)
        .map_err(|e| format!("Errore lettura file: {}", e))?;
    Ok(B64.encode(&bytes))
}

/// Select multiple files at once (for merge, batch operations).
async fn select_files_impl(
    app: AppHandle,
    extensions: Option<Vec<String>>,
) -> Result<Vec<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut builder = app.dialog().file();
    let exts: Vec<String> = extensions.unwrap_or_else(|| vec!["pdf".into()]);
    let ext_refs: Vec<&str> = exts.iter().map(|s| s.as_str()).collect();
    builder = builder.add_filter("Documenti", &ext_refs);
    builder.pick_files(move |file_paths| {
        let _ = tx.send(file_paths);
    });
    let result = rx.await.map_err(|e| format!("Dialog error: {}", e))?;
    // FIX-S5: canonicalize each returned path so consumers can rely on a
    // resolved absolute path with no symlinks.
    Ok(result
        .unwrap_or_default()
        .into_iter()
        .filter_map(|f| {
            f.into_path()
                .ok()
                .map(|p| p.canonicalize().unwrap_or(p).to_string_lossy().to_string())
        })
        .collect())
}

async fn select_folder_impl(app: AppHandle) -> Result<Option<String>, String> {
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
    // FIX-S5: canonicalize the folder path before returning.
    Ok(folder.and_then(|f| {
        f.into_path()
            .ok()
            .map(|p| p.canonicalize().unwrap_or(p).to_string_lossy().to_string())
    }))
}

// ─── PDF save/write ─────────────────────────────────────────

async fn select_pdf_save_path_impl(
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
            // FIX-S5: canonicalize the parent directory if the file does not
            // yet exist; otherwise canonicalize the full path. This produces
            // an absolute, symlink-free string for consumers.
            let canonical_str = if let Ok(c) = path.canonicalize() {
                c.to_string_lossy().into_owned()
            } else if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
                parent
                    .canonicalize()
                    .map(|c| c.join(name).to_string_lossy().into_owned())
                    .unwrap_or_else(|_| path.to_string_lossy().into_owned())
            } else {
                path.to_string_lossy().into_owned()
            };
            Ok(Some(canonical_str))
        }
        None => Ok(None),
    }
}

async fn write_pdf_to_path_impl(
    app: AppHandle,
    path: String,
    data: Vec<u8>,
) -> Result<bool, String> {
    if data.is_empty() {
        return Err("Cannot write empty PDF data".to_string());
    }
    // FIX-V4: cap incoming PDF payload to 100 MiB.
    if data.len() > WRITE_PDF_MAX_BYTES {
        return Err(format!(
            "Payload troppo grande ({} bytes), massimo consentito {} bytes",
            data.len(),
            WRITE_PDF_MAX_BYTES
        ));
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
    // FIX-S6: explicitly DENY any write inside the LexFlow data directory
    // even if otherwise allowed (we don't want callers overwriting vault state).
    if let Ok(lex_dir) = app.path().app_data_dir() {
        if let Ok(c_lex) = lex_dir.canonicalize() {
            if canonical_parent.starts_with(&c_lex) {
                return Err("Scrittura nella directory dati di LexFlow non consentita".into());
            }
        }
    }
    {
        // SECURITY FIX: write to canonical_parent + filename, not the original path.
        // Prevents path traversal via ".." segments that pass parent check but resolve elsewhere.
        let filename = p.file_name().ok_or("Nessun nome file")?;
        let safe_path = canonical_parent.join(filename);
        // FIX-S8: re-check extension on the canonicalized full path.
        let safe_ext = safe_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        if safe_ext != "pdf" {
            return Err("Solo file .pdf consentiti".into());
        }
        // A failed write must not leave a partial PDF under the final name.
        // Staging also preserves the existing no-overwrite/symlink protection.
        crate::hardening::publish_new_bytes(&data, &safe_path)?;
    }
    Ok(true)
}

// ─── List folder contents ───────────────────────────────────

fn list_folder_contents_impl(path: String) -> Result<Value, String> {
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
    let mut truncated = false;
    match std::fs::read_dir(&canonical) {
        Ok(rd) => {
            for entry in rd.flatten() {
                // FIX-V5: cap to LIST_FOLDER_MAX_ENTRIES.
                if items.len() >= LIST_FOLDER_MAX_ENTRIES {
                    truncated = true;
                    break;
                }
                // FIX-S9: use symlink_metadata to avoid following symlinks,
                // and skip any symlink entry rather than exposing its target.
                let md = match entry.path().symlink_metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if md.file_type().is_symlink() {
                    continue;
                }
                let is_dir = md.file_type().is_dir();
                let modified = md.modified().ok().map(|t| {
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
            if truncated {
                items.push(json!({
                    "name": "[truncated]",
                    "path": "",
                    "is_dir": false,
                    "modified": null,
                    "truncated": true,
                }));
            }
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

// Compatibility IPC: old clients used this to warm a runtime Swift compiler.
// Biometric detection is now compiled into the app; preserve the command name.
#[tauri::command]
pub(crate) fn warm_swift() -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    {
        Ok(crate::bio::check_bio())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(false)
    }
}

// ─── Typst PDF generation ───────────────────────────────────

/// FIX-S10: escape Typst metacharacters AND collapse control characters
/// (newlines, tabs, NULs, …) to plain spaces so they can never be used to
/// inject Typst markup or line-break templates.
fn escape_typst(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for ch in input.chars() {
        match ch {
            '`' | '#' | '$' | '*' | '@' | '[' | ']' | '\\' | '_' | '~' | '<' | '>' | '{' | '}'
            | '"' => {
                out.push('\\');
                out.push(ch);
            }
            '\n' | '\r' | '\t' => out.push(' '),
            c if (c as u32) < 0x20 => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// FIX-V6 / FIX-S10: cap a Typst input field at `TYPST_FIELD_MAX_BYTES` and
/// append a `[truncated]` marker if the input was clipped. Operates on byte
/// length but never splits a UTF-8 char.
fn cap_typst_field(input: &str) -> String {
    if input.len() <= TYPST_FIELD_MAX_BYTES {
        return input.to_string();
    }
    // Find a char boundary at or before the cap.
    let mut idx = TYPST_FIELD_MAX_BYTES;
    while idx > 0 && !input.is_char_boundary(idx) {
        idx -= 1;
    }
    let mut out = String::with_capacity(idx + 16);
    out.push_str(&input[..idx]);
    out.push_str(" [truncated]");
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

async fn generate_typst_pdf_impl(
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
                let date_safe = escape_typst(&cap_typst_field(&dl.date));
                let label_safe = escape_typst(&cap_typst_field(&dl.label));
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
                let date_safe = escape_typst(&cap_typst_field(&entry.date));
                let text_safe = escape_typst(&cap_typst_field(&entry.text));
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

    // FIX-V6 / FIX-S10: cap each input field to TYPST_FIELD_MAX_BYTES
    // (64 KiB) BEFORE escaping so the resulting Typst document size stays
    // bounded regardless of incoming payload size.
    let client_safe = escape_typst(&cap_typst_field(&data.client));
    let type_label_safe = escape_typst(&cap_typst_field(&data.type_label));
    let status_label_safe = escape_typst(&cap_typst_field(&data.status_label));
    let object_safe = escape_typst(&cap_typst_field(data.object.as_deref().unwrap_or("—")));
    let counterparty_safe = escape_typst(&cap_typst_field(
        data.counterparty.as_deref().unwrap_or("—"),
    ));
    let court_safe = escape_typst(&cap_typst_field(data.court.as_deref().unwrap_or("—")));
    let code_safe = escape_typst(&cap_typst_field(data.code.as_deref().unwrap_or("—")));
    let description_safe =
        escape_typst(&cap_typst_field(data.description.as_deref().unwrap_or("")));
    let counterparty_label_safe = escape_typst(&cap_typst_field(&data.counterparty_label));
    let court_label_safe = escape_typst(&cap_typst_field(&data.court_label));
    let code_label_safe = escape_typst(&cap_typst_field(&data.code_label));
    let studio_safe = escape_typst(&cap_typst_field(data.studio_name.as_deref().unwrap_or("")));
    let lawyer_safe = escape_typst(&cap_typst_field(data.lawyer_name.as_deref().unwrap_or("")));
    let lawyer_title_safe = escape_typst(&cap_typst_field(
        data.lawyer_title.as_deref().unwrap_or("Avv."),
    ));

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

    let work = crate::hardening::DocumentWorkspace::new()?;
    let file_typst = work.join("report.typ");
    let file_pdf = work.join("report.pdf");

    crate::io::secure_write(&file_typst, document.as_bytes())
        .map_err(|e| format!("Cannot write temp .typ: {}", e))?;

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

    let mut succeeded = false;
    while let Some(event) = rx.recv().await {
        if let CommandEvent::Terminated(payload) = event {
            if payload.code != Some(0) {
                return Err("Generazione PDF non riuscita.".to_string());
            }
            succeeded = true;
        }
    }

    if !succeeded {
        return Err("Generazione PDF interrotta.".to_string());
    }

    // TODO(audit:BE-11-S12): wrap pdf_bytes in `Zeroizing<Vec<u8>>` before
    // return. Currently the Tauri command signature returns Vec<u8>, which is
    // moved out and can leave plaintext PDF in process memory until dropped.
    let pdf_bytes = crate::io::safe_bounded_read(&file_pdf, 50 * 1024 * 1024)
        .map_err(|e| format!("Cannot read generated PDF: {}", e))?;
    let _ = crate::security::secure_delete_file(&file_typst);
    let _ = crate::security::secure_delete_file(&file_pdf);

    Ok(pdf_bytes)
}

// ─── Authenticated file IPC ──────────────────────────────

#[tauri::command]
pub(crate) fn open_path(
    state: State<'_, AppState>,
    app: AppHandle,
    path: String,
) -> Result<(), String> {
    let session = state.document_session()?;
    open_path_impl(app, path);
    state.validate_document_session(session)
}

#[tauri::command]
pub(crate) async fn select_file(
    state: State<'_, AppState>,
    app: AppHandle,
    extensions: Option<Vec<String>>,
) -> Result<Option<Value>, String> {
    let session = state.document_session()?;
    let mut result = select_file_impl(app, extensions).await;
    if let Err(error) = state.validate_document_session(session) {
        if let Ok(Some(value)) = &mut result {
            crate::state::scrub_json(value);
        }
        return Err(error);
    }
    result
}

#[tauri::command]
pub(crate) fn read_file_base64(
    state: State<'_, AppState>,
    app: AppHandle,
    path: String,
) -> Result<String, String> {
    let session = state.document_session()?;
    let mut result = read_file_base64_impl(app, path);
    if let Err(error) = state.validate_document_session(session) {
        use zeroize::Zeroize;
        if let Ok(value) = &mut result {
            value.zeroize();
        }
        return Err(error);
    }
    result
}

#[tauri::command]
pub(crate) async fn select_files(
    state: State<'_, AppState>,
    app: AppHandle,
    extensions: Option<Vec<String>>,
) -> Result<Vec<String>, String> {
    let session = state.document_session()?;
    let mut result = select_files_impl(app, extensions).await;
    if let Err(error) = state.validate_document_session(session) {
        use zeroize::Zeroize;
        if let Ok(value) = &mut result {
            value.zeroize();
        }
        return Err(error);
    }
    result
}

#[tauri::command]
pub(crate) async fn select_folder(
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<Option<String>, String> {
    let session = state.document_session()?;
    let mut result = select_folder_impl(app).await;
    if let Err(error) = state.validate_document_session(session) {
        use zeroize::Zeroize;
        if let Ok(value) = &mut result {
            value.zeroize();
        }
        return Err(error);
    }
    result
}

#[tauri::command]
pub(crate) async fn select_pdf_save_path(
    state: State<'_, AppState>,
    app: AppHandle,
    default_name: String,
) -> Result<Option<String>, String> {
    let session = state.document_session()?;
    let mut result = select_pdf_save_path_impl(app, default_name).await;
    if let Err(error) = state.validate_document_session(session) {
        use zeroize::Zeroize;
        if let Ok(value) = &mut result {
            value.zeroize();
        }
        return Err(error);
    }
    result
}

#[tauri::command]
pub(crate) async fn write_pdf_to_path(
    state: State<'_, AppState>,
    app: AppHandle,
    path: String,
    data: Vec<u8>,
) -> Result<bool, String> {
    let session = state.document_session()?;
    let result = write_pdf_to_path_impl(app, path, data).await;
    state.validate_document_session(session)?;
    result
}

#[tauri::command]
pub(crate) fn list_folder_contents(
    state: State<'_, AppState>,
    path: String,
) -> Result<Value, String> {
    let session = state.document_session()?;
    let mut result = list_folder_contents_impl(path);
    if let Err(error) = state.validate_document_session(session) {
        if let Ok(value) = &mut result {
            crate::state::scrub_json(value);
        }
        return Err(error);
    }
    result
}

#[tauri::command]
pub(crate) async fn generate_typst_pdf(
    state: State<'_, AppState>,
    app: AppHandle,
    data: TypstPracticeData,
) -> Result<Vec<u8>, String> {
    let session = state.document_session()?;
    let mut result = generate_typst_pdf_impl(app, data).await;
    if let Err(error) = state.validate_document_session(session) {
        use zeroize::Zeroize;
        if let Ok(value) = &mut result {
            value.zeroize();
        }
        return Err(error);
    }
    result
}

// ─── Platform info commands ─────────────────────────────────

#[tauri::command]
pub(crate) fn window_close(app: AppHandle, state: State<AppState>) {
    state.lock_vault();
    let _ = app.emit("lf-lock", ());
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
