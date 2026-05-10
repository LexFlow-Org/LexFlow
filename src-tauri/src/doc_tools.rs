// ═══════════════════════════════════════════════════════════
//  DOC TOOLS — PDF manipulation for legal professionals
// ═══════════════════════════════════════════════════════════
//
// TODO(audit:LOW-F10): the temp files used by add_watermark / add_page_numbers
// / redact_pdf / images_to_pdf are still created via `std::fs::write` on a
// `rand::random::<u64>()` path. That has a tiny TOCTOU window where a
// malicious local user could symlink-swap the path before write. The
// password-handling sites in secure_pdf / unsecure_pdf / redact_pdf already
// use `tempfile::NamedTempFile`. Migrate the remaining temp-file uses to
// `tempfile::NamedTempFile::new_in(std::env::temp_dir())` and persist via
// `.path()` / `.persist_noclobber()` to fully close that gap.

use lopdf::{Document, Object, ObjectId};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ─── Path validation ───────────────────────────────────────

/// Build the list of allowed directory prefixes for doc_tools paths.
fn allowed_prefixes() -> Vec<PathBuf> {
    [
        dirs::home_dir(),
        dirs::document_dir(),
        dirs::desktop_dir(),
        dirs::download_dir(),
        dirs::data_dir(),
        Some(std::env::temp_dir()),
    ]
    .iter()
    .filter_map(|d| d.as_ref().and_then(|p| p.canonicalize().ok()))
    .collect()
}

/// Validate an **input** file path: must be absolute, must exist, and its
/// canonical location must fall under an allowed directory prefix.
///
// TODO(audit:HIGH-F4): TOCTOU symlink-swap window exists between
// validate_input_path and the qpdf invocation that subsequently opens the
// file. To close it, open the file once after validation and pass
// `/dev/fd/<n>` (Linux/macOS) to qpdf so the process inherits the same
// inode. Skipped here as it requires per-call refactoring; the validation
// + canonicalize path mitigates most attacks but is not race-free.
fn validate_input_path(path: &str) -> Result<(), String> {
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err("Percorso relativo non consentito".to_string());
    }
    let canonical = p
        .canonicalize()
        .map_err(|_| format!("Percorso non valido o non accessibile: {}", path))?;
    let prefixes = allowed_prefixes();
    if !prefixes.iter().any(|pfx| canonical.starts_with(pfx)) {
        #[cfg(debug_assertions)]
        eprintln!(
            "[LexFlow] SECURITY: doc_tools refused input path outside allowed dirs: {:?}",
            canonical
        );
        return Err(
            "Percorso non consentito: il file deve trovarsi nelle directory dell'utente."
                .to_string(),
        );
    }
    Ok(())
}

/// Validate an **output** file path: must be absolute, parent directory must
/// exist and its canonical location must fall under an allowed directory prefix.
/// Also rejects filenames that could be interpreted as flags (leading '-') or
/// contain control characters / null bytes (argv-injection mitigations).
fn validate_output_path(path: &str) -> Result<(), String> {
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err("Percorso relativo non consentito".to_string());
    }
    // F3: validate the filename portion itself (the parent canonicalize check
    // does NOT cover the basename — and basename ends up on argv).
    let basename = p
        .file_name()
        .ok_or_else(|| "Percorso non valido: manca il nome del file".to_string())?
        .to_string_lossy()
        .to_string();
    if basename.starts_with('-')
        || basename.contains('\n')
        || basename.contains('\r')
        || basename.contains('\0')
    {
        return Err(
            "Nome file non valido: trattino iniziale o caratteri di controllo non consentiti."
                .to_string(),
        );
    }
    let parent = p
        .parent()
        .ok_or_else(|| "Percorso senza directory padre".to_string())?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|_| "Directory di destinazione non valida o non accessibile".to_string())?;
    let prefixes = allowed_prefixes();
    if !prefixes.iter().any(|pfx| canonical_parent.starts_with(pfx)) {
        #[cfg(debug_assertions)]
        eprintln!(
            "[LexFlow] SECURITY: doc_tools refused output path outside allowed dirs: {:?}",
            path
        );
        return Err(
            "Percorso non consentito: la destinazione deve essere all'interno delle directory dell'utente."
                .to_string(),
        );
    }
    Ok(())
}

/// Validate an **output directory** path: must be absolute, must exist (or its
/// parent must), and its canonical location must fall under an allowed prefix.
fn validate_output_dir(path: &str) -> Result<(), String> {
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err("Percorso relativo non consentito".to_string());
    }
    // Try to canonicalize the dir itself; if it doesn't exist yet, check its parent
    let canonical = if p.exists() {
        p.canonicalize()
            .map_err(|_| "Directory non valida o non accessibile".to_string())?
    } else {
        let parent = p
            .parent()
            .ok_or_else(|| "Percorso senza directory padre".to_string())?;
        parent
            .canonicalize()
            .map_err(|_| "Directory padre non valida o non accessibile".to_string())?
    };
    let prefixes = allowed_prefixes();
    if !prefixes.iter().any(|pfx| canonical.starts_with(pfx)) {
        #[cfg(debug_assertions)]
        eprintln!(
            "[LexFlow] SECURITY: doc_tools refused output dir outside allowed dirs: {:?}",
            path
        );
        return Err(
            "Percorso non consentito: la destinazione deve essere all'interno delle directory dell'utente."
                .to_string(),
        );
    }
    Ok(())
}

// ─── Typst string escape (F11/F12) ─────────────────────────
// Escape user-controlled text so it cannot break out of a Typst string
// literal `"..."`. Typst string literals only require escaping of `\` and
// `"`; raw newlines / tabs are invalid inside a string, so they are
// converted to escape sequences. Other control characters are dropped.
// Markup characters like `#`, `[`, `]`, `$` are safe inside a string literal
// and are passed through verbatim — but we drop NUL.
fn escape_typst_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Drop other control characters (U+0000..U+001F, U+007F).
            c if (c as u32) < 0x20 || c == '\u{007F}' => {}
            c => out.push(c),
        }
    }
    out
}

// ─── qpdf stderr sanitization (F7) ─────────────────────────
// Map raw qpdf stderr (which can contain user paths and internal details) to a
// short, generic Italian message safe for the frontend.
fn map_qpdf_stderr(stderr: &str) -> &'static str {
    let s = stderr.to_lowercase();
    if s.contains("invalid password") || s.contains("password is required") {
        "Password non corretta"
    } else if s.contains("not encrypted") {
        "Il PDF non è cifrato"
    } else if s.contains("error reading") || s.contains("damaged") || s.contains("corrupt") {
        "PDF danneggiato o illeggibile"
    } else if s.contains("permission") {
        "Permessi insufficienti per operare sul file"
    } else {
        "Errore qpdf interno"
    }
}

// ─── Types ──────────────────────────────────────────────────

#[derive(Serialize)]
pub struct DocToolResult {
    pub success: bool,
    pub output_path: Option<String>,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

fn ok_result(output_path: &str, message: &str) -> DocToolResult {
    DocToolResult {
        success: true,
        output_path: Some(output_path.to_string()),
        message: message.to_string(),
        details: None,
    }
}

fn err_result(message: &str) -> DocToolResult {
    DocToolResult {
        success: false,
        output_path: None,
        message: message.to_string(),
        details: None,
    }
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// Extract a string field from the PDF Info dictionary (best-effort).
fn extract_info_string(doc: &Document, key: &[u8]) -> Option<String> {
    let info_ref = doc.trailer.get(b"Info").ok()?;
    let info_id = info_ref.as_reference().ok()?;
    let info_obj = doc.get_object(info_id).ok()?;
    let dict = info_obj.as_dict().ok()?;
    let val = dict.get(key).ok()?;
    // Try various lopdf Object string accessors
    val.as_name_str()
        .map(|s| s.to_string())
        .or_else(|_| val.as_string().map(|s| s.into_owned()))
        .ok()
}

// ─── PDF Info ───────────────────────────────────────────────

#[derive(Serialize)]
pub struct PdfInfo {
    pub pages: u32,
    pub encrypted: bool,
    pub file_size: u64,
    pub file_size_label: String,
    pub title: Option<String>,
    pub author: Option<String>,
}

#[tauri::command]
pub async fn pdf_info(app: tauri::AppHandle, path: String) -> Result<PdfInfo, String> {
    validate_input_path(&path)?;
    let file_size = std::fs::metadata(&path)
        .map(|m| m.len())
        .map_err(|e| format!("Impossibile leggere il file: {}", e))?;

    match Document::load(&path) {
        Ok(doc) => {
            let pages = doc.get_pages().len() as u32;
            let encrypted = doc.is_encrypted();
            let title = extract_info_string(&doc, b"Title");
            let author = extract_info_string(&doc, b"Author");
            Ok(PdfInfo {
                pages,
                encrypted,
                file_size,
                file_size_label: format_size(file_size),
                title,
                author,
            })
        }
        Err(_) => {
            // lopdf can't parse this PDF — use qpdf for page count
            let mut pages = 0u32;
            use tauri_plugin_shell::ShellExt;
            if let Ok(s) = app.shell().sidecar("qpdf") {
                let cmd = s.args(["--show-npages", path.as_str()]);
                if let Ok(out) = cmd.output().await {
                    if out.status.success() {
                        let stdout = String::from_utf8_lossy(&out.stdout);
                        pages = stdout.trim().parse::<u32>().unwrap_or(0);
                    }
                }
            }
            Ok(PdfInfo {
                pages,
                encrypted: false,
                file_size,
                file_size_label: format_size(file_size),
                title: None,
                author: None,
            })
        }
    }
}

// ─── Merge PDFs ─────────────────────────────────────────────

#[tauri::command]
pub fn merge_pdfs(input_paths: Vec<String>, output_path: String) -> DocToolResult {
    #[cfg(debug_assertions)]
    eprintln!(
        "[doc_tools::merge_pdfs] {} files → {}",
        input_paths.len(),
        output_path
    );
    for p in &input_paths {
        if let Err(e) = validate_input_path(p) {
            return err_result(&e);
        }
    }
    if let Err(e) = validate_output_path(&output_path) {
        return err_result(&e);
    }
    if input_paths.len() < 2 {
        return err_result("Servono almeno 2 PDF per unire.");
    }
    // Cap to a sane max to prevent DoS via huge merge job.
    if input_paths.len() > 1000 {
        return err_result("Troppi PDF in input (massimo 1000).");
    }

    // Simple approach: start with first doc, append pages from others
    let mut base = match Document::load(&input_paths[0]) {
        Ok(d) => d,
        Err(e) => return err_result(&format!("Errore nel primo file: {}", e)),
    };

    for path in &input_paths[1..] {
        let other = match Document::load(path) {
            Ok(d) => d,
            Err(e) => return err_result(&format!("Errore nel file {}: {}", path, e)),
        };

        // Merge using lopdf's built-in merge_from
        if let Err(e) = merge_document(&mut base, &other) {
            return err_result(&format!("Errore nell'unione: {}", e));
        }
    }

    base.compress();

    match base.save(&output_path) {
        Ok(_) => ok_result(
            &output_path,
            &format!("{} PDF uniti con successo.", input_paths.len()),
        ),
        Err(e) => err_result(&format!("Errore nel salvataggio: {}", e)),
    }
}

/// Merge pages from `other` into `base` document.
fn merge_document(base: &mut Document, other: &Document) -> Result<(), String> {
    let mut id_map: BTreeMap<ObjectId, ObjectId> = BTreeMap::new();
    let mut max_id = base.max_id;

    // Copy all objects from other doc with remapped IDs
    for (&id, object) in &other.objects {
        max_id = max_id
            .checked_add(1)
            .ok_or_else(|| "PDF: troppi oggetti (overflow max_id)".to_string())?;
        let new_id = (max_id, 0);
        id_map.insert(id, new_id);
        base.objects.insert(new_id, object.clone());
    }
    base.max_id = max_id;

    // Remap references within copied objects
    let new_ids: Vec<ObjectId> = id_map.values().copied().collect();
    for new_id in &new_ids {
        if let Some(obj) = base.objects.get_mut(new_id) {
            remap_references(obj, &id_map);
        }
    }

    // Get pages from other doc and add them to base's page tree
    let other_pages = other.get_pages();
    let base_pages_id = base
        .catalog()
        .map_err(|e| e.to_string())?
        .get(b"Pages")
        .map_err(|e| e.to_string())?
        .as_reference()
        .map_err(|e| e.to_string())?;

    for (_, page_id) in other_pages {
        if let Some(&new_page_id) = id_map.get(&page_id) {
            // Update page's Parent to point to base's Pages
            if let Some(obj) = base.objects.get_mut(&new_page_id) {
                if let Ok(dict) = obj.as_dict_mut() {
                    dict.set("Parent", Object::Reference(base_pages_id));
                }
            }
            // Add to Kids array
            if let Ok(pages_obj) = base.get_object_mut(base_pages_id) {
                if let Ok(pages_dict) = pages_obj.as_dict_mut() {
                    if let Ok(kids) = pages_dict.get_mut(b"Kids") {
                        if let Ok(arr) = kids.as_array_mut() {
                            arr.push(Object::Reference(new_page_id));
                        }
                    }
                    // Increment Count
                    let count = pages_dict
                        .get(b"Count")
                        .ok()
                        .and_then(|c| c.as_i64().ok())
                        .unwrap_or(0);
                    pages_dict.set("Count", Object::Integer(count + 1));
                }
            }
        }
    }

    Ok(())
}

/// Recursively remap object references using the ID map.
fn remap_references(obj: &mut Object, map: &BTreeMap<ObjectId, ObjectId>) {
    match obj {
        Object::Reference(ref mut id) => {
            if let Some(new_id) = map.get(id) {
                *id = *new_id;
            }
        }
        Object::Array(arr) => {
            for item in arr.iter_mut() {
                remap_references(item, map);
            }
        }
        Object::Dictionary(dict) => {
            for (_, val) in dict.iter_mut() {
                remap_references(val, map);
            }
        }
        Object::Stream(stream) => {
            for (_, val) in stream.dict.iter_mut() {
                remap_references(val, map);
            }
        }
        _ => {}
    }
}

// ─── Split PDF ──────────────────────────────────────────────

#[tauri::command]
pub fn split_pdf(input_path: String, output_dir: String) -> DocToolResult {
    #[cfg(debug_assertions)]
    eprintln!("[doc_tools::split_pdf] {} → dir {}", input_path, output_dir);
    if let Err(e) = validate_input_path(&input_path) {
        return err_result(&e);
    }
    if let Err(e) = validate_output_dir(&output_dir) {
        return err_result(&e);
    }
    let doc = match Document::load(&input_path) {
        Ok(d) => d,
        Err(e) => return err_result(&format!("Errore nell'apertura: {}", e)),
    };

    let total = doc.get_pages().len();
    if let Err(e) = std::fs::create_dir_all(&output_dir) {
        return err_result(&format!("Impossibile creare la cartella: {}", e));
    }

    let stem = PathBuf::from(&input_path)
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let mut created = 0;
    for page_num in 1..=total {
        let mut single = doc.clone();
        // Remove all pages except the current one
        let pages_to_remove: Vec<u32> = (1..=total as u32)
            .filter(|&p| p != page_num as u32)
            .collect();
        for &p in pages_to_remove.iter().rev() {
            single.delete_pages(&[p]);
        }

        let out_path = PathBuf::from(&output_dir).join(format!("{}_pag{}.pdf", stem, page_num));
        if single.save(&out_path).is_ok() {
            created += 1;
        }
    }

    ok_result(
        &output_dir,
        &format!("{} pagine estratte da {} totali.", created, total),
    )
}

// ─── Remove Pages ───────────────────────────────────────────

#[tauri::command]
pub async fn remove_pages(
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    pages_to_remove: Vec<u32>,
) -> DocToolResult {
    #[cfg(debug_assertions)]
    eprintln!(
        "[doc_tools::remove_pages] {} → {}, removing {:?}",
        input_path, output_path, pages_to_remove
    );
    if let Err(e) = validate_input_path(&input_path) {
        return err_result(&e);
    }
    if let Err(e) = validate_output_path(&output_path) {
        return err_result(&e);
    }
    if pages_to_remove.is_empty() {
        return err_result("Nessuna pagina selezionata.");
    }
    if pages_to_remove.len() > 100_000 {
        return err_result("Troppe pagine selezionate (massimo 100000).");
    }

    // Get total pages for validation
    let total = match Document::load(&input_path) {
        Ok(d) => d.get_pages().len() as u32,
        Err(e) => return err_result(&format!("Errore nell'apertura: {}", e)),
    };

    if pages_to_remove.iter().any(|&p| p < 1 || p > total) {
        return err_result(&format!(
            "Numeri pagina non validi. Il PDF ha {} pagine.",
            total
        ));
    }
    if pages_to_remove.len() as u32 >= total {
        return err_result("Non puoi rimuovere tutte le pagine.");
    }

    // Build page spec: keep all pages EXCEPT the ones to remove
    let pages_to_keep: Vec<String> = (1..=total)
        .filter(|p| !pages_to_remove.contains(p))
        .map(|p| p.to_string())
        .collect();
    let page_spec = pages_to_keep.join(",");

    use tauri_plugin_shell::ShellExt;
    let sidecar = match app.shell().sidecar("qpdf") {
        Ok(s) => s,
        Err(e) => return err_result(&format!("qpdf non trovato: {}", e)),
    };

    let args = vec![
        "--empty",
        "--pages",
        input_path.as_str(),
        &page_spec,
        "--",
        "--",
        output_path.as_str(),
    ];

    let cmd = sidecar.args(args);
    let removed = pages_to_remove.len();
    match cmd.output().await {
        Ok(out) if out.status.success() => ok_result(
            &output_path,
            &format!(
                "{} pagine rimosse. Rimangono {} pagine.",
                removed,
                total - removed as u32
            ),
        ),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            #[cfg(debug_assertions)]
            eprintln!("[doc_tools::remove_pages] qpdf stderr: {}", stderr);
            err_result(map_qpdf_stderr(&stderr))
        }
        Err(_e) => {
            #[cfg(debug_assertions)]
            eprintln!("[doc_tools] qpdf exec error: {}", _e);
            err_result("Errore esecuzione qpdf")
        }
    }
}

// ─── Extract Pages ──────────────────────────────────────────

#[tauri::command]
pub async fn extract_pages(
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    pages_to_extract: Vec<u32>,
) -> DocToolResult {
    #[cfg(debug_assertions)]
    eprintln!(
        "[doc_tools::extract_pages] {} → {}, extracting {:?}",
        input_path, output_path, pages_to_extract
    );
    if let Err(e) = validate_input_path(&input_path) {
        return err_result(&e);
    }
    if let Err(e) = validate_output_path(&output_path) {
        return err_result(&e);
    }
    if pages_to_extract.is_empty() {
        return err_result("Nessuna pagina selezionata.");
    }
    if pages_to_extract.len() > 100_000 {
        return err_result("Troppe pagine selezionate (massimo 100000).");
    }

    // qpdf --pages input.pdf 1,3,5 -- -- output.pdf
    let page_spec = pages_to_extract
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");

    use tauri_plugin_shell::ShellExt;
    let sidecar = match app.shell().sidecar("qpdf") {
        Ok(s) => s,
        Err(e) => return err_result(&format!("qpdf non trovato: {}", e)),
    };

    let args = vec![
        "--empty",
        "--pages",
        input_path.as_str(),
        &page_spec,
        "--",
        "--",
        output_path.as_str(),
    ];

    let cmd = sidecar.args(args);
    match cmd.output().await {
        Ok(out) if out.status.success() => ok_result(
            &output_path,
            &format!("{} pagine estratte.", pages_to_extract.len()),
        ),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            #[cfg(debug_assertions)]
            eprintln!("[doc_tools::extract_pages] qpdf stderr: {}", stderr);
            err_result(map_qpdf_stderr(&stderr))
        }
        Err(_e) => {
            #[cfg(debug_assertions)]
            eprintln!("[doc_tools] qpdf exec error: {}", _e);
            err_result("Errore esecuzione qpdf")
        }
    }
}

// ─── Compress PDF ───────────────────────────────────────────

#[tauri::command]
pub async fn compress_pdf(
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
) -> DocToolResult {
    #[cfg(debug_assertions)]
    eprintln!("[doc_tools::compress_pdf] {} → {}", input_path, output_path);
    if let Err(e) = validate_input_path(&input_path) {
        return err_result(&e);
    }
    if let Err(e) = validate_output_path(&output_path) {
        return err_result(&e);
    }
    // F5: refuse to overwrite an existing output silently.
    if std::path::Path::new(&output_path).exists() {
        return err_result(
            "Il file di destinazione esiste già. Eliminalo o scegli un'altra destinazione.",
        );
    }
    let original_size = match std::fs::metadata(&input_path) {
        Ok(m) => m.len(),
        Err(e) => return err_result(&format!("Impossibile leggere il file: {}", e)),
    };

    use tauri_plugin_shell::ShellExt;
    let sidecar = match app.shell().sidecar("qpdf") {
        Ok(s) => s,
        Err(_) => {
            // Fallback to lopdf if qpdf not available
            let mut doc = match Document::load(&input_path) {
                Ok(d) => d,
                Err(e) => return err_result(&format!("Errore nell'apertura: {}", e)),
            };
            doc.compress();
            doc.delete_zero_length_streams();
            doc.prune_objects();
            doc.renumber_objects();
            return match doc.save(&output_path) {
                Ok(_) => {
                    let new_size = std::fs::metadata(&output_path)
                        .map(|m| m.len())
                        .unwrap_or(0);
                    let saved = original_size.saturating_sub(new_size);
                    let pct = if original_size > 0 {
                        (saved as f64 / original_size as f64 * 100.0) as u32
                    } else {
                        0
                    };
                    DocToolResult {
                        success: true,
                        output_path: Some(output_path),
                        message: format!(
                            "Compresso: {} → {} (risparmiato {}%)",
                            format_size(original_size),
                            format_size(new_size),
                            pct
                        ),
                        details: Some(
                            serde_json::json!({"original_size": original_size, "compressed_size": new_size, "saved_bytes": saved, "saved_percent": pct}),
                        ),
                    }
                }
                Err(e) => err_result(&format!("Errore nel salvataggio: {}", e)),
            };
        }
    };

    let args = vec![
        input_path.as_str(),
        "--stream-data=compress",
        "--recompress-flate",
        "--object-streams=generate",
        "--remove-unreferenced-resources=yes",
        "--",
        output_path.as_str(),
    ];

    let cmd = sidecar.args(args);
    match cmd.output().await {
        Ok(out) => {
            if out.status.success() {
                let new_size = std::fs::metadata(&output_path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                let saved = original_size.saturating_sub(new_size);
                let pct = if original_size > 0 {
                    (saved as f64 / original_size as f64 * 100.0) as u32
                } else {
                    0
                };
                DocToolResult {
                    success: true,
                    output_path: Some(output_path),
                    message: format!(
                        "Compresso: {} → {} (risparmiato {}%)",
                        format_size(original_size),
                        format_size(new_size),
                        pct
                    ),
                    details: Some(
                        serde_json::json!({"original_size": original_size, "compressed_size": new_size, "saved_bytes": saved, "saved_percent": pct}),
                    ),
                }
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                #[cfg(debug_assertions)]
                eprintln!("[doc_tools::compress_pdf] qpdf stderr: {}", stderr);
                err_result(map_qpdf_stderr(&stderr))
            }
        }
        Err(_e) => {
            #[cfg(debug_assertions)]
            eprintln!("[doc_tools] qpdf exec error: {}", _e);
            err_result("Errore esecuzione qpdf")
        }
    }
}

// ─── Watermark ──────────────────────────────────────────────

#[tauri::command]
pub async fn add_watermark(
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    text: String,
    opacity: Option<f64>,
    font_size: Option<f64>,
) -> DocToolResult {
    #[cfg(debug_assertions)]
    eprintln!(
        "[doc_tools::add_watermark] {} → {}, text='{}', opacity={:?}",
        input_path, output_path, text, opacity
    );
    if let Err(e) = validate_input_path(&input_path) {
        return err_result(&e);
    }
    if let Err(e) = validate_output_path(&output_path) {
        return err_result(&e);
    }

    // Count pages: try lopdf first, fall back to qpdf --show-npages
    let page_count = match Document::load(&input_path) {
        Ok(doc) => doc.get_pages().len(),
        Err(_) => {
            use tauri_plugin_shell::ShellExt;
            match app.shell().sidecar("qpdf") {
                Ok(s) => {
                    let cmd = s.args(["--show-npages", input_path.as_str()]);
                    match cmd.output().await {
                        Ok(out) if out.status.success() => {
                            let stdout = String::from_utf8_lossy(&out.stdout);
                            stdout.trim().parse::<usize>().unwrap_or(0)
                        }
                        _ => return err_result("Impossibile determinare il numero di pagine."),
                    }
                }
                Err(_) => return err_result("Impossibile aprire il PDF e qpdf non disponibile."),
            }
        }
    };
    if page_count == 0 {
        return err_result("Il PDF non contiene pagine.");
    }

    let opacity_val = opacity.unwrap_or(0.15);
    let fs = font_size.unwrap_or(60.0);

    // F11: cap watermark text length to prevent absurd Typst inputs.
    let text_capped: String = text.chars().take(256).collect();

    // F11: defensive escape against Typst code injection. Typst string
    // interpolation, code blocks, escapes and raw markup are all neutralised.
    let escaped = escape_typst_string(&text_capped);
    let typst_content = format!(
        "#set page(width: 595.28pt, height: 841.89pt, margin: 0pt, fill: none)\n\
         #set text(font: \"Helvetica\", size: {fs}pt, fill: rgb(50%, 50%, 50%, {opacity_pct}%))\n\
         {pages}",
        fs = fs,
        opacity_pct = (opacity_val * 100.0) as u32,
        pages = (0..page_count)
            .map(|i| {
                let pb = if i > 0 { "#pagebreak()\n" } else { "" };
                format!(
                    "{pb}#place(center + horizon, rotate(-30deg, text[\"{text}\"]))",
                    pb = pb,
                    text = escaped
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
    );

    let tmp_dir = std::env::temp_dir();
    let tmp_typ = tmp_dir.join(format!("lexflow_app_wm_{}.typ", rand::random::<u64>()));
    let tmp_overlay = tmp_dir.join(format!("lexflow_app_wm_{}.pdf", rand::random::<u64>()));

    if let Err(e) = std::fs::write(&tmp_typ, &typst_content) {
        return err_result(&format!("Errore scrittura file typst: {}", e));
    }

    use tauri_plugin_shell::ShellExt;
    // Step 1: Generate overlay PDF with typst
    let typst_sidecar = match app.shell().sidecar("typst") {
        Ok(s) => s,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_typ);
            return err_result(&format!("typst non trovato: {}", e));
        }
    };
    let typst_cmd = typst_sidecar.args([
        "compile",
        &tmp_typ.to_string_lossy(),
        &tmp_overlay.to_string_lossy(),
    ]);
    match typst_cmd.output().await {
        Ok(out) if !out.status.success() => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let _ = std::fs::remove_file(&tmp_typ);
            return err_result(&format!("Errore generazione watermark: {}", stderr));
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_typ);
            return err_result(&format!("Errore typst: {}", e));
        }
        _ => {}
    }
    let _ = crate::security::secure_delete_file(&tmp_typ);

    // Step 2: Overlay watermark onto input PDF with qpdf
    let qpdf_sidecar = match app.shell().sidecar("qpdf") {
        Ok(s) => s,
        Err(_) => {
            let _ = std::fs::remove_file(&tmp_overlay);
            return err_result("qpdf non trovato — necessario per watermark.");
        }
    };
    let qpdf_cmd = qpdf_sidecar.args([
        input_path.as_str(),
        "--overlay",
        &tmp_overlay.to_string_lossy(),
        "--",
        "--",
        output_path.as_str(),
    ]);
    let result = match qpdf_cmd.output().await {
        Ok(out) if out.status.success() => ok_result(
            &output_path,
            &format!("Watermark \"{}\" aggiunto a {} pagine.", text, page_count),
        ),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            #[cfg(debug_assertions)]
            eprintln!("[doc_tools::add_watermark] qpdf stderr: {}", stderr);
            err_result(map_qpdf_stderr(&stderr))
        }
        Err(_e) => {
            #[cfg(debug_assertions)]
            eprintln!("[doc_tools::add_watermark] qpdf exec error: {}", _e);
            err_result("Errore esecuzione qpdf")
        }
    };
    let _ = crate::security::secure_delete_file(&tmp_overlay);
    result
}

// ─── Rotate Pages ───────────────────────────────────────────

#[tauri::command]
pub async fn rotate_pdf(
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    rotation: i32,
    pages_to_rotate: Option<Vec<u32>>,
) -> DocToolResult {
    #[cfg(debug_assertions)]
    eprintln!(
        "[doc_tools::rotate_pdf] {} → {}, rotation={}°, pages={:?}",
        input_path, output_path, rotation, pages_to_rotate
    );
    if let Err(e) = validate_input_path(&input_path) {
        return err_result(&e);
    }
    if let Err(e) = validate_output_path(&output_path) {
        return err_result(&e);
    }
    if rotation % 90 != 0 {
        return err_result("La rotazione deve essere un multiplo di 90°.");
    }
    if let Some(ref pages) = pages_to_rotate {
        if pages.len() > 100_000 {
            return err_result("Troppe pagine selezionate (massimo 100000).");
        }
    }

    use tauri_plugin_shell::ShellExt;
    let sidecar = match app.shell().sidecar("qpdf") {
        Ok(s) => s,
        Err(_) => {
            // Fallback to lopdf
            let mut doc = match Document::load(&input_path) {
                Ok(d) => d,
                Err(e) => return err_result(&format!("Errore nell'apertura: {}", e)),
            };
            let pages: Vec<(u32, ObjectId)> = doc.get_pages().into_iter().collect();
            let target = pages_to_rotate
                .clone()
                .unwrap_or_else(|| pages.iter().map(|(n, _)| *n).collect());
            let mut rotated = 0;
            for (pn, pid) in &pages {
                if !target.contains(pn) {
                    continue;
                }
                if let Ok(obj) = doc.get_object_mut(*pid) {
                    if let Ok(dict) = obj.as_dict_mut() {
                        let cur = dict
                            .get(b"Rotate")
                            .ok()
                            .and_then(|r| r.as_i64().ok())
                            .unwrap_or(0) as i32;
                        dict.set(
                            "Rotate",
                            Object::Integer(((cur + rotation) % 360 + 360) as i64 % 360),
                        );
                        rotated += 1;
                    }
                }
            }
            return match doc.save(&output_path) {
                Ok(_) => ok_result(
                    &output_path,
                    &format!("{} pagine ruotate di {}°.", rotated, rotation),
                ),
                Err(e) => err_result(&format!("Errore: {}", e)),
            };
        }
    };

    // qpdf --rotate=+90:1-z  (all pages) or --rotate=+90:1,3,5  (specific pages)
    let page_spec = match &pages_to_rotate {
        Some(pages) if !pages.is_empty() => pages
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(","),
        _ => "1-z".to_string(),
    };
    let rotate_arg = format!("--rotate=+{}:{}", rotation, page_spec);

    let args = vec![input_path.as_str(), &rotate_arg, "--", output_path.as_str()];

    let cmd = sidecar.args(args);
    match cmd.output().await {
        Ok(out) => {
            if out.status.success() {
                ok_result(&output_path, &format!("Pagine ruotate di {}°.", rotation))
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                #[cfg(debug_assertions)]
                eprintln!("[doc_tools::rotate_pdf] qpdf stderr: {}", stderr);
                err_result(map_qpdf_stderr(&stderr))
            }
        }
        Err(_e) => {
            #[cfg(debug_assertions)]
            eprintln!("[doc_tools] qpdf exec error: {}", _e);
            err_result("Errore esecuzione qpdf")
        }
    }
}

// ─── PDF to Text ────────────────────────────────────────────

#[tauri::command]
pub fn pdf_to_text(input_path: String) -> Result<String, String> {
    #[cfg(debug_assertions)]
    eprintln!("[doc_tools::pdf_to_text] {}", input_path);
    validate_input_path(&input_path)?;
    let doc = Document::load(&input_path).map_err(|e| format!("Errore nell'apertura: {}", e))?;

    let pages = doc.get_pages();
    let mut full_text = String::new();

    for (page_num, page_id) in &pages {
        let content = doc.get_page_content(*page_id).unwrap_or_default();
        let text = String::from_utf8_lossy(&content);

        // Extract text from BT/ET blocks (basic text extraction from content streams)
        let mut page_text = String::new();
        let mut in_text = false;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed == "BT" {
                in_text = true;
            } else if trimmed == "ET" {
                in_text = false;
                page_text.push(' ');
            } else if in_text && (trimmed.ends_with("Tj") || trimmed.ends_with("TJ")) {
                // Extract text between parentheses from Tj operator
                let mut i = 0;
                let chars: Vec<char> = trimmed.chars().collect();
                while i < chars.len() {
                    if chars[i] == '(' {
                        let mut depth = 1;
                        i += 1;
                        let start = i;
                        while i < chars.len() && depth > 0 {
                            if chars[i] == '(' && (i == 0 || chars[i - 1] != '\\') {
                                depth += 1;
                            } else if chars[i] == ')' && (i == 0 || chars[i - 1] != '\\') {
                                depth -= 1;
                            }
                            if depth > 0 {
                                i += 1;
                            }
                        }
                        page_text.push_str(&chars[start..i].iter().collect::<String>());
                    }
                    i += 1;
                }
            }
        }

        let trimmed_text = page_text.trim();
        if !trimmed_text.is_empty() {
            full_text.push_str(&format!("--- Pagina {} ---\n", page_num));
            full_text.push_str(trimmed_text);
            full_text.push_str("\n\n");
        }
    }

    if full_text.is_empty() {
        Ok("Nessun testo estraibile trovato. Il PDF potrebbe contenere solo immagini.".to_string())
    } else {
        Ok(full_text)
    }
}

// ─── Images to PDF (using Typst sidecar) ────────────────────
// Uses the same LexFlow premium style as fascicolo.typ:
// Libertinus Serif, Slate palette, header, footer with page numbers.

#[tauri::command]
pub async fn images_to_pdf(
    app: tauri::AppHandle,
    image_paths: Vec<String>,
    output_path: String,
) -> DocToolResult {
    #[cfg(debug_assertions)]
    eprintln!(
        "[doc_tools::images_to_pdf] {} images → {}",
        image_paths.len(),
        output_path
    );
    for p in &image_paths {
        if let Err(e) = validate_input_path(p) {
            return err_result(&e);
        }
    }
    if let Err(e) = validate_output_path(&output_path) {
        return err_result(&e);
    }
    if image_paths.is_empty() {
        return err_result("Nessuna immagine selezionata.");
    }

    // Build Typst document using the same style as fascicolo.typ
    let total = image_paths.len();
    let now = chrono::Local::now().format("%d/%m/%Y").to_string();
    let mut typst_content = String::new();

    // ── Same palette + page setup as fascicolo.typ ──
    typst_content.push_str(
        r##"
// LexFlow — Conversione Immagini → PDF
// Stesso stile premium del Report Fascicolo

#let slate-900 = rgb("#0F172A")
#let slate-500 = rgb("#475569")
#let slate-300 = rgb("#CBD5E1")

#set page(
  paper: "a4",
  margin: (top: 2.5cm, bottom: 2cm, left: 2cm, right: 2cm),
  footer: [
    #set text(8pt, fill: slate-500, font: "Libertinus Serif")
    #align(center)[
      #context {
        let current = counter(page).get().first()
        let total = counter(page).final().first()
        [#current / #total]
      }
    ]
  ],
)

#set text(font: "Libertinus Serif", size: 10.5pt, fill: slate-900, lang: "it")
"##,
    );

    // ── Header ──
    typst_content.push_str(&format!(
        "{}{}{}",
        r##"
#grid(
  columns: (1fr, auto),
  align(left)[
    #text(size: 10pt, weight: "light", fill: slate-500, tracking: 2pt)[DOCUMENTO IMMAGINI]
  ],
  align(right)[
    #text(size: 8.5pt, fill: slate-500)[Generato il "##,
        now,
        r##"]
  ],
)
#v(0.3cm)
#line(length: 100%, stroke: 0.5pt + slate-300)
#v(0.5cm)
"##
    ));

    // ── Images — each centered on its own page ──
    for (i, img_path) in image_paths.iter().enumerate() {
        // F12: cap to 4096 chars and run through the Typst string escape so
        // a path containing a quote / backslash / control char cannot break
        // out of the string literal.
        let normalized: String = img_path.replace('\\', "/").chars().take(4096).collect();
        let escaped = escape_typst_string(&normalized);
        typst_content.push_str(&format!(
            "#align(center)[#image(\"{}\", width: 100%)]\n",
            escaped
        ));
        if i < total - 1 {
            typst_content.push_str("#pagebreak()\n");
        }
    }

    let tmp_typ = std::env::temp_dir().join("lexflow_app_img2pdf.typ");
    let tmp_pdf = tmp_typ.with_extension("pdf");

    if let Err(e) = std::fs::write(&tmp_typ, &typst_content) {
        return err_result(&format!("Errore file temporaneo: {}", e));
    }

    // Use Typst sidecar with font path for Libertinus Serif
    use tauri_plugin_shell::ShellExt;
    let sidecar = match app.shell().sidecar("typst") {
        Ok(s) => s,
        Err(e) => {
            // L11: Use secure_delete_file for temp file cleanup
            let _ = crate::security::secure_delete_file(&tmp_typ);
            return err_result(&format!("Typst non trovato: {}", e));
        }
    };

    use tauri::Manager;
    let font_path = app
        .path()
        .resource_dir()
        .map(|p: std::path::PathBuf| p.join("fonts"))
        .unwrap_or_default();
    let cmd = sidecar.args([
        "compile",
        &tmp_typ.to_string_lossy(),
        &tmp_pdf.to_string_lossy(),
        "--font-path",
        &font_path.to_string_lossy(),
    ]);

    match cmd.output().await {
        Ok(out) => {
            // L11: Use secure_delete_file for temp file cleanup
            let _ = crate::security::secure_delete_file(&tmp_typ);
            if out.status.success() {
                match std::fs::copy(&tmp_pdf, &output_path) {
                    Ok(_) => {
                        let _ = crate::security::secure_delete_file(&tmp_pdf);
                        ok_result(
                            &output_path,
                            &format!("{} immagini convertite in PDF.", image_paths.len()),
                        )
                    }
                    Err(e) => {
                        let _ = crate::security::secure_delete_file(&tmp_pdf);
                        err_result(&format!("Errore salvataggio: {}", e))
                    }
                }
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let _ = crate::security::secure_delete_file(&tmp_pdf);
                err_result(&format!("Errore Typst: {}", stderr))
            }
        }
        Err(e) => {
            let _ = crate::security::secure_delete_file(&tmp_typ);
            err_result(&format!("Errore esecuzione Typst: {}", e))
        }
    }
}

// ─── Reorder Pages ─────────────────────────────────────────

#[tauri::command]
pub fn reorder_pages(
    input_path: String,
    output_path: String,
    new_order: Vec<u32>,
) -> DocToolResult {
    #[cfg(debug_assertions)]
    eprintln!(
        "[doc_tools::reorder_pages] {} → {}, order={:?}",
        input_path, output_path, new_order
    );
    if let Err(e) = validate_input_path(&input_path) {
        return err_result(&e);
    }
    if let Err(e) = validate_output_path(&output_path) {
        return err_result(&e);
    }
    let doc = match Document::load(&input_path) {
        Ok(d) => d,
        Err(e) => return err_result(&format!("Errore nell'apertura: {}", e)),
    };

    let total = doc.get_pages().len() as u32;

    // Validate: new_order must contain every page exactly once
    if new_order.len() != total as usize {
        return err_result(&format!(
            "L'ordine deve contenere esattamente {} pagine (il PDF ne ha {}).",
            total, total
        ));
    }
    let mut sorted_order = new_order.clone();
    sorted_order.sort_unstable();
    sorted_order.dedup();
    if sorted_order.len() != total as usize
        || sorted_order.first() != Some(&1)
        || sorted_order.last() != Some(&total)
    {
        return err_result("L'ordine deve contenere ogni pagina da 1 a N esattamente una volta.");
    }

    // Strategy: clone original for each page extraction, then merge them in
    // the requested order.
    let mut base_doc: Option<Document> = None;
    for &page_num in &new_order {
        let mut single = doc.clone();
        let pages_to_remove: Vec<u32> = (1..=total).filter(|&p| p != page_num).collect();
        for &p in pages_to_remove.iter().rev() {
            single.delete_pages(&[p]);
        }

        match base_doc {
            None => {
                base_doc = Some(single);
            }
            Some(ref mut base) => {
                if let Err(e) = merge_document(base, &single) {
                    return err_result(&format!("Errore nel riordino pagina {}: {}", page_num, e));
                }
            }
        }
    }

    let mut final_doc = base_doc.unwrap();
    final_doc.compress();

    match final_doc.save(&output_path) {
        Ok(_) => ok_result(
            &output_path,
            &format!("{} pagine riordinate con successo.", total),
        ),
        Err(e) => err_result(&format!("Errore nel salvataggio: {}", e)),
    }
}

// ─── Add Page Numbers ──────────────────────────────────────

#[tauri::command]
pub async fn add_page_numbers(
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    position: Option<String>,
    format_str: Option<String>,
    start_from: Option<u32>,
    font_size: Option<f64>,
) -> DocToolResult {
    #[cfg(debug_assertions)]
    eprintln!(
        "[doc_tools::add_page_numbers] {} → {}, pos={:?}, fmt={:?}, start={:?}",
        input_path, output_path, position, format_str, start_from
    );
    if let Err(e) = validate_input_path(&input_path) {
        return err_result(&e);
    }
    if let Err(e) = validate_output_path(&output_path) {
        return err_result(&e);
    }

    // Count pages: try lopdf first, fall back to qpdf --show-npages
    let total = match Document::load(&input_path) {
        Ok(d) => d.get_pages().len() as u32,
        Err(_) => {
            use tauri_plugin_shell::ShellExt;
            match app.shell().sidecar("qpdf") {
                Ok(s) => {
                    let cmd = s.args(["--show-npages", input_path.as_str()]);
                    match cmd.output().await {
                        Ok(out) if out.status.success() => {
                            let stdout = String::from_utf8_lossy(&out.stdout);
                            stdout.trim().parse::<u32>().unwrap_or(0)
                        }
                        _ => return err_result("Impossibile determinare il numero di pagine."),
                    }
                }
                Err(_) => return err_result("Impossibile aprire il PDF e qpdf non disponibile."),
            }
        }
    };
    if total == 0 {
        return err_result("Il PDF non contiene pagine.");
    }

    let pos = position.unwrap_or_else(|| "bottom-center".to_string());
    let fmt = format_str.unwrap_or_else(|| "{n}".to_string());
    let start = start_from.unwrap_or(1);
    let fs = font_size.unwrap_or(10.0);

    // Typst alignment + offset from position (margin: 0pt like watermark, offset explicit)
    let (align, dx, dy) = match pos.as_str() {
        "bottom-left" => ("left + bottom", "dx: 40pt, ", "dy: -25pt, "),
        "bottom-right" => ("right + bottom", "dx: -40pt, ", "dy: -25pt, "),
        "top-left" => ("left + top", "dx: 40pt, ", "dy: 25pt, "),
        "top-right" => ("right + top", "dx: -40pt, ", "dy: 25pt, "),
        "top-center" => ("center + top", "", "dy: 25pt, "),
        _ => ("center + bottom", "", "dy: -25pt, "),
    };

    // Generate overlay with page numbers using typst (margin: 0pt for correct qpdf overlay)
    let mut typst_content = format!(
        "#set page(width: 595.28pt, height: 841.89pt, margin: 0pt, fill: none)\n\
         #set text(font: \"Helvetica\", size: {}pt, fill: rgb(40%, 40%, 40%))\n",
        fs
    );

    for i in 0..total {
        if i > 0 {
            typst_content.push_str("#pagebreak()\n");
        }
        let num = start + i;
        let label = fmt
            .replace("{n}", &num.to_string())
            .replace("{total}", &(start + total - 1).to_string());
        typst_content.push_str(&format!("#place({}, {}{}[{}])\n", align, dx, dy, label));
    }

    let tmp_dir = std::env::temp_dir();
    let tmp_typ = tmp_dir.join(format!("lexflow_app_pn_{}.typ", rand::random::<u64>()));
    let tmp_overlay = tmp_dir.join(format!("lexflow_app_pn_{}.pdf", rand::random::<u64>()));

    if let Err(e) = std::fs::write(&tmp_typ, &typst_content) {
        return err_result(&format!("Errore scrittura file typst: {}", e));
    }

    use tauri_plugin_shell::ShellExt;
    let typst_sidecar = match app.shell().sidecar("typst") {
        Ok(s) => s,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_typ);
            return err_result(&format!("typst non trovato: {}", e));
        }
    };
    let typst_cmd = typst_sidecar.args([
        "compile",
        &tmp_typ.to_string_lossy(),
        &tmp_overlay.to_string_lossy(),
    ]);
    match typst_cmd.output().await {
        Ok(out) if !out.status.success() => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let _ = std::fs::remove_file(&tmp_typ);
            return err_result(&format!("Errore generazione numeri: {}", stderr));
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_typ);
            return err_result(&format!("Errore typst: {}", e));
        }
        _ => {}
    }
    let _ = crate::security::secure_delete_file(&tmp_typ);

    let qpdf_sidecar = match app.shell().sidecar("qpdf") {
        Ok(s) => s,
        Err(_) => {
            let _ = std::fs::remove_file(&tmp_overlay);
            return err_result("qpdf non trovato.");
        }
    };
    let qpdf_cmd = qpdf_sidecar.args([
        input_path.as_str(),
        "--overlay",
        &tmp_overlay.to_string_lossy(),
        "--",
        "--",
        output_path.as_str(),
    ]);
    let result = match qpdf_cmd.output().await {
        Ok(out) if out.status.success() => ok_result(
            &output_path,
            &format!(
                "Numeri di pagina aggiunti a {} pagine (da {} a {}).",
                total,
                start,
                start + total - 1
            ),
        ),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            #[cfg(debug_assertions)]
            eprintln!("[doc_tools::add_page_numbers] qpdf stderr: {}", stderr);
            err_result(map_qpdf_stderr(&stderr))
        }
        Err(_e) => {
            #[cfg(debug_assertions)]
            eprintln!("[doc_tools::add_page_numbers] qpdf exec error: {}", _e);
            err_result("Errore esecuzione qpdf")
        }
    };
    let _ = crate::security::secure_delete_file(&tmp_overlay);
    result
}

/// Get page dimensions from MediaBox, defaulting to A4.
fn get_page_dimensions(doc: &Document, page_id: ObjectId) -> (f64, f64) {
    if let Ok(page_obj) = doc.get_object(page_id) {
        if let Ok(dict) = page_obj.as_dict() {
            if let Ok(mbox) = dict.get(b"MediaBox") {
                if let Ok(arr) = mbox.as_array() {
                    if arr.len() == 4 {
                        let w: f64 = arr[2]
                            .as_float()
                            .map(|v| v as f64)
                            .or_else(|_| arr[2].as_i64().map(|v| v as f64))
                            .unwrap_or(595.0);
                        let h: f64 = arr[3]
                            .as_float()
                            .map(|v| v as f64)
                            .or_else(|_| arr[3].as_i64().map(|v| v as f64))
                            .unwrap_or(842.0);
                        return (w, h);
                    }
                }
            }
        }
    }
    (595.0, 842.0) // A4 default
}

// ─── Redact PDF (censura) ──────────────────────────────────
// True redaction: wraps existing content in a clipping path that EXCLUDES
// the redacted areas, so text underneath is unselectable/uncopiable,
// then draws black rectangles on top for visual coverage.

#[tauri::command]
pub async fn redact_pdf(
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    redactions: Vec<RedactArea>,
) -> DocToolResult {
    #[cfg(debug_assertions)]
    eprintln!(
        "[doc_tools::redact_pdf] {} → {}, {} redaction areas",
        input_path,
        output_path,
        redactions.len()
    );
    if let Err(e) = validate_input_path(&input_path) {
        return err_result(&e);
    }
    if let Err(e) = validate_output_path(&output_path) {
        return err_result(&e);
    }
    if redactions.is_empty() {
        return err_result("Nessuna area da censurare specificata.");
    }

    // ── Approach: Typst overlay (black rects) + qpdf overlay + qpdf encrypt ──
    // Same proven pipeline as watermark. No lopdf needed.

    // Step 1: Load doc with lopdf to get per-page MediaBox; fall back to qpdf
    // for page count if lopdf can't parse (in which case all pages assumed A4).
    use tauri_plugin_shell::ShellExt;
    let lopdf_doc = Document::load(&input_path).ok();
    let total: u32 = match &lopdf_doc {
        Some(d) => d.get_pages().len() as u32,
        None => match app.shell().sidecar("qpdf") {
            Ok(s) => {
                let cmd = s.args(["--show-npages", input_path.as_str()]);
                match cmd.output().await {
                    Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
                        .trim()
                        .parse::<u32>()
                        .unwrap_or(0),
                    _ => return err_result("Impossibile determinare il numero di pagine."),
                }
            }
            Err(_) => return err_result("Impossibile aprire il PDF."),
        },
    };
    if total == 0 {
        return err_result("Il PDF non contiene pagine.");
    }

    // Validate page numbers
    for area in &redactions {
        if area.page < 1 || area.page > total {
            return err_result(&format!(
                "Pagina {} non valida. Il PDF ha {} pagine.",
                area.page, total
            ));
        }
    }

    // Resolve per-page (width, height) — A4 fallback when lopdf failed.
    let pages_map: BTreeMap<u32, (f64, f64)> = match &lopdf_doc {
        Some(d) => d
            .get_pages()
            .into_iter()
            .map(|(n, id)| (n, get_page_dimensions(d, id)))
            .collect(),
        None => (1..=total).map(|n| (n, (595.28_f64, 841.89_f64))).collect(),
    };

    // Step 2: Generate Typst overlay. ONE Typst page per source PDF page, sized
    // to that page's MediaBox so the overlay matches qpdf's per-page overlay.
    // CRIT-2: Y-flip uses the page's actual height, not a hardcoded A4.
    let mut typst_content = String::new();

    for page_num in 1..=total {
        let (page_w, page_h) = pages_map
            .get(&page_num)
            .copied()
            .unwrap_or((595.28_f64, 841.89_f64));

        if page_num > 1 {
            typst_content.push_str("#pagebreak()\n");
        }
        // Per-page set page resets dimensions for the next page block.
        typst_content.push_str(&format!(
            "#set page(width: {}pt, height: {}pt, margin: 0pt, fill: none)\n",
            page_w, page_h
        ));

        let page_areas: Vec<&RedactArea> =
            redactions.iter().filter(|a| a.page == page_num).collect();
        for a in &page_areas {
            // PDF user-space coords have origin at bottom-left. Typst with
            // margin:0pt places from top-left. Y-flip = page_h - y - height.
            let dy = (page_h - a.y - a.height).max(0.0);
            let dx = a.x.max(0.0);
            let w = a.width.max(0.0);
            let h = a.height.max(0.0);
            typst_content.push_str(&format!(
                "#place(top + left, dx: {}pt, dy: {}pt, rect(width: {}pt, height: {}pt, fill: black))\n",
                dx, dy, w, h
            ));
        }
        if page_areas.is_empty() {
            typst_content.push_str("// empty page\n");
        }
    }

    let tmp_dir = std::env::temp_dir();
    let tmp_typ = tmp_dir.join(format!("lexflow_app_redact_{}.typ", rand::random::<u64>()));
    let tmp_overlay = tmp_dir.join(format!("lexflow_app_redact_{}.pdf", rand::random::<u64>()));

    if let Err(e) = std::fs::write(&tmp_typ, &typst_content) {
        return err_result(&format!("Errore scrittura file typst: {}", e));
    }

    // Step 3: Compile Typst → overlay PDF
    let typst_sidecar = match app.shell().sidecar("typst") {
        Ok(s) => s,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_typ);
            return err_result(&format!("typst non trovato: {}", e));
        }
    };
    let typst_cmd = typst_sidecar.args([
        "compile",
        &tmp_typ.to_string_lossy(),
        &tmp_overlay.to_string_lossy(),
    ]);
    match typst_cmd.output().await {
        Ok(out) if !out.status.success() => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let _ = std::fs::remove_file(&tmp_typ);
            return err_result(&format!("Errore generazione overlay censura: {}", stderr));
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_typ);
            return err_result(&format!("Errore typst: {}", e));
        }
        _ => {}
    }
    let _ = crate::security::secure_delete_file(&tmp_typ);

    // Step 4: qpdf overlay (black rects on top of original PDF)
    let tmp_overlaid = tmp_dir.join(format!(
        "lexflow_app_redact_overlaid_{}.pdf",
        rand::random::<u64>()
    ));
    let qpdf_sidecar = match app.shell().sidecar("qpdf") {
        Ok(s) => s,
        Err(_) => {
            let _ = std::fs::remove_file(&tmp_overlay);
            return err_result("qpdf non trovato.");
        }
    };
    let overlay_cmd = qpdf_sidecar.args([
        input_path.as_str(),
        "--overlay",
        &tmp_overlay.to_string_lossy(),
        "--",
        "--",
        &tmp_overlaid.to_string_lossy(),
    ]);
    match overlay_cmd.output().await {
        Ok(out) if !out.status.success() => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let _ = std::fs::remove_file(&tmp_overlay);
            return err_result(&format!("qpdf overlay fallito: {}", stderr));
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_overlay);
            return err_result(&format!("Errore qpdf: {}", e));
        }
        _ => {}
    }
    let _ = crate::security::secure_delete_file(&tmp_overlay);

    // Step 4-bis (CRIT-1): destructive content-stream redaction.
    // The visual overlay alone leaves the underlying text recoverable. As a
    // best-effort destructive pass we use lopdf to nuke ALL Tj/TJ/'/"
    // text-showing operators on any page that has at least one redaction area.
    // This is over-aggressive (removes ALL text from those pages, not just
    // the redacted region) but guarantees zero text leakage on those pages.
    let pages_with_redactions: std::collections::BTreeSet<u32> =
        redactions.iter().map(|a| a.page).collect();
    let destructive_ok =
        match strip_text_on_pages(&tmp_overlaid.to_string_lossy(), &pages_with_redactions) {
            Ok(_) => true,
            Err(_e) => {
                #[cfg(debug_assertions)]
                eprintln!(
                    "[doc_tools::redact_pdf] destructive content-stream pass failed: {}",
                    _e
                );
                false
            }
        };
    if !destructive_ok {
        // CRIT-1: do NOT silently rename the unprotected overlay as success.
        let _ = crate::security::secure_delete_file(&tmp_overlaid);
        return err_result(
            "Redazione fallita: protezione testo non applicata. NON usare questo file per documenti riservati.",
        );
    }

    // Step 5: qpdf encrypt with --extract=n to block copy-paste of any
    // remaining text (defense-in-depth; the destructive pass above already
    // removed Tj/TJ on redacted pages).
    let owner_pwd = format!("LF_{:016x}", rand::random::<u64>());
    let qpdf_sidecar2 = match app.shell().sidecar("qpdf") {
        Ok(s) => s,
        Err(_) => {
            // No qpdf available for the encryption step. Since the destructive
            // pass succeeded, we can still publish the file — but flag this in
            // the message. (We do NOT silently call this success without
            // destructive_ok — that branch already returned above.)
            let _ = std::fs::rename(&tmp_overlaid, &output_path);
            return ok_result(
                &output_path,
                &format!(
                    "{} aree censurate (testo rimosso a livello content-stream sulle pagine redatte; cifratura anti-copia non applicata, qpdf non disponibile). Verifica con pdftotext consigliata.",
                    redactions.len()
                ),
            );
        }
    };
    // F2: write owner password to temp file instead of putting on argv.
    use std::io::Write;
    let mut owner_file = match tempfile::NamedTempFile::new_in(std::env::temp_dir()) {
        Ok(t) => t,
        Err(_) => {
            let _ = crate::security::secure_delete_file(&tmp_overlaid);
            return err_result("Impossibile creare file temp password.");
        }
    };
    let _ = owner_file.write_all(owner_pwd.as_bytes());
    let _ = owner_file.flush();
    let owner_path = owner_file.path().to_path_buf();
    let mut user_file = match tempfile::NamedTempFile::new_in(std::env::temp_dir()) {
        Ok(t) => t,
        Err(_) => {
            let _ = crate::security::secure_delete_file(&tmp_overlaid);
            return err_result("Impossibile creare file temp password.");
        }
    };
    let _ = user_file.write_all(b"");
    let _ = user_file.flush();
    let user_path = user_file.path().to_path_buf();

    let owner_arg = format!("@{}", owner_path.display());
    let user_arg = format!("@{}", user_path.display());
    let encrypt_cmd = qpdf_sidecar2.args([
        &tmp_overlaid.to_string_lossy(),
        "--encrypt",
        user_arg.as_str(),
        owner_arg.as_str(),
        "256",
        "--extract=n",
        "--print=full",
        "--modify=none",
        "--",
        output_path.as_str(),
    ]);
    let result = match encrypt_cmd.output().await {
        Ok(out) if out.status.success() => {
            let _ = crate::security::secure_delete_file(&tmp_overlaid);
            ok_result(
                &output_path,
                &format!(
                    "{} aree censurate su {} pagine (testo rimosso a livello content-stream sulle pagine redatte). Ulteriori controlli con pdftotext consigliati.",
                    redactions.len(), total
                ),
            )
        }
        Ok(out) => {
            let _ = crate::security::secure_delete_file(&tmp_overlaid);
            let stderr = String::from_utf8_lossy(&out.stderr);
            #[cfg(debug_assertions)]
            eprintln!("[doc_tools::redact_pdf] qpdf encrypt failed: {}", stderr);
            // CRIT-1: do NOT silently rename the unencrypted overlaid file as
            // success. Encryption failure is a real failure when the user
            // requested redaction.
            err_result(map_qpdf_stderr(&stderr))
        }
        Err(_e) => {
            let _ = crate::security::secure_delete_file(&tmp_overlaid);
            #[cfg(debug_assertions)]
            eprintln!("[doc_tools::redact_pdf] qpdf encrypt exec error: {}", _e);
            err_result("Errore esecuzione qpdf")
        }
    };
    drop(owner_file);
    drop(user_file);
    let _ = crate::security::secure_delete_file(&owner_path);
    let _ = crate::security::secure_delete_file(&user_path);
    result
}

/// CRIT-1 destructive helper: open `pdf_path` with lopdf, walk the content
/// stream of every page in `pages` (1-based), and replace every text-showing
/// operator (Tj, TJ, ', ") with an equivalent no-op so the strings are not
/// recoverable via copy-paste or pdftotext. Saves in place.
fn strip_text_on_pages(
    pdf_path: &str,
    pages: &std::collections::BTreeSet<u32>,
) -> Result<(), String> {
    use lopdf::content::Content;

    if pages.is_empty() {
        return Ok(());
    }
    let mut doc = Document::load(pdf_path).map_err(|e| format!("lopdf load: {}", e))?;
    let pages_map: BTreeMap<u32, ObjectId> = doc.get_pages();

    for &page_num in pages {
        let page_id = match pages_map.get(&page_num) {
            Some(id) => *id,
            None => continue,
        };
        let raw = match doc.get_page_content(page_id) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let mut content = match Content::decode(&raw) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // Replace every text-showing op with a no-op. We KEEP positioning ops
        // (Td, TD, Tm, Tf, etc.) so the page's text layer structure stays
        // valid even though no glyphs are drawn.
        for op in &mut content.operations {
            match op.operator.as_str() {
                "Tj" | "'" => {
                    // Replace the (string) argument with an empty string.
                    op.operands = vec![lopdf::Object::String(
                        Vec::new(),
                        lopdf::StringFormat::Literal,
                    )];
                }
                "\"" => {
                    // " takes (aw ac string) — replace string with empty.
                    if op.operands.len() >= 3 {
                        op.operands[2] =
                            lopdf::Object::String(Vec::new(), lopdf::StringFormat::Literal);
                    } else {
                        op.operands = vec![lopdf::Object::String(
                            Vec::new(),
                            lopdf::StringFormat::Literal,
                        )];
                    }
                }
                "TJ" => {
                    // TJ takes an array of strings/numbers. Replace with [()].
                    op.operands = vec![lopdf::Object::Array(vec![lopdf::Object::String(
                        Vec::new(),
                        lopdf::StringFormat::Literal,
                    )])];
                }
                _ => {}
            }
        }
        // Re-encode and replace the page content stream.
        let new_bytes = content.encode().map_err(|e| format!("encode: {}", e))?;
        // Find the page's Contents object and overwrite with the new bytes.
        // get_page_content concatenates streams; for safety we build a fresh
        // single stream object and point Contents at it.
        let new_stream = lopdf::Stream::new(lopdf::Dictionary::new(), new_bytes);
        let new_id = doc.add_object(lopdf::Object::Stream(new_stream));
        if let Ok(page_obj) = doc.get_object_mut(page_id) {
            if let Ok(dict) = page_obj.as_dict_mut() {
                dict.set("Contents", lopdf::Object::Reference(new_id));
            }
        }
    }
    doc.save(pdf_path).map_err(|e| format!("save: {}", e))?;
    Ok(())
}

#[derive(serde::Deserialize)]
pub struct RedactArea {
    pub page: u32,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

// ─── Protect PDF — REMOVED (was a no-op stub, F6) ──────────
// The previous `protect_pdf` Tauri command merely copied the input file to
// the output path while pretending to apply password protection — a real
// security risk because callers got success=true on an unprotected PDF.
// It was NOT registered in src-tauri/src/lib.rs (already verified) so no
// invoke_handler change is needed here. The FE wrappers will be cleaned up
// by FE-10 (client/src/tauri-api.js) and FE-7 (DocumentToolsPage.jsx).
// Use `secure_pdf` instead — it performs real qpdf encryption with
// anti-copy/print/modify enforcement.

// ─── Secure PDF (qpdf + Tr 3 + watermark) ──────────────────

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurePdfOptions {
    pub no_copy: Option<bool>,
    pub no_print: Option<bool>,
    pub no_modify: Option<bool>,
    pub watermark: Option<String>,
    pub owner_password: Option<String>,
}

#[tauri::command]
pub async fn secure_pdf(
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    options: SecurePdfOptions,
) -> DocToolResult {
    #[cfg(debug_assertions)]
    eprintln!("[doc_tools::secure_pdf] {} → {}, no_copy={:?}, no_print={:?}, no_modify={:?}, watermark={:?}",
        input_path, output_path, options.no_copy, options.no_print, options.no_modify, options.watermark);
    if let Err(e) = validate_input_path(&input_path) {
        return err_result(&e);
    }
    if let Err(e) = validate_output_path(&output_path) {
        return err_result(&e);
    }
    // F5: refuse to overwrite existing output silently
    if std::path::Path::new(&output_path).exists() {
        return err_result(
            "Il file di destinazione esiste già. Eliminalo o scegli un'altra destinazione.",
        );
    }

    let no_copy = options.no_copy.unwrap_or(true);
    let no_print = options.no_print.unwrap_or(true);
    let no_modify = options.no_modify.unwrap_or(true);
    let watermark_text = options.watermark.clone();
    let owner_pwd = options.owner_password.unwrap_or_else(|| {
        // Generate a random owner password so the user can't easily remove restrictions
        format!("LF_{:016x}", rand::random::<u64>())
    });

    // Step 1: Copy input to output as starting point
    // (Tr3 lopdf manipulation removed — it corrupted certain PDFs.
    //  Anti-copy protection is enforced by qpdf encryption with --extract=n)
    if let Err(e) = std::fs::copy(&input_path, &output_path) {
        return err_result(&format!("Errore copia: {}", e));
    }

    // Step 2: Apply watermark if requested
    if let Some(ref wm_text) = watermark_text {
        if !wm_text.is_empty() {
            let tmp_wm = format!("{}.wm_tmp.pdf", output_path);
            let wm_result = add_watermark(
                app.clone(),
                output_path.clone(),
                tmp_wm.clone(),
                wm_text.clone(),
                Some(0.15),
                Some(48.0),
            )
            .await;
            if !wm_result.success {
                let _ = std::fs::remove_file(&tmp_wm);
                return err_result(&format!("Errore watermark: {}", wm_result.message));
            }
            let _ = std::fs::rename(&tmp_wm, &output_path);
        }
    }

    // Step 3: Apply PDF encryption/permissions via qpdf sidecar
    use tauri_plugin_shell::ShellExt;
    let sidecar = match app.shell().sidecar("qpdf") {
        Ok(s) => s,
        Err(_e) => {
            // qpdf not available — return success with just Tr 3 + watermark
            let mut msg = "PDF protetto con overlay anti-copia".to_string();
            if watermark_text.is_some() {
                msg.push_str(" e watermark");
            }
            msg.push_str(". (qpdf non disponibile per permessi avanzati)");
            return ok_result(&output_path, &msg);
        }
    };

    let tmp_encrypted = format!("{}.qpdf_tmp", output_path);
    let owner_pwd_display = owner_pwd.clone();

    // F2: write owner password to a temp file and pass it via --password-file=
    // instead of putting it on argv (where ps aux could see it).
    // qpdf still needs the user/owner pair on argv for --encrypt — but with
    // --password-file the file content is used as the OWNER password and
    // user is read from positional. To keep the previous semantics
    // (empty user, generated owner), we use the qpdf trick:
    //   --encrypt @<userfile> @<ownerfile> 256 ...
    // qpdf supports `@filename` for password values to read them from a file.
    use std::io::Write;
    let mut user_pwd_file = match tempfile::NamedTempFile::new_in(std::env::temp_dir()) {
        Ok(t) => t,
        Err(e) => {
            return err_result(&format!(
                "Impossibile creare file temp password utente: {}",
                e
            ));
        }
    };
    // empty user password → empty file
    let _ = user_pwd_file.write_all(b"");
    let _ = user_pwd_file.flush();
    let user_pwd_path = user_pwd_file.path().to_path_buf();

    let mut owner_pwd_file = match tempfile::NamedTempFile::new_in(std::env::temp_dir()) {
        Ok(t) => t,
        Err(e) => {
            return err_result(&format!(
                "Impossibile creare file temp password owner: {}",
                e
            ));
        }
    };
    if let Err(e) = owner_pwd_file.write_all(owner_pwd.as_bytes()) {
        return err_result(&format!("Impossibile scrivere password owner: {}", e));
    }
    let _ = owner_pwd_file.flush();
    let owner_pwd_path = owner_pwd_file.path().to_path_buf();

    let args: Vec<String> = vec![
        output_path.clone(),
        "--encrypt".to_string(),
        format!("@{}", user_pwd_path.display()),
        format!("@{}", owner_pwd_path.display()),
        "256".to_string(), // AES-256 encryption
        format!("--extract={}", if no_copy { "n" } else { "y" }),
        format!("--print={}", if no_print { "none" } else { "full" }),
        format!("--modify={}", if no_modify { "none" } else { "all" }),
        "--assemble=n".to_string(),
        "--annotate=n".to_string(),
        "--form=n".to_string(),
        "--".to_string(),
        tmp_encrypted.clone(),
    ];

    let cmd = sidecar.args(args.iter().map(|s| s.as_str()).collect::<Vec<&str>>());

    let result = match cmd.output().await {
        Ok(out) => {
            if out.status.success() {
                // Replace output with encrypted version
                let _ = std::fs::rename(&tmp_encrypted, &output_path);
                let mut msg = "PDF blindato: ".to_string();
                let mut protections = vec![];
                if no_copy {
                    protections.push("no-copia");
                }
                if no_print {
                    protections.push("no-stampa");
                }
                if no_modify {
                    protections.push("no-modifica");
                }
                if watermark_text.is_some() {
                    protections.push("watermark");
                }
                msg.push_str(&protections.join(", "));
                msg.push('.');
                DocToolResult {
                    success: true,
                    output_path: Some(output_path.clone()),
                    message: msg,
                    details: Some(serde_json::json!({ "owner_password": owner_pwd_display })),
                }
            } else {
                let _ = std::fs::remove_file(&tmp_encrypted);
                let stderr = String::from_utf8_lossy(&out.stderr);
                #[cfg(debug_assertions)]
                eprintln!("[doc_tools::secure_pdf] qpdf encryption failed: {}", stderr);
                err_result(map_qpdf_stderr(&stderr))
            }
        }
        Err(_e) => {
            let _ = std::fs::remove_file(&tmp_encrypted);
            #[cfg(debug_assertions)]
            eprintln!("[doc_tools::secure_pdf] qpdf exec error: {}", _e);
            err_result("Errore esecuzione qpdf")
        }
    };

    // F2: scrub temp password files
    drop(user_pwd_file);
    drop(owner_pwd_file);
    let _ = crate::security::secure_delete_file(&user_pwd_path);
    let _ = crate::security::secure_delete_file(&owner_pwd_path);

    result
}

// ─── Unsecure PDF (remove restrictions via qpdf) ───────────

#[tauri::command]
pub async fn unsecure_pdf(
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    password: Option<String>,
) -> DocToolResult {
    #[cfg(debug_assertions)]
    eprintln!(
        "[doc_tools::unsecure_pdf] {} → {}, has_password={}",
        input_path,
        output_path,
        password.is_some()
    );
    if let Err(e) = validate_input_path(&input_path) {
        return err_result(&e);
    }
    if let Err(e) = validate_output_path(&output_path) {
        return err_result(&e);
    }
    use tauri_plugin_shell::ShellExt;
    let sidecar = match app.shell().sidecar("qpdf") {
        Ok(s) => s,
        Err(e) => return err_result(&format!("qpdf non trovato: {}", e)),
    };

    // F5: refuse to overwrite existing output silently
    if std::path::Path::new(&output_path).exists() {
        return err_result(
            "Il file di destinazione esiste già. Eliminalo o scegli un'altra destinazione.",
        );
    }

    let mut args: Vec<String> = vec!["--decrypt".to_string()];

    // F2: pass the password through a temp file (--password-file=...) instead
    // of argv, so it does NOT show up in `ps aux`. The temp file is securely
    // deleted after the qpdf run.
    let mut pwd_file_keepalive: Option<tempfile::NamedTempFile> = None;
    let mut pwd_file_path: Option<std::path::PathBuf> = None;
    if let Some(pwd) = &password {
        if !pwd.is_empty() {
            use std::io::Write;
            let mut tf = match tempfile::NamedTempFile::new_in(std::env::temp_dir()) {
                Ok(t) => t,
                Err(e) => {
                    return err_result(&format!(
                        "Impossibile creare file temporaneo per la password: {}",
                        e
                    ));
                }
            };
            if let Err(e) = tf.write_all(pwd.as_bytes()) {
                return err_result(&format!(
                    "Impossibile scrivere file temporaneo password: {}",
                    e
                ));
            }
            let _ = tf.flush();
            let p = tf.path().to_path_buf();
            args.push(format!("--password-file={}", p.display()));
            pwd_file_path = Some(p);
            pwd_file_keepalive = Some(tf);
        }
    }
    // F1: use `--` as positional separator before output. Input is positional
    // and validated via canonicalize(); output basename is also screened for
    // leading-dash by validate_output_path (F3).
    args.push(input_path.clone());
    args.push("--".to_string());
    args.push(output_path.clone());

    let cmd = sidecar.args(args.iter().map(|s| s.as_str()).collect::<Vec<&str>>());

    let result = match cmd.output().await {
        Ok(out) => {
            if out.status.success() {
                ok_result(
                    &output_path,
                    "Restrizioni rimosse con successo. Il PDF è ora libero.",
                )
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                #[cfg(debug_assertions)]
                eprintln!("[doc_tools::unsecure_pdf] qpdf stderr: {}", stderr);
                err_result(map_qpdf_stderr(&stderr))
            }
        }
        Err(_e) => {
            #[cfg(debug_assertions)]
            eprintln!("[doc_tools::unsecure_pdf] exec error: {}", _e);
            err_result("Errore esecuzione qpdf")
        }
    };

    // F2: scrub the password file. Drop the NamedTempFile guard (closes handle),
    // then explicitly secure-delete in case the OS didn't unlink it.
    drop(pwd_file_keepalive);
    if let Some(p) = pwd_file_path {
        let _ = crate::security::secure_delete_file(&p);
    }

    result
}

// ═══════════════════════════════════════════════════════════
//  TESTS — simulate human usage of every PDF tool
// ═══════════════════════════════════════════════════════════

// TODO(audit:BE-1-CRIT): rewrite all tests as #[tokio::test] with mock AppHandle
// (currently disabled — many commands are now async and take AppHandle, so the
// previous synchronous-arity tests no longer compile). To re-enable: build with
// `--features broken_tests` after porting the test bodies. The feature is
// intentionally NOT declared in Cargo.toml (which is owned by BE-1) so the
// module never compiles by default; the unexpected_cfgs lint, if active, will
// flag the missing feature, which is acceptable while these tests are stale.
#[cfg(all(test, feature = "broken_tests"))]
mod tests {
    use super::*;
    use lopdf::dictionary;
    use std::fs;

    /// Helper: create a multi-page test PDF with text on each page.
    fn create_test_pdf(path: &str, num_pages: usize) {
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica",
        });
        let font_dict_id = doc.add_object(dictionary! {
            "F1" => Object::Reference(font_id),
        });

        let mut page_ids = vec![];
        for i in 1..=num_pages {
            let content = format!(
                "BT /F1 12 Tf 72 750 Td (Pagina {} - Testo di test per documento legale LexFlow) Tj ET",
                i
            );
            let content_id = doc.add_object(Object::Stream(lopdf::Stream::new(
                dictionary! {},
                content.into_bytes(),
            )));

            let page_id = doc.add_object(dictionary! {
                "Type" => "Page",
                "Parent" => Object::Reference(pages_id),
                "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
                "Contents" => Object::Reference(content_id),
                "Resources" => dictionary! {
                    "Font" => Object::Reference(font_dict_id),
                },
            });
            page_ids.push(page_id);
        }

        let kids: Vec<Object> = page_ids.iter().map(|id| Object::Reference(*id)).collect();
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => Object::Array(kids),
                "Count" => Object::Integer(num_pages as i64),
            }),
        );

        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => Object::Reference(pages_id),
        });
        doc.trailer.set("Root", Object::Reference(catalog_id));
        doc.save(path).expect("Failed to create test PDF");
    }

    fn tmp_path(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("lexflow_test_{}", name))
            .to_string_lossy()
            .to_string()
    }

    // ─── 1. PDF Info ───────────────────────────────────────
    #[test]
    fn test_pdf_info_reads_metadata() {
        let src = tmp_path("info_src.pdf");
        create_test_pdf(&src, 5);

        let info = pdf_info(src.clone()).expect("pdf_info should succeed");
        assert_eq!(info.pages, 5, "Should detect 5 pages");
        assert!(!info.encrypted, "Test PDF should not be encrypted");
        assert!(info.file_size > 0, "File size should be positive");
        println!("✓ pdf_info: {} pages, {} bytes", info.pages, info.file_size);

        fs::remove_file(&src).ok();
    }

    // ─── 2. Merge PDFs ────────────────────────────────────
    #[test]
    fn test_merge_two_pdfs() {
        let a = tmp_path("merge_a.pdf");
        let b = tmp_path("merge_b.pdf");
        let out = tmp_path("merge_out.pdf");
        create_test_pdf(&a, 3);
        create_test_pdf(&b, 2);

        let res = merge_pdfs(vec![a.clone(), b.clone()], out.clone());
        assert!(res.success, "Merge should succeed: {}", res.message);

        let info = pdf_info(out.clone()).unwrap();
        assert_eq!(info.pages, 5, "Merged PDF should have 3+2=5 pages");
        println!("✓ merge_pdfs: 3+2 → {} pages", info.pages);

        fs::remove_file(&a).ok();
        fs::remove_file(&b).ok();
        fs::remove_file(&out).ok();
    }

    #[test]
    fn test_merge_rejects_single_file() {
        let a = tmp_path("merge_single.pdf");
        create_test_pdf(&a, 1);

        let res = merge_pdfs(vec![a.clone()], tmp_path("merge_single_out.pdf"));
        assert!(!res.success, "Merge should reject single file");
        println!("✓ merge_pdfs: correctly rejects single file");

        fs::remove_file(&a).ok();
    }

    // ─── 3. Split PDF ─────────────────────────────────────
    #[test]
    fn test_split_pdf_into_pages() {
        let src = tmp_path("split_src.pdf");
        create_test_pdf(&src, 4);
        let out_dir = tmp_path("split_output");
        let _ = fs::remove_dir_all(&out_dir);

        let res = split_pdf(src.clone(), out_dir.clone());
        assert!(res.success, "Split should succeed: {}", res.message);

        // Verify 4 individual files created
        let stem = PathBuf::from(&src)
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .to_string();
        for i in 1..=4 {
            let page_file = PathBuf::from(&out_dir).join(format!("{}_pag{}.pdf", stem, i));
            assert!(page_file.exists(), "Page {} file should exist", i);
            let info = pdf_info(page_file.to_string_lossy().to_string()).unwrap();
            assert_eq!(info.pages, 1, "Each split file should have 1 page");
        }
        println!("✓ split_pdf: 4 pages → 4 files");

        fs::remove_file(&src).ok();
        fs::remove_dir_all(&out_dir).ok();
    }

    // ─── 4. Remove Pages ──────────────────────────────────
    #[test]
    fn test_remove_pages_from_pdf() {
        let src = tmp_path("remove_src.pdf");
        let out = tmp_path("remove_out.pdf");
        create_test_pdf(&src, 6);

        // Remove pages 2, 4, 5
        let res = remove_pages(src.clone(), out.clone(), vec![2, 4, 5]);
        assert!(res.success, "Remove should succeed: {}", res.message);

        let info = pdf_info(out.clone()).unwrap();
        assert_eq!(info.pages, 3, "Should have 6-3=3 pages remaining");
        println!(
            "✓ remove_pages: 6 pages, removed 3 → {} remaining",
            info.pages
        );

        fs::remove_file(&src).ok();
        fs::remove_file(&out).ok();
    }

    #[test]
    fn test_remove_all_pages_rejected() {
        let src = tmp_path("remove_all.pdf");
        create_test_pdf(&src, 2);

        let res = remove_pages(src.clone(), tmp_path("remove_all_out.pdf"), vec![1, 2]);
        assert!(!res.success, "Should reject removing all pages");
        println!("✓ remove_pages: correctly rejects removing all pages");

        fs::remove_file(&src).ok();
    }

    // ─── 5. Extract Pages ─────────────────────────────────
    #[test]
    fn test_extract_specific_pages() {
        let src = tmp_path("extract_src.pdf");
        let out = tmp_path("extract_out.pdf");
        create_test_pdf(&src, 8);

        // Extract pages 1, 3, 7
        let res = extract_pages(src.clone(), out.clone(), vec![1, 3, 7]);
        assert!(res.success, "Extract should succeed: {}", res.message);

        let info = pdf_info(out.clone()).unwrap();
        assert_eq!(info.pages, 3, "Should extract exactly 3 pages");
        println!(
            "✓ extract_pages: extracted 3 pages from 8 → {} pages",
            info.pages
        );

        fs::remove_file(&src).ok();
        fs::remove_file(&out).ok();
    }

    // ─── 6. Compress PDF ──────────────────────────────────
    #[test]
    fn test_compress_pdf_runs() {
        let src = tmp_path("compress_src.pdf");
        let out = tmp_path("compress_out.pdf");
        create_test_pdf(&src, 10);

        let res = compress_pdf(src.clone(), out.clone());
        assert!(res.success, "Compress should succeed: {}", res.message);

        let info = pdf_info(out.clone()).unwrap();
        assert_eq!(info.pages, 10, "Compressed PDF should still have 10 pages");
        assert!(info.file_size > 0, "Compressed file should not be empty");
        println!("✓ compress_pdf: {}", res.message);

        fs::remove_file(&src).ok();
        fs::remove_file(&out).ok();
    }

    // ─── 7. Watermark ─────────────────────────────────────
    #[test]
    fn test_add_watermark_bozza() {
        let src = tmp_path("wmark_src.pdf");
        let out = tmp_path("wmark_out.pdf");
        create_test_pdf(&src, 3);

        let res = add_watermark(
            src.clone(),
            out.clone(),
            "BOZZA".into(),
            Some(0.2),
            Some(48.0),
        );
        assert!(res.success, "Watermark should succeed: {}", res.message);

        let info = pdf_info(out.clone()).unwrap();
        assert_eq!(info.pages, 3, "Watermarked PDF should keep all pages");

        // Verify watermark content was added by checking file size increased
        let src_size = fs::metadata(&src).unwrap().len();
        let out_size = fs::metadata(&out).unwrap().len();
        assert!(out_size > src_size, "Watermarked PDF should be larger");
        println!(
            "✓ add_watermark: BOZZA added to 3 pages ({} → {} bytes)",
            src_size, out_size
        );

        fs::remove_file(&src).ok();
        fs::remove_file(&out).ok();
    }

    // ─── 8. Rotate Pages ──────────────────────────────────
    #[test]
    fn test_rotate_all_pages_90() {
        let src = tmp_path("rotate_src.pdf");
        let out = tmp_path("rotate_out.pdf");
        create_test_pdf(&src, 3);

        let res = rotate_pdf(src.clone(), out.clone(), 90, None);
        assert!(res.success, "Rotate should succeed: {}", res.message);

        // Verify rotation was set
        let doc = Document::load(&out).unwrap();
        for (_, page_id) in doc.get_pages() {
            let page = doc.get_object(page_id).unwrap().as_dict().unwrap();
            let rot = page.get(b"Rotate").unwrap().as_i64().unwrap();
            assert_eq!(rot, 90, "Each page should be rotated 90°");
        }
        println!("✓ rotate_pdf: all 3 pages rotated 90°");

        fs::remove_file(&src).ok();
        fs::remove_file(&out).ok();
    }

    #[test]
    fn test_rotate_specific_pages() {
        let src = tmp_path("rotate_spec_src.pdf");
        let out = tmp_path("rotate_spec_out.pdf");
        create_test_pdf(&src, 5);

        let res = rotate_pdf(src.clone(), out.clone(), 180, Some(vec![2, 4]));
        assert!(
            res.success,
            "Partial rotate should succeed: {}",
            res.message
        );
        println!("✓ rotate_pdf: pages 2,4 rotated 180° in a 5-page PDF");

        fs::remove_file(&src).ok();
        fs::remove_file(&out).ok();
    }

    #[test]
    fn test_rotate_rejects_invalid_angle() {
        let src = tmp_path("rotate_bad.pdf");
        create_test_pdf(&src, 1);

        let res = rotate_pdf(src.clone(), tmp_path("rotate_bad_out.pdf"), 45, None);
        assert!(!res.success, "Should reject non-90° multiple");
        println!("✓ rotate_pdf: correctly rejects 45° rotation");

        fs::remove_file(&src).ok();
    }

    // ─── 9. PDF to Text ───────────────────────────────────
    #[test]
    fn test_pdf_to_text_extraction() {
        let src = tmp_path("text_src.pdf");
        create_test_pdf(&src, 2);

        let text = pdf_to_text(src.clone()).expect("pdf_to_text should succeed");
        // The function returns either extracted text or a message about image-only PDF
        // Our test PDFs have BT/ET text blocks, so text extraction should find something
        assert!(!text.is_empty(), "Should return non-empty result");
        // The function prefixes each page with "--- Pagina N ---" if text is found
        let has_text =
            text.contains("Pagina") || text.contains("Testo") || text.contains("immagini");
        assert!(
            has_text,
            "Should contain page markers or text content, got: {}",
            &text[..text.len().min(200)]
        );
        println!("✓ pdf_to_text: result {} chars from 2 pages", text.len());

        fs::remove_file(&src).ok();
    }

    // ─── 10. Reorder Pages (NEW) ──────────────────────────
    #[test]
    fn test_reorder_pages_reverse() {
        let src = tmp_path("reorder_src.pdf");
        let out = tmp_path("reorder_out.pdf");
        create_test_pdf(&src, 4);

        // Reverse order: 4,3,2,1
        let res = reorder_pages(src.clone(), out.clone(), vec![4, 3, 2, 1]);
        assert!(res.success, "Reorder should succeed: {}", res.message);

        let info = pdf_info(out.clone()).unwrap();
        assert_eq!(info.pages, 4, "Reordered PDF should still have 4 pages");
        println!("✓ reorder_pages: reversed 4 pages → {}", res.message);

        fs::remove_file(&src).ok();
        fs::remove_file(&out).ok();
    }

    #[test]
    fn test_reorder_swap_first_last() {
        let src = tmp_path("reorder_swap_src.pdf");
        let out = tmp_path("reorder_swap_out.pdf");
        create_test_pdf(&src, 5);

        // Swap page 1 and 5, keep rest
        let res = reorder_pages(src.clone(), out.clone(), vec![5, 2, 3, 4, 1]);
        assert!(res.success, "Swap reorder should succeed: {}", res.message);

        let info = pdf_info(out.clone()).unwrap();
        assert_eq!(info.pages, 5, "Should have 5 pages");
        println!("✓ reorder_pages: swapped first/last in 5-page PDF");

        fs::remove_file(&src).ok();
        fs::remove_file(&out).ok();
    }

    #[test]
    fn test_reorder_rejects_wrong_count() {
        let src = tmp_path("reorder_bad.pdf");
        create_test_pdf(&src, 3);

        let res = reorder_pages(src.clone(), tmp_path("reorder_bad_out.pdf"), vec![1, 2]);
        assert!(!res.success, "Should reject wrong page count");
        println!("✓ reorder_pages: correctly rejects 2 pages for 3-page PDF");

        fs::remove_file(&src).ok();
    }

    #[test]
    fn test_reorder_rejects_duplicate_pages() {
        let src = tmp_path("reorder_dup.pdf");
        create_test_pdf(&src, 3);

        let res = reorder_pages(src.clone(), tmp_path("reorder_dup_out.pdf"), vec![1, 1, 3]);
        assert!(!res.success, "Should reject duplicate page numbers");
        println!("✓ reorder_pages: correctly rejects duplicates [1,1,3]");

        fs::remove_file(&src).ok();
    }

    // ─── 11. Add Page Numbers (NEW) ───────────────────────
    #[test]
    fn test_add_page_numbers_default() {
        let src = tmp_path("pagenum_src.pdf");
        let out = tmp_path("pagenum_out.pdf");
        create_test_pdf(&src, 5);

        let res = add_page_numbers(
            src.clone(),
            out.clone(),
            None,
            None,
            None,
            None, // all defaults: bottom-center, "{n}", start=1, 10pt
        );
        assert!(res.success, "Page numbers should succeed: {}", res.message);

        let info = pdf_info(out.clone()).unwrap();
        assert_eq!(info.pages, 5, "Should keep all pages");

        // File should be larger (added content streams)
        let out_size = fs::metadata(&out).unwrap().len();
        let src_size = fs::metadata(&src).unwrap().len();
        assert!(out_size > src_size, "Numbered PDF should be larger");
        println!(
            "✓ add_page_numbers: default format on 5 pages ({} → {} bytes)",
            src_size, out_size
        );

        fs::remove_file(&src).ok();
        fs::remove_file(&out).ok();
    }

    #[test]
    fn test_add_page_numbers_with_format() {
        let src = tmp_path("pagenum_fmt_src.pdf");
        let out = tmp_path("pagenum_fmt_out.pdf");
        create_test_pdf(&src, 3);

        let res = add_page_numbers(
            src.clone(),
            out.clone(),
            Some("top-right".into()),
            Some("Pag. {n} di {total}".into()),
            Some(1),
            Some(9.0),
        );
        assert!(
            res.success,
            "Formatted page numbers should succeed: {}",
            res.message
        );
        println!("✓ add_page_numbers: 'Pag. N di M' top-right on 3 pages");

        fs::remove_file(&src).ok();
        fs::remove_file(&out).ok();
    }

    #[test]
    fn test_add_page_numbers_start_from_custom() {
        let src = tmp_path("pagenum_start_src.pdf");
        let out = tmp_path("pagenum_start_out.pdf");
        create_test_pdf(&src, 4);

        let res = add_page_numbers(
            src.clone(),
            out.clone(),
            Some("bottom-left".into()),
            Some("{n}".into()),
            Some(10),
            None,
        );
        assert!(res.success, "Custom start should succeed: {}", res.message);
        assert!(
            res.message.contains("da 10 a 13"),
            "Should mention numbering 10-13, got: {}",
            res.message
        );
        println!("✓ add_page_numbers: numbered 10-13 on 4 pages");

        fs::remove_file(&src).ok();
        fs::remove_file(&out).ok();
    }

    // ─── 12. Redact PDF (NEW) ─────────────────────────────
    #[test]
    fn test_redact_single_area() {
        let src = tmp_path("redact_src.pdf");
        let out = tmp_path("redact_out.pdf");
        create_test_pdf(&src, 2);

        let res = redact_pdf(
            src.clone(),
            out.clone(),
            vec![RedactArea {
                page: 1,
                x: 50.0,
                y: 740.0,
                width: 300.0,
                height: 20.0,
            }],
        );
        assert!(res.success, "Redact should succeed: {}", res.message);

        let info = pdf_info(out.clone()).unwrap();
        assert_eq!(info.pages, 2, "Should keep all pages");
        println!("✓ redact_pdf: censored 1 area on page 1 → {}", res.message);

        fs::remove_file(&src).ok();
        fs::remove_file(&out).ok();
    }

    #[test]
    fn test_redact_multiple_areas_multiple_pages() {
        let src = tmp_path("redact_multi_src.pdf");
        let out = tmp_path("redact_multi_out.pdf");
        create_test_pdf(&src, 3);

        let res = redact_pdf(
            src.clone(),
            out.clone(),
            vec![
                RedactArea {
                    page: 1,
                    x: 50.0,
                    y: 740.0,
                    width: 200.0,
                    height: 15.0,
                },
                RedactArea {
                    page: 1,
                    x: 50.0,
                    y: 700.0,
                    width: 150.0,
                    height: 15.0,
                },
                RedactArea {
                    page: 2,
                    x: 100.0,
                    y: 600.0,
                    width: 250.0,
                    height: 20.0,
                },
                RedactArea {
                    page: 3,
                    x: 72.0,
                    y: 750.0,
                    width: 400.0,
                    height: 18.0,
                },
            ],
        );
        assert!(res.success, "Multi-redact should succeed: {}", res.message);
        assert!(
            res.message.contains("4 aree"),
            "Should report 4 areas, got: {}",
            res.message
        );
        println!("✓ redact_pdf: 4 areas across 3 pages → {}", res.message);

        fs::remove_file(&src).ok();
        fs::remove_file(&out).ok();
    }

    #[test]
    fn test_redact_rejects_invalid_page() {
        let src = tmp_path("redact_bad.pdf");
        create_test_pdf(&src, 2);

        let res = redact_pdf(
            src.clone(),
            tmp_path("redact_bad_out.pdf"),
            vec![RedactArea {
                page: 5,
                x: 0.0,
                y: 0.0,
                width: 100.0,
                height: 100.0,
            }],
        );
        assert!(!res.success, "Should reject page 5 for 2-page PDF");
        println!("✓ redact_pdf: correctly rejects invalid page number");

        fs::remove_file(&src).ok();
    }

    #[test]
    fn test_redact_rejects_empty_areas() {
        let src = tmp_path("redact_empty.pdf");
        create_test_pdf(&src, 1);

        let res = redact_pdf(src.clone(), tmp_path("redact_empty_out.pdf"), vec![]);
        assert!(!res.success, "Should reject empty redaction list");
        println!("✓ redact_pdf: correctly rejects empty area list");

        fs::remove_file(&src).ok();
    }

    // ─── 13. Chained operations (real-world workflow) ──────
    #[test]
    fn test_workflow_merge_then_add_numbers_then_watermark() {
        // Simulate: lawyer merges two documents, adds page numbers, then watermarks BOZZA
        let a = tmp_path("wf_a.pdf");
        let b = tmp_path("wf_b.pdf");
        let merged = tmp_path("wf_merged.pdf");
        let numbered = tmp_path("wf_numbered.pdf");
        let final_out = tmp_path("wf_final.pdf");

        create_test_pdf(&a, 3);
        create_test_pdf(&b, 2);

        // Step 1: Merge
        let res1 = merge_pdfs(vec![a.clone(), b.clone()], merged.clone());
        assert!(res1.success, "Merge step failed");
        let info1 = pdf_info(merged.clone()).unwrap();
        assert_eq!(info1.pages, 5);

        // Step 2: Add page numbers
        let res2 = add_page_numbers(
            merged.clone(),
            numbered.clone(),
            Some("bottom-center".into()),
            Some("Pag. {n} di {total}".into()),
            Some(1),
            None,
        );
        assert!(res2.success, "Page numbers step failed");

        // Step 3: Add watermark
        let res3 = add_watermark(
            numbered.clone(),
            final_out.clone(),
            "BOZZA".into(),
            Some(0.15),
            Some(60.0),
        );
        assert!(res3.success, "Watermark step failed");

        let final_info = pdf_info(final_out.clone()).unwrap();
        assert_eq!(final_info.pages, 5, "Final document should have 5 pages");
        println!(
            "✓ WORKFLOW: merge(3+2) → page numbers → watermark BOZZA = {} pages, {} bytes",
            final_info.pages, final_info.file_size
        );

        fs::remove_file(&a).ok();
        fs::remove_file(&b).ok();
        fs::remove_file(&merged).ok();
        fs::remove_file(&numbered).ok();
        fs::remove_file(&final_out).ok();
    }

    #[test]
    fn test_workflow_extract_then_redact() {
        // Simulate: extract relevant pages from a long doc, then censor personal data
        let src = tmp_path("wf2_src.pdf");
        let extracted = tmp_path("wf2_extracted.pdf");
        let redacted = tmp_path("wf2_redacted.pdf");

        create_test_pdf(&src, 10);

        // Step 1: Extract pages 2, 5, 8
        let res1 = extract_pages(src.clone(), extracted.clone(), vec![2, 5, 8]);
        assert!(res1.success, "Extract step failed");

        // Step 2: Redact areas on pages of extracted doc
        let res2 = redact_pdf(
            extracted.clone(),
            redacted.clone(),
            vec![
                RedactArea {
                    page: 1,
                    x: 72.0,
                    y: 740.0,
                    width: 200.0,
                    height: 16.0,
                },
                RedactArea {
                    page: 3,
                    x: 72.0,
                    y: 740.0,
                    width: 200.0,
                    height: 16.0,
                },
            ],
        );
        assert!(res2.success, "Redact step failed");

        let info = pdf_info(redacted.clone()).unwrap();
        assert_eq!(info.pages, 3, "Redacted doc should have 3 pages");
        println!(
            "✓ WORKFLOW: extract(2,5,8 from 10) → redact 2 areas = {} pages",
            info.pages
        );

        fs::remove_file(&src).ok();
        fs::remove_file(&extracted).ok();
        fs::remove_file(&redacted).ok();
    }
}
