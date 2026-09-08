// ═══════════════════════════════════════════════════════════
//  DOC TOOLS — PDF manipulation for legal professionals
// ═══════════════════════════════════════════════════════════
//
use lopdf::{Document, Object, ObjectId};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const PDF_MAX_INPUT_BYTES: u64 = 100 * 1024 * 1024;
const PDF_MAX_BATCH_BYTES: u64 = 250 * 1024 * 1024;

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
    let metadata = std::fs::symlink_metadata(p)
        .map_err(|_| "File non valido o non accessibile.".to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("Seleziona un file regolare, senza collegamenti simbolici.".into());
    }
    if metadata.len() > PDF_MAX_INPUT_BYTES {
        return Err("File troppo grande (massimo 100 MiB).".into());
    }
    let canonical = p
        .canonicalize()
        .map_err(|_| format!("Percorso non valido o non accessibile: {}", path))?;
    let prefixes = allowed_prefixes();
    if !prefixes.iter().any(|pfx| canonical.starts_with(pfx)) {
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
    if std::fs::symlink_metadata(p).is_ok() {
        return Err("La destinazione esiste già. Scegli un nuovo nome.".into());
    }
    if p.extension()
        .and_then(|ext| ext.to_str())
        .is_none_or(|ext| !ext.eq_ignore_ascii_case("pdf"))
    {
        return Err("La destinazione deve avere estensione .pdf.".into());
    }
    let parent = p
        .parent()
        .ok_or_else(|| "Percorso senza directory padre".to_string())?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|_| "Directory di destinazione non valida o non accessibile".to_string())?;
    let prefixes = allowed_prefixes();
    if !prefixes.iter().any(|pfx| canonical_parent.starts_with(pfx)) {
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
    crate::hardening::typst_string(s)
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

fn publish_pdf_result(staged: &Path, destination: &str, message: &str) -> DocToolResult {
    match crate::hardening::publish_new_file(staged, Path::new(destination)) {
        Ok(()) => ok_result(destination, message),
        Err(error) => err_result(&error),
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
    lopdf::decode_text_string(val).ok().or_else(|| {
        val.as_name()
            .ok()
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
    })
}

/// Read through one bounded regular-file descriptor before invoking the parser.
fn load_pdf(path: impl AsRef<Path>) -> Result<Document, String> {
    let bytes = zeroize::Zeroizing::new(crate::io::safe_bounded_read(
        path.as_ref(),
        PDF_MAX_INPUT_BYTES,
    )?);
    Document::load_mem(&bytes).map_err(|_| "PDF danneggiato o non supportato.".into())
}

/// Save only a complete result, with private permissions and no overwrite.
fn save_pdf(doc: &mut Document, destination: impl AsRef<Path>) -> Result<(), String> {
    let work = crate::hardening::DocumentWorkspace::new()?;
    let staged = work.join("result.pdf");
    doc.save(&staged)
        .map_err(|_| "Impossibile preparare il PDF.".to_string())?;
    crate::hardening::publish_new_file(&staged, destination.as_ref())
}

/// Materialize inherited page properties before changing its parent.
fn inherited_page_attributes(
    doc: &Document,
    page_id: ObjectId,
) -> Result<lopdf::Dictionary, String> {
    let mut attributes = lopdf::Dictionary::new();
    let mut current = Some(page_id);
    let mut visited = BTreeSet::new();
    while let Some(id) = current {
        if !visited.insert(id) || visited.len() > 128 {
            return Err("Gerarchia delle pagine PDF non valida.".into());
        }
        let dict = doc
            .get_dictionary(id)
            .map_err(|_| "Pagina PDF non valida.")?;
        for key in [b"Resources".as_slice(), b"MediaBox", b"CropBox", b"Rotate"] {
            if !attributes.has(key) {
                if let Ok(value) = dict.get(key) {
                    attributes.set(key, value.clone());
                }
            }
        }
        current = dict
            .get(b"Parent")
            .ok()
            .and_then(|value| value.as_reference().ok());
    }
    Ok(attributes)
}

/// Some PDFs put a direct Resources dictionary on an ancestor; materializing
/// it also makes font decoding independent of parser inheritance shortcuts.
fn materialize_page_attributes(doc: &mut Document) -> Result<(), String> {
    for page_id in doc.get_pages().values() {
        let attributes = inherited_page_attributes(doc, *page_id)?;
        let page = doc
            .get_object_mut(*page_id)
            .and_then(Object::as_dict_mut)
            .map_err(|_| "Pagina PDF non valida.".to_string())?;
        for (key, value) in attributes.iter() {
            page.set(key.as_slice(), value.clone());
        }
    }
    Ok(())
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

async fn pdf_info_impl(app: tauri::AppHandle, path: String) -> Result<PdfInfo, String> {
    validate_input_path(&path)?;
    let file_size = std::fs::metadata(&path)
        .map(|m| m.len())
        .map_err(|e| format!("Impossibile leggere il file: {}", e))?;

    match load_pdf(&path) {
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

fn merge_pdfs_impl(input_paths: Vec<String>, output_path: String) -> DocToolResult {
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

    let total_bytes: u64 = input_paths
        .iter()
        .filter_map(|path| std::fs::metadata(path).ok())
        .map(|metadata| metadata.len())
        .sum();
    if total_bytes > PDF_MAX_BATCH_BYTES {
        return err_result("I PDF selezionati superano il limite complessivo di 250 MiB.");
    }

    // Keep a single result document, appending each input once.
    let mut base = match load_pdf(&input_paths[0]) {
        Ok(d) => d,
        Err(e) => return err_result(&format!("Errore nel primo file: {}", e)),
    };

    for path in &input_paths[1..] {
        let other = match load_pdf(path) {
            Ok(d) => d,
            Err(e) => return err_result(&format!("Errore nel file {}: {}", path, e)),
        };

        // Merge using lopdf's built-in merge_from
        if let Err(e) = merge_document(&mut base, &other) {
            return err_result(&format!("Errore nell'unione: {}", e));
        }
    }

    base.compress();

    match save_pdf(&mut base, &output_path) {
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
            let inherited = inherited_page_attributes(other, page_id)?;
            // Preserve inherited resources/geometry before attaching to base.
            if let Some(obj) = base.objects.get_mut(&new_page_id) {
                if let Ok(dict) = obj.as_dict_mut() {
                    for (key, value) in inherited.iter() {
                        let mut value = value.clone();
                        remap_references(&mut value, &id_map);
                        dict.set(key.as_slice(), value);
                    }
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

fn split_pdf_impl(input_path: String, output_dir: String) -> DocToolResult {
    if let Err(e) = validate_input_path(&input_path) {
        return err_result(&e);
    }
    if let Err(e) = validate_output_dir(&output_dir) {
        return err_result(&e);
    }
    let mut doc = match load_pdf(&input_path) {
        Ok(d) => d,
        Err(e) => return err_result(&format!("Errore nell'apertura: {}", e)),
    };

    if let Err(error) = materialize_page_attributes(&mut doc) {
        return err_result(&error);
    }
    let total = doc.get_pages().len();
    if total == 0 || total > 500 {
        return err_result("La divisione richiede da 1 a 500 pagine per operazione.");
    }
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
        single.delete_pages(&pages_to_remove);
        // Removing a page alone leaves its content and images in the file.
        single.prune_objects();
        single.renumber_objects();

        let out_path = PathBuf::from(&output_dir).join(format!("{}_pag{}.pdf", stem, page_num));
        if let Err(error) = save_pdf(&mut single, &out_path) {
            return err_result(&format!(
                "Divisione interrotta dopo {} pagine: {}",
                created, error
            ));
        }
        created += 1;
    }

    ok_result(
        &output_dir,
        &format!("{} pagine estratte da {} totali.", created, total),
    )
}

// ─── Remove Pages ───────────────────────────────────────────

async fn remove_pages_impl(
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    pages_to_remove: Vec<u32>,
) -> DocToolResult {
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
    let total = match load_pdf(&input_path) {
        Ok(d) => d.get_pages().len() as u32,
        Err(e) => return err_result(&format!("Errore nell'apertura: {}", e)),
    };

    if pages_to_remove.iter().any(|&p| p < 1 || p > total) {
        return err_result(&format!(
            "Numeri pagina non validi. Il PDF ha {} pagine.",
            total
        ));
    }
    let pages_to_remove: BTreeSet<u32> = pages_to_remove.into_iter().collect();
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

    let work = match crate::hardening::DocumentWorkspace::new() {
        Ok(work) => work,
        Err(error) => return err_result(&error),
    };
    let staged = work.join("result.pdf");
    let staged_path = staged.to_string_lossy();

    let args = vec![
        "--empty",
        "--pages",
        input_path.as_str(),
        &page_spec,
        "--",
        "--",
        staged_path.as_ref(),
    ];

    let cmd = sidecar.args(args);
    let removed = pages_to_remove.len();
    match cmd.output().await {
        Ok(out) if out.status.success() => publish_pdf_result(
            &staged,
            &output_path,
            &format!(
                "{} pagine rimosse. Rimangono {} pagine.",
                removed,
                total - removed as u32
            ),
        ),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            err_result(map_qpdf_stderr(&stderr))
        }
        Err(_e) => err_result("Errore esecuzione qpdf"),
    }
}

// ─── Extract Pages ──────────────────────────────────────────

async fn extract_pages_impl(
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    pages_to_extract: Vec<u32>,
) -> DocToolResult {
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

    let work = match crate::hardening::DocumentWorkspace::new() {
        Ok(work) => work,
        Err(error) => return err_result(&error),
    };
    let staged = work.join("result.pdf");
    let staged_path = staged.to_string_lossy();

    let args = vec![
        "--empty",
        "--pages",
        input_path.as_str(),
        &page_spec,
        "--",
        "--",
        staged_path.as_ref(),
    ];

    let cmd = sidecar.args(args);
    match cmd.output().await {
        Ok(out) if out.status.success() => publish_pdf_result(
            &staged,
            &output_path,
            &format!("{} pagine estratte.", pages_to_extract.len()),
        ),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            err_result(map_qpdf_stderr(&stderr))
        }
        Err(_e) => err_result("Errore esecuzione qpdf"),
    }
}

// ─── Compress PDF ───────────────────────────────────────────

async fn compress_pdf_impl(
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
) -> DocToolResult {
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
            let mut doc = match load_pdf(&input_path) {
                Ok(d) => d,
                Err(e) => return err_result(&format!("Errore nell'apertura: {}", e)),
            };
            doc.compress();
            doc.delete_zero_length_streams();
            doc.prune_objects();
            doc.renumber_objects();
            return match save_pdf(&mut doc, &output_path) {
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

    let work = match crate::hardening::DocumentWorkspace::new() {
        Ok(work) => work,
        Err(error) => return err_result(&error),
    };
    let staged = work.join("result.pdf");
    let staged_path = staged.to_string_lossy();

    let args = vec![
        input_path.as_str(),
        "--stream-data=compress",
        "--recompress-flate",
        "--object-streams=generate",
        "--remove-unreferenced-resources=yes",
        "--",
        staged_path.as_ref(),
    ];

    let cmd = sidecar.args(args);
    match cmd.output().await {
        Ok(out) => {
            if out.status.success() {
                if let Err(error) =
                    crate::hardening::publish_new_file(&staged, Path::new(&output_path))
                {
                    return err_result(&error);
                }
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
                err_result(map_qpdf_stderr(&stderr))
            }
        }
        Err(_e) => err_result("Errore esecuzione qpdf"),
    }
}

// ─── Watermark ──────────────────────────────────────────────

async fn add_watermark_impl(
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    text: String,
    opacity: Option<f64>,
    font_size: Option<f64>,
) -> DocToolResult {
    if let Err(e) = validate_input_path(&input_path) {
        return err_result(&e);
    }
    if let Err(e) = validate_output_path(&output_path) {
        return err_result(&e);
    }

    // Count pages: try lopdf first, fall back to qpdf --show-npages
    let page_count = match load_pdf(&input_path) {
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
    if !opacity_val.is_finite()
        || !(0.0..=1.0).contains(&opacity_val)
        || !fs.is_finite()
        || !(1.0..=144.0).contains(&fs)
    {
        return err_result("Opacità o dimensione del watermark non valide.");
    }

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
                    "{pb}#place(center + horizon, rotate(-30deg, text(\"{text}\")))",
                    pb = pb,
                    text = escaped
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
    );

    let work = match crate::hardening::DocumentWorkspace::new() {
        Ok(work) => work,
        Err(e) => return err_result(&e),
    };
    let tmp_typ = work.join("overlay.typ");
    let tmp_overlay = work.join("overlay.pdf");
    let staged = work.join("result.pdf");

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
        &staged.to_string_lossy(),
    ]);
    let result = match qpdf_cmd.output().await {
        Ok(out) if out.status.success() => publish_pdf_result(
            &staged,
            &output_path,
            &format!("Watermark \"{}\" aggiunto a {} pagine.", text, page_count),
        ),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            err_result(map_qpdf_stderr(&stderr))
        }
        Err(_e) => err_result("Errore esecuzione qpdf"),
    };
    let _ = crate::security::secure_delete_file(&tmp_overlay);
    result
}

// ─── Rotate Pages ───────────────────────────────────────────

async fn rotate_pdf_impl(
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    rotation: i32,
    pages_to_rotate: Option<Vec<u32>>,
) -> DocToolResult {
    if let Err(e) = validate_input_path(&input_path) {
        return err_result(&e);
    }
    if let Err(e) = validate_output_path(&output_path) {
        return err_result(&e);
    }
    if rotation % 90 != 0 {
        return err_result("La rotazione deve essere un multiplo di 90°.");
    }
    let rotation = rotation.rem_euclid(360);
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
            let mut doc = match load_pdf(&input_path) {
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
                            .unwrap_or(0)
                            .rem_euclid(360);
                        dict.set("Rotate", Object::Integer((cur + i64::from(rotation)) % 360));
                        rotated += 1;
                    }
                }
            }
            return match save_pdf(&mut doc, &output_path) {
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

    let work = match crate::hardening::DocumentWorkspace::new() {
        Ok(work) => work,
        Err(error) => return err_result(&error),
    };
    let staged = work.join("result.pdf");
    let staged_path = staged.to_string_lossy();

    let args = vec![input_path.as_str(), &rotate_arg, "--", staged_path.as_ref()];

    let cmd = sidecar.args(args);
    match cmd.output().await {
        Ok(out) => {
            if out.status.success() {
                if let Err(error) =
                    crate::hardening::publish_new_file(&staged, Path::new(&output_path))
                {
                    return err_result(&error);
                }
                ok_result(&output_path, &format!("Pagine ruotate di {}°.", rotation))
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                err_result(map_qpdf_stderr(&stderr))
            }
        }
        Err(_e) => err_result("Errore esecuzione qpdf"),
    }
}

// ─── PDF to Text ────────────────────────────────────────────

fn pdf_to_text_impl(input_path: String) -> Result<String, String> {
    validate_input_path(&input_path)?;
    let mut doc = load_pdf(&input_path).map_err(|e| format!("Errore nell'apertura: {}", e))?;

    materialize_page_attributes(&mut doc)?;
    let pages = doc.get_pages();
    let mut full_text = String::new();

    for page_num in pages.keys() {
        let page_text = doc
            .extract_text(&[*page_num])
            .map_err(|_| "Impossibile estrarre il testo da una pagina PDF.".to_string())?;
        if full_text.len().saturating_add(page_text.len()) > 10 * 1024 * 1024 {
            return Err("Testo estratto troppo grande (massimo 10 MiB).".into());
        }
        if !page_text.trim().is_empty() {
            full_text.push_str(&format!("--- Pagina {} ---\n", page_num));
            full_text.push_str(page_text.trim());
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

async fn images_to_pdf_impl(
    app: tauri::AppHandle,
    image_paths: Vec<String>,
    output_path: String,
) -> DocToolResult {
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

    if image_paths.len() > 500 {
        return err_result("Massimo 500 immagini per operazione.");
    }
    let work = match crate::hardening::DocumentWorkspace::new() {
        Ok(work) => work,
        Err(e) => return err_result(&e),
    };
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
        let extension = Path::new(img_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !["png", "jpg", "jpeg", "webp", "gif"].contains(&extension.as_str()) {
            return err_result("Formato immagine non consentito.");
        }
        let local_name = format!("image_{i}.{extension}");
        let bytes = match crate::io::safe_bounded_read(Path::new(img_path), 50 * 1024 * 1024) {
            Ok(bytes) => zeroize::Zeroizing::new(bytes),
            Err(_) => return err_result("Immagine non leggibile o troppo grande."),
        };
        if crate::io::secure_write(&work.join(&local_name), &bytes).is_err() {
            return err_result("Impossibile preparare l'immagine.");
        }
        let escaped = escape_typst_string(&local_name);
        typst_content.push_str(&format!(
            "#align(center)[#image(\"{}\", width: 100%)]\n",
            escaped
        ));
        if i < total - 1 {
            typst_content.push_str("#pagebreak()\n");
        }
    }

    let tmp_typ = work.join("images.typ");
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
                match crate::hardening::publish_new_file(&tmp_pdf, Path::new(&output_path)) {
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

fn reorder_pages_impl(
    input_path: String,
    output_path: String,
    new_order: Vec<u32>,
) -> DocToolResult {
    if let Err(e) = validate_input_path(&input_path) {
        return err_result(&e);
    }
    if let Err(e) = validate_output_path(&output_path) {
        return err_result(&e);
    }
    let doc = match load_pdf(&input_path) {
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

    let pages = doc.get_pages();
    let root_pages = match doc
        .catalog()
        .and_then(|catalog| catalog.get(b"Pages"))
        .and_then(Object::as_reference)
    {
        Ok(id) => id,
        Err(_) => return err_result("Gerarchia delle pagine PDF non valida."),
    };
    let mut final_doc = doc;
    let mut kids = Vec::with_capacity(new_order.len());
    for page_number in &new_order {
        let page_id = pages[page_number];
        let inherited = match inherited_page_attributes(&final_doc, page_id) {
            Ok(attributes) => attributes,
            Err(error) => return err_result(&error),
        };
        let page = match final_doc
            .get_object_mut(page_id)
            .and_then(Object::as_dict_mut)
        {
            Ok(page) => page,
            Err(_) => return err_result("Pagina PDF non valida."),
        };
        for (key, value) in inherited.iter() {
            page.set(key.as_slice(), value.clone());
        }
        page.set("Parent", Object::Reference(root_pages));
        kids.push(Object::Reference(page_id));
    }
    let mut page_tree = lopdf::Dictionary::new();
    page_tree.set("Type", Object::Name(b"Pages".to_vec()));
    page_tree.set("Kids", Object::Array(kids));
    page_tree.set("Count", Object::Integer(i64::from(total)));
    final_doc
        .objects
        .insert(root_pages, Object::Dictionary(page_tree));
    final_doc.prune_objects();
    final_doc.compress();

    match save_pdf(&mut final_doc, &output_path) {
        Ok(_) => ok_result(
            &output_path,
            &format!("{} pagine riordinate con successo.", total),
        ),
        Err(e) => err_result(&format!("Errore nel salvataggio: {}", e)),
    }
}

// ─── Add Page Numbers ──────────────────────────────────────

async fn add_page_numbers_impl(
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    position: Option<String>,
    format_str: Option<String>,
    start_from: Option<u32>,
    font_size: Option<f64>,
) -> DocToolResult {
    if let Err(e) = validate_input_path(&input_path) {
        return err_result(&e);
    }
    if let Err(e) = validate_output_path(&output_path) {
        return err_result(&e);
    }

    // Count pages: try lopdf first, fall back to qpdf --show-npages
    let total = match load_pdf(&input_path) {
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
    if fmt.len() > 1024 || start.checked_add(total).is_none() {
        return err_result("Formato o numerazione non validi.");
    }
    let fs = font_size.unwrap_or(10.0);
    if !fs.is_finite() || !(1.0..=144.0).contains(&fs) {
        return err_result("Dimensione del carattere non valida.");
    }

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
        let label = escape_typst_string(
            &fmt.replace("{n}", &num.to_string())
                .replace("{total}", &(start + total - 1).to_string()),
        );
        typst_content.push_str(&format!(
            "#place({}, {}{}text(\"{}\"))\n",
            align, dx, dy, label
        ));
    }

    let work = match crate::hardening::DocumentWorkspace::new() {
        Ok(work) => work,
        Err(e) => return err_result(&e),
    };
    let tmp_typ = work.join("overlay.typ");
    let tmp_overlay = work.join("overlay.pdf");
    let staged = work.join("result.pdf");

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
        &staged.to_string_lossy(),
    ]);
    let result = match qpdf_cmd.output().await {
        Ok(out) if out.status.success() => publish_pdf_result(
            &staged,
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
            err_result(map_qpdf_stderr(&stderr))
        }
        Err(_e) => err_result("Errore esecuzione qpdf"),
    };
    let _ = crate::security::secure_delete_file(&tmp_overlay);
    result
}

// Redaction is unavailable until image, Form XObject, annotation, metadata and
// orphan-object removal can all be verified. Overlays and PDF permissions do
// not remove confidential content. Keep IPC compatible and fail without I/O.
fn redact_pdf_impl(
    input_path: String,
    output_path: String,
    redactions: Vec<RedactArea>,
) -> DocToolResult {
    let _ = (input_path, output_path, redactions);
    err_result("Censura PDF disabilitata: la rimozione irreversibile dei contenuti non è ancora garantita. Nessun file è stato creato.")
}

#[derive(serde::Deserialize)]
#[allow(dead_code)] // Retained only for compatible rejection of the disabled IPC command.
pub struct RedactArea {
    pub page: u32,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

// ─── PDF permission restrictions ──────────────────────────

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurePdfOptions {
    pub no_copy: Option<bool>,
    pub no_print: Option<bool>,
    pub no_modify: Option<bool>,
    pub watermark: Option<String>,
    pub owner_password: Option<String>,
}

/// qpdf response files contain one argument per line. Prefixing the owner
/// password with its flag also prevents passwords beginning with '@' becoming
/// nested response-file reads. Requires qpdf >= 11.7.
fn encryption_arguments(
    password: &str,
    no_copy: bool,
    no_print: bool,
    no_modify: bool,
) -> Result<zeroize::Zeroizing<String>, String> {
    if password.is_empty() || password.len() > 127 || password.chars().any(char::is_control) {
        return Err(
            "Password proprietario non valida: usa da 1 a 127 byte senza caratteri di controllo."
                .into(),
        );
    }
    Ok(zeroize::Zeroizing::new(format!(
        "--encrypt\n--user-password=\n--owner-password={}\n--bits=256\n--extract={}\n--print={}\n--modify={}\n--\n",
        password, if no_copy { "n" } else { "y" },
        if no_print { "none" } else { "full" }, if no_modify { "none" } else { "all" }
    )))
}

async fn secure_pdf_impl(
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    options: SecurePdfOptions,
) -> DocToolResult {
    if let Err(e) =
        validate_input_path(&input_path).and_then(|_| validate_output_path(&output_path))
    {
        return err_result(&e);
    }
    if Path::new(&output_path).exists() {
        return err_result("Il file di destinazione esiste già. Scegli un nuovo nome.");
    }
    let work = match crate::hardening::DocumentWorkspace::new() {
        Ok(work) => work,
        Err(e) => return err_result(&e),
    };
    let owner_pwd = zeroize::Zeroizing::new(options.owner_password.unwrap_or_else(|| {
        use rand::RngCore;
        let mut random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random);
        hex::encode(random)
    }));
    let arguments = match encryption_arguments(
        &owner_pwd,
        options.no_copy.unwrap_or(true),
        options.no_print.unwrap_or(true),
        options.no_modify.unwrap_or(true),
    ) {
        Ok(arguments) => arguments,
        Err(e) => return err_result(&e),
    };
    let arguments_path = work.join("encryption.args");
    if crate::io::secure_write(&arguments_path, arguments.as_bytes()).is_err() {
        return err_result("Impossibile preparare la protezione PDF.");
    }
    let mut source = input_path;
    if let Some(text) = options.watermark.filter(|text| !text.is_empty()) {
        let watermarked = work.join("watermarked.pdf").to_string_lossy().into_owned();
        let result = add_watermark_impl(
            app.clone(),
            source,
            watermarked.clone(),
            text,
            Some(0.15),
            Some(48.0),
        )
        .await;
        if !result.success {
            return err_result(&result.message);
        }
        source = watermarked;
    }
    use tauri_plugin_shell::ShellExt;
    let sidecar = match app.shell().sidecar("qpdf") {
        Ok(sidecar) => sidecar,
        Err(_) => return err_result("qpdf non disponibile: nessun PDF protetto è stato creato."),
    };
    let encrypted = work.join("encrypted.pdf");
    let result = sidecar
        .args([
            source.as_str(),
            &format!("@{}", arguments_path.display()),
            &encrypted.to_string_lossy(),
        ])
        .output()
        .await;
    match result {
        Ok(out) if out.status.success() => {
            if let Err(e) = crate::hardening::publish_new_file(&encrypted, Path::new(&output_path))
            {
                return err_result(&e);
            }
            DocToolResult {
                success: true,
                output_path: Some(output_path),
                message: "Restrizioni PDF applicate. Il file si apre senza password: queste restrizioni non garantiscono la riservatezza e possono essere ignorate da altri programmi.".into(),
                details: Some(serde_json::json!({ "owner_password": owner_pwd.as_str() })),
            }
        }
        Ok(out) => err_result(map_qpdf_stderr(&String::from_utf8_lossy(&out.stderr))),
        Err(_) => err_result("Impossibile eseguire qpdf. Nessun PDF protetto è stato creato."),
    }
}

async fn unsecure_pdf_impl(
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    password: Option<String>,
) -> DocToolResult {
    if let Err(e) =
        validate_input_path(&input_path).and_then(|_| validate_output_path(&output_path))
    {
        return err_result(&e);
    }
    if Path::new(&output_path).exists() {
        return err_result("Il file di destinazione esiste già. Scegli un nuovo nome.");
    }
    let work = match crate::hardening::DocumentWorkspace::new() {
        Ok(work) => work,
        Err(e) => return err_result(&e),
    };
    let password = zeroize::Zeroizing::new(password.unwrap_or_default());
    if password.len() > 1024 || password.chars().any(char::is_control) {
        return err_result("Password non valida.");
    }
    let password_path = work.join("password.txt");
    if crate::io::secure_write(&password_path, password.as_bytes()).is_err() {
        return err_result("Impossibile preparare la password.");
    }
    let decrypted = work.join("decrypted.pdf");
    use tauri_plugin_shell::ShellExt;
    let sidecar = match app.shell().sidecar("qpdf") {
        Ok(sidecar) => sidecar,
        Err(_) => return err_result("qpdf non disponibile."),
    };
    let result = sidecar
        .args([
            &format!("--password-file={}", password_path.display()),
            "--decrypt",
            input_path.as_str(),
            &decrypted.to_string_lossy(),
        ])
        .output()
        .await;
    match result {
        Ok(out) if out.status.success() => {
            match crate::hardening::publish_new_file(&decrypted, Path::new(&output_path)) {
                Ok(()) => ok_result(&output_path, "Restrizioni rimosse con successo."),
                Err(e) => err_result(&e),
            }
        }
        Ok(out) => err_result(map_qpdf_stderr(&String::from_utf8_lossy(&out.stderr))),
        Err(_) => err_result("Errore esecuzione qpdf."),
    }
}

// ─── Authenticated document IPC ────────────────────────────

fn finish_document_result(
    state: &crate::state::AppState,
    session: crate::state::DocumentSession,
    mut result: DocToolResult,
) -> DocToolResult {
    if let Err(error) = state.validate_document_session(session) {
        if let Some(details) = &mut result.details {
            crate::state::scrub_json(details);
        }
        return err_result(&error);
    }
    result
}

#[tauri::command]
pub async fn pdf_info(
    state: tauri::State<'_, crate::state::AppState>,
    app: tauri::AppHandle,
    path: String,
) -> Result<PdfInfo, String> {
    let session = state.document_session()?;
    let mut result = pdf_info_impl(app, path).await;
    if let Err(error) = state.validate_document_session(session) {
        use zeroize::Zeroize;
        if let Ok(value) = &mut result {
            value.title.zeroize();
            value.author.zeroize();
        }
        return Err(error);
    }
    result
}

#[tauri::command]
pub fn merge_pdfs(
    state: tauri::State<'_, crate::state::AppState>,
    input_paths: Vec<String>,
    output_path: String,
) -> DocToolResult {
    let session = match state.document_session() {
        Ok(session) => session,
        Err(error) => return err_result(&error),
    };
    let result = merge_pdfs_impl(input_paths, output_path);
    finish_document_result(&state, session, result)
}

#[tauri::command]
pub fn split_pdf(
    state: tauri::State<'_, crate::state::AppState>,
    input_path: String,
    output_dir: String,
) -> DocToolResult {
    let session = match state.document_session() {
        Ok(session) => session,
        Err(error) => return err_result(&error),
    };
    let result = split_pdf_impl(input_path, output_dir);
    finish_document_result(&state, session, result)
}

#[tauri::command]
pub async fn remove_pages(
    state: tauri::State<'_, crate::state::AppState>,
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    pages_to_remove: Vec<u32>,
) -> Result<DocToolResult, String> {
    let session = match state.document_session() {
        Ok(session) => session,
        Err(error) => return Ok(err_result(&error)),
    };
    let result = remove_pages_impl(app, input_path, output_path, pages_to_remove).await;
    Ok(finish_document_result(&state, session, result))
}

#[tauri::command]
pub async fn extract_pages(
    state: tauri::State<'_, crate::state::AppState>,
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    pages_to_extract: Vec<u32>,
) -> Result<DocToolResult, String> {
    let session = match state.document_session() {
        Ok(session) => session,
        Err(error) => return Ok(err_result(&error)),
    };
    let result = extract_pages_impl(app, input_path, output_path, pages_to_extract).await;
    Ok(finish_document_result(&state, session, result))
}

#[tauri::command]
pub async fn compress_pdf(
    state: tauri::State<'_, crate::state::AppState>,
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
) -> Result<DocToolResult, String> {
    let session = match state.document_session() {
        Ok(session) => session,
        Err(error) => return Ok(err_result(&error)),
    };
    let result = compress_pdf_impl(app, input_path, output_path).await;
    Ok(finish_document_result(&state, session, result))
}

#[tauri::command]
pub async fn add_watermark(
    state: tauri::State<'_, crate::state::AppState>,
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    text: String,
    opacity: Option<f64>,
    font_size: Option<f64>,
) -> Result<DocToolResult, String> {
    let session = match state.document_session() {
        Ok(session) => session,
        Err(error) => return Ok(err_result(&error)),
    };
    let result = add_watermark_impl(app, input_path, output_path, text, opacity, font_size).await;
    Ok(finish_document_result(&state, session, result))
}

#[tauri::command]
pub async fn rotate_pdf(
    state: tauri::State<'_, crate::state::AppState>,
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    rotation: i32,
    pages_to_rotate: Option<Vec<u32>>,
) -> Result<DocToolResult, String> {
    let session = match state.document_session() {
        Ok(session) => session,
        Err(error) => return Ok(err_result(&error)),
    };
    let result = rotate_pdf_impl(app, input_path, output_path, rotation, pages_to_rotate).await;
    Ok(finish_document_result(&state, session, result))
}

#[tauri::command]
pub fn pdf_to_text(
    state: tauri::State<'_, crate::state::AppState>,
    input_path: String,
) -> Result<String, String> {
    let session = state.document_session()?;
    let mut result = pdf_to_text_impl(input_path);
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
pub async fn images_to_pdf(
    state: tauri::State<'_, crate::state::AppState>,
    app: tauri::AppHandle,
    image_paths: Vec<String>,
    output_path: String,
) -> Result<DocToolResult, String> {
    let session = match state.document_session() {
        Ok(session) => session,
        Err(error) => return Ok(err_result(&error)),
    };
    let result = images_to_pdf_impl(app, image_paths, output_path).await;
    Ok(finish_document_result(&state, session, result))
}

#[tauri::command]
pub fn reorder_pages(
    state: tauri::State<'_, crate::state::AppState>,
    input_path: String,
    output_path: String,
    new_order: Vec<u32>,
) -> DocToolResult {
    let session = match state.document_session() {
        Ok(session) => session,
        Err(error) => return err_result(&error),
    };
    let result = reorder_pages_impl(input_path, output_path, new_order);
    finish_document_result(&state, session, result)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)] // Preserve the existing flat IPC payload; State/AppHandle are injected.
pub async fn add_page_numbers(
    state: tauri::State<'_, crate::state::AppState>,
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    position: Option<String>,
    format_str: Option<String>,
    start_from: Option<u32>,
    font_size: Option<f64>,
) -> Result<DocToolResult, String> {
    let session = match state.document_session() {
        Ok(session) => session,
        Err(error) => return Ok(err_result(&error)),
    };
    let result = add_page_numbers_impl(
        app,
        input_path,
        output_path,
        position,
        format_str,
        start_from,
        font_size,
    )
    .await;
    Ok(finish_document_result(&state, session, result))
}

#[tauri::command]
pub fn redact_pdf(
    state: tauri::State<'_, crate::state::AppState>,
    input_path: String,
    output_path: String,
    areas: Vec<RedactArea>,
) -> DocToolResult {
    let session = match state.document_session() {
        Ok(session) => session,
        Err(error) => return err_result(&error),
    };
    let result = redact_pdf_impl(input_path, output_path, areas);
    finish_document_result(&state, session, result)
}

#[tauri::command]
pub async fn secure_pdf(
    state: tauri::State<'_, crate::state::AppState>,
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    options: SecurePdfOptions,
) -> Result<DocToolResult, String> {
    let session = match state.document_session() {
        Ok(session) => session,
        Err(error) => return Ok(err_result(&error)),
    };
    let result = secure_pdf_impl(app, input_path, output_path, options).await;
    Ok(finish_document_result(&state, session, result))
}

#[tauri::command]
pub async fn unsecure_pdf(
    state: tauri::State<'_, crate::state::AppState>,
    app: tauri::AppHandle,
    input_path: String,
    output_path: String,
    password: Option<String>,
) -> Result<DocToolResult, String> {
    let session = match state.document_session() {
        Ok(session) => session,
        Err(error) => return Ok(err_result(&error)),
    };
    let result = unsecure_pdf_impl(app, input_path, output_path, password).await;
    Ok(finish_document_result(&state, session, result))
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn metadata_preserves_unicode_with_updated_pdf_parser() {
        let mut doc = Document::new();
        let mut info = lopdf::Dictionary::new();
        info.set("Title", lopdf::text_string("Fascicolo — società É"));
        let id = doc.add_object(info);
        doc.trailer.set("Info", Object::Reference(id));
        assert_eq!(
            extract_info_string(&doc, b"Title").as_deref(),
            Some("Fascicolo — società É")
        );
    }

    #[test]
    fn pdf_parser_rejects_excessive_nesting_without_aborting() {
        fn nested_pdf(depth: usize) -> Vec<u8> {
            let mut pdf = String::from("%PDF-1.7\n");
            let first = pdf.len();
            pdf.push_str(&format!(
                "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /X {}0{} >>\nendobj\n",
                "[".repeat(depth),
                "]".repeat(depth)
            ));
            let second = pdf.len();
            pdf.push_str("2 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n");
            let xref = pdf.len();
            pdf.push_str(&format!("xref\n0 3\n0000000000 65535 f \n{first:010} 00000 n \n{second:010} 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"));
            pdf.into_bytes()
        }
        assert!(Document::load_mem(&nested_pdf(2))
            .unwrap()
            .catalog()
            .is_ok());
        // RUSTSEC-2026-0187: older lopdf could abort on a small hostile PDF.
        // A tolerant parser may return a document with the bad catalog omitted.
        if let Ok(document) = Document::load_mem(&nested_pdf(12_000)) {
            assert!(document.catalog().is_err());
        }
    }

    #[test]
    fn redaction_fails_without_touching_existing_output() {
        let work = crate::hardening::DocumentWorkspace::new().unwrap();
        let output = work.join("output.pdf");
        std::fs::write(&output, b"existing document").unwrap();
        let result = redact_pdf_impl(
            "unused.pdf".into(),
            output.to_string_lossy().into_owned(),
            vec![],
        );
        assert!(!result.success);
        assert!(result.output_path.is_none());
        assert_eq!(std::fs::read(output).unwrap(), b"existing document");
    }

    #[test]
    fn response_file_rejects_multiline_password_injection() {
        for password in ["", "secret\n--decrypt", "secret\r--empty", "secret\0value"] {
            assert!(encryption_arguments(password, true, true, true).is_err());
        }
        let arguments = encryption_arguments("@private.txt", true, false, true).unwrap();
        assert!(arguments.contains("--user-password=\n--owner-password=@private.txt\n"));
        assert!(arguments.contains("--print=full\n"));
        assert_eq!(arguments.lines().count(), 8);
    }

    #[cfg(unix)]
    #[test]
    fn output_validation_rejects_symlink() {
        use std::os::unix::fs::symlink;
        let work = crate::hardening::DocumentWorkspace::new().unwrap();
        let target = work.join("target.pdf");
        std::fs::write(&target, b"untouched").unwrap();
        let link = work.join("link.pdf");
        symlink(&target, &link).unwrap();
        assert!(validate_output_path(&link.to_string_lossy()).is_err());
    }
}

#[cfg(test)]
mod workflow_tests {
    use super::*;
    use lopdf::dictionary;

    fn create_pdf(path: &Path, count: u32) {
        let mut doc = Document::with_version("1.7");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica"
        });
        let mut kids = Vec::new();
        for page in 1..=count {
            let stream = doc.add_object(lopdf::Stream::new(
                dictionary! {},
                format!("BT /F1 12 Tf 72 700 Td (CASE_SECRET_{page}) Tj ET").into_bytes(),
            ));
            let id = doc.add_object(dictionary! {
                "Type" => "Page", "Parent" => pages_id, "Contents" => stream
            });
            kids.push(Object::Reference(id));
        }
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => kids, "Count" => i64::from(count),
                "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
                "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
                "Rotate" => 90,
            }),
        );
        let root = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", root);
        doc.save(path).unwrap();
    }

    #[test]
    fn merge_preserves_inherited_page_resources() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("a.pdf");
        let second = dir.path().join("b.pdf");
        let output = dir.path().join("merged.pdf");
        create_pdf(&first, 2);
        create_pdf(&second, 1);
        let result = merge_pdfs_impl(
            vec![first.display().to_string(), second.display().to_string()],
            output.display().to_string(),
        );
        assert!(result.success, "{}", result.message);
        let merged = load_pdf(output).unwrap();
        assert_eq!(merged.get_pages().len(), 3);
        assert!(merged.extract_text(&[3]).unwrap().contains("CASE_SECRET_1"));
        let third = merged.get_dictionary(merged.get_pages()[&3]).unwrap();
        assert_eq!(third.get(b"Rotate").unwrap().as_i64().unwrap(), 90);
        assert!(third.has(b"MediaBox"));
    }

    #[test]
    fn split_prunes_content_of_removed_pages() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("source.pdf");
        let output = dir.path().join("split");
        create_pdf(&input, 3);
        let result = split_pdf_impl(input.display().to_string(), output.display().to_string());
        assert!(result.success, "{}", result.message);
        for page in 1..=3 {
            let part = load_pdf(output.join(format!("source_pag{page}.pdf"))).unwrap();
            assert_eq!(part.get_pages().len(), 1);
            let text = part.extract_text(&[1]).unwrap();
            assert!(text.contains(&format!("CASE_SECRET_{page}")));
            for object in part.objects.values() {
                if let Ok(stream) = object.as_stream() {
                    let bytes = stream
                        .decompressed_content()
                        .unwrap_or_else(|_| stream.content.clone());
                    for other in (1..=3).filter(|other| *other != page) {
                        assert!(!String::from_utf8_lossy(&bytes)
                            .contains(&format!("CASE_SECRET_{other}")));
                    }
                }
            }
        }
    }

    #[test]
    fn split_reports_failure_and_preserves_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("source.pdf");
        create_pdf(&input, 2);
        let conflict = dir.path().join("source_pag1.pdf");
        std::fs::write(&conflict, b"existing legal document").unwrap();
        let result = split_pdf_impl(
            input.display().to_string(),
            dir.path().display().to_string(),
        );
        assert!(!result.success);
        assert_eq!(std::fs::read(conflict).unwrap(), b"existing legal document");
        assert!(!dir.path().join("source_pag2.pdf").exists());
    }

    #[test]
    fn reorder_keeps_one_copy_of_resources_and_inherited_properties() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("source.pdf");
        let output = dir.path().join("reordered.pdf");
        create_pdf(&input, 60);
        let original_count = load_pdf(&input).unwrap().objects.len();
        let result = reorder_pages_impl(
            input.display().to_string(),
            output.display().to_string(),
            (1..=60).rev().collect(),
        );
        assert!(result.success, "{}", result.message);
        let reordered = load_pdf(output).unwrap();
        assert_eq!(reordered.get_pages().len(), 60);
        assert!(reordered.objects.len() <= original_count);
        assert!(reordered
            .extract_text(&[1])
            .unwrap()
            .contains("CASE_SECRET_60"));
        assert!(reordered
            .extract_text(&[60])
            .unwrap()
            .contains("CASE_SECRET_1"));
        let first = reordered.get_dictionary(reordered.get_pages()[&1]).unwrap();
        assert_eq!(first.get(b"Rotate").unwrap().as_i64().unwrap(), 90);
        assert!(first.has(b"MediaBox"));
    }

    #[test]
    fn reorder_rejects_duplicates_and_never_overwrites_input() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("source.pdf");
        create_pdf(&input, 2);
        let before = std::fs::read(&input).unwrap();
        let result = reorder_pages_impl(
            input.display().to_string(),
            dir.path().join("bad.pdf").display().to_string(),
            vec![1, 1],
        );
        assert!(!result.success);
        let result = reorder_pages_impl(
            input.display().to_string(),
            input.display().to_string(),
            vec![2, 1],
        );
        assert!(!result.success);
        assert_eq!(std::fs::read(input).unwrap(), before);
    }

    #[test]
    fn text_extraction_handles_single_line_pdf_operators() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("source.pdf");
        create_pdf(&input, 2);
        let result = pdf_to_text_impl(input.display().to_string()).unwrap();
        assert!(result.contains("CASE_SECRET_1"));
        assert!(result.contains("CASE_SECRET_2"));
    }

    #[test]
    fn input_validation_rejects_directory_and_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(validate_input_path(&dir.path().display().to_string()).is_err());
        let input = dir.path().join("oversized.pdf");
        let file = std::fs::File::create(&input).unwrap();
        file.set_len(PDF_MAX_INPUT_BYTES + 1).unwrap();
        assert!(validate_input_path(&input.display().to_string()).is_err());
        assert!(load_pdf(input).is_err());
    }
}

#[cfg(test)]
mod session_result_tests {
    use super::*;
    use crate::state::{AppState, SecureKey};
    use zeroize::Zeroizing;

    #[test]
    fn expired_document_session_discards_owner_password_and_keeps_published_output() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("published.pdf");
        std::fs::write(&output, b"completed user output").unwrap();
        let state = AppState::new(dir.path().into(), dir.path().into());
        *state.vault_dek.lock().unwrap() = Some(SecureKey::new(Zeroizing::new(vec![3; 32])));
        let session = state.document_session().unwrap();
        state.lock_vault();
        let result = finish_document_result(
            &state,
            session,
            DocToolResult {
                success: true,
                output_path: Some(output.display().to_string()),
                message: "PDF creato".into(),
                details: Some(serde_json::json!({"owner_password": "test-secret"})),
            },
        );
        assert!(!result.success);
        assert!(result.details.is_none());
        assert!(result.output_path.is_none());
        assert_eq!(std::fs::read(output).unwrap(), b"completed user output");
    }
}
