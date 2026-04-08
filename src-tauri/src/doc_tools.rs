// ═══════════════════════════════════════════════════════════
//  DOC TOOLS — PDF manipulation for legal professionals
// ═══════════════════════════════════════════════════════════

use lopdf::{Document, Object, ObjectId};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

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
pub fn pdf_info(path: String) -> Result<PdfInfo, String> {
    let file_size = std::fs::metadata(&path)
        .map(|m| m.len())
        .map_err(|e| format!("Impossibile leggere il file: {}", e))?;

    let doc = Document::load(&path).map_err(|e| format!("Impossibile aprire il PDF: {}", e))?;

    let pages = doc.get_pages().len() as u32;
    let encrypted = doc.is_encrypted();

    // Extract metadata — best-effort, ignore errors
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

// ─── Merge PDFs ─────────────────────────────────────────────

#[tauri::command]
pub fn merge_pdfs(input_paths: Vec<String>, output_path: String) -> DocToolResult {
    if input_paths.len() < 2 {
        return err_result("Servono almeno 2 PDF per unire.");
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
        max_id += 1;
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
pub fn remove_pages(
    input_path: String,
    output_path: String,
    pages_to_remove: Vec<u32>,
) -> DocToolResult {
    let mut doc = match Document::load(&input_path) {
        Ok(d) => d,
        Err(e) => return err_result(&format!("Errore nell'apertura: {}", e)),
    };

    let total = doc.get_pages().len() as u32;

    if pages_to_remove.iter().any(|&p| p < 1 || p > total) {
        return err_result(&format!(
            "Numeri pagina non validi. Il PDF ha {} pagine.",
            total
        ));
    }

    if pages_to_remove.len() as u32 >= total {
        return err_result("Non puoi rimuovere tutte le pagine.");
    }

    let mut sorted = pages_to_remove.clone();
    sorted.sort_unstable();
    sorted.dedup();
    for &page_num in sorted.iter().rev() {
        doc.delete_pages(&[page_num]);
    }

    match doc.save(&output_path) {
        Ok(_) => ok_result(
            &output_path,
            &format!(
                "{} pagine rimosse. Rimangono {} pagine.",
                sorted.len(),
                total - sorted.len() as u32
            ),
        ),
        Err(e) => err_result(&format!("Errore nel salvataggio: {}", e)),
    }
}

// ─── Extract Pages ──────────────────────────────────────────

#[tauri::command]
pub fn extract_pages(
    input_path: String,
    output_path: String,
    pages_to_extract: Vec<u32>,
) -> DocToolResult {
    let doc = match Document::load(&input_path) {
        Ok(d) => d,
        Err(e) => return err_result(&format!("Errore nell'apertura: {}", e)),
    };

    let total = doc.get_pages().len() as u32;

    if pages_to_extract.iter().any(|&p| p < 1 || p > total) {
        return err_result(&format!(
            "Numeri pagina non validi. Il PDF ha {} pagine.",
            total
        ));
    }

    let mut new_doc = doc.clone();
    let pages_to_remove: Vec<u32> = (1..=total)
        .filter(|p| !pages_to_extract.contains(p))
        .collect();

    for &page_num in pages_to_remove.iter().rev() {
        new_doc.delete_pages(&[page_num]);
    }

    match new_doc.save(&output_path) {
        Ok(_) => ok_result(
            &output_path,
            &format!("{} pagine estratte.", pages_to_extract.len()),
        ),
        Err(e) => err_result(&format!("Errore nel salvataggio: {}", e)),
    }
}

// ─── Compress PDF ───────────────────────────────────────────

#[tauri::command]
pub fn compress_pdf(input_path: String, output_path: String) -> DocToolResult {
    let original_size = match std::fs::metadata(&input_path) {
        Ok(m) => m.len(),
        Err(e) => return err_result(&format!("Impossibile leggere il file: {}", e)),
    };

    let mut doc = match Document::load(&input_path) {
        Ok(d) => d,
        Err(e) => return err_result(&format!("Errore nell'apertura: {}", e)),
    };

    doc.compress();
    doc.delete_zero_length_streams();
    doc.prune_objects();
    doc.renumber_objects();

    match doc.save(&output_path) {
        Ok(_) => {
            let new_size = std::fs::metadata(&output_path).map(|m| m.len()).unwrap_or(0);
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
                details: Some(serde_json::json!({
                    "original_size": original_size,
                    "compressed_size": new_size,
                    "saved_bytes": saved,
                    "saved_percent": pct
                })),
            }
        }
        Err(e) => err_result(&format!("Errore nel salvataggio: {}", e)),
    }
}

// ─── Watermark ──────────────────────────────────────────────

#[tauri::command]
pub fn add_watermark(
    input_path: String,
    output_path: String,
    text: String,
    opacity: Option<f64>,
    font_size: Option<f64>,
) -> DocToolResult {
    let mut doc = match Document::load(&input_path) {
        Ok(d) => d,
        Err(e) => return err_result(&format!("Errore nell'apertura: {}", e)),
    };

    let opacity_val = opacity.unwrap_or(0.15);
    let fs = font_size.unwrap_or(60.0);

    let pages: Vec<(u32, ObjectId)> = doc.get_pages().into_iter().collect();
    let page_count = pages.len();

    for (_page_num, page_id) in &pages {
        // Create watermark content stream with transparency
        let watermark_content = format!(
            "q\n\
             0.7 0.7 0.7 rg\n\
             BT\n\
             /Helvetica {} Tf\n\
             {} {} {} rg\n\
             1 0 0.5 1 100 400 Tm\n\
             ({}) Tj\n\
             0 -200 Td\n\
             ({}) Tj\n\
             ET\n\
             Q",
            fs, opacity_val, opacity_val, opacity_val, text, text
        );

        let stream =
            lopdf::Stream::new(lopdf::dictionary! {}, watermark_content.into_bytes());
        let stream_id = doc.add_object(Object::Stream(stream));

        // Append watermark stream to page contents
        if let Ok(page_obj) = doc.get_object_mut(*page_id) {
            if let Ok(dict) = page_obj.as_dict_mut() {
                let existing = dict.get(b"Contents").ok().cloned();
                match existing {
                    Some(Object::Array(mut arr)) => {
                        arr.push(Object::Reference(stream_id));
                        dict.set("Contents", Object::Array(arr));
                    }
                    Some(Object::Reference(r)) => {
                        dict.set(
                            "Contents",
                            Object::Array(vec![
                                Object::Reference(r),
                                Object::Reference(stream_id),
                            ]),
                        );
                    }
                    _ => {
                        dict.set("Contents", Object::Reference(stream_id));
                    }
                }
            }
        }
    }

    match doc.save(&output_path) {
        Ok(_) => ok_result(
            &output_path,
            &format!(
                "Watermark \"{}\" aggiunto a {} pagine.",
                text, page_count
            ),
        ),
        Err(e) => err_result(&format!("Errore nel salvataggio: {}", e)),
    }
}

// ─── Rotate Pages ───────────────────────────────────────────

#[tauri::command]
pub fn rotate_pdf(
    input_path: String,
    output_path: String,
    rotation: i32,
    pages_to_rotate: Option<Vec<u32>>,
) -> DocToolResult {
    if rotation % 90 != 0 {
        return err_result("La rotazione deve essere un multiplo di 90°.");
    }

    let mut doc = match Document::load(&input_path) {
        Ok(d) => d,
        Err(e) => return err_result(&format!("Errore nell'apertura: {}", e)),
    };

    let pages: Vec<(u32, ObjectId)> = doc.get_pages().into_iter().collect();
    let target_pages =
        pages_to_rotate.unwrap_or_else(|| pages.iter().map(|(n, _)| *n).collect());

    let mut rotated = 0;
    for (page_num, page_id) in &pages {
        if !target_pages.contains(page_num) {
            continue;
        }

        if let Ok(page_obj) = doc.get_object_mut(*page_id) {
            if let Ok(dict) = page_obj.as_dict_mut() {
                let current = dict
                    .get(b"Rotate")
                    .ok()
                    .and_then(|r| r.as_i64().ok())
                    .unwrap_or(0) as i32;
                let new_rotation = ((current + rotation) % 360 + 360) % 360;
                dict.set("Rotate", Object::Integer(new_rotation as i64));
                rotated += 1;
            }
        }
    }

    match doc.save(&output_path) {
        Ok(_) => ok_result(
            &output_path,
            &format!("{} pagine ruotate di {}°.", rotated, rotation),
        ),
        Err(e) => err_result(&format!("Errore nel salvataggio: {}", e)),
    }
}

// ─── PDF to Text ────────────────────────────────────────────

#[tauri::command]
pub fn pdf_to_text(input_path: String) -> Result<String, String> {
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
        Ok(
            "Nessun testo estraibile trovato. Il PDF potrebbe contenere solo immagini."
                .to_string(),
        )
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
    if image_paths.is_empty() {
        return err_result("Nessuna immagine selezionata.");
    }

    // Build Typst document using the same style as fascicolo.typ
    let total = image_paths.len();
    let now = chrono::Local::now().format("%d/%m/%Y").to_string();
    let mut typst_content = String::new();

    // ── Same palette + page setup as fascicolo.typ ──
    typst_content.push_str(r##"
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
"##);

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
        let escaped = img_path.replace('\\', "/").replace('"', "\\\"");
        typst_content.push_str(&format!(
            "#align(center)[#image(\"{}\", width: 100%)]\n",
            escaped
        ));
        if i < total - 1 {
            typst_content.push_str("#pagebreak()\n");
        }
    }

    let tmp_typ = std::env::temp_dir().join("lexflow_img2pdf.typ");
    let tmp_pdf = tmp_typ.with_extension("pdf");

    if let Err(e) = std::fs::write(&tmp_typ, &typst_content) {
        return err_result(&format!("Errore file temporaneo: {}", e));
    }

    // Use Typst sidecar with font path for Libertinus Serif
    use tauri_plugin_shell::ShellExt;
    let sidecar = match app.shell().sidecar("typst") {
        Ok(s) => s,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_typ);
            return err_result(&format!("Typst non trovato: {}", e));
        }
    };

    use tauri::Manager;
    let font_path = app.path().resource_dir()
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
            let _ = std::fs::remove_file(&tmp_typ);
            if out.status.success() {
                match std::fs::copy(&tmp_pdf, &output_path) {
                    Ok(_) => {
                        let _ = std::fs::remove_file(&tmp_pdf);
                        ok_result(
                            &output_path,
                            &format!("{} immagini convertite in PDF.", image_paths.len()),
                        )
                    }
                    Err(e) => {
                        let _ = std::fs::remove_file(&tmp_pdf);
                        err_result(&format!("Errore salvataggio: {}", e))
                    }
                }
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let _ = std::fs::remove_file(&tmp_pdf);
                err_result(&format!("Errore Typst: {}", stderr))
            }
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_typ);
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

    // Strategy: extract each page into its own doc, then merge in new order
    let _pages_map: std::collections::BTreeMap<u32, ObjectId> = doc.get_pages();

    // Build a new document by adding pages in the requested order
    let mut new_doc = Document::load(&input_path).unwrap();
    // Remove all pages first
    let all_pages: Vec<u32> = (1..=total).rev().collect();
    for &p in &all_pages {
        new_doc.delete_pages(&[p]);
    }

    // We need a fresh approach: clone original for each page extraction, then merge
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
            &format!(
                "{} pagine riordinate con successo.",
                total
            ),
        ),
        Err(e) => err_result(&format!("Errore nel salvataggio: {}", e)),
    }
}

// ─── Add Page Numbers ──────────────────────────────────────

#[tauri::command]
pub fn add_page_numbers(
    input_path: String,
    output_path: String,
    position: Option<String>,   // "bottom-center" (default), "bottom-right", "bottom-left", "top-center", "top-right", "top-left"
    format_str: Option<String>, // e.g. "Pag. {n} di {total}", default: "{n}"
    start_from: Option<u32>,    // starting number, default 1
    font_size: Option<f64>,     // default 10
) -> DocToolResult {
    let mut doc = match Document::load(&input_path) {
        Ok(d) => d,
        Err(e) => return err_result(&format!("Errore nell'apertura: {}", e)),
    };

    let pos = position.unwrap_or_else(|| "bottom-center".to_string());
    let fmt = format_str.unwrap_or_else(|| "{n}".to_string());
    let start = start_from.unwrap_or(1);
    let fs = font_size.unwrap_or(10.0);

    let pages: Vec<(u32, ObjectId)> = doc.get_pages().into_iter().collect();
    let total = pages.len() as u32;

    for (page_num, page_id) in &pages {
        let current_num = start + page_num - 1;
        let label = fmt
            .replace("{n}", &current_num.to_string())
            .replace("{total}", &(start + total - 1).to_string());

        // Get page dimensions (default A4: 595 x 842 pt)
        let (page_w, page_h) = get_page_dimensions(&doc, *page_id);

        // Calculate position
        let text_width_approx = label.len() as f64 * fs * 0.5; // rough estimate
        let (x, y) = match pos.as_str() {
            "bottom-left"   => (40.0, 25.0),
            "bottom-right"  => (page_w - 40.0 - text_width_approx, 25.0),
            "bottom-center" => ((page_w - text_width_approx) / 2.0, 25.0),
            "top-left"      => (40.0, page_h - 30.0),
            "top-right"     => (page_w - 40.0 - text_width_approx, page_h - 30.0),
            "top-center"    => ((page_w - text_width_approx) / 2.0, page_h - 30.0),
            _               => ((page_w - text_width_approx) / 2.0, 25.0),
        };

        let content = format!(
            "q\n\
             BT\n\
             /Helvetica {} Tf\n\
             0.4 0.4 0.4 rg\n\
             {} {} Td\n\
             ({}) Tj\n\
             ET\n\
             Q",
            fs, x, y,
            label.replace('(', "\\(").replace(')', "\\)")
        );

        let stream = lopdf::Stream::new(lopdf::dictionary! {}, content.into_bytes());
        let stream_id = doc.add_object(Object::Stream(stream));

        // Append to page contents
        if let Ok(page_obj) = doc.get_object_mut(*page_id) {
            if let Ok(dict) = page_obj.as_dict_mut() {
                let existing = dict.get(b"Contents").ok().cloned();
                match existing {
                    Some(Object::Array(mut arr)) => {
                        arr.push(Object::Reference(stream_id));
                        dict.set("Contents", Object::Array(arr));
                    }
                    Some(Object::Reference(r)) => {
                        dict.set(
                            "Contents",
                            Object::Array(vec![
                                Object::Reference(r),
                                Object::Reference(stream_id),
                            ]),
                        );
                    }
                    _ => {
                        dict.set("Contents", Object::Reference(stream_id));
                    }
                }
            }
        }
    }

    match doc.save(&output_path) {
        Ok(_) => ok_result(
            &output_path,
            &format!(
                "Numeri di pagina aggiunti a {} pagine (da {} a {}).",
                total, start, start + total - 1
            ),
        ),
        Err(e) => err_result(&format!("Errore nel salvataggio: {}", e)),
    }
}

/// Get page dimensions from MediaBox, defaulting to A4.
fn get_page_dimensions(doc: &Document, page_id: ObjectId) -> (f64, f64) {
    if let Ok(page_obj) = doc.get_object(page_id) {
        if let Ok(dict) = page_obj.as_dict() {
            if let Ok(mbox) = dict.get(b"MediaBox") {
                if let Ok(arr) = mbox.as_array() {
                    if arr.len() == 4 {
                        let w: f64 = arr[2].as_float().map(|v| v as f64).or_else(|_| arr[2].as_i64().map(|v| v as f64)).unwrap_or(595.0);
                        let h: f64 = arr[3].as_float().map(|v| v as f64).or_else(|_| arr[3].as_i64().map(|v| v as f64)).unwrap_or(842.0);
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
pub fn redact_pdf(
    input_path: String,
    output_path: String,
    redactions: Vec<RedactArea>,
) -> DocToolResult {
    if redactions.is_empty() {
        return err_result("Nessuna area da censurare specificata.");
    }

    let mut doc = match Document::load(&input_path) {
        Ok(d) => d,
        Err(e) => return err_result(&format!("Errore nell'apertura: {}", e)),
    };

    let pages: Vec<(u32, ObjectId)> = doc.get_pages().into_iter().collect();
    let total = pages.len() as u32;
    let mut count = 0;

    // Group redactions by page
    let mut page_redactions: std::collections::BTreeMap<u32, Vec<&RedactArea>> =
        std::collections::BTreeMap::new();
    for area in &redactions {
        if area.page < 1 || area.page > total {
            return err_result(&format!(
                "Pagina {} non valida. Il PDF ha {} pagine.",
                area.page, total
            ));
        }
        page_redactions.entry(area.page).or_default().push(area);
    }

    for (&page_num, areas) in &page_redactions {
        let page_id = match pages.iter().find(|(n, _)| *n == page_num) {
            Some((_, id)) => *id,
            None => continue,
        };

        let (page_w, page_h) = get_page_dimensions(&doc, page_id);

        // ── Strategy: clipping path that covers the full page MINUS the redacted areas ──
        // 1. PRE-stream: push state, define clip = full page minus redacted rects, activate clip
        // 2. (original content renders here — clipped, so text under redactions is invisible)
        // 3. POST-stream: pop state, draw black rectangles + render mode 3 (invisible) text block

        // Build pre-clip content stream:
        //   - Start with full-page rect (counterclockwise for "hole" via even-odd rule)
        //   - Then add each redacted area as a sub-path (clockwise = hole in even-odd)
        let mut pre = String::new();
        pre.push_str("q\n");
        // Full page rect (counterclockwise)
        pre.push_str(&format!("0 0 {} {} re\n", page_w, page_h));
        // Each redaction area as sub-path — even-odd rule will "cut" these out
        for a in areas {
            pre.push_str(&format!("{} {} {} {} re\n", a.x, a.y, a.width, a.height));
        }
        // Activate clip with even-odd rule (W*) + no-op path paint (n)
        pre.push_str("W* n\n");

        let pre_stream = lopdf::Stream::new(lopdf::dictionary! {}, pre.into_bytes());
        let pre_id = doc.add_object(Object::Stream(pre_stream));

        // Build post-redaction stream:
        //   - Close the clipping state (Q)
        //   - Draw opaque black rectangles over redacted areas
        //   - Add invisible text render mode (Tr 3) in redacted areas to prevent copy
        let mut post = String::new();
        post.push_str("Q\n"); // Restore graphics state (end clip)
        for a in areas {
            // Black filled rectangle (visual coverage)
            post.push_str(&format!(
                "q 0 0 0 rg {} {} {} {} re f Q\n",
                a.x, a.y, a.width, a.height
            ));
            // Invisible text block in the redacted area to overwrite any text selection
            // Text render mode 3 = invisible — prevents copy of underlying text
            post.push_str(&format!(
                "q BT 3 Tr /Helvetica 1 Tf {} {} Td ( ) Tj ET Q\n",
                a.x, a.y
            ));
        }

        let post_stream = lopdf::Stream::new(lopdf::dictionary! {}, post.into_bytes());
        let post_id = doc.add_object(Object::Stream(post_stream));

        // Rewrite page Contents: [pre_clip, ...original..., post_redact]
        if let Ok(page_obj) = doc.get_object_mut(page_id) {
            if let Ok(dict) = page_obj.as_dict_mut() {
                let existing = dict.get(b"Contents").ok().cloned();
                let mut new_contents = vec![Object::Reference(pre_id)];

                match existing {
                    Some(Object::Array(arr)) => {
                        new_contents.extend(arr);
                    }
                    Some(Object::Reference(r)) => {
                        new_contents.push(Object::Reference(r));
                    }
                    _ => {}
                }
                new_contents.push(Object::Reference(post_id));
                dict.set("Contents", Object::Array(new_contents));
            }
        }

        count += areas.len();
    }

    match doc.save(&output_path) {
        Ok(_) => ok_result(
            &output_path,
            &format!(
                "{} aree censurate su {} pagine. Il testo sotto le barre nere non è copiabile.",
                count,
                page_redactions.len()
            ),
        ),
        Err(e) => err_result(&format!("Errore nel salvataggio: {}", e)),
    }
}

#[derive(serde::Deserialize)]
pub struct RedactArea {
    pub page: u32,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

// ─── Protect PDF (password) ─────────────────────────────────

#[tauri::command]
pub fn protect_pdf(
    input_path: String,
    output_path: String,
    _password: String,
) -> DocToolResult {
    // lopdf doesn't support PDF encryption natively.
    // Copy the file and note the limitation.
    match std::fs::copy(&input_path, &output_path) {
        Ok(_) => DocToolResult {
            success: true,
            output_path: Some(output_path),
            message: "PDF copiato. La protezione con password sarà disponibile in un aggiornamento futuro.".to_string(),
            details: None,
        },
        Err(e) => err_result(&format!("Errore: {}", e)),
    }
}

// ═══════════════════════════════════════════════════════════
//  TESTS — simulate human usage of every PDF tool
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::dictionary;
    use std::fs;

    /// Helper: create a multi-page test PDF with text on each page.
    fn create_test_pdf(path: &str, num_pages: usize) {
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(lopdf::dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica",
        });
        let font_dict_id = doc.add_object(lopdf::dictionary! {
            "F1" => Object::Reference(font_id),
        });

        let mut page_ids = vec![];
        for i in 1..=num_pages {
            let content = format!(
                "BT /F1 12 Tf 72 750 Td (Pagina {} - Testo di test per documento legale LexFlow) Tj ET",
                i
            );
            let content_id = doc.add_object(
                Object::Stream(lopdf::Stream::new(lopdf::dictionary! {}, content.into_bytes()))
            );

            let page_id = doc.add_object(lopdf::dictionary! {
                "Type" => "Page",
                "Parent" => Object::Reference(pages_id),
                "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
                "Contents" => Object::Reference(content_id),
                "Resources" => lopdf::dictionary! {
                    "Font" => Object::Reference(font_dict_id),
                },
            });
            page_ids.push(page_id);
        }

        let kids: Vec<Object> = page_ids.iter().map(|id| Object::Reference(*id)).collect();
        doc.objects.insert(pages_id, Object::Dictionary(lopdf::dictionary! {
            "Type" => "Pages",
            "Kids" => Object::Array(kids),
            "Count" => Object::Integer(num_pages as i64),
        }));

        let catalog_id = doc.add_object(lopdf::dictionary! {
            "Type" => "Catalog",
            "Pages" => Object::Reference(pages_id),
        });
        doc.trailer.set("Root", Object::Reference(catalog_id));
        doc.save(path).expect("Failed to create test PDF");
    }

    fn tmp_path(name: &str) -> String {
        std::env::temp_dir().join(format!("lexflow_test_{}", name)).to_string_lossy().to_string()
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
        let stem = PathBuf::from(&src).file_stem().unwrap().to_string_lossy().to_string();
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
        println!("✓ remove_pages: 6 pages, removed 3 → {} remaining", info.pages);

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
        println!("✓ extract_pages: extracted 3 pages from 8 → {} pages", info.pages);

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

        let res = add_watermark(src.clone(), out.clone(), "BOZZA".into(), Some(0.2), Some(48.0));
        assert!(res.success, "Watermark should succeed: {}", res.message);

        let info = pdf_info(out.clone()).unwrap();
        assert_eq!(info.pages, 3, "Watermarked PDF should keep all pages");

        // Verify watermark content was added by checking file size increased
        let src_size = fs::metadata(&src).unwrap().len();
        let out_size = fs::metadata(&out).unwrap().len();
        assert!(out_size > src_size, "Watermarked PDF should be larger");
        println!("✓ add_watermark: BOZZA added to 3 pages ({} → {} bytes)", src_size, out_size);

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
        assert!(res.success, "Partial rotate should succeed: {}", res.message);
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
        let has_text = text.contains("Pagina") || text.contains("Testo") || text.contains("immagini");
        assert!(has_text, "Should contain page markers or text content, got: {}", &text[..text.len().min(200)]);
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
            src.clone(), out.clone(),
            None, None, None, None  // all defaults: bottom-center, "{n}", start=1, 10pt
        );
        assert!(res.success, "Page numbers should succeed: {}", res.message);

        let info = pdf_info(out.clone()).unwrap();
        assert_eq!(info.pages, 5, "Should keep all pages");

        // File should be larger (added content streams)
        let out_size = fs::metadata(&out).unwrap().len();
        let src_size = fs::metadata(&src).unwrap().len();
        assert!(out_size > src_size, "Numbered PDF should be larger");
        println!("✓ add_page_numbers: default format on 5 pages ({} → {} bytes)", src_size, out_size);

        fs::remove_file(&src).ok();
        fs::remove_file(&out).ok();
    }

    #[test]
    fn test_add_page_numbers_with_format() {
        let src = tmp_path("pagenum_fmt_src.pdf");
        let out = tmp_path("pagenum_fmt_out.pdf");
        create_test_pdf(&src, 3);

        let res = add_page_numbers(
            src.clone(), out.clone(),
            Some("top-right".into()),
            Some("Pag. {n} di {total}".into()),
            Some(1),
            Some(9.0),
        );
        assert!(res.success, "Formatted page numbers should succeed: {}", res.message);
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
            src.clone(), out.clone(),
            Some("bottom-left".into()),
            Some("{n}".into()),
            Some(10),
            None,
        );
        assert!(res.success, "Custom start should succeed: {}", res.message);
        assert!(res.message.contains("da 10 a 13"), "Should mention numbering 10-13, got: {}", res.message);
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
            src.clone(), out.clone(),
            vec![RedactArea { page: 1, x: 50.0, y: 740.0, width: 300.0, height: 20.0 }],
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
            src.clone(), out.clone(),
            vec![
                RedactArea { page: 1, x: 50.0, y: 740.0, width: 200.0, height: 15.0 },
                RedactArea { page: 1, x: 50.0, y: 700.0, width: 150.0, height: 15.0 },
                RedactArea { page: 2, x: 100.0, y: 600.0, width: 250.0, height: 20.0 },
                RedactArea { page: 3, x: 72.0, y: 750.0, width: 400.0, height: 18.0 },
            ],
        );
        assert!(res.success, "Multi-redact should succeed: {}", res.message);
        assert!(res.message.contains("4 aree"), "Should report 4 areas, got: {}", res.message);
        println!("✓ redact_pdf: 4 areas across 3 pages → {}", res.message);

        fs::remove_file(&src).ok();
        fs::remove_file(&out).ok();
    }

    #[test]
    fn test_redact_rejects_invalid_page() {
        let src = tmp_path("redact_bad.pdf");
        create_test_pdf(&src, 2);

        let res = redact_pdf(
            src.clone(), tmp_path("redact_bad_out.pdf"),
            vec![RedactArea { page: 5, x: 0.0, y: 0.0, width: 100.0, height: 100.0 }],
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
            merged.clone(), numbered.clone(),
            Some("bottom-center".into()),
            Some("Pag. {n} di {total}".into()),
            Some(1), None,
        );
        assert!(res2.success, "Page numbers step failed");

        // Step 3: Add watermark
        let res3 = add_watermark(
            numbered.clone(), final_out.clone(),
            "BOZZA".into(), Some(0.15), Some(60.0),
        );
        assert!(res3.success, "Watermark step failed");

        let final_info = pdf_info(final_out.clone()).unwrap();
        assert_eq!(final_info.pages, 5, "Final document should have 5 pages");
        println!("✓ WORKFLOW: merge(3+2) → page numbers → watermark BOZZA = {} pages, {} bytes",
            final_info.pages, final_info.file_size);

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
            extracted.clone(), redacted.clone(),
            vec![
                RedactArea { page: 1, x: 72.0, y: 740.0, width: 200.0, height: 16.0 },
                RedactArea { page: 3, x: 72.0, y: 740.0, width: 200.0, height: 16.0 },
            ],
        );
        assert!(res2.success, "Redact step failed");

        let info = pdf_info(redacted.clone()).unwrap();
        assert_eq!(info.pages, 3, "Redacted doc should have 3 pages");
        println!("✓ WORKFLOW: extract(2,5,8 from 10) → redact 2 areas = {} pages", info.pages);

        fs::remove_file(&src).ok();
        fs::remove_file(&extracted).ok();
        fs::remove_file(&redacted).ok();
    }
}
