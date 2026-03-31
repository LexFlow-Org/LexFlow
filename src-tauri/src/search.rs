// ═══════════════════════════════════════════════════════════
//  SEARCH — Encrypted trigram index with BM25 ranking
// ═══════════════════════════════════════════════════════════
//
//  - Trigram-based fuzzy search (typo-tolerant, prefix-native)
//  - BM25 ranking for relevance ordering
//  - Generation counter for crash-consistency
//  - Encrypted with DEK (AES-256-GCM-SIV via encrypt_record)
//  - Stored as search_index.enc, no fsync (rebuilt on corruption)

use crate::state::{get_vault_dek, get_vault_version, AppState};
use crate::vault_engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use tauri::State;

const SEARCH_INDEX_FILE: &str = "search_index.enc";

// Italian legal stop words — excluded from indexing
const STOP_WORDS: &[&str] = &[
    "il", "lo", "la", "i", "gli", "le", "di", "del", "della", "dei", "delle", "dello", "a", "al",
    "alla", "ai", "alle", "allo", "da", "dal", "dalla", "dai", "dalle", "in", "nel", "nella",
    "nei", "nelle", "con", "su", "sul", "sulla", "sui", "sulle", "per", "tra", "fra", "e", "ed",
    "o", "ma", "che", "chi", "cui", "non", "un", "una", "uno", "sono", "è", "ha", "hanno",
    "essere", "avere", "fare", "questo", "quella", "come", "quando", "anche", "più", "già",
    "ancora", "solo", "tutto", "tutti",
    // Legal-specific high-frequency terms (excluded to reduce noise)
    "art", "articolo", "comma", "legge", "decreto", "norma", "sensi",
];

// ─── Types ──────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub(crate) struct SearchIndex {
    /// trigram → set of record IDs containing this trigram
    trigrams: HashMap<String, HashSet<String>>,
    /// term → list of (record_id, term_frequency)
    terms: HashMap<String, Vec<(String, u32)>>,
    /// record_id → generation counter (for consistency check)
    indexed_gens: HashMap<String, u64>,
    /// metadata for BM25
    total_docs: u32,
    avg_doc_len: f64,
}

// ─── Tokenization ───────────────────────────────────────────

pub(crate) fn tokenize(text: &str) -> Vec<String> {
    let stop_set: HashSet<&str> = STOP_WORDS.iter().copied().collect();
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric() && c != '\'')
        .filter(|w| w.len() >= 3 && !stop_set.contains(w))
        .map(|w| w.to_string())
        .collect()
}

pub(crate) fn trigrams(s: &str) -> Vec<String> {
    let bytes: Vec<char> = s.chars().collect();
    if bytes.len() < 3 {
        return vec![s.to_string()]; // short words: use as-is
    }
    bytes
        .windows(3)
        .map(|w| w.iter().collect::<String>())
        .collect()
}

fn extract_searchable_text(record: &Value, field: &str) -> String {
    let mut parts = Vec::new();
    match field {
        "practices" => {
            for f in &[
                "client",
                "counterparty",
                "object",
                "description",
                "court",
                "code",
            ] {
                if let Some(v) = record.get(f).and_then(|v| v.as_str()) {
                    parts.push(v.to_string());
                }
            }
            // Also index diary entries
            if let Some(diary) = record.get("diary").and_then(|d| d.as_array()) {
                for entry in diary {
                    if let Some(text) = entry.get("text").and_then(|t| t.as_str()) {
                        parts.push(text.to_string());
                    }
                }
            }
        }
        "agenda" => {
            for f in &["title", "text", "notes"] {
                if let Some(v) = record.get(f).and_then(|v| v.as_str()) {
                    parts.push(v.to_string());
                }
            }
        }
        "contacts" => {
            for f in &[
                "name",
                "email",
                "pec",
                "phone",
                "fiscalCode",
                "vatNumber",
                "notes",
            ] {
                if let Some(v) = record.get(f).and_then(|v| v.as_str()) {
                    parts.push(v.to_string());
                }
            }
        }
        _ => {
            // Generic: index all string values
            if let Some(obj) = record.as_object() {
                for v in obj.values() {
                    if let Some(s) = v.as_str() {
                        parts.push(s.to_string());
                    }
                }
            }
        }
    }
    parts.join(" ")
}

// ─── Index building ─────────────────────────────────────────

impl SearchIndex {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn add_document(&mut self, record_id: &str, text: &str, gen: u64) {
        let tokens = tokenize(text);
        let doc_len = tokens.len() as u32;

        // Update average doc length
        self.total_docs += 1;
        self.avg_doc_len = ((self.avg_doc_len * (self.total_docs - 1) as f64) + doc_len as f64)
            / self.total_docs as f64;

        // Count term frequencies
        let mut tf_map: HashMap<String, u32> = HashMap::new();
        for token in &tokens {
            *tf_map.entry(token.clone()).or_insert(0) += 1;
        }

        // Update term index
        for (term, tf) in &tf_map {
            self.terms
                .entry(term.clone())
                .or_default()
                .push((record_id.to_string(), *tf));
        }

        // Update trigram index
        let unique_tokens: HashSet<&String> = tokens.iter().collect();
        for token in unique_tokens {
            for tri in trigrams(token) {
                self.trigrams
                    .entry(tri)
                    .or_default()
                    .insert(record_id.to_string());
            }
        }

        // Track generation
        self.indexed_gens.insert(record_id.to_string(), gen);
    }

    fn remove_document(&mut self, record_id: &str) {
        // Remove from term index
        for entries in self.terms.values_mut() {
            entries.retain(|(id, _)| id != record_id);
        }
        // Remove empty terms
        self.terms.retain(|_, v| !v.is_empty());

        // Remove from trigram index
        for ids in self.trigrams.values_mut() {
            ids.remove(record_id);
        }
        self.trigrams.retain(|_, v| !v.is_empty());

        // Remove generation
        self.indexed_gens.remove(record_id);

        if self.total_docs > 0 {
            self.total_docs -= 1;
        }
    }

    /// BM25 score for a query term against a document
    fn bm25_score(&self, term: &str, record_id: &str) -> f64 {
        let k1: f64 = 1.2;
        let b: f64 = 0.75;

        let entries = match self.terms.get(term) {
            Some(e) => e,
            None => return 0.0,
        };

        let tf = entries
            .iter()
            .find(|(id, _)| id == record_id)
            .map(|(_, f)| *f as f64)
            .unwrap_or(0.0);

        if tf == 0.0 {
            return 0.0;
        }

        let df = entries.len() as f64;
        let n = self.total_docs.max(1) as f64;
        let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();

        // Estimate doc_len from total terms for this doc
        let doc_len = self
            .terms
            .values()
            .flat_map(|e| e.iter())
            .filter(|(id, _)| id == record_id)
            .map(|(_, f)| *f as f64)
            .sum::<f64>();

        let avg_dl = self.avg_doc_len.max(1.0);
        let tf_norm = (tf * (k1 + 1.0)) / (tf + k1 * (1.0 - b + b * doc_len / avg_dl));

        idf * tf_norm
    }

    /// Search with trigram fuzzy matching + BM25 ranking
    pub(crate) fn search(&self, query: &str, limit: usize) -> Vec<(String, f64)> {
        let query_lower = query.to_lowercase();
        let query_tokens = tokenize(&query_lower);

        if query_tokens.is_empty() {
            // Fallback: use query as-is for short queries
            let query_tris = trigrams(&query_lower);
            return self.search_by_trigrams(&query_tris, &query_lower, limit);
        }

        // Collect candidate IDs from trigram intersection
        let mut all_scores: HashMap<String, f64> = HashMap::new();

        for token in &query_tokens {
            let query_tris = trigrams(token);
            // Find docs matching all trigrams of this token
            let mut candidates: Option<HashSet<String>> = None;
            for tri in &query_tris {
                if let Some(docs) = self.trigrams.get(tri) {
                    let doc_strings: HashSet<String> = docs.iter().cloned().collect();
                    candidates = Some(match candidates {
                        Some(c) => c.intersection(&doc_strings).cloned().collect(),
                        None => doc_strings,
                    });
                }
            }

            // BM25 score each candidate
            if let Some(cands) = candidates {
                for id in cands {
                    let score = self.bm25_score(token, &id);
                    *all_scores.entry(id).or_insert(0.0) += score;
                }
            }
        }

        let mut results: Vec<(String, f64)> = all_scores.into_iter().collect();
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(limit);
        results
    }

    fn search_by_trigrams(
        &self,
        query_tris: &[String],
        _query: &str,
        limit: usize,
    ) -> Vec<(String, f64)> {
        let mut candidates: Option<HashSet<String>> = None;
        for tri in query_tris {
            if let Some(docs) = self.trigrams.get(tri) {
                let doc_strings: HashSet<String> = docs.iter().cloned().collect();
                candidates = Some(match candidates {
                    Some(c) => c.intersection(&doc_strings).cloned().collect(),
                    None => doc_strings,
                });
            }
        }
        let mut results: Vec<(String, f64)> = candidates
            .unwrap_or_default()
            .into_iter()
            .map(|id| {
                let score = query_tris.len() as f64; // simple trigram count score
                (id, score)
            })
            .collect();
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(limit);
        results
    }
}

// ─── Persistence (encrypted with DEK) ──────────────────────

fn load_search_index(data_dir: &std::path::Path, dek: &[u8]) -> SearchIndex {
    let path = data_dir.join(SEARCH_INDEX_FILE);
    if !path.exists() {
        return SearchIndex::new();
    }
    let raw = match crate::io::safe_bounded_read(&path, 100 * 1024 * 1024) {
        Ok(r) => r,
        Err(_) => return SearchIndex::new(),
    };
    // Decrypt using vault_engine record encryption (includes zstd decompression)
    let block: vault_engine::EncryptedBlock = match serde_json::from_slice(&raw) {
        Ok(b) => b,
        Err(_) => return SearchIndex::new(), // corrupted → rebuild
    };
    let plaintext = match vault_engine::decrypt_record(dek, &block) {
        Ok(p) => p,
        Err(_) => return SearchIndex::new(), // corrupted → rebuild
    };
    serde_json::from_slice(&plaintext).unwrap_or_default()
}

fn save_search_index(
    data_dir: &std::path::Path,
    dek: &[u8],
    index: &SearchIndex,
) -> Result<(), String> {
    let plaintext =
        serde_json::to_vec(index).map_err(|e| format!("Search index serialize: {}", e))?;
    let block = vault_engine::encrypt_record(dek, &plaintext)?;
    let encrypted =
        serde_json::to_vec(&block).map_err(|e| format!("Search block serialize: {}", e))?;
    // No fsync — search index is a derived cache, rebuilt on corruption
    let path = data_dir.join(SEARCH_INDEX_FILE);
    fs::write(&path, &encrypted).map_err(|e| format!("Search index write: {}", e))
}

// ─── Consistency check (generation counter) ─────────────────

fn ensure_index_consistent(
    data_dir: &std::path::Path,
    dek: &[u8],
    vault_index: &[vault_engine::IndexEntry],
    vault: &vault_engine::VaultData,
) -> SearchIndex {
    let mut search_idx = load_search_index(data_dir, dek);

    // Find stale records (gen mismatch or missing from index)
    let mut stale_ids: Vec<String> = Vec::new();
    for entry in vault_index {
        let vault_gen = vault
            .records
            .get(&entry.id)
            .map(|r| r.current as u64)
            .unwrap_or(0);
        let indexed_gen = search_idx.indexed_gens.get(&entry.id).copied().unwrap_or(0);
        if indexed_gen < vault_gen {
            stale_ids.push(entry.id.clone());
        }
    }

    // Find phantom records (in search index but not in vault)
    let vault_ids: HashSet<&str> = vault_index.iter().map(|e| e.id.as_str()).collect();
    let phantom_ids: Vec<String> = search_idx
        .indexed_gens
        .keys()
        .filter(|id| !vault_ids.contains(id.as_str()))
        .cloned()
        .collect();

    // Remove phantoms
    for id in &phantom_ids {
        search_idx.remove_document(id);
    }

    // Re-index stale records
    if !stale_ids.is_empty() {
        eprintln!(
            "[LexFlow] Search index: re-indexing {} stale records",
            stale_ids.len()
        );
        for id in &stale_ids {
            // Remove old entry first
            search_idx.remove_document(id);

            // Find field from vault index
            let field = vault_index
                .iter()
                .find(|e| e.id == *id)
                .map(|e| e.field.as_str())
                .unwrap_or("practices");

            // Decrypt record
            if let Some(record_entry) = vault.records.get(id) {
                if let Ok(plaintext) = vault_engine::read_current_version(record_entry, dek) {
                    if let Ok(record) = serde_json::from_slice::<Value>(&plaintext) {
                        let text = extract_searchable_text(&record, field);
                        let gen = record_entry.current as u64;
                        search_idx.add_document(id, &text, gen);
                    }
                }
            }
        }
        // Save updated index
        let _ = save_search_index(data_dir, dek, &search_idx);
    }

    if !phantom_ids.is_empty() {
        let _ = save_search_index(data_dir, dek, &search_idx);
    }

    search_idx
}

// ─── Tauri commands ─────────────────────────────────────────

/// Full-text search across all vault records.
/// Returns ranked results with record ID, field, title, and score.
#[tauri::command]
pub(crate) fn search_vault(
    state: State<AppState>,
    query: String,
    limit: Option<usize>,
) -> Result<Value, String> {
    let version = get_vault_version(&state);
    if version < 4 {
        return Err("Search requires vault v4+ format".into());
    }

    let dek = get_vault_dek(&state)?;
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    let vault_path = dir.join(crate::constants::VAULT_FILE);
    if !vault_path.exists() {
        return Ok(json!([]));
    }
    let raw =
        crate::io::safe_bounded_read(&vault_path, 500 * 1024 * 1024).map_err(|e| e.to_string())?;
    let vault = vault_engine::deserialize_vault(&raw)?;
    let vault_index = vault_engine::decrypt_index(&dek, &vault.index)?;

    // Ensure consistency and get search index
    let search_idx = ensure_index_consistent(&dir, &dek, &vault_index, &vault);

    let max_results = limit.unwrap_or(50);
    let results = search_idx.search(&query, max_results);

    // Enrich results with metadata from vault index
    let enriched: Vec<Value> = results
        .iter()
        .filter_map(|(id, score)| {
            let meta = vault_index.iter().find(|e| e.id == *id)?;
            Some(json!({
                "id": id,
                "field": meta.field,
                "title": meta.title,
                "tags": meta.tags,
                "score": score,
            }))
        })
        .collect();

    Ok(json!(enriched))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Tokenization ────────────────────────────────────────

    #[test]
    fn test_tokenize_basic() {
        let tokens = tokenize("avvocato difensore civile");
        assert!(tokens.contains(&"avvocato".to_string()));
        assert!(tokens.contains(&"difensore".to_string()));
        assert!(tokens.contains(&"civile".to_string()));
    }

    #[test]
    fn test_tokenize_removes_stop_words() {
        let tokens = tokenize("il fascicolo della causa");
        assert!(!tokens.contains(&"il".to_string()));
        assert!(!tokens.contains(&"della".to_string()));
        assert!(tokens.contains(&"fascicolo".to_string()));
        assert!(tokens.contains(&"causa".to_string()));
    }

    #[test]
    fn test_tokenize_filters_short_words() {
        let tokens = tokenize("io la di un me");
        assert!(
            tokens.is_empty(),
            "All words < 3 chars or stop words should be filtered"
        );
    }

    #[test]
    fn test_tokenize_case_insensitive() {
        let tokens = tokenize("TRIBUNALE Avvocato MiLaNo");
        assert!(tokens.contains(&"tribunale".to_string()));
        assert!(tokens.contains(&"avvocato".to_string()));
        assert!(tokens.contains(&"milano".to_string()));
    }

    #[test]
    fn test_tokenize_special_chars() {
        let tokens = tokenize("art. 1218 c.c. — responsabilità");
        assert!(
            tokens.contains(&"1218".to_string()) || tokens.contains(&"responsabilità".to_string())
        );
    }

    #[test]
    fn test_tokenize_empty() {
        assert!(tokenize("").is_empty());
    }

    #[test]
    fn test_tokenize_legal_stop_words() {
        let tokens = tokenize("articolo comma legge decreto norma");
        // All are legal stop words
        assert!(tokens.is_empty());
    }

    // ─── Trigrams ────────────────────────────────────────────

    #[test]
    fn test_trigrams_normal_word() {
        let tris = trigrams("avvocato");
        assert!(tris.contains(&"avv".to_string()));
        assert!(tris.contains(&"vvo".to_string()));
        assert!(tris.contains(&"voc".to_string()));
        assert!(tris.contains(&"oca".to_string()));
        assert!(tris.contains(&"cat".to_string()));
        assert!(tris.contains(&"ato".to_string()));
        assert_eq!(tris.len(), 6); // 8 chars - 2 = 6 trigrams
    }

    #[test]
    fn test_trigrams_exactly_3_chars() {
        let tris = trigrams("abc");
        assert_eq!(tris, vec!["abc"]);
    }

    #[test]
    fn test_trigrams_short_word() {
        let tris = trigrams("ab");
        assert_eq!(tris, vec!["ab"]); // used as-is
    }

    #[test]
    fn test_trigrams_single_char() {
        let tris = trigrams("a");
        assert_eq!(tris, vec!["a"]);
    }

    // ─── SearchIndex ─────────────────────────────────────────

    #[test]
    fn test_search_index_add_and_find() {
        let mut idx = SearchIndex::new();
        idx.add_document("p_001", "Mario Rossi causa civile risarcimento danni", 1);
        idx.add_document("p_002", "Anna Bianchi ricorso lavoro pensione", 1);

        let results = idx.search("Rossi", 10);
        assert!(!results.is_empty());
        assert_eq!(results[0].0, "p_001");
    }

    #[test]
    fn test_search_index_bm25_ranking() {
        let mut idx = SearchIndex::new();
        // Doc with more mentions of "risarcimento" should rank higher
        idx.add_document("p_001", "risarcimento danni contrattuale", 1);
        idx.add_document(
            "p_002",
            "risarcimento risarcimento risarcimento danni enormi",
            1,
        );

        let results = idx.search("risarcimento", 10);
        assert!(results.len() >= 2);
        // p_002 has higher TF for "risarcimento" → should score higher
        assert_eq!(results[0].0, "p_002");
    }

    #[test]
    fn test_search_index_no_results() {
        let mut idx = SearchIndex::new();
        idx.add_document("p_001", "Mario Rossi causa civile", 1);
        let results = idx.search("penale", 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_index_remove_document() {
        let mut idx = SearchIndex::new();
        idx.add_document("p_001", "Mario Rossi", 1);
        idx.add_document("p_002", "Anna Bianchi", 1);
        idx.remove_document("p_001");

        let results = idx.search("Mario", 10);
        assert!(
            results.is_empty(),
            "Removed document should not appear in results"
        );
        assert_eq!(idx.total_docs, 1);
    }

    #[test]
    fn test_search_index_fuzzy_trigram() {
        let mut idx = SearchIndex::new();
        idx.add_document("p_001", "risarcimento", 1);
        // Search with partial match (same trigrams)
        let results = idx.search("risarc", 10);
        assert!(
            !results.is_empty(),
            "Trigram search should find partial matches"
        );
    }

    #[test]
    fn test_search_index_case_insensitive() {
        let mut idx = SearchIndex::new();
        idx.add_document("p_001", "TRIBUNALE CIVILE ROMA", 1);
        let results = idx.search("tribunale", 10);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_search_index_limit() {
        let mut idx = SearchIndex::new();
        for i in 0..20 {
            idx.add_document(
                &format!("p_{:03}", i),
                &format!("fascicolo numero {}", i),
                1,
            );
        }
        let results = idx.search("fascicolo", 5);
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_search_index_empty_query() {
        let mut idx = SearchIndex::new();
        idx.add_document("p_001", "Mario Rossi", 1);
        // Empty query after tokenization (all stop words)
        let results = idx.search("il la di", 10);
        // Falls back to trigram search, might return results or not
        // The important thing is it doesn't panic
        let _ = results;
    }

    // ─── extract_searchable_text ─────────────────────────────

    #[test]
    fn test_extract_searchable_text_practices() {
        let record = serde_json::json!({
            "client": "Mario Rossi",
            "counterparty": "INPS",
            "object": "Ricorso",
            "description": "Causa lavoro",
            "court": "Tribunale Roma",
            "code": "2026/001",
            "diary": [
                {"text": "Prima udienza fissata"},
                {"text": "Depositate memorie"}
            ]
        });
        let text = extract_searchable_text(&record, "practices");
        assert!(text.contains("Mario Rossi"));
        assert!(text.contains("INPS"));
        assert!(text.contains("Prima udienza fissata"));
        assert!(text.contains("Depositate memorie"));
    }

    #[test]
    fn test_extract_searchable_text_contacts() {
        let record = serde_json::json!({
            "name": "Avv. Giuseppe Neri",
            "email": "neri@studio.it",
            "pec": "neri@pec.it",
            "phone": "+39 02 1234567",
            "fiscalCode": "NRSGPP80A01F205X",
            "vatNumber": "12345678901",
            "notes": "Controparte abituale"
        });
        let text = extract_searchable_text(&record, "contacts");
        assert!(text.contains("Giuseppe Neri"));
        assert!(text.contains("NRSGPP80A01F205X"));
        assert!(text.contains("Controparte abituale"));
    }

    #[test]
    fn test_extract_searchable_text_agenda() {
        let record = serde_json::json!({
            "title": "Udienza CTU",
            "text": "Consulenza tecnica d'ufficio",
            "notes": "Portare documentazione medica"
        });
        let text = extract_searchable_text(&record, "agenda");
        assert!(text.contains("Udienza CTU"));
        assert!(text.contains("Consulenza tecnica"));
    }

    // ─── Realistic scenario: lawyer searches across vault ────

    #[test]
    fn test_realistic_lawyer_search_workflow() {
        let mut idx = SearchIndex::new();

        // Populate with realistic Italian legal data
        idx.add_document("practices_p001",
            "Mario Rossi S.r.l. contro Bianchi & Associati risarcimento danni inadempimento contrattuale art 1218 codice civile Tribunale Civile Milano Sezione Nona", 1);
        idx.add_document("practices_p002",
            "Anna Verdi ricorso avverso INPS diniego pensione invalidità civile Tribunale Lavoro Roma", 1);
        idx.add_document(
            "practices_p003",
            "Condominio Via Roma 42 opposizione decreto ingiuntivo pagamento spese straordinarie",
            1,
        );
        idx.add_document(
            "contacts_c001",
            "Avvocato Giuseppe Neri neri@pec.ordineavvocati.mi.it studio legale Milano",
            1,
        );
        idx.add_document(
            "agenda_a001",
            "Udienza di trattazione Rossi vs Bianchi Tribunale Milano Aula 7 ore 9:30",
            1,
        );

        // Search for client name
        let r = idx.search("Rossi", 10);
        assert!(!r.is_empty());
        assert!(r.iter().any(|(id, _)| id == "practices_p001"));

        // Search for court
        let r = idx.search("Tribunale Milano", 10);
        assert!(r.iter().any(|(id, _)| id == "practices_p001"));

        // Search for legal term
        let r = idx.search("inadempimento", 10);
        assert!(r.iter().any(|(id, _)| id == "practices_p001"));

        // Search across types
        let r = idx.search("Milano", 10);
        assert!(
            r.len() >= 2,
            "Should find practices, contacts, and agenda in Milano"
        );

        // Typo-tolerant search (trigram match)
        let r = idx.search("risarcim", 10); // partial
        assert!(
            !r.is_empty(),
            "Partial search should find results via trigrams"
        );
    }
}

/// Rebuild the entire search index from scratch.
/// Called manually or after detecting corruption.
#[tauri::command]
pub(crate) fn rebuild_search_index(state: State<AppState>) -> Result<Value, String> {
    let version = get_vault_version(&state);
    if version < 4 {
        return Err("Search requires vault v4+ format".into());
    }

    let dek = get_vault_dek(&state)?;
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    let vault_path = dir.join(crate::constants::VAULT_FILE);
    let raw =
        crate::io::safe_bounded_read(&vault_path, 500 * 1024 * 1024).map_err(|e| e.to_string())?;
    let vault = vault_engine::deserialize_vault(&raw)?;
    let vault_index = vault_engine::decrypt_index(&dek, &vault.index)?;

    let mut search_idx = SearchIndex::new();

    for entry in &vault_index {
        if let Some(record_entry) = vault.records.get(&entry.id) {
            if let Ok(plaintext) = vault_engine::read_current_version(record_entry, &dek) {
                if let Ok(record) = serde_json::from_slice::<Value>(&plaintext) {
                    let text = extract_searchable_text(&record, &entry.field);
                    let gen = record_entry.current as u64;
                    search_idx.add_document(&entry.id, &text, gen);
                }
            }
        }
    }

    save_search_index(&dir, &dek, &search_idx)?;

    Ok(json!({
        "totalDocs": search_idx.total_docs,
        "totalTerms": search_idx.terms.len(),
        "totalTrigrams": search_idx.trigrams.len(),
    }))
}
