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
use crate::vault_v4;
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
struct SearchIndex {
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
    fn new() -> Self {
        Self::default()
    }

    fn add_document(&mut self, record_id: &str, text: &str, gen: u64) {
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
    fn search(&self, query: &str, limit: usize) -> Vec<(String, f64)> {
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
    // Decrypt using vault_v4 record encryption (includes zstd decompression)
    let block: vault_v4::EncryptedBlock = match serde_json::from_slice(&raw) {
        Ok(b) => b,
        Err(_) => return SearchIndex::new(), // corrupted → rebuild
    };
    let plaintext = match vault_v4::decrypt_record(dek, &block) {
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
    let block = vault_v4::encrypt_record(dek, &plaintext)?;
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
    vault_index: &[vault_v4::IndexEntry],
    vault: &vault_v4::VaultV4,
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
                if let Ok(plaintext) = vault_v4::read_current_version(record_entry, dek) {
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
    if version != 4 {
        return Err("Search requires vault v4 format".into());
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
    let vault = vault_v4::deserialize_vault(&raw)?;
    let vault_index = vault_v4::decrypt_index(&dek, &vault.index)?;

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

/// Rebuild the entire search index from scratch.
/// Called manually or after detecting corruption.
#[tauri::command]
pub(crate) fn rebuild_search_index(state: State<AppState>) -> Result<Value, String> {
    let version = get_vault_version(&state);
    if version != 4 {
        return Err("Search requires vault v4 format".into());
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
    let vault = vault_v4::deserialize_vault(&raw)?;
    let vault_index = vault_v4::decrypt_index(&dek, &vault.index)?;

    let mut search_idx = SearchIndex::new();

    for entry in &vault_index {
        if let Some(record_entry) = vault.records.get(&entry.id) {
            if let Ok(plaintext) = vault_v4::read_current_version(record_entry, &dek) {
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
