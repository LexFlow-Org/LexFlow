// ═══════════════════════════════════════════════════════════
//  SEARCH — Encrypted trigram index with BM25 ranking
// ═══════════════════════════════════════════════════════════
//
//  - Trigram-based fuzzy search (typo-tolerant, prefix-native)
//  - BM25 ranking for relevance ordering
//  - Generation counter for crash-consistency
//  - Encrypted with DEK (AES-256-GCM-SIV via encrypt_record)
//  - Atomically stored as search_index.enc (rebuilt on corruption)

use crate::state::{AppState, DocumentSession, SecureKey};
use crate::vault_engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
#[cfg(test)]
use std::fs;
use tauri::State;

const SEARCH_INDEX_FILE: &str = "search_index.enc";
const SEARCH_INDEX_FORMAT: u32 = 2;

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
    /// The cache is derived data; old formats are rebuilt from authenticated records.
    #[serde(default)]
    format: u32,
    /// trigram → unique terms, avoiding a copy of every record ID per trigram.
    trigrams: HashMap<String, HashSet<String>>,
    /// term → record_id → term_frequency, with constant-time scoring lookup.
    terms: HashMap<String, HashMap<String, u32>>,
    /// record_id → generation counter (for consistency check)
    indexed_gens: HashMap<String, u64>,
    /// metadata for BM25
    total_docs: u32,
    avg_doc_len: f64,
    /// FIX-B1: per-document token count, populated by `add_document`,
    /// removed by `remove_document`. Lets `bm25_score` look up `doc_len` in
    /// O(1) instead of O(N) (full scan over all term postings).
    /// `#[serde(default)]` keeps the field backward-compatible with indexes
    /// serialized before this field existed.
    #[serde(default)]
    doc_lens: HashMap<String, u32>,
    /// FIX-B2: running sum of doc_len so we can recompute `avg_doc_len`
    /// correctly on remove without a full scan. Backward-compatible default.
    #[serde(default)]
    total_terms: u64,
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
        Self {
            format: SEARCH_INDEX_FORMAT,
            ..Self::default()
        }
    }

    pub(crate) fn add_document(&mut self, record_id: &str, text: &str, gen: u64) {
        // FIX-B3: make `add_document` idempotent — re-adding the same record
        // would otherwise inflate `total_docs` and duplicate postings.
        if self.indexed_gens.contains_key(record_id) {
            self.remove_document(record_id);
        }

        let tokens = tokenize(text);
        let doc_len = tokens.len() as u32;

        // Update doc count and total terms first, then derive avg_doc_len.
        self.total_docs += 1;
        self.total_terms = self.total_terms.saturating_add(doc_len as u64);
        self.avg_doc_len = if self.total_docs > 0 {
            self.total_terms as f64 / self.total_docs as f64
        } else {
            0.0
        };

        // FIX-B1: store per-doc length for O(1) BM25 lookup.
        self.doc_lens.insert(record_id.to_string(), doc_len);

        // Count term frequencies
        let mut tf_map: HashMap<String, u32> = HashMap::new();
        for token in &tokens {
            *tf_map.entry(token.clone()).or_insert(0) += 1;
        }

        // Update term index
        for (term, tf) in tf_map {
            self.terms
                .entry(term.clone())
                .or_default()
                .insert(record_id.to_string(), tf);
            for tri in trigrams(&term) {
                self.trigrams.entry(tri).or_default().insert(term.clone());
            }
        }

        // Track generation
        self.indexed_gens.insert(record_id.to_string(), gen);
    }

    fn remove_document(&mut self, record_id: &str) {
        if self.indexed_gens.remove(record_id).is_none() {
            return;
        }
        // FIX-B2: drop this doc's contribution to total_terms BEFORE we tear
        // down its postings, so avg_doc_len stays correct.
        if let Some(doc_len) = self.doc_lens.remove(record_id) {
            self.total_terms = self.total_terms.saturating_sub(doc_len as u64);
        }

        // Remove from term index
        for entries in self.terms.values_mut() {
            entries.remove(record_id);
        }
        // Remove empty terms
        self.terms.retain(|_, v| !v.is_empty());

        // Remove from trigram index
        for terms in self.trigrams.values_mut() {
            terms.retain(|term| self.terms.contains_key(term));
        }
        self.trigrams.retain(|_, v| !v.is_empty());

        // Remove generation
        if self.total_docs > 0 {
            self.total_docs -= 1;
        }

        // Recompute avg_doc_len after the removal.
        self.avg_doc_len = if self.total_docs > 0 {
            self.total_terms as f64 / self.total_docs as f64
        } else {
            0.0
        };
    }

    /// BM25 score for a query term against a document
    fn bm25_score(&self, term: &str, record_id: &str) -> f64 {
        let k1: f64 = 1.2;
        let b: f64 = 0.75;

        let entries = match self.terms.get(term) {
            Some(e) => e,
            None => return 0.0,
        };

        let tf = entries.get(record_id).map(|f| *f as f64).unwrap_or(0.0);

        if tf == 0.0 {
            return 0.0;
        }

        let df = entries.len() as f64;
        let n = self.total_docs.max(1) as f64;
        let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();

        // FIX-B1: O(1) doc_len lookup via the cached `doc_lens` map. Falls
        // back to 0.0 (which makes b*doc_len/avg_dl = 0) if the entry is
        // missing — this can only happen for indexes serialized BEFORE the
        // field was added; they will be rebuilt on next add/remove.
        let doc_len = self
            .doc_lens
            .get(record_id)
            .copied()
            .map(|n| n as f64)
            .unwrap_or(0.0);

        let avg_dl = self.avg_doc_len.max(1.0);
        let tf_norm = (tf * (k1 + 1.0)) / (tf + k1 * (1.0 - b + b * doc_len / avg_dl));

        idf * tf_norm
    }

    /// Trigrams identify candidate terms; actual prefix/edit-distance matching
    /// rejects incidental overlaps before any record is scored.
    fn matching_terms(&self, query: &str) -> Vec<(&str, f64)> {
        let query_tris: HashSet<String> = trigrams(query).into_iter().collect();
        let mut overlap: HashMap<&str, usize> = HashMap::new();
        for tri in &query_tris {
            if let Some(terms) = self.trigrams.get(tri) {
                for term in terms {
                    *overlap.entry(term.as_str()).or_default() += 1;
                }
            }
        }
        let minimum_overlap = query_tris.len().saturating_sub(3).max(1);
        overlap
            .into_iter()
            .filter_map(|(term, count)| {
                if term == query {
                    Some((term, 1.0))
                } else if term.starts_with(query) {
                    Some((term, 0.75))
                } else if query.chars().count() >= 5
                    && count >= minimum_overlap
                    && one_edit_apart(query, term)
                {
                    Some((term, 0.5))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Search with validated fuzzy matches + BM25 ranking. Iterate each matching
    /// posting once, rather than scanning its whole list again per document.
    pub(crate) fn search(&self, query: &str, limit: usize) -> Vec<(String, f64)> {
        if limit == 0 {
            return Vec::new();
        }
        let query_tokens = tokenize(query);
        let mut all_scores: HashMap<&str, f64> = HashMap::new();
        for token in &query_tokens {
            for (term, weight) in self.matching_terms(token) {
                if let Some(entries) = self.terms.get(term) {
                    for id in entries.keys() {
                        let score = self.bm25_score(term, id) * weight;
                        if score > 0.0 {
                            *all_scores.entry(id.as_str()).or_default() += score;
                        }
                    }
                }
            }
        }
        let mut results: Vec<(&str, f64)> = all_scores.into_iter().collect();
        results.sort_unstable_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        results.truncate(limit);
        results
            .into_iter()
            .map(|(id, score)| (id.to_owned(), score))
            .collect()
    }
}

/// One Unicode insertion, deletion or replacement; linear space/time in word
/// length. Trigram overlap alone is insufficient evidence of a fuzzy match.
fn one_edit_apart(left: &str, right: &str) -> bool {
    let left: Vec<char> = left.chars().collect();
    let right: Vec<char> = right.chars().collect();
    if left.len().abs_diff(right.len()) > 1 {
        return false;
    }
    let (mut i, mut j, mut edits) = (0, 0, 0);
    while i < left.len() && j < right.len() {
        if left[i] == right[j] {
            i += 1;
            j += 1;
            continue;
        }
        edits += 1;
        if edits > 1 {
            return false;
        }
        if left.len() >= right.len() {
            i += 1;
        }
        if right.len() >= left.len() {
            j += 1;
        }
    }
    edits + usize::from(i < left.len() || j < right.len()) <= 1
}

fn decode_search_record(plaintext: &[u8]) -> Option<Value> {
    vault_engine::decode_record_object(plaintext).ok()
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
    // FIX-S3: serde_json::from_slice has no built-in nesting cap; we accept
    // this risk because the input was just produced by `safe_bounded_read`
    // (100 MiB hard cap) and is then verified by the AEAD tag inside
    // `decrypt_record` before any further deserialization. A maliciously
    // deeply-nested document can only be planted by an attacker who already
    // holds the DEK, in which case the integrity property is moot. If
    // upstream serde_json gains a stable depth limit, gate it here.
    let block: vault_engine::EncryptedBlock = match serde_json::from_slice(&raw) {
        Ok(b) => b,
        Err(_) => return SearchIndex::new(), // corrupted → rebuild
    };
    let plaintext = match vault_engine::decrypt_record(dek, &block) {
        Ok(p) => p,
        Err(_) => return SearchIndex::new(), // corrupted → rebuild
    };
    match serde_json::from_slice::<SearchIndex>(&plaintext) {
        Ok(index) if index.format == SEARCH_INDEX_FORMAT => index,
        _ => SearchIndex::new(),
    }
}

fn encode_search_index(dek: &[u8], index: &SearchIndex) -> Result<Vec<u8>, String> {
    let plaintext = zeroize::Zeroizing::new(
        serde_json::to_vec(index).map_err(|e| format!("Search index serialize: {}", e))?,
    );
    let block = vault_engine::encrypt_record(dek, &plaintext)?;
    serde_json::to_vec(&block).map_err(|e| format!("Search block serialize: {}", e))
}

#[cfg(test)]
fn save_search_index(
    data_dir: &std::path::Path,
    dek: &[u8],
    index: &SearchIndex,
) -> Result<(), String> {
    let encrypted = encode_search_index(dek, index)?;
    publish_search_cache(data_dir, &encrypted)
}

fn publish_search_cache(data_dir: &std::path::Path, encrypted: &[u8]) -> Result<(), String> {
    crate::io::atomic_write_with_sync(&data_dir.join(SEARCH_INDEX_FILE), encrypted)
}

fn capture_search_session(
    state: &AppState,
) -> Result<(DocumentSession, SecureKey, std::path::PathBuf), String> {
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let session = state.document_session()?;
    if *state
        .vault_version
        .read()
        .unwrap_or_else(|e| e.into_inner())
        < 4
    {
        return Err("Search requires vault v4+ format".into());
    }
    // Indexing runs without holding the vault mutex, so autolock stays responsive.
    // Its temporary key has the same zeroization and memory locking as the session key.
    let dek = state.vault_dek.lock().unwrap_or_else(|e| e.into_inner());
    let key = dek.as_ref().ok_or("Locked")?;
    let key_copy = SecureKey::new(zeroize::Zeroizing::new(key.0.to_vec()));
    let dir = state
        .data_dir
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    Ok((session, key_copy, dir))
}

fn finish_search(
    state: &AppState,
    session: DocumentSession,
    dir: &std::path::Path,
    mut response: Value,
    publish: impl FnOnce() -> Result<(), String>,
) -> Result<Value, String> {
    // Only publication holds the write mutex; expensive indexing/encryption is finished.
    let _guard = state.write_mutex.lock().unwrap_or_else(|e| e.into_inner());
    let result = state.validate_document_session(session).and_then(|_| {
        if *state.data_dir.read().unwrap_or_else(|e| e.into_inner()) != dir {
            return Err("Cartella archivio cambiata durante la ricerca.".into());
        }
        publish()
    });
    if let Err(error) = result {
        crate::state::scrub_json(&mut response);
        return Err(error);
    }
    Ok(response)
}

// ─── Consistency check (generation counter) ─────────────────

fn ensure_index_consistent(
    data_dir: &std::path::Path,
    dek: &[u8],
    vault_index: &[vault_engine::IndexEntry],
    vault: &vault_engine::VaultData,
) -> (SearchIndex, bool) {
    let mut search_idx = load_search_index(data_dir, dek);

    // Find stale records (gen mismatch or missing from index)
    let mut stale_ids: Vec<String> = Vec::new();
    for entry in vault_index {
        let vault_gen = vault
            .records
            .get(&entry.id)
            .map(|r| r.current as u64)
            .unwrap_or(0);
        let indexed_gen = search_idx.indexed_gens.get(&entry.id).copied();
        if indexed_gen != Some(vault_gen) {
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
        // FIX-S1: only log the count (never IDs/text/records) and only in
        // debug builds — release builds stay quiet to avoid leaking any
        // metadata about how many records changed.
        #[cfg(debug_assertions)]
        eprintln!(
            "[LexFlow] Search index: re-indexing {} stale records",
            stale_ids.len()
        );
        let fields: HashMap<&str, &str> = vault_index
            .iter()
            .map(|entry| (entry.id.as_str(), entry.field.as_str()))
            .collect();
        for id in &stale_ids {
            // Remove old entry first
            search_idx.remove_document(id);

            // Find field from vault index
            let field = fields.get(id.as_str()).copied().unwrap_or("practices");

            // Decrypt record
            if let Some(record_entry) = vault.records.get(id) {
                if let Ok(plaintext) = vault_engine::read_current_version(record_entry, dek) {
                    if let Some(record) = decode_search_record(&plaintext) {
                        let text = extract_searchable_text(&record, field);
                        let gen = record_entry.current as u64;
                        search_idx.add_document(id, &text, gen);
                    }
                }
            }
        }
    }
    (search_idx, !stale_ids.is_empty() || !phantom_ids.is_empty())
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
    // FIX-S2: cap query length at 1024 bytes. Anything larger is almost
    // certainly noise / abuse and can only slow the index down.
    if query.len() > 1024 {
        return Err("query troppo lunga".into());
    }
    let (session, dek, dir) = capture_search_session(&state)?;

    let vault_path = dir.join(crate::constants::VAULT_FILE);
    if !vault_path.exists() {
        return finish_search(&state, session, &dir, json!([]), || Ok(()));
    }
    let raw =
        crate::io::safe_bounded_read(&vault_path, 500 * 1024 * 1024).map_err(|e| e.to_string())?;
    let vault = vault_engine::deserialize_authenticated_vault(&raw, &dek.0)?;
    let vault_index = vault_engine::decrypt_index(&dek.0, &vault.index)?;

    // Ensure consistency and get search index
    let (search_idx, changed) = ensure_index_consistent(&dir, &dek.0, &vault_index, &vault);

    // FIX-V2: clamp the requested limit to a hard ceiling so a malicious
    // caller cannot ask for an unbounded number of results.
    let max_results = limit.unwrap_or(50).min(500);
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

    let encrypted = changed
        .then(|| encode_search_index(&dek.0, &search_idx))
        .transpose()?;
    drop(dek);
    finish_search(&state, session, &dir, json!(enriched), || {
        if let Some(encrypted) = encrypted {
            // A cache write failure must not make otherwise readable records unsearchable.
            let _ = publish_search_cache(&dir, &encrypted);
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_search_session_never_publishes_cache_or_results() {
        let directory = tempfile::tempdir().unwrap();
        let state = AppState::new(directory.path().into(), directory.path().into());
        *state.vault_dek.lock().unwrap() =
            Some(SecureKey::new(zeroize::Zeroizing::new(vec![3; 32])));
        *state.vault_version.write().unwrap() = 8;
        let (session, temporary_key, dir) = capture_search_session(&state).unwrap();
        // A running search keeps its own bounded key; locking the app can still finish.
        state.lock_vault();
        assert_eq!(temporary_key.0.len(), 32);
        let cache_path = dir.join(SEARCH_INDEX_FILE);
        fs::write(&cache_path, b"previous-cache").unwrap();
        for reunlock in [false, true] {
            if reunlock {
                *state.vault_dek.lock().unwrap() =
                    Some(SecureKey::new(zeroize::Zeroizing::new(vec![3; 32])));
                *state.vault_version.write().unwrap() = 8;
            }
            let result = finish_search(
                &state,
                session,
                &dir,
                json!([{"title":"Cliente sintetico riservato"}]),
                || publish_search_cache(&dir, b"stale-cache"),
            );
            assert!(result.is_err());
            assert_eq!(fs::read(&cache_path).unwrap(), b"previous-cache");
        }
        let (current, _, _) = capture_search_session(&state).unwrap();
        assert_eq!(
            finish_search(&state, current, &dir, json!([]), || publish_search_cache(
                &dir,
                b"current-cache"
            ))
            .unwrap(),
            json!([])
        );
        assert_eq!(fs::read(cache_path).unwrap(), b"current-cache");
    }

    #[cfg(unix)]
    #[test]
    fn publishing_search_cache_replaces_symlink_without_touching_target() {
        let directory = tempfile::tempdir().unwrap();
        let unrelated = directory.path().join("unrelated-synthetic-file");
        fs::write(&unrelated, b"preserve this file").unwrap();
        let cache_path = directory.path().join(SEARCH_INDEX_FILE);
        std::os::unix::fs::symlink(&unrelated, &cache_path).unwrap();
        let dek = [9; 32];
        let mut index = SearchIndex::new();
        index.add_document("synthetic", "contratto sintetico", 1);
        save_search_index(directory.path(), &dek, &index).unwrap();
        assert_eq!(fs::read(&unrelated).unwrap(), b"preserve this file");
        assert!(!fs::symlink_metadata(&cache_path).unwrap().is_symlink());
        assert_eq!(
            load_search_index(directory.path(), &dek)
                .search("contratto", 10)
                .len(),
            1
        );
    }

    #[test]
    fn shared_trigrams_are_not_false_positive_results() {
        let mut index = SearchIndex::new();
        index.add_document("real", "contratto termine sintetico", 1);
        assert!(index.search("termineinesistentexyz", 50).is_empty());
        let typo = index.search("contrato", 50);
        assert_eq!(typo.len(), 1);
        assert_eq!(typo[0].0, "real");
        assert!(typo[0].1 > 0.0);
        assert!(index.search("contrat", 50)[0].1 > 0.0);
    }

    #[test]
    fn term_trigrams_do_not_grow_with_repeated_documents() {
        let mut index = SearchIndex::new();
        for n in 0..1000 {
            index.add_document(&format!("record-{n}"), "contratto sintetico", 1);
        }
        assert_eq!(index.trigrams["con"].len(), 1);
        assert_eq!(index.terms["contratto"].len(), 1000);
        let encoded = serde_json::to_vec(&index).unwrap();
        let restored: SearchIndex = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            restored.search("contratto", 20),
            index.search("contratto", 20)
        );
        assert!(encoded.len() < 150_000);
    }

    #[test]
    fn current_msgpack_and_legacy_json_records_both_index() {
        let directory = std::env::temp_dir().join(format!(
            "lexflow-search-validation-{}",
            rand::random::<u64>()
        ));
        fs::create_dir(&directory).unwrap();
        let dek = [0x45; 32];
        let mut vault: vault_engine::VaultData = serde_json::from_value(json!({
            "version": 8, "kdf": {"alg":"argon2id", "m":65536, "t":3, "p":1, "salt":""},
            "wrapped_dek": "", "dek_iv":"", "dek_alg":"aes-256-gcm-siv",
            "rotation":{"created":"", "interval_days":90, "writes":0, "max_writes":10000},
            "header_mac":"", "index":{"iv":"", "tag":"", "data":""}, "records":{}
        }))
        .unwrap();
        let mut entries = Vec::new();
        for (id, msgpack) in [("practices_modern", true), ("practices_legacy", false)] {
            let record = json!({"client":"Cliente sintetico", "object":"contratto"});
            let data = if msgpack {
                rmp_serde::to_vec_named(&record).unwrap()
            } else {
                serde_json::to_vec(&record).unwrap()
            };
            let mut versions = vault_engine::RecordEntry {
                versions: vec![],
                current: 0,
            };
            vault_engine::append_record_version(&mut versions, &dek, &data).unwrap();
            vault.records.insert(id.into(), versions);
            entries.push(vault_engine::IndexEntry {
                id: id.into(),
                field: "practices".into(),
                title: String::new(),
                tags: vec![],
                updated_at: String::new(),
                summary: None,
            });
        }
        let (first, changed) = ensure_index_consistent(&directory, &dek, &entries, &vault);
        assert_eq!(first.total_docs, 2);
        assert_eq!(first.search("contratto", 50).len(), 2);
        assert!(changed);
        save_search_index(&directory, &dek, &first).unwrap();
        let cached = load_search_index(&directory, &dek);
        assert_eq!(cached.total_docs, 2, "Encrypted cache is reused");
        // A backup restore can reduce generation numbers. A cache from the
        // newer snapshot must not retain text from the discarded revision.
        let mut newer = cached;
        newer.add_document("practices_modern", "contenuto successivo", 99);
        save_search_index(&directory, &dek, &newer).unwrap();
        let (recovered, changed) = ensure_index_consistent(&directory, &dek, &entries, &vault);
        assert!(changed);
        assert!(recovered.search("successivo", 50).is_empty());
        assert_eq!(recovered.search("contratto", 50).len(), 2);
        fs::remove_dir_all(directory).unwrap();
    }

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
///
/// FIX-P3: this function performs heavy CPU work (JSON deserialization,
/// AEAD decryption per record, tokenization). On the Tauri main async
/// runtime that would block other commands. We extract Send-able state
/// from `State<AppState>` first, then move the work to
/// `tokio::task::spawn_blocking` so the runtime stays responsive.
#[tauri::command]
pub(crate) async fn rebuild_search_index(state: State<'_, AppState>) -> Result<Value, String> {
    let (session, dek, dir) = capture_search_session(&state)?;
    let worker_dir = dir.clone();

    // FIX-S3 (mirror of search_vault): same depth-limit caveat applies to
    // the deserialize_vault / decrypt_index path — input is bounded by
    // safe_bounded_read and authenticated by the AEAD tag.
    let (encrypted, response) = tokio::task::spawn_blocking(move || -> Result<_, String> {
        let vault_path = worker_dir.join(crate::constants::VAULT_FILE);
        let raw = crate::io::safe_bounded_read(&vault_path, 500 * 1024 * 1024)
            .map_err(|e| e.to_string())?;
        let vault = vault_engine::deserialize_authenticated_vault(&raw, &dek.0)?;
        let vault_index = vault_engine::decrypt_index(&dek.0, &vault.index)?;

        let mut search_idx = SearchIndex::new();

        for entry in &vault_index {
            if let Some(record_entry) = vault.records.get(&entry.id) {
                if let Ok(plaintext) = vault_engine::read_current_version(record_entry, &dek.0) {
                    if let Some(record) = decode_search_record(&plaintext) {
                        let text = extract_searchable_text(&record, &entry.field);
                        let gen = record_entry.current as u64;
                        search_idx.add_document(&entry.id, &text, gen);
                    }
                }
            }
        }

        let encrypted = encode_search_index(&dek.0, &search_idx)?;
        Ok((
            encrypted,
            json!({
                "totalDocs": search_idx.total_docs,
                "totalTerms": search_idx.terms.len(),
                "totalTrigrams": search_idx.trigrams.len(),
            }),
        ))
    })
    .await
    .map_err(|e| format!("rebuild_search_index join error: {}", e))??;
    finish_search(&state, session, &dir, response, || {
        publish_search_cache(&dir, &encrypted)
    })
}
