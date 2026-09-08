// Synthetic backend validation. Modules are supplied from production sources by
// validate-backend.py; this executable never resolves application data folders.
#![allow(dead_code, unused_imports)]
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path, time::Instant};
use vault_engine as engine;

const PASSWORD: &str = "SYNTHETIC-Validation-Password-2026!";
const NEW_PASSWORD: &str = "SYNTHETIC-Changed-Password-2026!";
const BACKUP_PASSWORD: &str = "SYNTHETIC-Backup-Password-2026!";

fn elapsed(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn synthetic_record(number: usize, generation: &str) -> Value {
    let topics = [
        "locazione",
        "contratto",
        "successione",
        "risarcimento",
        "condominio",
    ];
    json!({
        "id": format!("synthetic-{number:06}"), "client": format!("Cliente sintetico {number}"),
        "counterparty": format!("Controparte sintetica {}", number.wrapping_mul(37) % 100003),
        "object": format!("Procedimento {} riferimento {number:06}", topics[number % topics.len()]),
        "court": format!("Tribunale sintetico {}", number % 17), "status": "In corso",
        "code": format!("SYN-{number:06}"), "generation": generation,
        "diary": [
            {"text": format!("Verifica contratto e documenti sintetici fascicolo {number}; scadenza udienza, deposito memoria e comunicazione alla controparte.")},
            {"text": format!("Attivita fittizia {} per benchmark. Nessun documento o dato personale reale utilizzato; valutazione della controversia e aggiornamento istruttoria.", number.wrapping_mul(104729))}
        ]
    })
}

fn fill(vault: &mut engine::VaultData, dek: &[u8], count: usize, generation: &str) -> usize {
    let mut index = Vec::with_capacity(count);
    let mut plaintext_bytes = 0;
    for number in 0..count {
        let record = synthetic_record(number, generation);
        let bytes = rmp_serde::to_vec_named(&record).unwrap();
        plaintext_bytes += bytes.len();
        let id = format!("practices_synthetic-{number:06}");
        let entry = vault
            .records
            .entry(id.clone())
            .or_insert(engine::RecordEntry {
                versions: vec![],
                current: 0,
            });
        engine::append_record_version(entry, dek, &bytes).unwrap();
        index.push(engine::IndexEntry {
            id,
            field: "practices".into(),
            title: format!("Cliente sintetico {number}"),
            tags: vec!["synthetic".into()],
            updated_at: "2026-09-07T00:00:00Z".into(),
            summary: Some(
                json!({"client": format!("Cliente sintetico {number}"), "status": "In corso"}),
            ),
        });
    }
    vault.index = engine::encrypt_index(dek, &index).unwrap();
    plaintext_bytes
}

fn assert_contents(vault: &engine::VaultData, dek: &[u8], count: usize, generation: &str) {
    assert_eq!(vault.records.len(), count);
    assert_eq!(
        engine::decrypt_index(dek, &vault.index).unwrap().len(),
        count
    );
    for number in 0..count {
        let entry = &vault.records[&format!("practices_synthetic-{number:06}")];
        let bytes = engine::read_current_version(entry, dek).unwrap();
        let actual: Value = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(actual, synthetic_record(number, generation));
    }
}

fn peak_rss_bytes() -> u64 {
    #[cfg(unix)]
    unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut usage) == 0 {
            #[cfg(target_os = "macos")]
            {
                return usage.ru_maxrss as u64;
            }
            #[cfg(not(target_os = "macos"))]
            {
                return usage.ru_maxrss as u64 * 1024;
            }
        }
    }
    0
}

fn vault_benchmark(directory: &Path, count: usize) -> Value {
    fs::create_dir_all(directory).unwrap();
    let start = Instant::now();
    let (mut vault, dek) = engine::create_vault(PASSWORD).unwrap();
    let create_ms = elapsed(start);
    let start = Instant::now();
    let plaintext_bytes = fill(&mut vault, &dek, count, "initial");
    let encrypt_records_ms = elapsed(start);
    let start = Instant::now();
    engine::write_canonical_vault(directory, &mut vault, &dek).unwrap();
    let commit_ms = elapsed(start);
    let snapshot_bytes = fs::metadata(directory.join("vault.lex")).unwrap().len();
    let start = Instant::now();
    let (loaded, loaded_dek) = engine::open_current_vault(directory, PASSWORD).unwrap();
    let unlock_and_manifest_ms = elapsed(start);
    let start = Instant::now();
    assert_contents(&loaded, &loaded_dek, count, "initial");
    let decrypt_all_and_assert_ms = elapsed(start);
    let first = vault.records.get_mut("practices_synthetic-000000").unwrap();
    engine::append_record_version(
        first,
        &dek,
        &rmp_serde::to_vec_named(&synthetic_record(0, "edited")).unwrap(),
    )
    .unwrap();
    let start = Instant::now();
    engine::write_canonical_vault(directory, &mut vault, &dek).unwrap();
    let single_record_commit_ms = elapsed(start);
    let start = Instant::now();
    let name = backup::create_backup(directory).unwrap();
    let backup_ms = elapsed(start);
    assert!(backup::verify_fixture_backup(
        &directory.join(".auto-backups").join(name)
    ));
    json!({"kind":"vault", "records":count, "plaintext_bytes":plaintext_bytes,
        "snapshot_bytes":snapshot_bytes, "create_ms":create_ms, "encrypt_records_ms":encrypt_records_ms,
        "commit_ms":commit_ms, "unlock_and_manifest_ms":unlock_and_manifest_ms,
        "decrypt_all_and_assert_ms":decrypt_all_and_assert_ms, "single_record_commit_ms":single_record_commit_ms,
        "backup_ms":backup_ms, "kdf":{"m_kib":vault.kdf.m,"iterations":vault.kdf.t,"parallelism":vault.kdf.p},
        "peak_rss_bytes":peak_rss_bytes(), "integrity":"all synthetic records compared"})
}

fn search_benchmark(count: usize) -> Value {
    let start = Instant::now();
    let mut index = search::SearchIndex::new();
    for number in 0..count {
        index.add_document(
            &format!("synthetic-{number:06}"),
            &search::fixture_searchable_text(&synthetic_record(number, "initial")),
            1,
        );
    }
    let build_ms = elapsed(start);
    let mut queries = Vec::new();
    // Common terms deliberately expose the cost of scoring many candidates.
    for query in [
        format!("SYN-{:06}", count - 1),
        "contratto".into(),
        "contrato".into(),
        "termineinesistentexyz".into(),
    ] {
        let repetitions = 5;
        let mut durations = Vec::new();
        let mut hits = 0;
        let mut zero_score_hits = 0;
        for _ in 0..repetitions {
            let start = Instant::now();
            let result = index.search(&query, 50);
            durations.push(elapsed(start));
            hits = result.len();
            zero_score_hits = result.iter().filter(|(_, score)| *score == 0.0).count();
            std::hint::black_box(result);
        }
        durations.sort_by(f64::total_cmp);
        queries.push(json!({"query":query,"samples_ms":durations,"median_ms":durations[durations.len()/2],"hits":hits,"zero_score_hits":zero_score_hits}));
    }
    let serialized = serde_json::to_vec(&index).unwrap();
    let start = Instant::now();
    let encrypted = engine::encrypt_record(&[0x31; 32], &serialized).unwrap();
    let cache_encrypt_ms = elapsed(start);
    let start = Instant::now();
    let decrypted = engine::decrypt_record(&[0x31; 32], &encrypted).unwrap();
    let cache_decrypt_ms = elapsed(start);
    let exact_cache_roundtrip = decrypted.as_slice() == serialized.as_slice();
    let cache_parses = serde_json::from_slice::<search::SearchIndex>(&decrypted).is_ok();
    json!({"kind":"search","records":count,"index_build_ms":build_ms,"serialized_index_bytes":serialized.len(),
        "queries":queries,"peak_rss_bytes":peak_rss_bytes(),"cache_encrypt_ms":cache_encrypt_ms,
        "cache_decrypt_ms":cache_decrypt_ms,"cache_ciphertext_base64_bytes":encrypted.data.len(),
        "cache_decrypted_bytes":decrypted.len(),"cache_exact_roundtrip":exact_cache_roundtrip,"cache_parses":cache_parses})
}

fn search_snapshot(directory: &Path, count: usize) -> Value {
    let (vault, dek) = engine::open_current_vault(directory, PASSWORD).unwrap();
    let start = Instant::now();
    let first = search::fixture_consistent_index(directory, &dek, &vault);
    let cold_build_ms = elapsed(start);
    assert_eq!(first.search("contratto", count).len(), count);
    drop(first);
    let start = Instant::now();
    let second = search::fixture_consistent_index(directory, &dek, &vault);
    let cached_load_ms = elapsed(start);
    assert_eq!(second.search("contratto", count).len(), count);
    let cache_bytes = fs::metadata(directory.join("search_index.enc")).unwrap().len();
    json!({"kind":"search-snapshot", "records":count, "cold_build_ms":cold_build_ms,
        "cached_load_ms":cached_load_ms, "cache_file_bytes":cache_bytes,
        "authenticated_snapshot_records_matched":count,"peak_rss_bytes":peak_rss_bytes()})
}

fn reliability(directory: &Path) -> Value {
    fs::create_dir_all(directory).unwrap();
    let (mut vault, dek) = engine::create_vault(PASSWORD).unwrap();
    fill(&mut vault, &dek, 25, "before-update");
    engine::write_canonical_vault(directory, &mut vault, &dek).unwrap();
    let canonical = fs::read(directory.join("vault.lex")).unwrap();
    let backup_name = backup::create_backup(directory).unwrap();
    let backup_path = directory.join(".auto-backups").join(backup_name);
    assert_eq!(fs::read(&backup_path).unwrap(), canonical);
    assert!(backup::verify_fixture_backup(&backup_path));
    fill(&mut vault, &dek, 25, "after-update");
    engine::write_canonical_vault(directory, &mut vault, &dek).unwrap();
    // Restore the authenticated snapshot via the production atomic publisher.
    io::atomic_write_with_sync(
        &directory.join("vault.lex"),
        &fs::read(&backup_path).unwrap(),
    )
    .unwrap();
    let (restored, restored_dek) = engine::open_current_vault(directory, PASSWORD).unwrap();
    assert_contents(&restored, &restored_dek, 25, "before-update");
    let mut altered = canonical.clone();
    let last = altered.len() - 3;
    altered[last] ^= 0x01;
    assert!(engine::open_vault(PASSWORD, &altered).is_err());
    assert!(engine::open_vault("WRONG-SYNTHETIC-PASSWORD", &canonical).is_err());
    for _ in 0..5 {
        backup::create_backup(directory).unwrap();
    }
    let backups: Vec<_> = fs::read_dir(directory.join(".auto-backups"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|p| p.to_string_lossy().ends_with(".lex.bak"))
        .collect();
    assert_eq!(backups.len(), 3);
    assert!(backups.iter().all(|p| backup::verify_fixture_backup(p)));
    engine::change_password_snapshot(directory, PASSWORD, NEW_PASSWORD).unwrap();
    assert!(engine::open_current_vault(directory, PASSWORD).is_err());
    let (changed, changed_dek) = engine::open_current_vault(directory, NEW_PASSWORD).unwrap();
    assert_contents(&changed, &changed_dek, 25, "before-update");

    let legacy_dir = directory.join("legacy");
    fs::create_dir(&legacy_dir).unwrap();
    let mut legacy = restored.clone();
    legacy.version = 7;
    legacy.header_mac =
        engine::compute_header_mac(&engine::derive_kek(PASSWORD, &legacy.kdf).unwrap(), &legacy);
    io::atomic_write_with_sync(
        &legacy_dir.join("vault.lex"),
        &engine::serialize_vault(&legacy).unwrap(),
    )
    .unwrap();
    fill(&mut legacy, &dek, 25, "latest-split");
    engine::write_split_vault(&legacy_dir, &legacy, &dek).unwrap();
    assert!(
        backup::create_backup(&legacy_dir).is_err(),
        "Unmigrated split backup must fail"
    );
    let (mut current, current_dek) = engine::open_current_vault(&legacy_dir, PASSWORD).unwrap();
    assert_contents(&current, &current_dek, 25, "latest-split");
    engine::upgrade_canonical_header(&mut current, PASSWORD).unwrap();
    engine::write_canonical_vault(&legacy_dir, &mut current, &current_dek).unwrap();
    fs::write(
        legacy_dir.join("vault-data/header.enc"),
        b"corrupt retained old split",
    )
    .unwrap();
    let (migrated, migrated_dek) = engine::open_current_vault(&legacy_dir, PASSWORD).unwrap();
    assert_contents(&migrated, &migrated_dek, 25, "latest-split");
    assert!(engine::has_canonical_vault(&legacy_dir));
    let invalid_target = directory.join("cannot-replace-directory");
    fs::create_dir(&invalid_target).unwrap();
    fs::write(invalid_target.join("preserved"), b"synthetic sentinel").unwrap();
    assert!(io::atomic_write_with_sync(&invalid_target, b"replacement").is_err());
    assert_eq!(
        fs::read(invalid_target.join("preserved")).unwrap(),
        b"synthetic sentinel"
    );
    assert!(!fs::read_dir(directory).unwrap().any(|p| p
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".cannot-replace-directory.tmp.")));
    json!({"kind":"reliability","passed":["snapshot backup byte equality","backup HMAC under synthetic platform identity",
        "restore and compare all 25 records","altered snapshot rejection","wrong password rejection","backup rotation retains 3 complete pairs",
        "password change survives reopen","latest split data selected","unmigrated split backup refused",
        "V7 split migration to V8","retained corrupt split cannot override V8","failed rename preserves original and removes staging"],
        "limits":["No Tauri IPC/dialogs or OS identity integration","Snapshot restore uses production IO, not an installer/UI flow"],
        "peak_rss_bytes":peak_rss_bytes()})
}

fn prepare_crash(directory: &Path) -> Value {
    fs::create_dir_all(directory).unwrap();
    let (mut vault, dek) = engine::create_vault(PASSWORD).unwrap();
    fill(&mut vault, &dek, 250, "old");
    engine::write_canonical_vault(directory, &mut vault, &dek).unwrap();
    fs::copy(directory.join("vault.lex"), directory.join("before.bin")).unwrap();
    fill(&mut vault, &dek, 250, "new");
    engine::seal_snapshot_manifest(&mut vault, &dek).unwrap();
    let mut candidate = engine::CANONICAL_MAGIC.to_vec();
    candidate.extend(serde_json::to_vec(&vault).unwrap());
    io::secure_write(&directory.join("candidate.bin"), &candidate).unwrap();
    json!({"kind":"crash-fixture","records":250,"candidate_bytes":candidate.len()})
}

fn gui_fixture(source: &Path, directory: &Path, count: usize) -> Value {
    use sha2::{Digest, Sha256};
    assert!(!directory.exists(), "GUI fixture output must not exist");
    let (mut vault, dek) = engine::open_current_vault(source, PASSWORD).unwrap();
    assert_eq!(vault.records.len(), count);
    let mut index = Vec::with_capacity(count);
    for number in 0..count {
        let mut record = synthetic_record(number, "initial");
        record["status"] = json!("active");
        record["type"] = json!("civil");
        record["createdAt"] = json!("2026-09-07T00:00:00Z");
        record["updatedAt"] = json!("2026-09-07T00:00:00Z");
        record["deadlines"] = json!([]);
        record["attachments"] = json!([]);
        for (item, entry) in record["diary"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .enumerate()
        {
            entry["id"] = json!(format!("synthetic-note-{number}-{item}"));
            entry["date"] = json!("2026-09-07");
        }
        let id = format!("practices_synthetic-{number:06}");
        let mut entry = engine::RecordEntry {
            versions: vec![],
            current: 0,
        };
        engine::append_record_version(&mut entry, &dek, &rmp_serde::to_vec_named(&record).unwrap())
            .unwrap();
        vault.records.insert(id.clone(), entry);
        index.push(engine::IndexEntry {
            id,
            field: "practices".into(),
            title: engine::extract_record_title_pub(&record, "practices"),
            tags: vec!["synthetic".into()],
            updated_at: "2026-09-07T00:00:00Z".into(),
            summary: engine::extract_record_summary(&record, "practices"),
        });
    }
    vault.index = engine::encrypt_index(&dek, &index).unwrap();
    fs::create_dir_all(directory).unwrap();
    engine::write_canonical_vault(directory, &mut vault, &dek).unwrap();
    // Match tauri-api.hashPwd exactly; only the UI hashes a human password.
    let hashed_password = hex::encode(Sha256::digest(PASSWORD.as_bytes()));
    engine::change_password_snapshot(directory, PASSWORD, &hashed_password).unwrap();
    let (reopened, reopened_dek) = engine::open_current_vault(directory, &hashed_password).unwrap();
    assert_eq!(reopened.records.len(), count);
    assert_eq!(
        engine::decrypt_index(&reopened_dek, &reopened.index)
            .unwrap()
            .len(),
        count
    );
    assert!(engine::open_current_vault(directory, PASSWORD).is_err());
    json!({"kind":"gui-fixture", "records":count, "vault":directory.join("vault.lex"),
        "ui_password":PASSWORD,"prehash":"SHA-256 hexadecimal","bytes":fs::metadata(directory.join("vault.lex")).unwrap().len()})
}

fn verify_crash(directory: &Path) -> Value {
    let observed = fs::read(directory.join("vault.lex")).unwrap();
    let before = fs::read(directory.join("before.bin")).unwrap();
    let after = fs::read(directory.join("candidate.bin")).unwrap();
    let generation = if observed == before {
        "old"
    } else if observed == after {
        "new"
    } else {
        panic!("Partial/mixed snapshot published")
    };
    let (vault, dek) = engine::open_current_vault(directory, PASSWORD).unwrap();
    assert_contents(&vault, &dek, 250, generation);
    json!({"kind":"crash-verification","generation":generation,"authenticated_records":250})
}

fn verify_native_export(path: &Path, count: usize, distinct_password: bool) -> Value {
    let raw = io::safe_bounded_read(path, 500 * 1024 * 1024).unwrap();
    assert!(raw.len() > 32);
    let backup_password = if distinct_password { BACKUP_PASSWORD } else { PASSWORD };
    let password = hex::encode(Sha256::digest(backup_password.as_bytes()));
    let key = crypto::derive_secure_key(&password, &raw[..32]).unwrap();
    let plaintext = crypto::decrypt_data(&key, &raw[32..]).unwrap();
    let data: Value = serde_json::from_slice(&plaintext).unwrap();
    let practices = data["practices"].as_array().unwrap();
    assert_eq!(practices.len(), count);
    let note_present = practices.iter().any(|practice| {
        practice.get("diary").and_then(Value::as_array).is_some_and(|notes| {
            notes.iter().any(|note| note.get("text").and_then(Value::as_str)
                .is_some_and(|text| text.starts_with("COLLAUDO-20260907-MAC:")))
        })
    });
    assert!(note_present, "The note committed by the native app must be in its backup");
    let wrong_password = hex::encode(Sha256::digest(b"SYNTHETIC-WRONG"));
    let wrong_key = crypto::derive_secure_key(&wrong_password, &raw[..32]).unwrap();
    assert!(crypto::decrypt_data(&wrong_key, &raw[32..]).is_err());
    let master_password_rejected = if distinct_password {
        let master_password = hex::encode(Sha256::digest(PASSWORD.as_bytes()));
        let master_key = crypto::derive_secure_key(&master_password, &raw[..32]).unwrap();
        assert!(crypto::decrypt_data(&master_key, &raw[32..]).is_err(),
            "A distinct backup password must reject the source vault's master password");
        Some(true)
    } else {
        None
    };
    json!({"kind":"native-export-verification", "records":practices.len(),
        "native_saved_note_present":note_present, "wrong_password_rejected":true,
        "distinct_backup_password":distinct_password,
        "master_password_rejected":master_password_rejected,
        "limits":"Native export verified with production cryptography; native import dialog not exercised"})
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let operation = args.get(1).expect("operation");
    let result = match operation.as_str() {
        "verify-native-export" => {
            assert!(args.len() == 4 || (args.len() == 5 && args[4] == "--distinct-backup-password"),
                "Usage: verify-native-export PATH RECORDS [--distinct-backup-password]; synthetic passwords only");
            verify_native_export(Path::new(&args[2]), args[3].parse().unwrap(), args.len() == 5)
        }
        "search" => search_benchmark(args[2].parse().unwrap()),
        "search-snapshot" => search_snapshot(Path::new(&args[2]), args[3].parse().unwrap()),
        "vault" => vault_benchmark(Path::new(&args[2]), args[3].parse().unwrap()),
        "reliability" => reliability(Path::new(&args[2])),
        "prepare-crash" => prepare_crash(Path::new(&args[2])),
        "gui-fixture" => gui_fixture(
            Path::new(&args[2]),
            Path::new(&args[3]),
            args[4].parse().unwrap(),
        ),
        "write-crash" => {
            let dir = Path::new(&args[2]);
            io::atomic_write_with_sync(
                &dir.join("vault.lex"),
                &fs::read(dir.join("candidate.bin")).unwrap(),
            )
            .unwrap();
            json!({"kind":"write-complete"})
        }
        "verify-crash" => verify_crash(Path::new(&args[2])),
        _ => panic!("unknown operation"),
    };
    println!("{}", serde_json::to_string(&result).unwrap());
}
