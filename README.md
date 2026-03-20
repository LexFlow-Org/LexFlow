# LexFlow

> Gestionale per Studi Legali con Crittografia Zero-Knowledge

**Versione:** 2.0.5
**Piattaforme:** macOS (Universal) · Windows 10/11 · Android 7+
**Tecnologia:** Tauri v2 · React 19 · Rust
**Bundle ID:** `com.pietrolongo.lexflow`

---

## Panoramica

LexFlow è un gestionale completo per studi legali con crittografia di livello bancario. Tutti i dati — fascicoli, agenda, contatti, time tracking — sono cifrati localmente con AES-256-GCM-SIV e non transitano mai su server esterni.

### Funzionalità Principali

| Modulo | Descrizione |
|--------|-------------|
| **Fascicoli** | Gestione pratiche con ricerca fuzzy, esportazione PDF professionale |
| **Agenda** | Calendario giorno/settimana/mese con notifiche native |
| **Scadenzario** | Deadline processuali con briefing giornalieri configurabili |
| **Contatti** | Rubrica professionale con verifica conflitti di interesse |
| **Gestione Ore** | Time tracking con timer live e griglia settimanale |
| **Ricerca** | Trigram index con BM25 ranking — ricerca parziale, fuzzy, typo-tolerant |

### Sicurezza

| Feature | Dettaglio |
|---------|-----------|
| **Cifratura** | AES-256-GCM-SIV (nonce-misuse resistant) |
| **Derivazione chiave** | Argon2id con parametri adattivi (benchmark ~300-500ms) |
| **Architettura** | Envelope encryption KEK/DEK — cambio password O(1) |
| **Per-record** | Ogni fascicolo cifrato individualmente con compressione zstd |
| **Biometria** | Touch ID (macOS) / Windows Hello / Impronta (Android) |
| **Recovery** | Chiave di emergenza base32 (XXXX-XXXX-XXXX-XXXX) |
| **Anti brute-force** | Backoff esponenziale: 5s → 15s → 30s → 60s → 5min → 15min |
| **Licenze** | Firma digitale Ed25519 offline, chiavi monouso (burn-hash) |
| **Test** | 111 test di sicurezza (penetration, APT, timing oracle, fuzzing) |

---

## Stack Tecnologico

| Layer | Tecnologia |
|-------|------------|
| Frontend | React 19 + Vite 7 + Tailwind CSS 4 |
| Backend | Rust (Tauri v2.10) — 18 moduli |
| Vault | Formato v4 — envelope encryption + per-record + HMAC header |
| Crypto | aes-gcm-siv + argon2 + hmac-sha2 + ed25519-dalek (RustCrypto) |
| Search | Trigram index cifrato + BM25 ranking |
| PDF | Typst (sidecar nativo) |
| Notifiche | AOT scheduling (Android) + cron async (desktop) |

## Architettura Backend (Rust)

```
src-tauri/src/
├── lib.rs              ← Entry point + Tauri command registration
├── constants.rs        ← Crypto constants, file names, platform detection
├── crypto.rs           ← AES-256-GCM-SIV encrypt/decrypt, Argon2id derive
├── vault_v4.rs         ← Vault engine: KEK/DEK, envelope, per-record, HMAC
├── vault.rs            ← Tauri commands: unlock, lock, load, save, change_password
├── state.rs            ← AppState: SecureKey, DEK, mutex, mlock
├── security.rs         ← Sensitive<T>, disable_core_dumps, mlock, secure_delete
├── lockout.rs          ← Exponential backoff, HMAC-protected counter
├── search.rs           ← Trigram index, BM25, Italian stop words
├── license.rs          ← Ed25519 verification, burn registry, sentinel
├── bio.rs              ← Biometric auth (Touch ID, Windows Hello, Android)
├── audit.rs            ← Encrypted audit log
├── settings.rs         ← Encrypted settings with migration
├── import_export.rs    ← Vault export/import (.lex backup files)
├── notifications.rs    ← Desktop cron + mobile AOT scheduling
├── platform.rs         ← Machine fingerprint, local encryption key
├── io.rs               ← Atomic write, secure_write, safe_bounded_read
├── files.rs            ← File picker, PDF generation, typst sidecar
├── window.rs           ← Window controls, minimize, maximize, tray
├── setup.rs            ← App initialization, tray, autolock, integrity check
└── vault_v4_tests.rs   ← 111 security tests
```

## Sviluppo

```bash
# Dev
npm run dev              # Avvia dev (Tauri + Vite)

# Build
npm run build            # Build macOS Universal
npm run build:me         # Build + deploy in /Applications

# Test
cd src-tauri && cargo test --lib   # 111 test di sicurezza

# Lint
cd src-tauri && cargo fmt && cargo clippy -- -W clippy::all -D warnings
```

## Documentazione

| Documento | Percorso |
|-----------|----------|
| Security Whitepaper | [`docs/security-whitepaper.typ`](docs/security-whitepaper.typ) |
| Guida Utente | [`docs/guida-utente.typ`](docs/guida-utente.typ) |
| Release Notes v2.0 | [`docs/release-notes-v2.typ`](docs/release-notes-v2.typ) |
| Security Testing CI | [`ci/README-security-testing.md`](ci/README-security-testing.md) |
| Changelog | [`CHANGELOG.md`](CHANGELOG.md) |

## Licenza

Software proprietario. Tutti i diritti riservati.
© 2024-2026 Pietro Longo
