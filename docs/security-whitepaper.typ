// ══════════════════════════════════════════════════════════════════════════
// LexFlow — Security Whitepaper v2.0
// Architettura Crittografica del Vault v4
// ══════════════════════════════════════════════════════════════════════════

// ── Palette Premium (Tailwind Slate) ──
#let slate-900 = rgb("#0F172A")
#let slate-700 = rgb("#334155")
#let slate-500 = rgb("#475569")
#let slate-300 = rgb("#CBD5E1")
#let slate-100 = rgb("#F1F5F9")
#let slate-50  = rgb("#F8FAFC")
#let divider   = rgb("#E2E8F0")
#let gold      = rgb("#b89520")

#set page(
  paper: "a4",
  margin: (top: 3cm, bottom: 2.5cm, left: 2.5cm, right: 2.5cm),
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
#set par(justify: true, leading: 0.75em)
#set heading(numbering: "1.1")

// ══════════════════════════════════════════════════════════════════════════
//  COPERTINA
// ══════════════════════════════════════════════════════════════════════════

#v(4cm)
#align(center)[
  #text(size: 28pt, weight: "bold", fill: slate-900, tracking: 1pt)[LexFlow]
  #v(4pt)
  #text(size: 12pt, fill: gold, tracking: 3pt, weight: "medium")[LAW SUITE]
  #v(2cm)
  #line(length: 40%, stroke: 0.5pt + slate-300)
  #v(1cm)
  #text(size: 18pt, weight: "bold", fill: slate-900)[Security Whitepaper]
  #v(8pt)
  #text(size: 11pt, fill: slate-500)[Architettura Crittografica — Vault v4]
  #v(4pt)
  #text(size: 10pt, fill: slate-500)[Versione 2.0 · Marzo 2026]
  #v(3cm)
  #text(size: 9pt, fill: slate-500)[
    Documento tecnico di architettura \
    macOS · Windows · Android
  ]
]

#pagebreak()

// ══════════════════════════════════════════════════════════════════════════
//  INDICE
// ══════════════════════════════════════════════════════════════════════════

#outline(title: "Indice", indent: 1.5em)
#pagebreak()

// ══════════════════════════════════════════════════════════════════════════
//  1. PANORAMICA
// ══════════════════════════════════════════════════════════════════════════

= Panoramica

LexFlow è un gestionale per studi legali con crittografia *zero-knowledge*. Tutti i dati sensibili — fascicoli, agenda, contatti, time tracking, fatturazione — sono cifrati localmente con AES-256-GCM-SIV prima di essere scritti su disco. Nessun dato transita mai in chiaro su rete o cloud.

Il vault v4, introdotto nella versione 2.0, rappresenta un'evoluzione completa dell'architettura crittografica rispetto al precedente formato monolitico. L'obiettivo è fornire la massima sicurezza senza compromettere le performance, con un design verificabile e standard industriali.

== Principi di Design

- *Zero-Knowledge*: solo l'utente conosce la password. Nessun server, nessun recovery remoto.
- *Defense in Depth*: ogni layer aggiunge protezione indipendente.
- *Fail-Closed*: ogni errore blocca l'accesso, mai lo permette.
- *Minimo Privilegio*: le chiavi vivono in RAM solo il tempo necessario.
- *Verifica Formale*: 111 test di sicurezza + property-based testing.

#v(0.5cm)
#line(length: 100%, stroke: 0.3pt + divider)

= Architettura Crittografica

== Gerarchia delle Chiavi (KEK/DEK)

Il vault v4 utilizza un pattern *envelope encryption* a due livelli:

#table(
  columns: (auto, 1fr),
  stroke: 0.5pt + slate-300,
  inset: 8pt,
  [*Livello*], [*Descrizione*],
  [KEK], [Key Encryption Key — derivata dalla password via Argon2id. Wrappa la DEK. Zeroizzata dalla RAM immediatamente dopo l'unwrap.],
  [DEK], [Data Encryption Key — 256 bit random (OsRng). Cifra i record e l'indice. Resta in RAM durante la sessione, protetta da mlock.],
)

*Vantaggi*:
- *Cambio password O(1)*: si ri-wrappa solo la DEK (32 byte), non l'intero vault.
- *Recovery key*: secondo wrapper della stessa DEK con chiave stampabile.
- *Biometria*: la DEK può essere cachata nel keystore nativo (Keychain, DPAPI, AndroidKeyStore).

== Derivazione Chiave (Argon2id)

La KEK è derivata dalla password tramite Argon2id con parametri adattivi:

#table(
  columns: (auto, auto, 1fr),
  stroke: 0.5pt + slate-300,
  inset: 8pt,
  [*Parametro*], [*Valore*], [*Funzione*],
  [Algoritmo], [Argon2id v0x13], [Resistente sia a GPU che side-channel],
  [m_cost], [Adattivo (16–512 MB)], [Auto-benchmark: target 300–500ms per device],
  [t_cost], [3], [Iterazioni (OWASP minimum)],
  [p_cost], [1–4], [Parallelismo adattivo al numero di core],
  [Salt], [32 byte OsRng], [Fresh per ogni creazione/cambio password],
  [Output], [256 bit], [Chiave AES-256],
)

*Validazione parametri*: all'apertura del vault, i parametri KDF sono validati con floor minimo (m ≥ 8192, t ≥ 2, salt ≥ 16 byte) e ceiling massimo (m ≤ 512MB, t ≤ 100) per prevenire attacchi di downgrade e denial-of-service.

== Cifratura (AES-256-GCM-SIV)

Tutti i dati sono cifrati con AES-256-GCM-SIV (*nonce-misuse resistant*):

- *Nonce*: 96 bit, generati con `OsRng` (CSPRNG del kernel) per ogni operazione di cifratura.
- *AAD* (Additional Authenticated Data): `b"LEXFLOW-RECORD"` per i record, `b"LEXFLOW-DEK-WRAP"` per il wrapping della DEK. Previene cross-context confusion.
- *Tag*: 128 bit, separato dal ciphertext e verificato prima della decifratura.

*Perché GCM-SIV e non GCM?* In caso di riutilizzo accidentale del nonce (bug software), GCM perde la confidenzialità di tutti i dati cifrati con quella chiave. GCM-SIV perde solo l'indistinguibilità dei messaggi identici — un fallback molto meno catastrofico.

== Per-Record Encryption

Ogni fascicolo è cifrato individualmente con il proprio nonce:

- *Corruzione isolata*: un record danneggiato non compromette gli altri.
- *Lazy decryption*: l'indice (titoli, tag) si decifra all'unlock; i contenuti on-demand al click.
- *Compressione*: zstd livello 3 pre-encrypt (60–80% riduzione su testo legale).
- *Versioning*: ultime 5 versioni per record (undo, cronologia modifiche).

== Header HMAC

L'header del vault è protetto da HMAC-SHA256 calcolato con la KEK:

- Copre: `version`, `kdf`, `wrapped_dek`, `dek_iv`, `dek_alg`.
- Verifica *constant-time* (via `hmac::Mac::verify_slice`).
- Previene tampering dei parametri KDF (es. downgrade m_cost per velocizzare brute-force).

#pagebreak()

= Protezione a Runtime

== Gestione Memoria

#table(
  columns: (auto, 1fr),
  stroke: 0.5pt + slate-300,
  inset: 8pt,
  [*Meccanismo*], [*Descrizione*],
  [Zeroizing], [Tutte le chiavi (KEK, DEK, password) in `Zeroizing<Vec<u8>>` — azzerate automaticamente alla drop.],
  [mlock], [Le pagine di memoria contenenti la DEK sono bloccate in RAM (non swappabili su disco).],
  [Core dump], [Disabilitati all'avvio via `setrlimit(RLIMIT_CORE, 0)` su Unix e `SetErrorMode` su Windows.],
  [Sensitive\<T\>], [Wrapper type che implementa `Debug`/`Display` come `[REDACTED]` — previene log accidentali.],
)

== Brute-Force Protection

Backoff esponenziale persistito su disco con HMAC integrity:

#table(
  columns: (auto, auto),
  stroke: 0.5pt + slate-300,
  inset: 8pt,
  [*Tentativo*], [*Delay*],
  [1–3], [Nessuno],
  [4], [5 secondi],
  [5], [15 secondi],
  [6], [30 secondi],
  [7], [60 secondi],
  [8], [5 minuti],
  [9+], [15 minuti],
  [10], [Wipe DEK dal keystore],
)

Combinato con Argon2 a ~400ms per tentativo: un attaccante può provare ~5 password/ora.

== Auto-Lock

Timer configurabile dall'utente (default 5 minuti). Al lock:
1. DEK zeroizzata dalla RAM
2. Cache in-memory svuotata
3. Frontend mostra LoginScreen
4. Biometria auto-trigger al ritorno

Trigger aggiuntivi: chiusura finestra (X), app in background (mobile), screen lock del sistema.

#pagebreak()

= Formato Vault v4

```
LEXFLOW_V4 (10 byte magic)
{
  "version": 4,
  "kdf": {
    "alg": "argon2id",
    "m": 65536, "t": 3, "p": 2,
    "salt": "base64..."
  },
  "wrapped_dek": "base64...",
  "dek_iv": "base64...",
  "dek_alg": "aes-256-gcm-siv",
  "header_mac": "base64...",
  "rotation": {
    "created": "2026-03-20T...",
    "interval_days": 90,
    "writes": 0, "max_writes": 10000
  },
  "index": { "iv": "...", "tag": "...", "data": "..." },
  "records": {
    "uuid-1": {
      "versions": [
        { "v": 1, "ts": "...", "iv": "...", "tag": "...", "data": "..." }
      ],
      "current": 1
    }
  }
}
```

= Generazione IV/Nonce

Tutti i nonce sono generati con `rand::rngs::OsRng` — il CSPRNG del sistema operativo:
- macOS: `SecRandomCopyBytes` (Common Crypto)
- Windows: `BCryptGenRandom` (CNG)
- Android: `/dev/urandom` (kernel CSPRNG)
- Linux: `getrandom(2)` syscall

14 punti di generazione verificati, zero `thread_rng` nel codice.

= Recovery Key

Chiave di emergenza in formato base32 leggibile: `XXXX-XXXX-XXXX-XXXX`.

- Generata alla creazione del vault (16 byte OsRng).
- Secondo wrapper della stessa DEK (Argon2id + AES-256-GCM-SIV).
- Mostrata una sola volta — l'utente la stampa o la salva in un password manager.
- Opzionale: l'utente può rifiutarla.

= Encrypted Search

Indice trigrammi cifrato con BM25 ranking:
- Ricerca fuzzy, typo-tolerant, prefix nativo.
- Stop words specifiche per il dominio legale italiano.
- Generation counter per crash-consistency.
- L'indice è una *cache derivata*: se si corrompe, si ricostruisce dai record.

#pagebreak()

= Stack Crittografico

Tutte le dipendenze sono del progetto RustCrypto (auditato, standard industriale):

#table(
  columns: (auto, auto, 1fr),
  stroke: 0.5pt + slate-300,
  inset: 8pt,
  [*Crate*], [*Versione*], [*Funzione*],
  [aes-gcm-siv], [0.11], [Cifratura autenticata nonce-misuse resistant],
  [argon2], [0.5], [Derivazione chiave da password],
  [hmac + sha2], [0.12 / 0.10], [HMAC-SHA256 per integrity check],
  [rand], [0.8], [OsRng — CSPRNG del sistema operativo],
  [zeroize], [1.7], [Azzeramento memoria alla drop],
  [ed25519-dalek], [2.1], [Firma digitale licenze],
  [zstd], [0.13], [Compressione pre-encrypt],
  [base64 + hex], [0.22 / 0.4], [Encoding],
)

= Testing

111 test di sicurezza suddivisi in:
- *Roundtrip crypto* (9): encrypt/decrypt, wrap/unwrap, serialize/deserialize
- *Penetration tampering* (22): bit flip, tag corruption, IV tampering, KDF downgrade
- *Attack simulation* (20): timing oracle, record swap, memory bomb, decompression bomb
- *APT advanced* (17): metadata leakage, exhaustive bit flip, IND-CPA 1000x
- *Crash resilience* (5): crash during write/index update/password change
- *Property-based* (4): 100+ input random per proprietà
- *Stress/concurrency* (3): 10 thread reader + 3 writer simultanei
- *Unicode edge cases* (10): null byte, emoji, zero-width chars, 1MB strings
- *Cross-platform* (2): Argon2 determinismo, formato portabile

Plus: CI con `cargo audit`, binary leak check, Python attack scripts.

= Threat Model

#table(
  columns: (auto, 1fr),
  stroke: 0.5pt + slate-300,
  inset: 8pt,
  [*Scenario*], [*Protezione*],
  [Attaccante remoto], [AES-256-GCM-SIV + Argon2id. Senza password il vault è un blob opaco.],
  [Accesso al file vault], [Header HMAC, per-record auth, AAD. Manomissione rilevata.],
  [Device sbloccato incustodito], [Auto-lock + DEK zeroize + clipboard timeout.],
  [Brute-force locale], [Argon2 ~400ms + backoff esponenziale. ~5 tentativi/ora.],
  [Device compromesso (root)], [*Non protetto*. Un OS compromesso può leggere la RAM.],
)

#v(2cm)
#align(center)[
  #text(size: 9pt, fill: slate-500)[
    LexFlow Security Whitepaper · v2.0 · Marzo 2026 \
    Documento generato automaticamente — aggiornato ad ogni release.
  ]
]
