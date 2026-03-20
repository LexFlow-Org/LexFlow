#let slate-900 = rgb("#0F172A")
#let slate-700 = rgb("#334155")
#let slate-500 = rgb("#475569")
#let slate-300 = rgb("#CBD5E1")
#let slate-100 = rgb("#F1F5F9")
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

#v(4cm)
#align(center)[
  #text(size: 28pt, weight: "bold", fill: slate-900, tracking: 1pt)[LexFlow]
  #v(4pt)
  #text(size: 12pt, fill: gold, tracking: 3pt, weight: "medium")[LAW SUITE]
  #v(2cm)
  #line(length: 40%, stroke: 0.5pt + slate-300)
  #v(1cm)
  #text(size: 18pt, weight: "bold", fill: slate-900)[Documentazione Tecnica]
  #v(8pt)
  #text(size: 11pt, fill: slate-500)[Gestionale per Studi Legali con Crittografia Zero-Knowledge]
  #v(4pt)
  #text(size: 10pt, fill: slate-500)[Versione 2.0.5 · Marzo 2026]
  #v(3cm)
  #text(size: 9pt, fill: slate-500)[
    macOS (Universal) · Windows 10/11 · Android 7+ \
    Tauri v2 · React 19 · Rust
  ]
]

#pagebreak()
#outline(title: "Indice", indent: 1.5em)
#pagebreak()

= Panoramica

LexFlow è un gestionale completo per studi legali con crittografia *zero-knowledge*. Tutti i dati sensibili — fascicoli, agenda, contatti, time tracking — sono cifrati localmente con AES-256-GCM-SIV prima di essere scritti su disco. Nessun dato transita mai in chiaro su rete o cloud.

#v(0.3cm)

#table(
  columns: (auto, 1fr),
  stroke: 0.5pt + slate-300,
  inset: 8pt,
  [*Versione*], [2.0.5],
  [*Piattaforme*], [macOS (Apple Silicon + Intel), Windows 10/11, Android 7+],
  [*Tecnologia*], [Tauri v2 · React 19 · Rust],
  [*Bundle ID*], [`com.pietrolongo.lexflow`],
)

= Funzionalità Principali

#table(
  columns: (auto, 1fr),
  stroke: 0.5pt + slate-300,
  inset: 8pt,
  [*Modulo*], [*Descrizione*],
  [Fascicoli], [Gestione pratiche con ricerca fuzzy, esportazione PDF professionale],
  [Agenda], [Calendario giorno/settimana/mese con notifiche native],
  [Scadenzario], [Deadline processuali con briefing giornalieri configurabili],
  [Contatti], [Rubrica professionale con verifica conflitti di interesse],
  [Gestione Ore], [Time tracking con timer live e griglia settimanale],
  [Ricerca], [Trigram index con BM25 ranking — ricerca parziale, fuzzy, typo-tolerant],
)

= Sicurezza

#table(
  columns: (auto, 1fr),
  stroke: 0.5pt + slate-300,
  inset: 8pt,
  [*Feature*], [*Dettaglio*],
  [Cifratura], [AES-256-GCM-SIV (nonce-misuse resistant)],
  [Derivazione chiave], [Argon2id con parametri adattivi (benchmark ~300–500ms)],
  [Architettura], [Envelope encryption KEK/DEK — cambio password O(1)],
  [Per-record], [Ogni fascicolo cifrato individualmente con compressione zstd],
  [Biometria], [Touch ID (macOS) / Windows Hello / Impronta (Android)],
  [Recovery], [Chiave di emergenza base32 (XXXX-XXXX-XXXX-XXXX)],
  [Anti brute-force], [Backoff esponenziale: 5s → 15s → 30s → 60s → 5min → 15min],
  [Licenze], [Firma digitale Ed25519 offline, chiavi monouso (burn-hash)],
  [Test], [111 test di sicurezza (penetration, APT, timing oracle)],
)

#pagebreak()

= Stack Tecnologico

#table(
  columns: (auto, 1fr),
  stroke: 0.5pt + slate-300,
  inset: 8pt,
  [*Layer*], [*Tecnologia*],
  [Frontend], [React 19 + Vite 7 + Tailwind CSS 4],
  [Backend], [Rust (Tauri v2.10) — 18 moduli],
  [Vault], [Formato v4 — envelope encryption + per-record + HMAC header],
  [Crypto], [aes-gcm-siv + argon2 + hmac-sha2 + ed25519-dalek (RustCrypto)],
  [Search], [Trigram index cifrato + BM25 ranking],
  [PDF], [Typst (sidecar nativo)],
  [Notifiche], [AOT scheduling (Android) + cron async (desktop)],
)

= Architettura Backend (Rust)

Il backend è organizzato in 18 moduli Rust indipendenti:

#table(
  columns: (auto, 1fr),
  stroke: 0.5pt + slate-300,
  inset: 8pt,
  [*Modulo*], [*Funzione*],
  [`lib.rs`], [Entry point + registrazione comandi Tauri],
  [`constants.rs`], [Costanti crypto, nomi file, detection piattaforma],
  [`crypto.rs`], [AES-256-GCM-SIV encrypt/decrypt, Argon2id derive],
  [`vault_v4.rs`], [Engine vault: KEK/DEK, envelope, per-record, HMAC],
  [`vault.rs`], [Comandi Tauri: unlock, lock, load, save, change\_password],
  [`state.rs`], [AppState: SecureKey, DEK, mutex, mlock],
  [`security.rs`], [Sensitive\<T\>, disable\_core\_dumps, mlock, secure\_delete],
  [`lockout.rs`], [Backoff esponenziale, contatore HMAC-protetto],
  [`search.rs`], [Trigram index, BM25, stop words legali italiane],
  [`license.rs`], [Verifica Ed25519, burn registry, sentinel],
  [`bio.rs`], [Autenticazione biometrica (Touch ID, Windows Hello, Android)],
  [`audit.rs`], [Log di audit cifrato],
  [`settings.rs`], [Impostazioni cifrate con migrazione],
  [`import_export.rs`], [Export/import vault (file .lex di backup)],
  [`notifications.rs`], [Cron desktop + scheduling AOT mobile],
  [`platform.rs`], [Machine fingerprint, chiave cifratura locale],
  [`io.rs`], [Scrittura atomica, secure\_write, safe\_bounded\_read],
  [`files.rs`], [File picker, generazione PDF, sidecar Typst],
  [`window.rs`], [Controlli finestra, minimize, maximize, tray],
  [`setup.rs`], [Inizializzazione app, tray, autolock, integrity check],
)

= Sviluppo

```
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

#pagebreak()

= Documentazione Disponibile

#table(
  columns: (auto, 1fr),
  stroke: 0.5pt + slate-300,
  inset: 8pt,
  [*Documento*], [*Descrizione*],
  [Security Whitepaper], [Architettura crittografica completa del vault v4],
  [Guida Utente], [Manuale completo dell'applicazione per utenti finali],
  [Release Notes v2.0], [Novità della versione 2.0 per utenti],
  [Security Testing CI], [Guida MIRI, ASan, Frida, binary analysis per CI],
  [Changelog], [Storico completo delle modifiche],
)

#v(1cm)

= Licenza

Software proprietario. Tutti i diritti riservati. \
© 2024–2026 Pietro Longo

#v(2cm)
#align(center)[
  #text(size: 9pt, fill: slate-500)[
    LexFlow · Documentazione Tecnica · v2.0.5 · Marzo 2026
  ]
]
