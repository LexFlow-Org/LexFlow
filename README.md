# LexFlow

Gestionale per studi legali con archivio locale cifrato, realizzato con Tauri, React e Rust.

**Versione configurata: 1.0.1.** I [quattro installer aggiornati](releases/2026-09-07/LEGGIMI.txt) includono le correzioni del 7 settembre per Impostazioni, backup e prestazioni; Android ha codice interno 253. Il [collaudo](docs/COLLAUDO-2026-09-07.md) e la [verifica di interruttori, licenze e Touch ID](docs/CORREZIONE-IMPOSTAZIONI-2026-09-07.md) distinguono risultati e limiti. Restano il collaudo completo sui dispositivi di destinazione, il crash Android emulato irrisolto e la firma Apple necessaria per Touch ID.

Dal successivo aggiornamento Windows dell’8 settembre è stato rimosso Windows Hello: accesso con Master Password, cancellazione della vecchia credenziale biometrica e licenze invariate. [Dettagli e conseguenze dell’aggiornamento](docs/RIMOZIONE-WINDOWS-HELLO-2026-09-08.md).

**Sorgenti successivi agli installer:** il nuovo [audit backend dell’8 settembre](docs/AUDIT-BACKEND-2026-09-08.md) corregge licenze, reset, concorrenza, registro attività, backup, ricerca e notifiche. Queste modifiche devono ancora essere distribuite nella 1.0.2. Le vecchie attivazioni richiederanno una conferma con il codice originale sul dispositivo già attivato; l'emittente resta invariato.

## Funzioni e confini di sicurezza

LexFlow gestisce fascicoli, agenda, scadenze, contatti, ore e fatturazione senza un servizio cloud applicativo. I dati del vault sono cifrati con AES-256-GCM-SIV; Argon2id deriva la chiave dalla password. Il formato V8 conserva header, indice e record in uno snapshot atomico con manifest autenticato.

Gli allegati esterni restano file separati: il vault ne conserva i percorsi. PDF e CSV esportati, appunti, notifiche e servizi del sistema operativo richiedono protezioni proprie. L'assenza di traffico di rete dell'intero processo deve essere verificata sui pacchetti nativi; l'audit dei sorgenti non equivale a una certificazione di isolamento.

La redazione PDF è sospesa perché la precedente implementazione non garantiva la rimozione irreversibile dei contenuti. Le restrizioni PDF su copia e stampa non sostituiscono la cifratura per impedire l'apertura del documento.

I target previsti sono **macOS, Windows e Android**. Sono stati preparati binari PDF autonomi per desktop; restano prove complete su dispositivi da completare. **iOS non è disponibile**. Lo sblocco dei formati precedenti tramite password migra al V8; consultare l'audit prima di intervenire su un archivio esistente o su una chiave di recupero legacy.

Il pacchetto macOS richiede macOS 11+ con Safari/WebKit 16.4+; Android richiede ARM64, Android 7+ e WebView Chromium 111+. Il solo numero di versione del sistema non garantisce un motore WebView abbastanza recente: [compatibilità Tailwind 4](https://tailwindcss.com/docs/compatibility#browser-support). Android usa la password; i componenti PDF qpdf/Typst sono disponibili soltanto su desktop.

## Sviluppo e verifica

Sono necessari Node.js/npm, Rust e i prerequisiti Tauri del sistema di destinazione. Le versioni usate nelle verifiche sono riportate nell'audit. Installare le dipendenze del progetto e del frontend:

```sh
npm ci
npm --prefix client ci
npm run dev
```

I comandi principali di verifica sono:

```sh
npm --prefix client test
npm --prefix client run lint
npm --prefix client run build
cargo test --locked --lib --manifest-path src-tauri/Cargo.toml -- --test-threads=1
cargo clippy --locked --lib --manifest-path src-tauri/Cargo.toml -- -D warnings
npm run test:native-hardening
```

Per generare un pacchetto sul sistema e con gli strumenti appropriati:

| Destinazione | Comando |
|---|---|
| macOS Apple Silicon e Intel, due DMG separati | `npm run build:mac` |
| macOS Apple Silicon | `npm run build:mac-arm` |
| macOS Intel | `npm run build:mac-intel` |
| Windows NSIS, da Developer PowerShell su Windows x64 | `npm run build:win` |
| Android, inizializzazione | `npm run android:init` |
| Android APK | `npm run android:build` |
| Android AAB | `npm run android:build-aab` |

Per Windows il runner prepara Typst, qpdf con DLL e WebView2 Fixed a versioni e SHA256 fissati. Per la firma locale macOS, anche da un progetto in iCloud, usare il flusso `package-macos-local.sh` documentato in [scripts/README.md](scripts/README.md); `build:me` ora compila senza cancellare o installare app.

Questi comandi non attestano che il relativo pacchetto sia pronto alla distribuzione. I controlli sui sidecar PDF, la firma e il collaudo della release sono descritti nelle [note sulle piattaforme](docs/platform-audit-notes.md).

Su macOS il controllo Touch ID è compilato nell'app: chi la usa non deve installare Swift, Xcode o Command Line Tools. L'attivazione richiede però hardware configurato e firma/entitlement compatibili con il Portachiavi Data Protection. Nei pacchetti locali con firma ad hoc e senza tali entitlement la biometria risulta indisponibile e si usa la Master Password. Le credenziali biometriche legacy non protette vanno riconfigurate dopo un accesso con password; non vengono lette come ripiego. Dettagli e limiti del collaudo sono nel [rapporto backend](docs/COLLAUDO-2026-09-07-backend.md).

## Generazione delle licenze

Gli strumenti di emissione delle licenze sono separati dall'app distribuita. Su Mac puoi fare doppio clic su `Crea licenza LexFlow.command`, nella radice del progetto. Da Terminale su macOS/Linux usare `scripts/generate-license.sh`; su Windows eseguire `python scripts/generate_license_v2.py`. Opzioni, requisiti e gestione del registro sono descritti in [scripts/README.md](scripts/README.md). Chiavi private e registri delle licenze devono restare fuori dal controllo versione e dai pacchetti per gli utenti.

## Documentazione corrente

| Documento | Contenuto |
|---|---|
| [Rapporto di audit](docs/AUDIT-SICUREZZA-2026-09-06.md) | Risultati complessivi, prestazioni e verifiche prima della consegna |
| [Vault](docs/vault-audit-notes.md) | Cifratura, migrazione, persistenza, recupero e limiti antiregressione |
| [Piattaforme](docs/platform-audit-notes.md) | Offline, sidecar, firme e supporto effettivo dei dispositivi |
| [Dipendenze](docs/dependency-audit-notes.md) | Metodo dell'audit, vulnerabilità, avvisi residui e impronte dei lockfile |
| [Strumenti](scripts/README.md) | Licenze, preparazione e verifiche della distribuzione |
| [Changelog](CHANGELOG.md) | Modifiche correnti e cronologia delle versioni precedenti |

Le vecchie copie Typst del README, delle release notes, della guida e del whitepaper V4 sono state rimosse perché duplicate o superate. Per le affermazioni sul comportamento attuale fanno riferimento i rapporti sopra elencati.

## Licenza

Software proprietario. Tutti i diritti riservati.
© 2024–2026 Pietro Longo
