# Audit piattaforme e distribuzione — 6 settembre 2026

L'esame riguarda sorgenti, configurazioni, dipendenze dichiarate e pipeline.
Non sono stati letti archivi legali, credenziali o chiavi private preesistenti. Una nuova chiave di firma Android è stata creata e conservata fuori iCloud. Le verifiche
di rete su app installate e i test su Windows/Android/iOS non sono stati eseguiti.

## Esito e correzioni

Nel codice applicativo esaminato non risultano client HTTP, WebSocket,
telemetria remota, SDK pubblicitari o sincronizzazioni cloud. Le occorrenze
di “telemetry” in `platform.rs` scrivono solo log locali di migrazione.
Le descrizioni dei permessi Calendario inutilizzati sono state rimosse da
Info.plist: nei sorgenti non è presente una sincronizzazione EventKit. Questo è un risultato statico,
non una certificazione di assenza di traffico di tutti i processi coinvolti.

| Priorità | Riscontro | Stato |
| --- | --- | --- |
| Alta | Il template Android della CLI 2.10.1 dichiara INTERNET e non disabilita i backup; il progetto viene rigenerato in CI | Aggiunto `scripts/harden-android.py`: esclusioni cloud/trasferimento, Internet rimosso dal manifest release, cleartext vietato, verifica APK reale in CI |
| Alta | `set_content_protection` Android dichiara successo senza applicare protezione nativa | Lo script applica `FLAG_SECURE` all'Activity generata; resta necessaria verifica sul dispositivo |
| Alta | qpdf macOS copiato dalla singola architettura Homebrew, rinominato Intel e universale; fallback nasconde errore lipo | Eliminato fallback; verifica bloccante architetture e librerie. Sidecar locali ricostruiti e verificati per entrambe le architetture |
| Alta | Audit delle vulnerabilità continuava la release anche con errori | `cargo audit` e `npm audit` delle dipendenze runtime sono ora bloccanti |
| Media | Pipeline firmava APK ma copiava AAB senza firmarlo | AAB firmato con jarsigner; APK e AAB verificati dopo la firma |
| Alta | Sidecar scaricati da `latest` senza checksum indipendente e versioni fisse | Script macOS e preparazione Windows aggiornati con versioni/SHA256 fissati; un solo job Windows NSIS usa il runner. La CI completa non è stata eseguita |

I due difetti dei sidecar macOS sono stati corretti durante la preparazione dei
pacchetti: Typst 0.15.1 contiene le slice reali ARM64/Intel; qpdf 12.4.1 incorpora
staticamente libqpdf e libjpeg-turbo 3.2.0, con sole librerie Apple di sistema.
Sorgenti e archivi sono stati confrontati con SHA256 ufficiali. Il verificatore
supera tutte le sei varianti. Prove sintetiche reali su ARM64 e Intel tramite
Rosetta coprono template fascicolo, cifratura/decifratura, unione, estrazione,
rotazione, compressione e overlay. La versione minima macOS è ora 11.0.
Resta necessario provare l’intera app su sistemi puliti e le DLL Windows su VM.

## Supporto effettivo

| Piattaforma | Evidenza | Limite da chiudere |
| --- | --- | --- |
| macOS Apple Silicon | DMG ARM64 dedicato; sidecar autonomi e firma ad hoc verificata | Notarizzazione e collaudo completo dell’app, con monitoraggio rete |
| macOS Intel | DMG x86_64 dedicato e verificato; componenti provati via Rosetta | Collaudo su hardware Intel e macOS minimo 11 con WebKit 16.4+ |
| Windows x64 | NSIS reale, qpdf con 9 DLL e WebView2 Fixed incluso; 573 file verificati tramite SHA256 | Firma Authenticode, VM pulita, avvio, biometria, percorsi, file lock e traffico |
| Windows ARM | Nessun target nativo di release | Non dichiarare ottimizzazione ARM; eventuale emulazione va provata |
| Android | APK ARM64 firmato; manifest senza Internet e ZIP/ELF 16 KB verificati | WebView Chromium 111+, startup/storage/content URI/background e test fisici. Biometria e qpdf/Typst non disponibili |
| iPhone/iPad | Alcuni controlli `cfg(ios)` e rilevamento piattaforma | Nessuna pipeline/progetto iOS; funzioni critiche in platform.rs mancano di ramo iOS. Non è un port funzionante dimostrato |

Tauri separa il frontend dal codice Rust. La CSP e le capability limitano
il frontend; il core Rust, i plugin e i processi sidecar mantengono accesso
alle risorse del sistema. Quindi “CSP senza rete” non significa “processo
isolato dalla rete”. [Modello di sicurezza Tauri](https://v2.tauri.app/security/).

Typst locale può utilizzare pacchetti esterni: i template esaminati non ne
importano, ma il binario generale dispone di quella funzionalità. Una garanzia
rigorosa richiede blocco del traffico a livello di processo/sistema e verifica
dinamica. [Typst locale e pacchetti](https://typst.app/open-source/).

La precedente modalità offlineInstaller distribuiva WebView2 Evergreen. Il
pacchetto Windows finale include invece WebView2 Fixed 152.0.4191.62: non
richiede un download in fase di installazione e non usa gli aggiornamenti
automatici Evergreen. Aggiornare il motore richiede una nuova distribuzione.
L’installer NSIS applica inoltre i permessi RX ai due SID AppPackages sulla
sola directory del runtime, come richiesto da Fixed Runtime 120+ su Windows 10;
un errore impedisce il completamento dell’installazione. L’hook è stato
compilato e ispezionato, senza esecuzione su Windows.
Il traffico del motore e del sistema resta da misurare: l'inclusione del runtime
non certifica da sola l'isolamento dalla rete.
[Distribuzione WebView2](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/evergreen-vs-fixed-version).

Le esportazioni in chiaro, i documenti aperti con altre applicazioni, le
notifiche del sistema e le cartelle scelte dall'utente costituiscono confini
di riservatezza distinti dal vault cifrato. Backup OS e cartelle sincronizzate
possono trasferire dati anche senza un client cloud dentro LexFlow. Su Android
`allowBackup=false` da solo non copre ogni trasferimento tra dispositivi;
per questo sono state aggiunte anche regole di esclusione per entrambe le
modalità. [Backup Android](https://developer.android.com/identity/data/autobackup?hl=en).

## Validazione effettuata e necessaria

Eseguiti otto test isolati per idempotenza, conservazione dei componenti nativi,
separazione debug/release, esclusioni backup, rifiuto template sconosciuti,
rifiuto manifest APK insicuri, librerie Android 64 bit prive di allineamento 16 KB e librerie macOS non autonome. È stato inoltre
verificato che l'inserimento `FLAG_SECURE` accetti il template effettivamente
incorporato nella CLI Tauri installata 2.10.1.

Prima della consegna: costruire pacchetti di produzione con dati sintetici,
controllare i manifest finali e le firme, installare su macOS Intel/Apple
Silicon, Windows pulito e Android fisico; esercitare export/import, PDF,
blocco/sospensione, notifiche e recupero. Monitorare DNS e connessioni del
processo principale, WebView e sidecar durante tutti i flussi, ripeterli con
rete disabilitata. Su Android provare screenshot/recents e backup/restore
cloud e da dispositivo. [Protezione Activity Android](https://developer.android.com/security/fraud-prevention/activities).
