# Changelog -- LexFlow

Formato: [SemVer](https://semver.org/) -- `MAJOR.MINOR.PATCH`

---

## [1.6.5] -- 2026-03-14

### Fixed
- **Notifiche desktop non arrivavano** -- Le notifiche macOS ora vengono inviate tramite subprocess Swift su un thread dedicato invece che via `run_on_main_thread`. Quando la finestra era nascosta (chiusa con ✕ ma app in background), il main thread non processava le callback e le notifiche venivano silenziosamente ignorate. Ora tutte le notifiche (briefing, promemoria singoli e raggruppati) usano il percorso Swift diretto che funziona indipendentemente dallo stato della finestra
- **Icona ExternalLink rimossa dagli eventi autoSync** -- Nella vista Agenda (sia nella sidebar "In Arrivo" che nella timeline giornaliera), l'icona ExternalLink è stata rimossa dagli eventi sincronizzati dai fascicoli. Il pulsante "Fascicolo" nel modal evento è sufficiente per navigare al fascicolo collegato; l'icona Briefcase ora appare per tutti gli eventi con fascicolo collegato

### Added
- **Logging diagnostico cron job** -- Il cron desktop ora logga ad ogni tick: numero di briefing times, numero di schedule items, e i prossimi 5 fire times per facilitare il debug. Se il file schedule non viene trovato o la decifratura fallisce, viene loggato un warning esplicito

---

## [1.6.4] -- 2026-03-14

### Changed
- **Toast attivazione licenza** -- Mostra sia il nome dello studio che il nome dell'avvocato: "Registrata a: Studio Legale Rossi — Avv. Mario Rossi". Il backend ora restituisce `lawyerName` nella risposta di attivazione

---

## [1.6.3] -- 2026-03-14

### Added
- **Preavviso "Alle" nel Fascicolo** -- Il selettore preavviso scadenze nel fascicolo ora include tutte le opzioni dell'Agenda: 5, 10, 15, 30 min, 1 ora, 2 ore, 1 giorno + selettore orario personalizzato "Alle HH:MM"
- **Pulsante "Fascicolo" in Agenda** -- Il modal evento Agenda mostra un pulsante dedicato con icona `FolderOpen` per navigare al fascicolo collegato, separato dall'apertura card
- **Campo "Sede" separato** -- I fascicoli ora hanno campi distinti "Autorità" (tribunale/corte/giudice) e "Sede" (città/sezione), sia in creazione che nella scheda info

### Changed
- **Mini-agenda UI** -- Bottone "Aggiungi" con testo esplicito; preavviso con stile pill allineato all'Agenda (font bold, uppercase, bordi arrotondati, evidenziazione gold)
- **Sync bidirezionale preavviso** -- `syncDeadlinesToAgenda` propaga e preserva anche `customRemindTime` in entrambe le direzioni (fascicolo ↔ agenda)
- **Badge preavviso** -- Le schede scadenza nel fascicolo ora mostrano correttamente "alle HH:MM" per preavvisi custom e "1g" per 1440 min

### Fixed
- **Scadenze duplicate in DeadlinesPage** -- Aggiunto filtro `!e.autoSync` alla raccolta agendaEvents per escludere gli eventi auto-sincronizzati (che duplicavano le scadenze dei fascicoli)
- **Click evento Agenda** -- Il clic su un evento auto-sincronizzato ora apre sempre la card modale invece di navigare direttamente al fascicolo

---

## [1.6.2] -- 2026-03-14

### Added
- **Mini-Agenda Scadenze Fascicolo** -- Il form "Aggiungi scadenza" nel fascicolo ora include selettore orario (`<input type="time">`) e preavviso specifico (Generale / 15min / 30min / 1h / 2h); il dato si propaga via `syncDeadlinesToAgenda` → Agenda → Notifiche
- **Notifiche Raggruppate (Desktop)** -- `fire_grouped_desktop_reminders` sostituisce `fire_desktop_reminder`: eventi con lo stesso minuto di fuoco vengono raggruppati in un'unica notifica smart (1 evento = individuale, 2-3 = elencati, 4+ = primi 2 + "…e altri N")
- **Notifiche Raggruppate (Mobile AOT)** -- `schedule_grouped_reminder_aot` sostituisce `schedule_reminder_aot`: stessa logica di raggruppamento su Android/iOS con BTreeMap per fire-minute

### Changed
- **Calendario Persistente** -- Il flag anti-popup TCC del calendario macOS ora è persistente in `localStorage` (`lexflow_calendar_denied`), non più session-only (`useRef`); il popup appare una sola volta in assoluto. L'utente può riabilitare da Impostazioni → toggle "Sincronizzazione Calendario" (cancella il flag)
- **Orario scadenze dinamico** -- `syncDeadlinesToAgenda` legge `d.time` dalla scadenza del fascicolo (fallback `09:00`) e calcola `timeEnd` automaticamente; propaga `remindMinutes` per preavviso personalizzato
- **Save Integrity Audit** -- Tutte le operazioni di salvataggio in TimeTrackingPage (5 funzioni), ContactsPage e PracticeDetail convertite da fire-and-forget a `await` con `try/catch` + feedback errore

### Fixed
- **Popup calendario ad ogni unlock** -- Risolto: il popup TCC macOS non riappare più dopo kill/restart dell'app (era causato dal ref di sessione che si azzerava)
- **Impostazioni default a false** -- Privacy blur, protezione screenshot, notifiche ora defaultano a `true` alla prima apertura (coalescenza `?? true` / `!== false`)
- **Scadenze duplicate** -- Rimosso il blocco `deadlineItems` in `syncScheduleToBackend` che duplicava le scadenze già presenti come eventi agenda via `syncDeadlinesToAgenda`
- **Campo `category` mancante** -- Aggiunto `category: e.category || ''` in `mapAgendaToScheduleItems` per la corretta rilevazione time-sensitive nel backend Rust
- **Crash Rust `.unwrap()`** -- Sostituito `.unwrap()` con `match` guard in `fire_grouped_desktop_reminders` per evitare panic su dati malformati

---
## [1.5.7] -- 2026-03-13

### Added
- **Panic Logger** -- `std::panic::set_hook` scrive `crash.log` nella app-data dir (rotazione a 1 MB) con timestamp ISO, thread, location e messaggio; facilita debug crash remoti
- **Window State Persistence** -- `tauri-plugin-window-state` memorizza posizione, dimensione e stato massimizzato della finestra tra un lancio e l'altro (macOS + Windows, escluso Android)
- **TCC Location Banner** -- Banner ambra dismissabile (sessionStorage) che avvisa l'utente macOS quando l'app gira fuori da `/Applications` (path non standard / App Translocation); emesso da `check_tcc_location()` via evento `lf-tcc-location-warning`

### Changed
- **WebView cache invalidation on upgrade** -- `clear_webview_cache_on_upgrade()` cancella la cache WKWebView/WebView2/WebKitGTK ad ogni cambio versione; risolve stale asset post-update
- **Vite cache busting** -- `rollupOptions.output` con `[hash]` esplicito in tutti i filename (JS, CSS, asset); i contenuti aggiornati non vengono mai serviti dalla cache del browser
- **Garbage Collection temp files** -- `garbage_collect_temp_files()` rimuove in background file `lexflow_*` più vecchi di 7 giorni da temp dir e cache dir di sistema

### Fixed
- **Windows Single Instance Mutex** -- `CreateMutexA("Global\\com.pietrolongo.lexflow")` previene avvii multipli simultanei su Windows; handle persistito in `OnceLock`
- **LaunchServices Gold Standard** -- Memoizzazione via `ls_cleanup_state.txt` + guard Anti-Translocation + `fs::canonicalize()`: pulizia eseguita solo quando necessaria, in thread background

---

## [1.5.6] -- 2026-03-13

### Fixed
- **ESLint zero-warning compliance** -- Risolti 7 errori e 6 warning per passare quality gate `--max-warnings 0`:
  - `react-refresh/only-export-components` -- Costanti estratte in `utils/conflictConstants.js`
  - `no-unused-vars` -- Rimosso import `api` inutilizzato in `useTheme.js`, parametro `_theme` in `theme.js`
  - `react-hooks/exhaustive-deps` -- `ROLE_PAIRS` spostato a scope modulo in `ContactsPage.jsx`
  - `react-hooks/set-state-in-effect` -- Stato derivato in `TimeTrackingPage`, setter inline in `PracticeCombobox`, promise chain in `SettingsPage`
- **CI macOS typst sidecar** -- Estrazione typst ora usa `mktemp -d` + path deterministico invece di `find /tmp` (unreliable sui CI runner)
- **CI Linux pre-flight typst** -- Stesso fix `mktemp -d` + path deterministico
- **CI Android build** -- Creato `tauri.android.conf.json` overlay con `externalBin: []` (Typst non ha build Android); workflow passa `--config` per Android

## [1.5.5] -- 2026-03-12

### Changed
- **Componente condiviso ConflictCheckPanel** -- Estratto `ConflictCheckPanel.jsx` (~240 righe) condiviso tra `ConflictCheckPage` e `ContactsPage`, eliminando ~230 righe duplicate
- **Helper PDF export DRY** -- Estratto `runPdfExport()` in `PracticeDetail.jsx`: sia `handleExportConfirmed` che `handleExportWithPassword` delegano a un unico helper

### Fixed
- **Accessibilità PracticeCombobox** -- Trigger split in `<button>` (chiuso) / `<div>+<input>` (aperto); rimossi `role="listbox"`, `aria-expanded` da input; pulsante clear estratto come sibling (nessun bottone annidato)
- **Accessibilità ContactsPage** -- Riga contatto con overlay `<button>` invisibile per espansione + edit button reale in layer z-10 separato
- **Ternari annidati eliminati** -- ArrowUp usa aritmetica modulare; Enter usa `Math.max()`; bio status className usa map lookup
- **SonarQube code smells risolti** -- Duplicate functions rimosse in SettingsPage (`initBioStatus` → `refreshBioStatus`), status maps estratte, bottoni nativi ovunque servivano

## [1.5.4] -- 2026-03-11

### Security
- **Path traversal PDF** (M1) -- `write_pdf_to_path` ora valida: percorso assoluto, estensione `.pdf` obbligatoria, parent canonicalizzato e controllato contro allowlist (home/documenti/desktop/download). Impedisce scrittura arbitraria di file da potenziale XSS
- **Bio subprocess timeout** (M3) -- `bio_login` su macOS ora applica timeout di 60 secondi al subprocess Swift. Previene hang indefinito se Touch ID si congela o il dialog viene abbandonato
- **Lock mutex singolo** (L5) -- `ping_activity` usa ora un solo scope di lock per read+write, eliminando la race condition TOCTOU tra le due acquisizioni consecutive
- **Lockout crash-safe** (L2) -- `lockout_save` usa `atomic_write_with_sync` invece di `fs::write` grezzo. Previene file `.lockout` corrotto in caso di crash a metà scrittura
- **Marker file mode 0600** (L3/L4) -- I file sentinella `.bio-enabled` e di notifica ora scritti con `secure_write` (mode 0600). Prima potevano essere world-readable su sistemi con umask permissivo
- **Helper interno non esposto** (L1) -- Rimosso `#[tauri::command]` da `count_urgent_deadlines` (helper interno chiamato solo da `get_summary`)
- **verifyLicense bridge corretto** (I3) -- `verifyLicense` ora passa correttamente il parametro `keyString` al comando Rust (prima non passava argomenti, rendendo il comando non invocabile dal frontend)
- **Parametro spoofabile rimosso** (I4) -- Rimosso `_client_name` da `activate_license`; il nome cliente viene estratto dal token Ed25519 firmato, non accettato dal frontend
- **DRY vault helpers** (D1/D2) -- Creati `load_vault_field`/`save_vault_field`, refactoring di 5 coppie load/save (practices, agenda, timeLogs, invoices, contacts)
- **Listener notifiche negate** -- Aggiunto `onNotificationPermissionDenied` in `tauri-api.js` per gestire l'evento backend `notification-permission-denied`
- **Documentazione trade-off** (M2/M4) -- Documentato il trade-off keychain biometria, il piano deprecazione AAD legacy (v2.0.0), e le limitazioni intrinseche dello zeroing password

---

## [1.5.3] -- 2026-03-11

### Fix
- **Flusso biometria completamente riscritto** -- Il bottone Biometria nelle Impostazioni ora ha due flussi distinti:
  - **Non configurata** → chiede Master Password → salva biometria (popup nativo del dispositivo) → configurata
  - **Attiva** → conferma disattivazione → biometria rimossa
  Prima il flusso era identico in entrambi i casi (partiva con verifica biometrica anche quando non era configurata, il che non ha senso)
- **Lock Screen fascicoli senza biometria** -- Se la biometria non è configurata ma il fascicolo è protetto, ora mostra direttamente il campo password con avviso "Biometria non configurata — usa la password" (prima tentava Touch ID/Face ID comunque, che falliva)
- **Export PDF con biometria** -- Se la biometria è configurata, l'export PDF può ora essere autorizzato con Touch ID/Face ID (prima richiedeva sempre la password). Se la biometria fallisce o non è configurata, fallback alla password
- **Toast biometria corretti** -- "Biometria resettata" appariva durante il flusso; ora il toast appare solo a fine operazione ("Biometria disattivata" / "Biometria configurata con successo!")
- **Bordo verde dialog export** -- Rimosso l'outline/focus nativo del browser (verde) dal `<dialog>` del ModalOverlay tramite `outline-none`
- **Caratteri unicode in Gestione Ore** -- `\u00B7` (middot) e `\u2014` (em-dash) apparivano come testo letterale; ora renderizzano correttamente come `·` e `—`
- **Scadenze Agenda visibili nel fascicolo** -- Le scadenze create in Agenda e collegate a un fascicolo ora appaiono nella tab Scadenze del fascicolo con badge "Agenda" (prima erano visibili solo nell'Agenda)
- **Dashboard click diretto** -- Gli impegni nella Dashboard ora si cliccano direttamente: click sul titolo → apre in Agenda; icona valigetta → vai al fascicolo collegato. Rimosso il popover intermedio
- **Toast nascosti sotto i modali** -- Il Toaster z-index era inferiore ai modali (z-9999): i toast di avanzamento/successo/errore non erano visibili durante export PDF e backup. Ora `zIndex: 99999` garantisce visibilità sopra qualsiasi overlay
- **Export PDF mostra il percorso** -- Il toast di successo dell'export PDF ora mostra il nome del file salvato ("PDF salvato: LexFlow_Cliente_2026-03-11.pdf") invece del generico "PDF esportato correttamente"

### UX / UI
- **Dashboard riga impegno cliccabile** -- L'intera riga dell'impegno nella Dashboard è ora un unico bottone cliccabile che apre l'Agenda al giorno corrispondente. Fix hover BG tagliato ai bordi (ora `rounded-xl` con padding corretto). Icona fascicolo più grande (`15px`) con sfondo `bg-primary/5` e bordo, posizionata come bottone separato ben visibile
- **Contatti riga cliccabile** -- Click su tutta la riga del contatto apre la scheda dettaglio (prima bisognava cliccare la piccola icona info). Il bottone Modifica resta accessibile con `stopPropagation`
- **Scadenze sezioni colorate** -- La pagina Scadenze ha ora sezioni visivamente distinte: Scadute (rosso), Oggi (ambra), Prossimi 7 giorni (blu), Future (attenuato). Header con dot colorato e bordo inferiore
- **Modale Agenda compatta** -- La modale evento Agenda usa ora il 95% dell'altezza viewport con padding ridotto, riducendo lo scroll interno
- **Icona fascicolo vicina al nome** -- Nella Dashboard, l'icona valigetta per gli impegni collegati a un fascicolo è ora posizionata subito dopo il titolo (prima era allineata a destra, distante)

---

## [1.5.2] -- 2026-03-10

### Fix
- **PDF export non funzionante** -- L'esportazione PDF falliva silenziosamente perché il plugin FS era limitato a `$APPDATA`. Ora il backend Rust scrive direttamente il file nel percorso scelto dall'utente tramite dialog nativo (`write_pdf_to_path` command)
- **Export progress toast** -- Durante l'esportazione PDF appare un toast di caricamento "Generazione PDF in corso…" che si aggiorna a successo/errore al completamento
- **Export password modal centrato** -- Il dialog di verifica password per l'export usa ora `ModalOverlay` centrato con blur e X di chiusura (prima era in alto a sinistra senza blur)

### UX / UI
- **Diario UX modernizzato** -- Card note con bordi arrotondati `rounded-2xl`, spaziatura migliorata, timeline dot più grande con ring, date in formato "10 mar 2026" leggibile
- **Contrasto testo migliorato** -- `--text-muted` da `#b0b4cc` → `#c0c4dc`, `--text-dim` da `#8b90ad` → `#9da2be`; tutti i testi secondari in PracticeDetail convertiti da `text-text-dim/text-text-muted` a `text-white/XX` per WCAG AA
- **Send button centrato** -- Il pulsante invio nel diario ora è `w-9 h-9 flex items-center justify-center` con icona `text-black` centrata nel cerchio dorato
- **Empty states leggibili** -- Gli stati vuoti (diario, documenti, cartelle, scadenze) usano `text-white/40–50` invece di `text-text-dim` quasi invisibile
- **Textarea diario moderna** -- Campo di input con `rounded-2xl`, bordi `white/10`, placeholder `white/30`, focus con glow `primary/40`

---

## [1.5.1] -- 2026-03-10

### Fix
- **Mobile notification priority** -- I reminder su Android/iOS vengono ora ordinati per data/ora (piu vicini prima) prima della schedulazione. Con 80+ eventi, i 60 slot vanno sempre ai piu urgenti; i restanti rientrano automaticamente man mano che gli eventi passano o vengono completati
- **Email/PEC validation** -- ContactsPage ora valida il formato email e PEC al salvataggio (pattern regex); toast di errore se il formato non e' valido
- **Dashboard popover fix** -- Il popover "Apri in Agenda / Vai al Fascicolo" ora si apre correttamente al click sugli eventi (fix race condition outside-click listener)
- **Week range en-dash** -- Corretto `\u2013` che appariva come testo letterale nella barra settimana di Gestione Ore; ora mostra il carattere – corretto
- **Week start date** -- Corretta la formula di calcolo inizio settimana (lunedi) che in alcuni casi mostrava il giorno precedente (es. 9 marzo invece di 10)
- **Stats card cleanup** -- Rimossa la card "Ore" ridondante; singola card "Totale Settimana" in primary con min-width uniforme
- **Biometria reset flow** -- Il fallimento della verifica biometrica non chiude piu il modal ma procede al passo "Conferma"; il re-enrollment verifica la password prima della bio e non blocca se la bio viene annullata
- **Screenshot protection first launch** -- Il blocco screenshot ora viene applicato al primo avvio (default true) anche se il file settings non contiene ancora la chiave
- **Toast screenshot uniformi** -- I messaggi toast per attivazione/disattivazione screenshot hanno ora la stessa lunghezza ("Screenshot bloccati" / "Screenshot sbloccati")
- **Preavviso sync Settings↔Agenda** -- Il preavviso standard in Impostazioni e quello nel popup Avvisi Agenda ora condividono la stessa chiave; modificare uno aggiorna automaticamente l'altro

### UX / UI
- **PracticeCombobox browsable** -- Il combobox fascicolo mostra la lista completa all'apertura con ChevronDown, icona Briefcase e navigazione Arrow Up/Down con evidenziazione
- **Factory Reset button redesign** -- Stile unificato con il bottone "Blocca Vault" della sidebar (rounded-2xl, bordo, sfondo semi-trasparente)
- **Sidebar footer redesign** -- Versione e badge AES-256 su una riga compatta, spaziatura ridotta, tipografia piu leggera
- **Stats card unificata** -- Rimossa la card "Ore" ridondante; la card "Totale Settimana" ora usa colore primary, larghezza minima uniforme e label chiara
- **Biometria reset resiliente** -- Il modal di reset biometria non si chiude piu se la verifica biometrica viene annullata; procede al passo di conferma. Il re-enrollment verifica prima la password, poi tenta la bio (senza bloccare se annullata)

### UX
- **PracticeCombobox browsable** -- Il combobox fascicoli ora mostra la lista completa all'apertura (con icona Briefcase e chevron); il campo di ricerca appare solo dopo il click per filtrare. Aggiunta navigazione Arrow Up/Down con highlight e scroll-into-view

---

## [1.5.0] -- 2026-03-10

### UX / UI -- Redesign Contatti (Piano 1)
- **Inline-expand pattern** -- Rimosso split-panel fisso: ogni contatto ha icone Edit (modifica) e Info (dettagli) inline; la card dettaglio si espande sotto (mobile) o a fianco (desktop)
- **ChevronRight per chiudere** -- L'icona `>` chiude la card espansa (prima non funzionava)
- **Card dinamica per tipo** -- `ContactDetailCard` mostra campi diversi in base al tipo: codice fiscale e P.IVA solo per clienti, foro per giudici, albo per avvocati/consulenti
- **Soggetti collegati** -- Sezione "Soggetti Collegati" nella card mostra contatti correlati tramite fascicoli condivisi (es. controparte ↔ avv. controparte)
- **Fascicoli linkati** -- Bottoni cliccabili con stato (Attivo/Chiuso) per navigare direttamente al fascicolo

### UX / UI -- Redesign Timer/Ore (Piano 2)
- **PracticeCombobox** -- Nuovo componente ricerca fascicolo con dropdown glass-card, icona Search, navigazione keyboard (Escape/Enter), click-outside
- **Pre-lancio timer** -- Il timer non parte piu con `practices[0]`: ora richiede selezione esplicita del fascicolo + descrizione opzionale; pulsante Avvia disabilitato senza selezione
- **Timer attivo redesign** -- Card con sezioni etichettate (Fascicolo + Attivita), icone Briefcase/FileText, timer grande centrale, bottone "Ferma" prominente
- **PracticeSelect rimosso** -- Il vecchio `<select>` nativo e' stato sostituito da PracticeCombobox in tutto il codice (ManualLogModal, InvoiceModal, timer)
- **Placeholder corretto** -- Corretto `\u00E0` che appariva come testo letterale → ora mostra "Attivita" correttamente

### UX / UI -- Navigazione Dashboard/Agenda/Scadenze
- **Dashboard popover** -- Click su evento con fascicolo mostra popover con scelta "Apri in Agenda" / "Vai al Fascicolo" (prima navigava direttamente)
- **Agenda ?date= param** -- AgendaPage supporta `?date=YYYY-MM-DD` per navigare a una data specifica con `focusDate` e calcolo automatico weekOffset
- **Scadenze navigazione** -- Le scadenze di agenda navigano con `?date=`; le scadenze da fascicolo mostrano popover analogo al Dashboard

### Bug Fix
- **Platform detection** -- SettingsPage ora usa `getPlatform()` invece di `isMac()` per mostrare il nome piattaforma corretto (macOS/Windows/Android) con fallback

---

## [1.0.3] -- 2026-03-10

### Bug Fix
- **ConfirmDialog non si apriva** -- I dialog di conferma eliminazione (documenti, cartelle, note, scadenze, log ore, fatture) non venivano mai mostrati perché mancava la prop `open` — corretto in PracticeDetail e TimeTrackingPage

---

## [1.0.2] -- 2026-03-10

### UX / UI
- **Multi-cartella fascicoli** -- I fascicoli ora supportano più cartelle collegate (array), stessa UX dei documenti con pulsante "Collega Cartella" sempre visibile
- **Bio system auth** -- Verifica biometrica di sistema (Touch ID/Face ID) richiesta prima di factory reset e reset biometria
- **Bio button redesign** -- Card colorata con icona Fingerprint (emerald=attiva, amber=disponibile, grigio=N/A)
- **Bio reset verify step** -- Nuovo step di verifica identità con animazione pulse prima del reset biometria
- **Contrast boost** -- Migliorata leggibilità: text-dim, text-muted, text, border, glass-card opacity aumentate
- **Sidebar contrast** -- Bordi, etichette categorie e versione più visibili

### Bug Fix
- **Touch ID focus guard** -- Il prompt Touch ID non appare più quando LexFlow non è in primo piano (fix in tauri-api + LoginScreen + PracticeDetail)

### Cleanup
- Rimosso codice morto: folder viewer inline, file-type helpers, import Unlink/RefreshCw

---

## [1.0.1] -- 2026-03-08

### UX / UI
- **Biometria re-enrollment** -- Dopo il reset biometria, viene offerto un flusso a 3 step per riconfigurare subito Face ID / Touch ID
- **Drag-and-drop Agenda** -- Corretto il blocco del drag sugli eventi: rimosso guard errato sul button overlay, fix del flag `_didDrag` sul parent `.agenda-event`
- **Click eventi più intuitivo** -- Rimossa l'icona chevron invisibile, sostituita con hint "Clicca per aprire" visibile on hover
- **Notifiche popup centrato** -- `NotificationSettingsPopup` usa ora `ModalOverlay` per posizionamento centrato coerente
- **Conflitti unificati in Contatti** -- La pagina Conflitto di Interessi è ora un tab dentro Contatti & Conflitti, rimossa la route separata `/conflitti`
- **Sidebar semplificata** -- Voce unica "Contatti & Conflitti" nella sezione Studio

### Miglioramenti precedenti (Round 1)
- **Cursor pointer globale** -- Aggiunto `cursor: pointer` su tutti gli elementi interattivi
- **Gestione cartelle fascicolo** -- Pulsanti Scollega / Cambia cartella in PracticeDetail
- **Timer persistente** -- Il timer attivo in Gestione Ore sopravvive all'autolock (localStorage)
- **Hardware ID rimosso** -- Eliminata la visualizzazione dell'ID macchina dalle impostazioni licenza

---

## [1.0.0] -- 2026-03-03

### Sicurezza -- Audit Completo (Backend + Frontend)
- **Backend (lib.rs)** -- 18 chunk di audit di sicurezza applicati: crittografia AAD, atomic writes con fsync, lockout centralizzato, burned keys fail-closed, bio_login con zeroize, audit log con mutex, bounded reads, transactional change_password, TOCTOU fixes, MissedTickBehavior::Skip, e altro
- **Frontend** -- 6 fix applicati: safeInvoke error wrapping, bioLogin try/catch, exportPDF buffer validation, backup password min 8 chars, remindMinutes coercion in AgendaPage e DeadlinesPage
- **Zero allucinazioni** -- Verifica indipendente di tutti i 18 chunk dell'audit: tutte le claim verificate come correttamente implementate

### Pulizia
- **Audit folders rimossi** -- Eliminate le cartelle `src-tauri/src/audit/` (17 file) e `client/src/audit/` (10 file) di documentazione audit
- **Version reset** -- Tutti i file di versione allineati a 1.0.0 (Cargo.toml, tauri.conf.json, package.json root e client)

### CI/CD
- **Workflow rifatti da zero** -- Eliminato vecchio `release-all.yml`, creati 2 workflow separati: `desktop.yml` (macOS Universal + Windows MSI) e `android.yml`

---

## [3.7.0] -- 2026-03-02

### Sicurezza
- **window.confirm() eliminato** -- Consenso biometria in LoginScreen.jsx sostituito con ConfirmDialog React (modale nativo, non bloccante)
- **WebView2 downloadBootstrapper** -- Windows: `webviewInstallMode` cambiato da `offlineInstaller` a `downloadBootstrapper` per allineamento cross-app

### Pulizia
- **Em-dash cleanup** -- Tutti i `--` (em-dash Unicode) sostituiti con `--` (ASCII) in package.json, Cargo.toml, CHANGELOG.md
- **Frecce Unicode cleanup** -- Tutte le frecce Unicode sostituite con `-->` ASCII
- **ConfirmDialog.jsx** -- Nuovo componente riutilizzabile per conferme modali

### Note
- **whoami mantenuto** -- Il crate `whoami` e' necessario per la derivazione delle chiavi di crittografia locale (AES-256-GCM). Rimuoverlo renderebbe inaccessibili i dati crittografati esistenti. Uso legittimo e verificato.
- **TechnoJaw refs in lib.rs** -- Le 2 occorrenze di "TechnoJaw" in lib.rs (righe ~2696/2699) sono codice di migrazione legittimo dal vecchio bundle ID `com.technojaw.lexflow`

---

## [3.6.1] -- 2026-03-01

### CI Build Fix
- **tauri-plugin-shell --> tauri-plugin-opener** -- Migrazione completa: `ShellExt/shell().open()` --> `OpenerExt/opener().open_path()`. Aggiornati Cargo.toml, lib.rs, capabilities/default.json, client/package.json
- **Gradle pre-download retry** -- Aggiunto step con 5 tentativi e 10s delay in `release-all.yml` per risolvere `SocketException: Unexpected end of file` su Android CI
- **Static notification import** -- `import('@tauri-apps/plugin-notification')` convertito in import statico in App.jsx per eliminare warning Vite "dynamically imported but also statically imported"

### Deep Audit Cleanup
- **LicenseActivation.jsx** -- `invoke()` diretto sostituito con import centralizzato `tauri-api.js`
- **LicenseSettings.jsx** -- `invoke()` diretto sostituito con import centralizzato `tauri-api.js`
- **PracticeDetail.jsx** -- `prompt()` per password sostituito con modale React dedicata
- **SettingsPage.jsx** -- `window.confirm()` per reset biometria sostituito con modale di conferma
- **CreatePracticeModal.jsx** -- `<input type="file">` browser sostituito con `api.selectFile()` nativo Tauri
- **README.md** -- Aggiornato a v3.6.1 con feature list accurata

---

## [3.6.0] -- 2026-02-28

### Security Audit (Gemini AI -- 20+ fix)

#### Critici
- **UB memory zeroing eliminato** -- Tutti i blocchi `unsafe { ptr.write_volatile(0) }` sostituiti con `zeroize_password()` (safe, via crate `zeroize`). Colpite: `unlock_vault`, `reset_vault`, `change_password`, `import_vault`
- **change_password data loss race** -- Aggiunto `write_mutex`, backup `.vault.bak` prima della sequenza di rename, ordine vault-first
- **Audit log silent destruction** -- File corrotto salvato come `.audit.corrupt` con evento TAMPER_DETECTED inserito
- **AAD per AES-GCM** -- `encrypt_data`/`decrypt_data` ora usano `Payload` con `VAULT_MAGIC` come Additional Authenticated Data. Fallback backward-compatible per file senza AAD

#### Sicurezza
- **Hostname fragility fix** -- L'encryption key locale non dipende piu dall'hostname (volatile). Usa un machine-id persistente (256-bit random) con migrazione automatica silenziosa
- **open_path RCE** -- Path sanitization: must exist, must be absolute, blocca URL/script/eseguibili
- **Sentinel bypass fix** -- Quando il file `.burned-keys` manca ma il sentinel esiste, TUTTE le attivazioni vengono bloccate (non solo le nuove chiavi)
- **withGlobalTauri=false** -- XSS non puo piu accedere a `invoke()` tramite namespace globale
- **CSP aggiunta** -- `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'`
- **tauri-api.js ES imports** -- Switch da `window.__TAURI__` a import ES module (`@tauri-apps/api`)
- **bio_login password leak** -- Rimossi path legacy `res.password`/`res.pwd` dal frontend
- **console.error sanitizzato** -- In produzione, errori loggati come `console.warn` senza stack trace
- **fs scope ristretto** -- Capabilities limitano fs a `$APPDATA/**`

#### Architettura
- **Mutex poisoning protection** -- Tutti i `.lock().unwrap()` sostituiti con `.lock().unwrap_or_else(|e| e.into_inner())`
- **DRY refactor** -- 6 helper centralizzati: `check_lockout()`, `record_failed_attempt()`, `clear_lockout()`, `atomic_write_with_sync()`, `authenticate_vault_password()`, `zeroize_password()`
- **write_mutex su reset_vault e import_vault** -- Previene race condition su vault write concorrenti
- **decrypt_local_with_migration()** -- Helper per decriptazione con fallback a chiave legacy e migrazione automatica. Usato in: `get_settings`, `check_license`, `load_burned_keys`, `read_notification_schedule`
- **atomic_write_with_sync()** -- Usato in: `save_settings`, `sync_notification_schedule`, `burn_key`, `activate_license` (license + sentinel)

---

## [3.5.2] -- 2026-02-28

### Fix (Critici -- Sicurezza)

#### Biometria non richiesta al login
- **Stale closure fix** -- `handleBioLogin` era catturata come closure stale nei `useEffect` di init e autolock. Ora usa `useRef` (`handleBioLoginRef`) per chiamare sempre la versione più recente
- **Double-trigger guard** -- Aggiunto `bioInFlight` ref per prevenire chiamate concorrenti alla biometria (es. StrictMode, double-mount, focus+visibility race)
- **Verify-tag check in `bio_login`** -- Il backend macOS/Windows ora verifica la chiave derivata dalla password keyring contro `vault.verify` PRIMA di accettarla. Se la password nel keyring è stale (utente ha cambiato password), la biometria viene disabilitata automaticamente e l'utente viene informato
- **Auto-clear stale bio** -- Se la password biometrica non corrisponde più, le credenziali keyring e il marker `.bio-enabled` vengono cancellati per evitare loop di errore

#### Chiave privata riutilizzabile (CRITICO)
- **Burn-hash machine-independent** -- Il burn-hash ora è calcolato come `SHA256("BURN-GLOBAL-V2:<token>")` senza il machine fingerprint. Questo impedisce di riutilizzare la stessa chiave su una macchina diversa
- **Backward compatibility** -- `is_key_burned()` controlla sia il nuovo hash v2 che il legacy (fingerprint-salted) per non invalidare chiavi già bruciate
- **Tamper detection** -- Se il file `.burned-keys` viene eliminato ma il sentinel esiste, l'attivazione di QUALSIASI nuova chiave viene bloccata con errore "Registro chiavi compromesso"
- **Anti-replay nonce** -- Il payload della licenza ora include un nonce a 128-bit (`"n"` field) che rende ogni chiave univoca anche con stessi dati cliente/scadenza
- **`LicensePayload` aggiornato** -- Campo `n: Option<String>` aggiunto con `#[serde(default)]` per backward compatibility con token v1

### Aggiunto
- **`generate_license_v2.py`** -- Nuovo script di generazione licenze con registro crittografato (AES-256-GCM + Scrypt) di tutte le chiavi emesse. Comandi: `generate`, `list`, `verify`, `export`, `stats`
- **Registro chiavi locale** -- File `.lexflow-issued-keys.enc` traccia ogni chiave emessa con: ID, cliente, data emissione, scadenza, burn-hash, stato. Protetto da password
- **`compute_burn_hash_legacy()`** -- Funzione helper per compatibilità con vecchi burn-hash (fingerprint-salted)

### Modifiche
- **`generate_license.py`** -- Aggiunto nonce anti-replay nel payload
- **`.gitignore`** -- Esclusi file registro chiavi (`scripts/.lexflow-issued-keys.enc`, `scripts/.lexflow-registry-salt`, `scripts/lexflow-keys-export.csv`)

---

## [3.5.0] -- 2026-02-27

### Aggiunto
- **CRM Legale completo** -- 4 nuove pagine: Time Tracking, Fatturazione, Rubrica Contatti, Conflict Check
- **Time Tracking** -- Timer live con pratica associata, inserimento manuale, griglia settimanale ore, esportazione sessioni. `practiceName` salvato al momento dello start (fix: lookup post-autolock rimosso)
- **Fatturazione** -- CRUD fatture, calcolo automatico CPA 4% + IVA 22%, generazione PDF via jsPDF/autotable. `calcTotals` refactored in funzione standalone (fix: spread overwrite)
- **Rubrica Contatti** -- 6 tipologie (cliente, controparte, teste, CTU, avvocato, altro), ricerca/filtro, panel dettaglio, pratiche collegate
- **Conflict Check** -- Ricerca debounced su parti di tutte le pratiche + rubrica contatti, con indicazione del ruolo
- **8 nuovi comandi Rust** -- `load_time_logs`, `save_time_logs`, `load_invoices`, `save_invoices`, `load_contacts`, `save_contacts`, `check_conflict` (fix tipo di ritorno), `select_folder` separato da `select_file`
- **`select_folder`** -- Nuovo comando distinto che apre picker directory (fix: usava il picker file)

### Fix (Security Audit -- 10 bug totali confermati)
- **`check_conflict("")`** -- restituiva tipo errato su stringa vuota; ora ritorna `[]` correttamente
- **`BillingPage.calcTotals`** -- spread overwrite azzerava i totali; refactored in funzione standalone
- **`TimeTrackingPage` practiceName** -- lookup post-autolock restituiva undefined; salvato al momento dello start
- **Autolock biometric popup** -- focus rubato al login manuale; gate popup solo se `!autoLocked`
- **HamburgerButton posizione** -- era bottom-right; spostato top-right per standard UX mobile
- **Mobile sidebar overflow** -- contenuto fuori schermo; aggiunto `overflow-y-auto` + `max-h-screen`
- **Sidebar ordine non gerarchico** -- riordinato: Quotidiano --> Studio --> Amministrazione --> Configurazione
- **PracticeDetail nessun fallback password** -- biometric gate senza fallback; aggiunto input password
- **`select_folder` usava picker file** -- apertura errata; separato in comando dedicato `select_folder`
- **Desktop sidebar spacing** -- spazio eccessivo tra voci; ridotto a layout compatto

### Audit Finale
- **~9.600+ righe analizzate** su 29 file -- 0 nuovi bug trovati

---

## [3.0.0] -- 2026-02-26

### Breaking Changes
- **Rotazione chiavi Ed25519** -- Nuova coppia di chiavi per firma licenze (le vecchie licenze non sono più valide)

### Aggiunto
- **Architettura ibrida notifiche** -- Desktop usa Tokio cron job (60s interval) per notifiche affidabili; Mobile mantiene `Schedule::At` nativo AOT
- **Prevenzione App Nap macOS** -- FFI `NSProcessInfo.beginActivityWithOptions` impedisce a macOS di sospendere il cron job in background
- **Capability `notification:default`** -- Permessi notifiche allineati per Desktop e Mobile

### Fix
- **Notifiche Desktop ignorate** -- `notify-rust` (backend Desktop di `tauri-plugin-notification`) ignora silenziosamente `Schedule::At`; risolto con cron job Tokio
- **Dead code warnings** -- `notif_id`, `Schedule`, `TimeZone` gated con `#[cfg(target_os = "android/ios")]`

### Dipendenze
- Aggiunto `tokio` feature `time` per `tokio::time::interval`
- Aggiunto `objc 0.2.7` + `cocoa 0.24.1` (macOS only) per App Nap prevention

---

## [2.6.0] -- 2026-02-26

### Pulizia Progetto
- **Root cause fix**: rimosso `src-tauri/src/bin/keygen.rs` (Tauri bundlava il binario sbagliato)
- Rimosso `patches/tao/` (~200 file non necessari)
- Rimosso `scripts/license-keygen.js` (sistema licenze HMAC vecchio, sostituito da Ed25519)
- Rimosso `scripts/gen_keys.py` (monouso, chiave pubblica già embedded)
- Rimosso `install-macos.sh`, `build-android.sh` (duplicati di script npm)
- Rimosso `ANDROID_BUILD.md` (guida SDK obsoleta)
- Rimosso `client/e2e/` (test Playwright non integrati)
- Rimosso `client/src/api.js` (dead code, mai importato)
- Rimosso `lexflow-release.keystore` e `.env.android` (segreti rimossi dal disco)
- Rimosso dipendenze Rust inutilizzate: `uuid`, `image`
- Rimosso config Electron residue da `package.json`
- Rimosso README ridondanti (client, assets, scripts)
- Pulito `.gitignore` da voci fantasma (electron/, build/, supabase/, .next/)
- Allineata versione `Cargo.toml` a 2.6.0

### Fix
- `tauri.conf.json`: `visible: true`, CSP rimossa, identifier allineato
- `vite.config.js`: `base: '/'` (era `'./'` stile Electron)
- Build macOS produce correttamente `LexFlow.app` (8MB) con binario `lexflow` arm64
- DMG funzionante: `LexFlow_2.6.0_aarch64.dmg` (4.5MB)

---

## [2.4.0] -- 2026-02-24

### Sicurezza (Audit L7 · L8 · L9)
- **Argon2**: costo memoria unificato a 16 MB su tutte le piattaforme (anti-downgrade)
- **Permessi file**: scrittura vault con `0600` (owner-only), `sync_all()` garantita
- **Difesa symlink**: `is_safe_write_path()` previene attacchi di path traversal
- **`write_mutex`**: serializzazione scrittura vault, elimina race condition
- **`secure_write()`**: scrittura atomica con `rename()` e sync disco
- **`zeroize`**: cancellazione sicura password in RAM dopo unlock/reset/change/import vault
- **Scheduler persistente**: `NOTIF_LAST_CHECKED_FILE` sopravvive a riavvii, catchup capped a 24h
- **OOM guard**: limite dimensione file settings a 10 MB prima del parse
- **Difesa symlink su export**: `is_safe_write_path()` applicato a tutti i path di scrittura
- **`main.rs`**: rimosso codice WebView2/PowerShell, solo `run()` minimo
- **License**: rimosso comando `delete_license` (prevenzione manomissione)
- **`offlineInstaller`**: WebView2 bundled, nessuna connessione a runtime richiesta

### Funzionalità
- **System Tray**: chiudere la finestra nasconde l'app (non la termina), lo scheduler rimane attivo
- **Tray menu**: voci "Mostra LexFlow" e "Esci" con icone native
- **ExportWarningModal**: avviso sicurezza prima di ogni export PDF (GDPR / segreto professionale)
- **Conferma password export**: verifica vault prima di procedere con `exportPracticePDF()`

### Build & Distribuzione
- **macOS**: DMG universale `LexFlow_2.4.0_universal.dmg` (arm64 + x86_64)
- **Windows**: installer WiX MSI (sostituisce NSIS) -- si installa in `Program Files`, supporta GPO/Intune
- **Android**: APK universale firmato V2+V3, keystore RSA-4096, validità 27 anni
- **Android permessi**: `POST_NOTIFICATIONS`, `VIBRATE`, `SCHEDULE_EXACT_ALARM`, `WAKE_LOCK`
- **GitHub Actions**: workflow `build-windows.yml` aggiornato NSIS-->MSI, build on tag `v*`
- **`build-android.sh`**: script locale con Java 21 auto-select e caricamento keystore
- **`upgradeCode` WiX**: UUID fisso `8166B188-49AA-4B0E-BAE7-31D8DA09BA84` per upgrade Windows

### Fix
- `BIO_SERVICE`: aggiunto `#[allow(dead_code)]` per warning falso positivo su target macOS
- `package.json` root e client allineati alla versione Tauri (erano rimasti a 2.3.24)
- `versionCode` Android: 240

---

## [1.9.7] -- 2026-02-18

### Cambiato
- Icone tray arrotondate stile macOS
- Notifiche native via `send_notification`
- Migrazione completa a Tauri v2

### Struttura
- Riorganizzazione completa cartelle secondo BUILD_MASTER
- Rimossa cartella `build/` (residuo Electron)
- Aggiunto `assets/icon-master.png` come sorgente unica
- Aggiunto `scripts/generate-icons.py`
- Aggiunto `releases/`
- Script npm standardizzati
- .gitignore aggiornato

# v2.0.2
