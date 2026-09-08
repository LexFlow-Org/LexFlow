# Collaudo frontend e disponibilità Windows — 7 settembre 2026

Le modifiche descritte sono nei sorgenti. Questo rapporto non certifica che gli installer precedenti contengano le correzioni: occorre rigenerarli e verificarli separatamente.

## Esito e ambiente effettivo

- **58/58 test frontend superati**, 12 file, Vitest 4.1.11; durata suite 7,92 s. Prima delle nuove regressioni: 46/46 test.
- **36/36 scenari browser superati**: fascicoli/rubrica × 1.000/10.000/50.000 record × due profili × tre ripetizioni.
- Quattro aperture del dettaglio rubrica misurate dopo la correzione; lista virtualizzata e ripristino del focus verificati.
- Build frontend riuscita, Vite 7.3.6, 8,54 s. ESLint: zero errori e un warning preesistente `react-hooks/set-state-in-effect` in AgendaPage, riga 1301 al momento del controllo.
- Nessuna esecuzione Windows nativa effettuata. Nessuna VM Windows, ISO o sistema operativo installato.

Host reale: macOS 26.6.2 (25G83), Apple M5, 10 CPU logiche, 24 GiB RAM. Browser reale: Chromium headless 151.0.7922.34 ARM64, Playwright Core 1.62.1, Node 25.9.0. Browser e dipendenze erano già disponibili in cache: nessun download necessario per queste misure.

Questo sottocollaudo ha usato soltanto Chromium con profili temporanei e dati sintetici. Non ha aperto LexFlow.app, letto o modificato il profilo `com.pietrolongo.lexflow`, attivato licenze o utilizzato vault, password o chiavi reali. Il collaudo dell'app nativa è separato ed è gestito dal rapporto principale.

## Metodo e limiti delle misure

Harness compilato in modalità produzione che importa i componenti reali `PracticesList`, `ContactsPage`, `ReportPage` e il CSS del progetto. I dati sono generati in memoria; l'IPC Tauri è simulato con contatti sintetici, registro attività vuoto e rifiuto degli altri comandi. Le misure riportate riguardano fascicoli e contatti; ReportPage non è stato sottoposto a un benchmark dedicato.

Il tempo di montaggio parte subito prima del render React e termina dopo la presenza della lista e due frame di animazione. Esclude generazione dei dati, caricamento dei moduli, lettura del vault, crittografia, IPC, avvio del processo e compilazione. Il tempo di ricerca include il debounce di 200 ms. Questi valori non sono tempi di avvio dell'app nativa.

Il profilo desktop usa 1440×1000 e CPU 1×; quello mobile usa 360×800 e rallentamento CPU 4× tramite CDP. Quest'ultimo è una simulazione in Chromium sul Mac: non equivale a un telefono Android/iPhone, a Safari o a WebView2 su Windows. Tre campioni per cella, mediane sotto; non è uno studio statistico esteso né una promessa per ogni dispositivo.

Le 36 navigazioni principali consentono richieste soltanto al server temporaneo `127.0.0.1`: **zero tentativi esterni registrati**, zero errori JavaScript e zero pixel di overflow orizzontale nei campioni. Questo controllo riguarda i componenti dell'harness, non dimostra l'assenza di rete dell'app nativa o del sistema operativo.

Una prima esecuzione aveva CSS incompleto; una successiva guardia dell'harness presumeva erroneamente titoli mobili da almeno 32px, mentre il CSS di produzione imposta 24px. Quei risultati sono stati esclusi. Tutte le 36 misure finali utilizzano il CSS completo e la guardia corretta.

## Prestazioni liste: mediane in millisecondi

| Profilo | Pagina | Record | Montaggio | Ricerca ultimo record | Righe iniziali |
|---|---|---:|---:|---:|---:|
| Desktop | Fascicoli | 1.000 | 27,0 | 247,9 | 50 |
| Desktop | Fascicoli | 10.000 | 44,9 | 247,7 | 50 |
| Desktop | Fascicoli | 50.000 | 52,3 | 247,8 | 50 |
| Desktop | Contatti | 1.000 | 49,1 | 248,2 | 14 |
| Desktop | Contatti | 10.000 | 47,1 | 248,1 | 14 |
| Desktop | Contatti | 50.000 | 68,8 | 248,3 | 14 |
| Mobile simulato, CPU 4× | Fascicoli | 1.000 | 89,8 | 277,0 | 50 |
| Mobile simulato, CPU 4× | Fascicoli | 10.000 | 122,3 | 279,2 | 50 |
| Mobile simulato, CPU 4× | Fascicoli | 50.000 | 165,9 | 278,6 | 50 |
| Mobile simulato, CPU 4× | Contatti | 1.000 | 119,4 | 247,3 | 12 |
| Mobile simulato, CPU 4× | Contatti | 10.000 | 212,6 | 261,7 | 12 |
| Mobile simulato, CPU 4× | Contatti | 50.000 | 331,9 | 262,2 | 12 |

La ricerca senza accento `niccolo ultimo` trova il record sintetico finale `Niccolò Ultimo` nell'intero archivio. Per i fascicoli sono verificati anche ID della selezione, cancellazione della ricerca, ritorno a 50 righe e pulsante “Mostra altri 50” che porta a 100 righe. La rubrica mantiene 374 nodi DOM desktop/328 mobili indipendentemente dal numero totale di contatti; i fascicoli iniziali mantengono 1.376 nodi.

## Difetto corretto: aprire un contatto montava tutto l'archivio

Prima della correzione `!expandedId` disabilitava la virtualizzazione quando si apriva un dettaglio. Con 10.000 contatti il browser montava 10.000 righe e 230.153 nodi DOM. Ora, sopra 50 risultati, il dettaglio si apre in un dialogo accessibile e la lista conserva altezza fissa e virtualizzazione. Per gli elenchi piccoli resta il dettaglio inline.

| Record / CPU | Prima: apertura | Dopo: apertura | Righe prima → dopo | Nodi DOM prima → dopo |
|---|---:|---:|---:|---:|
| 1.000 / 1× | 134,6 ms | 31,8 ms | 1.000 → 14 | 23.153 → 437 |
| 10.000 / 1× | 1.199,2 ms | 28,3 ms | 10.000 → 14 | 230.153 → 437 |
| 10.000 / 4× | 4.619,6 ms | 68,3 ms | 10.000 → 14 | 230.153 → 437 |
| 50.000 / 4× | Non eseguito | 62,1 ms | — → 14 | — → 437 |

Sono singole misure comparabili del dettaglio, non mediane. Il browser ha verificato focus nel dialogo e ritorno al pulsante tramite Escape in tutti i quattro casi finali. I test unitari verificano inoltre che l'apertura su 10.000 contatti mantenga solo il sottoinsieme virtualizzato, che il collegamento al fascicolo selezioni l'ID corretto e che l'espansione degli elenchi piccoli rimanga disponibile. In jsdom il virtualizzatore è sostituito con un intervallo visibile limitato: la misura browser usa quello reale.

I valori di `performance.memory` nei dati grezzi sono stime quantizzate dell'heap JavaScript, non RAM totale del processo. Non vengono usati per dichiarare un risparmio di RAM nativa.

## Correzioni funzionali e verifica statica

**Biometria facoltativa.** LoginScreen non chiama più `saveBio` dopo ogni accesso manuale. “Salta per ora” e la disattivazione non provocano una nuova registrazione al prossimo accesso. “Configura” nell'onboarding apre il vero modulo con una nuova richiesta della Master Password; il wizard non annuncia una registrazione inesistente. App non conserva la password fra login e onboarding. Il modulo verifica la password, controlla la generazione della sessione, impedisce richieste duplicate e svuota il campo. Le diciture sono Windows Hello su Windows e Touch ID su macOS; quando il backend dichiara indisponibilità, Android presenta solo Master Password.

Sei regressioni specifiche verificano accesso manuale senza enrollment, salto, configurazione esplicita senza falso successo, dispositivo non supportato, password fresca e nome Windows Hello, password errata/chiusura/blocco prima del completamento. Una regressione aggiuntiva in App verifica che il pulsante apra il modulo e che il blocco lo rimuova. Questi test simulano le API: non certificano sensori biometrici o Keychain/Windows Hello reali.

**Password del backup distinta dalla Master Password.** Il modulo richiede Master attuale, password del backup e conferma; `exportVault(pwd, currentPassword)` calcola due digest SHA-256 indipendenti e invia `pwd` e `currentPassword`. Verificata corrispondenza con il comando Rust `export_vault(..., pwd: String, current_password: String, ...)`: la conversione camelCase Tauri instrada `currentPassword` a `current_password`. Rust autentica il vault con `current_password` sotto il mutex, conserva il controllo lockout e deriva la chiave del backup da `pwd`. Tre regressioni verificano campi obbligatori e instradamento distinti, errore backend visibile senza falso successo e hash IPC dei due valori. I digest restano credenziali equivalenti alla password: il pre-hashing non è una protezione indipendente dell'IPC.

La correzione CSS del login mobile è stata effettuata da un altro sottocollaudo dopo la scoperta su Android emulato: `.drag-region` non deve essere nascosta perché contiene l'intero form. La prova Chromium aggiuntiva a 412/360px non è stata eseguita: la revisione automatica ha rifiutato il comando per limite d'uso raggiunto. Anche una prova aggiuntiva di scroll fino all'ultimo contatto non è partita. Nessuna di queste due prove viene conteggiata come superata qui.

## Windows: ciò che è disponibile e ciò che manca

Inventario mirato: nessuna applicazione Parallels Desktop, UTM, VMware Fusion o VirtualBox nelle cartelle applicazioni controllate; assenti dal PATH `qemu-system-x86_64`, `qemu-system-aarch64`, `wine`, `wine64`, `prlctl`, `vmrun`, `VBoxManage`, `pwsh`. Nessuna VM individuata nelle cartelle standard controllate o nei risultati Spotlight per estensioni `.pvm`, `.utm`, `.vmwarevm`, `.vbox`. Non è stata effettuata una scansione indiscriminata dei dati dell'utente. Docker.app/CLI sono presenti ma senza socket locale attivo; Docker non è stato avviato e non fornisce un Windows già pronto.

L'installer precedente è un NSIS x64 compilato sul Mac: le verifiche archivio, PE, runtime e ACL compilati sono registrate separatamente in `releases/2026-09-06/Windows/BUILD-VERIFICATION.json`. Questo sottocollaudo non ne ha misurato avvio, crash o traffico su Windows. Non è stato prodotto né promesso un MSI.

Un collaudo Windows locale è tecnicamente possibile con UTM/QEMU e virtualizzazione ARM64 sul Mac; l'app x64 funzionerebbe sotto l'emulazione x64 di Windows ARM. Questo non sarebbe un test prestazionale di un PC x64 fisico. Occorrono hypervisor, ISO ufficiale Windows ARM64, driver guest e una licenza valida. Riferimenti: [guida UTM Windows](https://docs.getutm.app/guides/windows/), [download ufficiale Microsoft Windows ARM64](https://www.microsoft.com/en-us/software-download/windows11arm64).

Stima di pianificazione, non download o installazione eseguiti: ISO circa 6–8 GB, disco virtuale sparso da almeno 64 GB (circa 20–35 GB inizialmente occupati, variabile), 4 vCPU e 6 GB RAM assegnati, circa 45–90 minuti secondo connessione e configurazione. Evitare contemporaneità con un emulatore Android impegnativo. Installazione OS, accettazione EULA, acquisti e attivazione non sono stati eseguiti.

## Runner Windows isolato preparato, non eseguito

[Invoke-LexFlowWindowsValidation.ps1](validation/2026-09-07-frontend-windows/Invoke-LexFlowWindowsValidation.ps1) è standalone PowerShell 5.1. Verifica SHA-256 obbligatorio. Per impostazione predefinita prepara soltanto un file Windows Sandbox `.wsb`, senza avviarlo né abilitare funzionalità OS. Condivide soltanto due nuove cartelle: installer/script in sola lettura e output vuoto in scrittura; niente profilo utente, sorgenti, vault o chiavi. Rete e clipboard sono disattivate per default.

La modalità guest richiede `-InsideDisposableVm -DisposableVmConfirmed`, riconosce un modello VM/Sandbox e rifiuta profili LexFlow preesistenti o processi già avviati. Dentro il guest esegue NSIS in una destinazione nuova, verifica versione, nove DLL, Fixed WebView2 e ACL ereditabili dei due SID AppContainer; compila un documento Typst sintetico e lo verifica con qpdf. Avvia quindi l'app fino alla schermata iniziale di attivazione, campiona CPU/RAM e endpoint TCP/UDP del processo e discendenti, controlla eventi crash e scrive JSON UTF-8. Non richiede né include una licenza applicativa reale e non esercita vault, importazioni o biometria.

Il campionamento degli endpoint può perdere connessioni brevi; non registra payload e non prova assenza di rete. La modalità con rete disattivata misura solo l'avvio offline: per il comportamento outbound occorre una distinta esecuzione guest con rete abilitata e, se necessario, cattura di rete dedicata. Un handle di finestra non dimostra che WebView visualizzi il contenuto: è richiesta ispezione della schermata nel guest. La somma dei working set può contare memoria condivisa più volte.

Esempio di preparazione su Windows, sostituendo il digest con quello dell'installer esatto:

```powershell
.\Invoke-LexFlowWindowsValidation.ps1 -Installer C:\Pacchetto\LexFlow-setup.exe -ExpectedSha256 <SHA256>
```

In una VM già installata, autorizzata e sacrificabile, senza profilo LexFlow:

```powershell
.\Invoke-LexFlowWindowsValidation.ps1 -Installer C:\Pacchetto\LexFlow-setup.exe -ExpectedSha256 <SHA256> -InsideDisposableVm -DisposableVmConfirmed
```

Review statica eseguita: isolamento delle cartelle, rifiuto profilo esistente, hash prima dell'installazione, `/D` NSIS ultimo argomento, lettura ACL senza modifiche sull'host, output UTF-8 e distinzione fra campionamento indisponibile e prova riuscita. **Non eseguito né analizzato da un parser PowerShell su Windows**, perché Windows e `pwsh` non sono disponibili. Le funzionalità Sandbox e i comandi di rete sono basati su [documentazione Microsoft WSB](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file) e [Get-NetTCPConnection](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection).

## Evidenze e riproduzione

La cartella [validation/2026-09-07-frontend-windows](validation/2026-09-07-frontend-windows/) conserva risultati browser finali, soli campioni validi del dettaglio prima della correzione, log test/lint/build, screenshot sintetici, runner Windows e SHA-256 degli allegati.

L'harness browser è riproducibile dal root del progetto con dipendenze frontend già installate. Impostare `LEXFLOW_BENCH_DIR` a una cartella temporanea dedicata, `LEXFLOW_PLAYWRIGHT_MODULE` al file `index.mjs` di Playwright Core disponibile e `LEXFLOW_CHROMIUM_EXECUTABLE` all'eseguibile Chromium. Poi:

```sh
node docs/validation/2026-09-07-frontend-windows/build-harness.mjs
node docs/validation/2026-09-07-frontend-windows/browser-benchmark.mjs
```

L'harness di riproduzione non scarica browser e non avvia LexFlow.app. Le variabili rendono i percorsi portabili; le misure presenti sono quelle della versione locale eseguita durante il collaudo. Il server richiede che l'ambiente consenta un socket loopback.
