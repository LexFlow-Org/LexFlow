# LexFlow — audit di sicurezza, affidabilità e prestazioni

Aggiornamento successivo: [collaudo del 7 settembre 2026](COLLAUDO-2026-09-07.md), con misure di rete, archivi sintetici grandi, nuove correzioni e limiti delle prove native. Questo documento conserva lo stato storico del 6 settembre.

Data: 6 settembre 2026. Ambito: sorgenti React/Rust, IPC Tauri, persistenza, PDF, configurazioni native, dipendenze e pipeline. Le correzioni sono nel progetto e sono state compilate per macOS, Windows e Android. Nessuna app è stata installata con dati reali o pubblicata. Nessun archivio legale reale, chiave privata preesistente o password dell'utente è stato aperto; è stata creata una nuova chiave locale per firmare l’APK Android. Il file preesistente non tracciato `LexFlow` è rimasto invariato.

## Esito per la consegna

**Non considerare ancora questa versione pronta per consegnarla come applicazione completamente isolata da Internet e verificata su tutti i dispositivi.** Sono stati corretti difetti importanti di riservatezza e perdita dei dati. Lo stato dei pacchetti creati è riportato nella sezione 8; restano necessarie prove complete sulle piattaforme di destinazione. iPhone/iPad non hanno oggi un port funzionante dimostrato.

La censura PDF è stata disabilitata sia nell'interfaccia sia nel comando Rust: l'implementazione precedente non rimuoveva tutti i contenuti recuperabili. Il comando ora restituisce un errore senza creare o sovrascrivere documenti. È una riduzione deliberata di funzionalità per evitare esportazioni falsamente anonimizzate; non è stata sostituita con una nuova censura certificata.

## 1. Funzionamento locale e possibili fughe di dati

Nel codice applicativo esaminato non risultano chiamate HTTP/WebSocket, servizi cloud, telemetria remota o aggiornamenti automatici di LexFlow. Licenza e cifratura sono elaborate localmente. Il normale canale `ipc:` / `http://ipc.localhost` serve la comunicazione Tauri locale: non è un server Internet.

Questo risultato statico non dimostra assenza assoluta di traffico. La CSP limita la WebView; Rust, il sistema operativo e i binari Typst/qpdf hanno confini diversi. Il compilatore Typst può scaricare pacchetti se riceve codice che li importa, la build Windows finale include WebView2 Fixed senza aggiornamento automatico Evergreen, e un programma esterno aperto per leggere un documento può usare la rete. Per dimostrare l'isolamento serve monitorare anche processi figli, WebView e DNS, poi ripetere i flussi con rete disabilitata. [Modello di sicurezza Tauri](https://v2.tauri.app/security/), [pacchetti Typst](https://typst.app/open-source/), [WebView2](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/evergreen-vs-fixed-version).

Correzioni applicate:

- Eliminate le autorizzazioni JavaScript per eseguire sidecar e aprire URL/percorsi direttamente. Le operazioni PDF passano dai comandi Rust con validazione. La capability desktop è limitata alle piattaforme desktop e non si somma più a quella Android.
- Disabilitata l'apertura automatica di link JavaScript del plugin opener. Un filtro nativo consente solo l'origine dell'app in produzione; in sviluppo consente anche l'origine di sviluppo configurata.
- CSP allineata fra HTML e Tauri: connessioni IPC, worker PDF locali, niente form, frame o oggetti remoti. Nessun CDN richiesto dalle risorse esaminate.
- Dati temporanei dell'interfaccia (recupero, notifiche, cronologia PDF, descrizione timer) spostati in RAM. Ripulite le chiavi persistenti delle versioni precedenti all'avvio e al blocco.
- Un blocco del sistema operativo impedisce l’accesso concorrente allo stesso archivio da due istanze aggiornate sui desktop Unix; Windows conserva il mutex nativo già presente.
- Blocco nativo centralizzato: chiavi, versione della sessione e cache decifrata vengono eliminati insieme, anche alla chiusura della finestra e al blocco automatico. Letture e scritture condividono la sincronizzazione.
- Le notifiche future mobili usano titoli generici; i dettagli sono nascosti per impostazione predefinita. Rimossi i titoli dei fascicoli dai log delle notifiche. Il crash log conserva posizione e orario, senza il payload della panic.
- I temporanei PDF sono in directory uniche e private, con pulizia anche quando un'operazione fallisce. Nessun nome condiviso fisso per immagini → PDF.
- Android: script ripetibile dopo la generazione del progetto nativo; rimozione del permesso Internet dalle release, esclusioni backup cloud e trasferimento dispositivo, divieto cleartext e `FLAG_SECURE`. Verifica anche del manifest dell'APK finale in CI. Queste modifiche non cambiano gli APK già esistenti sul disco.

**Riservatezza del singolo fascicolo:** la richiesta biometrica del dettaglio è una barriera dell’interfaccia. La sessione sbloccata carica ancora tutti i fascicoli; non esiste oggi una chiave crittografica o autorizzazione backend distinta per ciascun fascicolo. Non presentarla come isolamento fra utenti o come cifratura separata.

**Confini residui:** documenti allegati esterni, export PDF/CSV, appunti di sistema, notifiche e documenti aperti con altri programmi non diventano cifrati dal vault. Una destinazione in iCloud/OneDrive/Dropbox o una clipboard sincronizzata può trasferire dati anche se LexFlow non ha un client cloud. Impostazioni e programma notifiche usano una chiave locale ricostruibile dagli identificativi del dispositivo, non la password del vault. La protezione da screenshot e backup Android richiede prova sul dispositivo. La cancellazione su SSD/snapshot e l'azzeramento di tutte le copie JavaScript/IPC non sono garantiti.

## 2. Riscontri principali e interventi

| Gravità | Riscontro confermato | Intervento |
| --- | --- | --- |
| Critica | Censura PDF con overlay, rimozione incompleta degli operatori testuali e oggetti originali recuperabili | Funzione disabilitata; test verifica che non tocchi neppure un output preesistente |
| Critica | Cambio password del vault diviso aggiornava un header diverso da quello usato allo sblocco | Password e dati correnti salvati nello stesso snapshot atomico; verifica nuova/vecchia password dopo riavvio |
| Alta | Salvataggio del vault diviso poteva lasciare header, indice e record incoerenti dopo errore/interruzione | Un solo commit atomico dell'archivio completo; manifest autenticato mantiene il legame con i record |
| Alta | Backup automatico copiava un file assente o non aggiornato | Backup del nuovo snapshot corrente; rifiuto esplicito del vecchio diviso non ancora migrato |
| Alta | Importazione pubblicava un archivio vuoto prima di salvare tutti i dati | Preparazione completa e commit finale; nessuna sostituzione del vault con un import incompleto |
| Alta | Record corrotti venivano ignorati e potevano sparire al salvataggio successivo | Caricamento interrotto con errore e conservazione dei file |
| Alta | Cache decifrata accessibile dopo blocco; risultati asincroni potevano ripopolare l'interfaccia | Controllo sessione prima della cache, pulizia centralizzata, invalidazione delle risposte precedenti |
| Alta | Errori di lettura frontend trasformati in liste vuote, poi salvate | Errori visibili, scritture impedite finché il caricamento non riesce; salvataggi serializzati |
| Alta | Testo utente inserito come codice Typst in watermark/numeri di pagina | Argomenti stringa con escaping, progetto temporaneo isolato e prove con input ostili sintetici |
| Alta | Proteggi PDF poteva dichiarare successo senza qpdf lasciando un documento in chiaro | Errore obbligatorio, output pubblicato solo a operazione conclusa; password fuori dagli argomenti di processo |
| Alta | Parser PDF vulnerabile a stack overflow su un documento piccolo e profondamente annidato | Aggiornamento lopdf e test che il documento ostile non faccia terminare il processo |
| Alta | Credenziali biometriche macOS potevano ricadere sul portachiavi senza ACL biometrica | Nessun ripiego silenzioso; resta possibile l'accesso con password |
| Alta | Binari macOS etichettati Intel/Universal senza architetture o librerie necessarie | Sostituiti con Typst 0.15.1 e qpdf 12.4.1 autonomi, slice ARM64/Intel reali; architetture e dipendenze verificate |
| Media | Permessi dei file già esistenti non ristretti, scritture Unix seguivano symlink | `0600` anche sui file esistenti, `O_NOFOLLOW`, letture con limite effettivo e pulizia staging |
| Funzionale | Scorciatoia ricerca duplicata, risposte ricerca obsolete, stato del dettaglio di un altro fascicolo, export fattura AutoTable incompatibile | Correzioni e test frontend dedicati |

La protezione PDF con password proprietario imposta restrizioni di copia/stampa/modifica, **non una password necessaria per aprire il file**. Altri lettori possono ignorare le restrizioni; non impedisce la condivisione. L'interfaccia e il risultato ora lo dichiarano. [CLI qpdf](https://qpdf.readthedocs.io/en/stable/cli.html#encryption).

Dettagli tecnici: [vault e migrazione](vault-audit-notes.md), [piattaforme e distribuzione](platform-audit-notes.md), [dipendenze](dependency-audit-notes.md).

## 3. Migrazione e tutela dei dati

Lo snapshot `LEXFLOW_ATOMIC_V8` conserva AES-256-GCM-SIV, Argon2id, indice cifrato e versioni dei record. La versione 8 è inclusa nel MAC dell'header e impone la verifica del manifest: cambiare il prefisso esterno, svuotare l'indice o ripristinare un vecchio indice senza manifest non deve disattivare l'integrità dei record. Si migrano soltanto archivi leggibili e verificati, usando i dati divisi più recenti; un errore non autorizza il ritorno a una copia vecchia.

Prima di usare una nuova build con dati reali, fare una copia dell'intera directory applicativa a programma chiuso e conservarla separatamente. I vecchi file sono preservati per il recupero. Un'app precedente non riconosce il nuovo snapshot: evitare un downgrade sullo stesso archivio.

Un archivio già colpito dal vecchio bug del cambio password può richiedere recupero assistito con i materiali precedenti. Il codice ora rifiuta l'incoerenza e conserva i file. Il recupero ordinario richiede il nuovo snapshot verificabile: per un archivio precedente occorre prima la migrazione tramite password, oppure un recupero assistito su copie. Cambiare password non revoca accesso a vecchie copie possedute da chi conosce la vecchia password. Il contatore accessorio non è autenticato: non garantisce protezione dal ripristino integrale di vecchie copie contro chi può sostituire tutti i file locali.

La rotazione automatica della DEK resta rinviata quando è configurata una chiave di recupero, perché aggiornarla senza il segreto renderebbe il recupero inutilizzabile. Il backup portatile attuale non include i file allegati esterni né tutta la storia delle versioni: non va presentato come backup completo dello studio.

## 4. Prestazioni e compatibilità

Tolti i caricamenti anticipati di tutte le pagine all'accesso. Dashboard, dettagli, dialoghi e PDF vengono caricati quando necessari. Il viewer PDF dedicato alla censura sospesa e la relativa dipendenza PDF.js sono stati rimossi: il relativo worker non viene più distribuito. I salvataggi riutilizzano il ciphertext dei record invariati; il nuovo formato elimina la ricifratura esterna di tutti i file. Lo snapshot viene ancora serializzato interamente: non si tratta di scritture incrementali a costo costante. Nessun parametro crittografico è stato ridotto.

La finestra desktop può ridursi fino a 360 px di larghezza, invece del minimo di 1100 px. Sono mantenuti i layout responsive esistenti e corretti gli stati di navigazione. La riduzione dei bundle indica meno codice da caricare, non una misura universale di consumo RAM o tempo d'avvio su hardware reale.

Misure finali e verifiche sono riportate sotto. La build finale del frontend è stata completata in 4,33 s su questo Mac, durante altri controlli concorrenti; il dato non misura l’avvio dell’app. Non sono stati eseguiti benchmark su Mac Intel, Windows, Android o iPhone fisici.

## 5. Blocchi e verifiche prima della distribuzione

1. Sidecar macOS corretti: Typst 0.15.1 scaricato per entrambe le architetture con SHA256 verificati; qpdf 12.4.1 e libjpeg-turbo 3.2.0 compilati staticamente da sorgenti verificati. Il controllo delle sei varianti passa, senza dipendenze Homebrew. PDF sintetici, cifratura/decifratura qpdf e template fascicolo Typst provati su ARM64 e Intel tramite Rosetta. Requisito effettivo macOS aggiornato a 11.0. Restano le prove dell’intera app su hardware e sistemi di destinazione, incluse le DLL Windows su una VM pulita.
2. Download macOS e preparazione Windows vincolati a versioni e SHA256 verificati. La pipeline CI completa non è stata eseguita né pubblicata; conservare i controlli di filiera anche per gli altri job. Per la consegna firmata commercialmente servono certificati Developer ID/notarizzazione Apple e Authenticode Windows, qui non disponibili.
3. Provare una copia sintetica e poi una copia del vault su pacchetti di produzione, inclusi riavvio, cambio password, recupero, import/export, errori disco e blocco durante i salvataggi. Gli allegati vanno verificati separatamente.
4. Windows: WebView2, biometria, percorsi e sostituzioni di file. Android: avvio, storage privato, content URI dei documenti, blocco in background, notifiche, screenshot e backup. L'assenza del permesso Internet deve risultare dal pacchetto finale, non soltanto dal sorgente.
5. iPhone/iPad: serve un port nativo e un ciclo di test dedicato. Le condizioni `cfg` attuali e l'assenza di progetto/pipeline iOS non consentono di dichiararne il supporto.
6. Per una garanzia rigorosa di isolamento, applicare controlli di rete del sistema e acquisire traffico del processo principale e dei processi figli durante tutti i flussi. Il browser con IPC simulata non sostituisce questa prova.

## 6. Verifiche eseguite

| Controllo | Esito |
| --- | --- |
| Test frontend | 46 test superati in 8 suite dopo la pulizia e la rimozione delle dipendenze inutilizzate |
| Lint frontend | Nessun errore; 1 avviso residuo sulla sincronizzazione dei parametri URL in Agenda |
| Bundle principale JS | 324,80 → 257,65 kB: −20,7% complessivo; prima della seconda pulizia 258,35 kB |
| Chunk strumenti PDF | 440,71 → circa 24,48 kB: −94,4% |
| Risorse frontend complessive | Circa 4,154 → 1,564 MB; rimosso il worker PDF.js da circa 2,186 MB |
| Browser con dati sintetici e IPC simulata, prima della seconda pulizia CSS | Larghezze 390, 768 e 1366 px; nessuno scorrimento orizzontale della pagina; creazione/salvataggio fascicolo, navigazione, contatti, ore, agenda e report verificati |
| Test PDF, IO e sessione documenti | 12 prove PDF, 2 letture limitate e 3 nuove prove di autorizzazione documenti superate; restano le 5 prove isolamento/temporanei/blocco istanza |
| Test hardening Android/macOS | 8 test superati dopo il controllo ELF 16 KB; manifest e allineamento verificati anche nell’APK finale |
| Test confronto OSV locale | 5 test superati |
| Generatore licenze | 19 prove sintetiche superate; nessuna chiave privata o registro reale usato nei test |
| Dipendenze npm | 0 corrispondenze note, 0 intervalli non valutati su 370 percorsi dei lockfile |
| Dipendenze Rust | 0 segnalazioni `vulnerabilities`; restano 18 `unmaintained` e 2 `unsound` descritti nel rapporto dedicato |
| Suite Rust finale 1.0.1 | 412 test superati, 0 falliti e 0 ignorati; esecuzione con un solo thread in 222,29 s durante altre compilazioni |
| Clippy Rust | Superato con `-D warnings`, nessun avviso |
| Formattazione e patch | `cargo fmt --check` e `git diff --check` superati |

I test usano Node 25.9.0 e Rust 1.95.0 su questo Mac; il progetto dichiara ora Rust >=1.88 per riflettere il requisito delle dipendenze. Non è stata provata qui una compilazione con la versione minima.


La dipendenza PDF.js segnalata durante l'audit è stata rimossa insieme al viewer inutilizzato.

La numerosità dei test non equivale a certificazione. Le circa 680 righe di vecchie prove PDF disabilitate sono state rimosse; sono mantenute prove attive mirate ai rischi modificati. Le fixture che costruivano manualmente archivi sono state aggiornate al manifest V8; gli attacchi rimangono non autenticati e devono essere rifiutati già all'apertura. Alcuni vecchi test statistici misurano solo due campioni temporali e sono sensibili al carico: nella verifica finale l'intera suite è passata con un solo thread e senza compilazioni concorrenti, senza indebolire le asserzioni.

## 7. Seconda revisione: pulizia, licenze e nuovi difetti corretti

- Rimossi 74 selettori CSS senza uso, animazioni/duplicazioni e helper frontend irraggiungibili. CSS sorgente da 56.187 a 46.706 byte (−16,9%); CSS generato circa 105 kB. Non sono stati trovati fogli di stile remoti. Conservate le classi dinamiche necessarie a calendario, grafici e liste.
- Eliminati quattro documenti Typst obsoleti o duplicati (885 righe), il modulo Rust `error.rs` senza chiamanti, sei validatori inutilizzati e vecchi wrapper di memoria senza utilizzatori. README e script documentano solo percorsi esistenti. Conservati audit correnti, cronologia storica, migrazione del vault, installer, registri e backup.
- Rimossi dal client i pacchetti JavaScript dialog/log/opener non importati e la CLI Tauri duplicata; le corrispondenti operazioni native rimangono in Rust. Eliminato il comando per generare icone che puntava a uno script inesistente.
- Fascicoli: massimo 50 righe nel primo gruppo renderizzato, poi «Mostra altri». Ricerca sull'intero archivio e normalizzazione riutilizzata nei filtri. Una prova DOM con 125 fascicoli verifica risultati oltre il primo gruppo e caricamento progressivo; dopo la seconda pulizia CSS non è stata ripetuta una verifica visiva su browser o dispositivo. Il guadagno principale è meno DOM iniziale, non un benchmark universale di velocità.
- Contatti, ore e parcelle: scritture accodate sullo stato più recente; nessun rollback sopra modifiche successive e identificativi stabili contro doppio invio. La ricerca globale non consente di selezionare risultati della query precedente. La password proprietario PDF rivelata scade 60 secondi dopo il clic, anche se il primo minuto dall'esportazione era già trascorso.
- Riordino PDF: riscrittura unica della struttura delle pagine, senza clonare e riunire il documento per ogni pagina; risorse, geometria e rotazioni ereditate preservate. Divisione: oggetti senza riferimenti rimossi, errori parziali espliciti. Questo non equivale a censura completa di metadati, risorse condivise o contenuti.
- Output PDF pubblicati solo da file completi in area privata, senza sovrascrivere destinazioni esistenti. Ingressi PDF limitati a 100 MiB, unione a 250 MiB totali, divisione a 500 pagine. Letture limitate tramite descrittore, rifiuto di symlink/FIFO senza bloccare il processo; rimossi 26 log PDF contenenti percorsi, testo o stderr. I limiti dei file non garantiscono un tetto alla memoria dopo decompressione. Rimane una race nei percorsi riaperti dai sidecar, da verificare nel collaudo nativo.
- I 15 comandi PDF e 9 comandi file richiedono una sessione sbloccata, con verifica anche al completamento. Il blocco seguito da un nuovo sblocco invalida comunque il risultato precedente. I risultati sensibili scartati vengono azzerati; i documenti già pubblicati restano sul disco. Le operazioni esterne già iniziate non vengono necessariamente interrotte dal blocco.

### Generatore licenze

Il vero generatore era `scripts/generate_license_v2.py`; è stato semplificato ed è disponibile anche il launcher `scripts/generate-license.sh`. Il comando `verify` precedente decodificava soltanto il payload: ora verifica realmente la firma Ed25519. L'emissione confronta la chiave privata con entrambe le costanti pubbliche del progetto prima di chiedere i dati della licenza. Il generatore non salva la chiave privata e l'input segreto fallisce se il terminale può mostrarlo. Durante questa revisione iniziale non erano state generate o cambiate chiavi reali; la successiva rotazione esplicitamente richiesta per la versione 1.0.1 è descritta sotto.

Il registro V3 usa AES-256-GCM e Scrypt con gli stessi parametri del predecessore, salvataggio atomico, permessi Unix `0600` e blocco fra processi. I due layout V2 vengono riconosciuti tramite autenticazione, evitando il precedente errore di rilevamento del salt. Un salt storico corrotto non blocca un registro incorporato valido. Limiti di lettura/scrittura coerenti impediscono di salvare registri poi illeggibili. Il vecchio generatore non legge V3: usare il nuovo strumento dopo la migrazione.

Il comando `burn` registra solo il ritiro locale e mantiene l'hash identificativo; non può revocare una licenza su un altro computer offline. Il vecchio “ultra-burn” non aveva questa capacità e cancellava proprio l'hash utile per riconoscere il token. Backup e salt storici restano disponibili. Esportazione CSV protetta dalle formule e senza sovrascrittura; durata/grace period Rust calcolati senza overflow e token troppo grandi rifiutati prima della decodifica. I dettagli operativi sono in [scripts/README.md](../scripts/README.md).

Pulizia finale dei file generati: eliminati la cache incrementale Rust debug (circa 3 GB), `scripts/__pycache__` e `.DS_Store` della radice. Dipendenze installate, eseguibili di test/build, installer, font, icone e sidecar conservati. Lo spazio recuperato nel progetto non è una riduzione delle dimensioni dell’app distribuita; la prossima ricompilazione ricreerà la cache.

## 8. Compilazione e pacchetti locali

- **macOS:** due DMG distinti, Apple Silicon (31.018.411 byte) e Intel (33.518.435 byte), ciascuno con una sola architettura in tutti e tre gli eseguibili; macOS minimo 11.0. Il precedente installer universale è stato sostituito. Typst 0.15.1 e qpdf 12.4.1 autonomi; licenze dei componenti e dei font incluse. Firma ad hoc con hardened runtime verificata (`codesign --deep --strict`), immagine verificata e montata in sola lettura per confrontare contenuti e firma. I componenti PDF inclusi hanno prodotto e verificato un fascicolo sintetico su ARM64 e Intel tramite Rosetta. L’app principale non è stata aperta sull’archivio dell’utente. Nessuna notarizzazione Apple.
- **Windows:** eseguibile x64 e installer NSIS compilati da questo Mac. Typst 0.15.1, qpdf 12.4.1 e nove DLL inclusi insieme a WebView2 Fixed 152.0.4191.62. Installer estratto con successo: 573 file applicativi confrontati tramite SHA256, inclusi tutti i 548 file del runtime. Firma Microsoft dell’archivio CAB verificata (digest, catena e timestamp; controllo CRL online disabilitato). Aggiunto all’installer il permesso RX ereditabile per i due SID AppPackages sulla sola cartella WebView2, necessario per Fixed Runtime 120+ su Windows 10: un errore di icacls interrompe l’installazione. Hook compilato e verificato staticamente, senza modificare ACL del Mac. LexFlow non ha firma Authenticode. Nessun MSI è stato prodotto qui, né è stata eseguita l’app su Windows. Il runner e la CI Windows ora producono soltanto NSIS; i due job duplicati sono stati consolidati.
- **Android:** APK ARM64 release firmato v2/v3, Android minimo 7/API 24, target API 36. Manifest finale privo di Internet; esclusioni backup/cloud/trasferimento e licenze verificate. Allineamento ZIP e di ogni libreria ELF ARM64 a 16 KB verificato. La precedente dichiarazione di disponibilità della biometria Android era uno stub: ora è disabilitata e l’accesso usa la password. qpdf e Typst restano componenti desktop. Nessun collaudo su telefono fisico.
- **Motore WebView:** il numero minimo del sistema non basta. Il CSS usa Tailwind 4, che richiede Safari/WebKit 16.4+ su Mac e Chromium 111+ su Android. Aggiornare il componente del sistema prima dell’uso offline; non si dichiara compatibilità con le vecchie WebView fornite originariamente da quei sistemi. [Supporto browser Tailwind](https://tailwindcss.com/docs/compatibility#browser-support).
- **Ripetibilità macOS:** script con versioni/SHA fissati per Typst e qpdf, e `package-macos-local.sh` per la firma ad hoc. Quest’ultimo prepara una copia fuori iCloud, elimina gli attributi non compatibili con la firma, normalizza soltanto i permessi delle risorse pubbliche e pubblica il DMG senza sovrascrivere file. Il flusso completo è stato eseguito con successo. Rimossi dal plist i permessi Calendario inutilizzati. Il comando `build:me` non cancella né installa più applicazioni.
- **Chiave firma Android:** nuova chiave conservata localmente fuori iCloud, separata dalla consegna, con directory 0700 e file 0600. Va preservata per firmare aggiornamenti della stessa app; non è la chiave Ed25519 usata per emettere licenze.

I pacchetti locali e le relative impronte si trovano in `releases/2026-09-06/`. Sono copie da collaudare con dati sintetici prima dell’uso professionale. Non è stato prodotto un pacchetto iPhone/iPad, né sono stati verificati Windows ARM o Android a 32 bit. Le prove di rete dinamiche e i limiti di sicurezza delle sezioni precedenti restano applicabili.

### Consegna Mac separata e pulizia Spotlight

Su richiesta, eliminate le due copie `.app` generate sotto `src-tauri/target` e la copia temporanea usata per confezionare i DMG. Le registrazioni delle copie di compilazione sono state rimosse puntualmente; Spotlight restituisce soltanto `/Applications/LexFlow.app`, il cui eseguibile coincide con la versione verificata precedentemente consegnata. App installata e dati utente non modificati. Nuovi DMG verificati montati in sola lettura, con firme e slice CPU corrette; staging in directory `.noindex` e flag di esclusione indice nel volume. Build locali e job macOS della CI distinguono Apple Silicon e Intel; la CI non è stata eseguita.

Aggiunto `Crea licenza LexFlow.command` nella radice del progetto per aprire il generatore esistente in Terminale con doppio clic. Verificati sintassi e `--help` anche con PATH minimo; nessuna licenza o chiave privata è stata generata o letta durante questa modifica. I file `.sha256` sono impronte di integrità degli installer, non chiavi di attivazione.

## 9. Rotazione licenze 1.0.1: revoca delle chiavi precedenti

Su richiesta esplicita è stata generata una nuova coppia Ed25519 per le licenze. Le build 1.0.1 incorporano soltanto la nuova pubblica, coerente fra runtime e controllo d'integrità; nessuna pubblica precedente viene conservata come alternativa accettata. La rotazione non cambia la password, la DEK o il formato del vault.

Le attivazioni memorizzate non conservano il token Ed25519 originale: sostituire la sola pubblica non le avrebbe invalidate. Ogni nuovo record cifrato e autenticato ora contiene `signingKeyId`, il SHA256 della pubblica attuale. Un record senza questo campo o con un emittente diverso restituisce `activated=false` e `revoked=true`. I token nel vecchio formato vengono verificati con la nuova pubblica prima di qualunque migrazione. Il record revocato presente può essere sostituito con una nuova licenza valida, conservando verifica della firma, registro monouso e controlli antimanomissione.

Il test completo ora firma il solo payload Base64, come il generatore, e dimostra accettazione della firma nuova, rifiuto di una firma precedente valida sotto la propria chiave, rifiuto del payload alterato e del protocollo errato. Un nuovo test copre cache precedente, emittente revocato, cache corrente e manomissione del record. Le prove usano soltanto chiavi e record sintetici; nessun registro o segreto reale viene aperto.

Verifica 1.0.1 completata: **412 test Rust superati, 0 falliti e 0 ignorati**, inclusi i 12 test licenze/integrità, in 222,29 secondi. Eseguito `cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --jobs 2 --lib -- --test-threads=1` con la cache Cargo locale già disponibile; nessun download. Il tempo include concorrenza con le compilazioni dei pacchetti e non è un benchmark dell'app.

**Limiti della revoca offline:** le copie precedenti dell'app continuano a incorporare la vecchia pubblica; devono essere aggiornate per applicare questa revoca. Non esiste una revoca remota di quei binari. Se il vecchio file licenza è stato eliminato ma resta il sentinel, il blocco antimanomissione continua a richiedere lo stesso ID licenza o assistenza; non viene cancellato automaticamente. L'interfaccia torna alla schermata di attivazione quando riceve `activated=false`, anche se al controllo iniziale non mostra il motivo specifico della revoca.

Il launcher Mac `Crea licenza LexFlow.command` usa `generate --local-key`: legge la configurazione pubblica in Application Support e verifica emittente, percorso locale e permessi esclusivi prima di usare la chiave. La nuova privata resta fuori da iCloud e dagli installer. I 19 test del generatore includono percorsi esterni, symlink, permessi errati, emittente non corrispondente e firma con una chiave sintetica configurata. Il registro reale non è stato aperto né modificato e non è stata emessa una licenza intestata a persone reali.

### Installer 1.0.1 e verifica della chiave distribuita

Ricompilati e verificati quattro pacchetti: macOS Apple Silicon e Intel separati, Windows x64 NSIS e Android ARM64 (versionCode 251). Versioni e impronte sono in `releases/2026-09-06/pacchetti.json`; le ricevute nelle sottocartelle documentano firma, contenuto e limiti di collaudo. La nuova pubblica è presente nei binari distribuiti. Su Intel macOS il compilatore la costruisce con quattro immediati `movabs` da 64 bit: il disassemblato del binario montato dimostra la ricostruzione esatta in quattro slot consecutivi; una ricerca della sola sequenza continua non era sufficiente. Le copie installer 1.0.0 sono state rimosse dopo il confronto delle rispettive impronte. La firma Android resta quella precedente per consentire aggiornamenti senza disinstallazione. Nessun eseguibile principale è stato avviato per queste verifiche.

### Pulizia finale e app installata

Eliminati 148 percorsi di build/cache/temp nella pulizia finale, oltre ai 29 percorsi Android già rimossi: circa 42,55 GB di file logici complessivi (non una garanzia di recupero fisico su SSD/APFS). Rimossi `src-tauri/target`, i progetti nativi generati, `client/dist`, toolchain e cache temporanee della lavorazione; conservati sorgenti, dipendenze del progetto, sidecar necessari, generatore, registro cifrato e chiavi in Application Support. Restano quattro installer 1.0.1, ricontrollati tramite SHA256 dopo la pulizia. Spotlight restituisce soltanto `/Applications/LexFlow.app`.

La copia installata risulta aperta ed è ancora 1.0.0: il controllo dei processi ha fermato l’aggiornamento prima di qualunque modifica. È stata richiesta la chiusura all’utente. Nessun documento o archivio reale è stato letto e nessun processo dell’app è stato terminato. La revoca si applicherà anche a questa copia dopo l’aggiornamento; i nuovi installer sono già pronti.

### Rimozione definitiva richiesta dal proprietario

La richiesta successiva sostituisce il precedente aggiornamento sospeso: eliminati `/Applications/LexFlow.app` 1.0.0 e tutti i dati locali individuati nei percorsi applicativi correnti e legacy, preferenze, log, cache e temporanei. Le due voci del portachiavi login (servizi `LexFlow_Bio` e `LexFlow.Burned`) sono state cancellate con lo strumento Apple `security`, senza leggere valori; successiva ricerca per cancellazione restituisce elemento assente per entrambi. Il primo tentativo via API aveva restituito errori di proprietario/entitlement ed è stato sostituito dal metodo CLI riuscito. I sei nomi dei file recenti dei due identificatori risultano assenti.

Eliminati anche vecchio APK 1.0.0 nella radice, alias Finder, `.env.keys` inutilizzato, cache Vite e vecchia worktree priva di modifiche. Conservato il suo unico backup cifrato del registro nel generatore; rinominata la copia storica non identica del registro con un nome di backup esplicito. Il progetto corrente, generatore con registro, nuova privata 0600 fuori iCloud, chiave di firma Android necessaria agli aggiornamenti e quattro installer 1.0.1 sono stati ricontrollati. Nessuna app LexFlow resta installata o in esecuzione. Dettaglio locale in `releases/2026-09-06/rimozione-app.json`.
