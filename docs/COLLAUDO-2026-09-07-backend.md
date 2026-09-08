# Collaudo backend — 7 settembre 2026

Il core Rust supera 78 test in modalità release, 12 verifiche di integrità e
backup sintetici e quattro interruzioni forzate della scrittura atomica. Il
collaudo ha individuato e corretto difetti nella ricerca, nel decoder dei record
legacy e nella calibrazione Argon2. Le correzioni sono nei sorgenti: gli
installer 1.0.1 preparati il 6 settembre non includono queste modifiche.

## Ambiente e fedeltà delle prove

- Mac17,3, Apple M5, 10 core logici/fisici, 24 GiB RAM; macOS/Darwin 25.6.0,
  processo ARM64. Modello, CPU e RAM letti da `sysctl`, senza dati applicativi.
- Rust/Cargo 1.95.0; harness compilato con ottimizzazione release, LTO thin e
  due job. Python 3.14.5 per l'orchestrazione.
- Tutti i fascicoli sono sintetici: 1.000, 10.000 e 50.000 record, circa 521–527
  byte MessagePack ciascuno prima della cifratura. Ogni record ha due note.
- L'harness compila direttamente `constants.rs`, `io.rs`, `crypto.rs`,
  `security.rs` e `vault_engine.rs`. Per ricerca e backup conserva i corpi
  delle funzioni reali, escludendo solo gli import di stato e i comandi Tauri.
  Il decoder indicizzato di `vault.rs` e la sua regressione sono inclusi.
- Il modulo `platform` fornisce esplicitamente una chiave e un ID macchina
  fittizi. Le prove HMAC backup verificano l'algoritmo e i file reali, **non** il
  Portachiavi, l'identità OS, i dialoghi Tauri o la sicurezza della chiave locale.
- Nessun vault reale, registro licenze o chiave privata del proprietario è stato
  letto. L'harness non risolve cartelle dati applicative e non ha aperto
  `~/Library/Application Support/com.pietrolongo.lexflow`.
- La prima compilazione è avvenuta offline copiando dalla cache Cargo globale
  gli archivi già disponibili in una cache temporanea. La cache globale è
  rimasta invariata. Target del solo harness circa 145 MiB; cache privata circa
  157 MiB prima dei successivi lavori di compilazione completa del coordinatore.

I tempi sono osservazioni su questo Mac, con attività funzionali dell'app e
un emulatore Android presenti durante parte della sessione. Non sono misure su
computer lenti, telefoni fisici o Windows; baseline e nuova esecuzione non
hanno una contesa CPU controllata. I picchi RAM sono quelli del processo del
singolo caso, non dell'app Tauri completa. Le query usano cinque campioni; la
baseline a 50.000 ne usa due e riporta il valore centrale superiore.

## Difetti riprodotti e correzioni

1. **Calibrazione Argon2.** I probe sotto 200 ms erano scartati; un Mac veloce
   poteva esaurire i candidati e ripiegare a 16 MiB. Riprodotto due volte, con
   sblocco core intorno a 16–25 ms. Ora tutti i probe riusciti sono considerati,
   gli errori non diventano misure valide e il profilo minimo è 64 MiB desktop,
   24 MiB Android, tre iterazioni. Android resta limitato a 32 MiB. I parametri
   dei vault già esistenti continuano a essere letti dal loro header, senza
   modificarli automaticamente. I test simulano CPU veloci, lente ed errori.
2. **Risultati di ricerca falsi.** Trigrammi mancanti erano ignorati e venivano
   restituiti anche risultati con punteggio zero. Una parola inesistente
   produceva 50 risultati. Ora i candidati sono termini realmente corrispondenti
   per prefisso o per una modifica Unicode, prima del calcolo BM25. I risultati
   hanno punteggio positivo; parità ordinate anche per ID.
3. **Costo quadratico e dimensione dell'indice.** Ogni candidato faceva una
   scansione completa del posting del termine. I posting ora usano lookup per
   ID e i trigrammi contengono termini distinti, evitando di duplicare tutti gli
   ID record per ogni trigramma. La cache derivata ha formato 2; le cache vecchie
   vengono ricostruite dal vault autenticato.
4. **Cache troncata a 50.000 record.** La vecchia serializzazione raggiungeva
   206.629.375 byte; la decompressione restituiva 100 MiB senza segnalare il
   troncamento. Il parser falliva e la cache non era riutilizzabile. Ora il limite
   resta 100 MiB, ma superarlo produce un errore esplicito. Il nuovo indice
   sintetico da 50.000 record occupa 50.215.632 byte e supera il roundtrip.
5. **Ricerca e storico incompatibili con MessagePack.** Due percorsi ricerca e
   lo storico tentavano soltanto JSON, saltando i record delle versioni correnti.
   Ora usano un decoder condiviso per MessagePack e JSON legacy. Il decoder
   richiede un oggetto: altrimenti la parentesi iniziale di un JSON può essere
   accettata come numero MessagePack, impedendo il fallback. Corretto anche il
   caricamento completo/singolo del vault; il controllo dell'ID rimane attivo.
6. **Ricerca dopo ripristino precedente.** Una generazione inferiore a quella
   della cache non veniva reindicizzata. Ora qualsiasi differenza richiede
   aggiornamento. La rimozione di un ID assente non altera più il numero documenti.

## Misure ricerca

Tempo della sola ricerca su indice **già in memoria**, query `contratto`, limite
50 risultati. Non comprende apertura del vault, IPC, caricamento cache o UI.

| Record | Prima, ms | Dopo, ms | JSON indice prima | JSON indice dopo | Picco processo prima/dopo |
|---:|---:|---:|---:|---:|---:|
| 1.000 | 1,70 | 0,22 | 4,10 MB | 0,97 MB | 62 / 25 MB |
| 10.000 | 119,41 | 3,00 | 41,19 MB | 9,92 MB | 395 / 142 MB |
| 50.000 | 2.177,31 | 9,42 | 206,63 MB | 50,22 MB | 1.385 / 621 MB |

MB indica 1.000.000 byte. A 50.000 record il refuso `contrato` produce risultati
positivi in 9,24 ms; la parola inesistente non restituisce risultati. La cache
nuova passa confronto integrale e parsing a tutte e tre le dimensioni.

La prova sullo snapshot V8 reale da 50.000 record autentica e trova **tutti** i
50.000 fascicoli. La costruzione iniziale dell'indice richiede 6,90 s; ricaricare
la cache cifrata e verificarne la coerenza richiede 1,95 s. Il file cache è
13.688.566 byte; il picco del processo è 687 MB. Questo resta un limite concreto:
il comando ricerca ricarica l'indice da disco a ogni chiamata, quindi i 9,42 ms
non rappresentano la latenza dell'app. La prova non dimostra usabilità fluida
con 50.000 fascicoli su un telefono con poca memoria.

## Snapshot e backup sintetici

Misure dell'esecuzione dopo la patch. Le differenze di KDF e contesa CPU non
consentono di interpretare questi numeri come regressioni rispetto alla baseline.

| Record | Snapshot | Cifratura record | Commit snapshot | Sblocco + manifest | Lettura e confronto di tutti i record | Commit singola modifica | Backup |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1.000 | 0,75 MB | 37 ms | 21 ms | 273 ms | 17 ms | 17 ms | 13 ms |
| 10.000 | 7,53 MB | 953 ms | 138 ms | 554 ms | 374 ms | 132 ms | 56 ms |
| 50.000 | 37,72 MB | 2.552 ms | 529 ms | 708 ms | 1.675 ms | 541 ms | 194 ms |

Creazione/calibrazione: rispettivamente 3,11 / 3,83 / 2,45 s. Parametri scelti:
128 MiB/p2, 128 MiB/p1, 64 MiB/p3, sempre tre iterazioni. Picchi processo:
217 / 282 / 531 MB. Il commit di una modifica riscrive lo snapshot completo;
non è un aggiornamento del solo record sul disco.

Le 12 verifiche di affidabilità confrontano il backup byte per byte, il suo
HMAC con identità sintetica, il ripristino e tutti i 25 record, la reiezione di
snapshot alterati/password errata, la rotazione di tre coppie backup+HMAC, il
cambio password dopo riapertura, la selezione dell'ultimo split, il rifiuto di
backup split non migrati, la migrazione V7→V8, l'impossibilità per uno split
corrotto residuo di prevalere sul V8 e il fallimento sicuro di una rename.

Il coordinatore ha inoltre esportato dalla UI macOS un backup di 10.000
fascicoli contenente una nota appena salvata: la verifica con crittografia reale
ha trovato la nota, contato 10.000 record e rifiutato la password errata.
L'importazione tramite dialogo nativo non è verificata da questa prova.

## Crash durante la pubblicazione

Il figlio esegue `io::atomic_write_with_sync` di produzione su uno snapshot V8
con 250 record. Un interposer macOS osserva solo il path sintetico; scrive un
checkpoint, ferma il figlio e il processo padre invia `SIGKILL`. La riapertura
autentica il vault e confronta **tutti** i record e tutti i byte pubblicati.

| Punto osservato | Snapshot dopo riapertura | Esito |
|---|---|---|
| Metà scrittura del file temporaneo | Precedente completo | PASS |
| Chiusura del temporaneo dopo il percorso di flush | Precedente completo | PASS |
| Prima della rename | Precedente completo | PASS |
| Dopo la rename, prima del flush della directory | Nuovo completo | PASS |

I primi tre crash lasciano un file temporaneo cifrato orfano, mai trattato come
vault canonico. Il quarto non lo lascia. La pulizia del file orfano è un tema di
spazio, non un dato pubblicato parzialmente. Queste prove coprono crash del
processo: non simulano mancanza di corrente, guasto fisico o filesystem Windows/
Android. Una prima versione dell'harness attendeva `fsync`, non osservato dal
percorso Rust macOS che usa `F_FULLFSYNC`; quel caso è stato marcato fallito,
senza attribuirgli un PASS. La ripetizione con checkpoint di chiusura è nei
risultati crash separati ed è quella conclusiva.

## Riproducibilità e prove conservate

Dal progetto, con dipendenze già disponibili nella cache Cargo:

```sh
python3 scripts/validate-backend.py --unit-tests-only --results /private/tmp/backend-tests.json
python3 scripts/validate-backend.py --sizes 1000 10000 50000 --results /private/tmp/backend-results.json
python3 scripts/validate-backend.py --crash-only --results /private/tmp/backend-crash.json
python3 scripts/validate-backend.py --gui-fixture 10000
```

Lo scratch è un figlio dedicato di
`/private/tmp/lexflow-validation-2026-09-07/`, con marcatore di proprietà; il
runner rifiuta di usare directory esistenti senza marcatore. Per impostazione
predefinita elimina lo scratch al termine. `--keep-scratch` lo conserva;
`--gui-fixture` lo conserva per la copia nel profilo isolato e rifiuta di
sovrascrivere una fixture GUI esistente. Non eseguire due istanze sullo stesso
scratch durante altre compilazioni o prove. Lo scratch della sessione resta
temporaneamente disponibile al coordinatore per le verifiche complete e sarà
eliminato al termine di tali lavori.

La fixture GUI usa la password pubblica di test
`SYNTHETIC-Validation-Password-2026!`, prehash SHA-256 esadecimale come nel bridge
Tauri, header e DEK reali, `status: active` e summary ottenuti dalla funzione di
produzione. La fixture non deve essere usata per dati reali.

- [Baseline, hash sorgenti e risultati grezzi](COLLAUDO-2026-09-07-backend-baseline.json).
- [Misure successive alla patch](COLLAUDO-2026-09-07-backend-results.json).
- [78 test Rust release](COLLAUDO-2026-09-07-backend-tests.json).
- [Quattro checkpoint crash conclusivi](COLLAUDO-2026-09-07-crash-results.json).
- [Verifica export nativo macOS](COLLAUDO-2026-09-07-backup-nativo.json).

I file JSON mantengono gli hash dei sorgenti realmente misurati. Il report dei
benchmark conserva anche il primo checkpoint `fsync` non osservato: non viene
riscritto per nascondere il tentativo fallito. Questi risultati non sostituiscono
la compilazione e la suite completa Tauri, i collaudi dei nuovi installer o le
prove su Windows e dispositivi Android fisici.

## Revisione finale biometria, prima dei nuovi installer

Individuati altri due difetti in `bio.rs`: `save_bio` poteva scrivere una
credenziale ricevuta dall'IPC senza verificare sblocco e password; il timeout
macOS/Windows provava ad acquisire lo stesso mutex che il thread di attesa
teneva durante `Child::wait`, potendo restare bloccato oltre i 60 secondi.

La patch richiede una sessione attiva, verifica il prehash della password sul
vault corrente e confronta la DEK risultante con quella della sessione. Il token
di sessione viene ricontrollato dopo l'acquisizione dei lock; la scrittura è
serializzata con blocco del vault e cambio password. Il buffer ricevuto usa
`Zeroizing` anche in caso di errore. I processi ausiliari vengono controllati con
`try_wait`, terminati alla scadenza e raccolti senza un mutex condiviso con
un'attesa bloccante. Nel codice finale questo percorso riguarda Windows Hello,
con 10 secondi per il rilevamento hardware e 60 per il processo di login; macOS
usa invece i framework nativi descritti sotto.

Tre regressioni coprono sessione bloccata/password errata/DEK diversa, timeout
con terminazione e raccolta di un processo sintetico, e conservazione dell'exit
status di un processo già terminato. Questi test aggiunti sono separati dai 78
test registrati nel JSON precedente; l'esito della suite completa appartiene
alla verifica finale del coordinatore. Nessuna prova ha toccato il Portachiavi
o la configurazione biometrica reale dell'utente.

La revisione successiva, prima del candidato Mac, ha eliminato la dipendenza
runtime da `/usr/bin/swift`. `build.rs` compila `macos_biometry.m` esclusivamente
per target macOS, usando clang e SDK sulla macchina di sviluppo; non aggiunge
dipendenze Cargo. Il programma distribuito chiama LocalAuthentication e
Security di sistema. Il bridge compila e collega per ARM64 e x86_64 con
`-Werror`, deployment target 11.0; `otool` mostra solo framework e librerie di
sistema. Il vecchio IPC `warm_swift` è conservato senza eseguire Swift.

L'accesso macOS non esegue più una richiesta biometrica preliminare: la lettura
della credenziale protetta richiede l'autenticazione tramite l'ACL del
Portachiavi. Non esiste più fallback di lettura tramite keyring ordinario. Una
quarta regressione verifica che un ACL assente, non protetto o non verificabile
impedisca persino la chiamata al lettore; una cancellazione resta un errore.

Le query di salvataggio, lettura, autotest e cancellazione selezionano tutte
`kSecUseDataProtectionKeychain`. Questa scelta è documentata da Apple per gli
attributi di accessibilità e i gruppi di accesso su macOS; il Portachiavi richiede
entitlement adatti all'applicazione. Fonti: [Data Protection Keychain](https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain),
[entitlement mancanti](https://developer.apple.com/documentation/security/errsecmissingentitlement).

La disponibilità comprende ora sia LocalAuthentication sia l'identificativo
applicazione/gruppo Keychain negli entitlement del processo. I pacchetti con
firma **ad hoc** attuali, che non li possiedono, dichiarano biometria
indisponibile. Resta l'accesso con Master Password; non sono stati inventati
entitlement né ridotta la protezione ACL per far riuscire l'attivazione. Una
distribuzione firmata con gli entitlement necessari richiede ancora il test
reale di enrollment, riavvio e login prima di promettere Touch ID funzionante.

Il coordinatore aveva osservato `OSStatus -25244` durante l'enrollment nativo
precedente. Un probe aggiuntivo limitato a un namespace Keychain sintetico non
è stato eseguito: la compilazione iniziale segnalava una deprecazione SDK e la
successiva richiesta di esecuzione è stata respinta dalla revisione automatica
per quota Codex esaurita. Nessuna voce è stata creata o letta da quel probe e
non è stato tentato di aggirare il rifiuto. Non si attribuisce quindi un esito
positivo alla registrazione ACL su una build ad hoc. I due test isolati del
timeout, senza Keychain, sono passati in 0,10 s.

## Revisione finale import/export

I dialoghi conservano il token della sessione iniziale, ricontrollato al
completamento e prima della pubblicazione sotto `write_mutex`. Nessun mutex è
tenuto durante l'attesa del dialogo. La password dell'archivio corrente e la
password portabile del backup sono parametri distinti dell'esportazione.

Due ulteriori correzioni sono in `import_export.rs`:

- La password di autorizzazione export deve ricavare la stessa DEK della
  sessione, con confronto a tempo costante. Una sostituzione del file sul disco
  non può far autorizzare una vecchia cache con la password del file sostitutivo.
- L'importazione eredita `max(contatore snapshot autenticato, watermark locale,
  contatore importato) + 1`; un sidecar invalido, non leggibile o un overflow
  interrompono l'operazione. Il watermark non viene più abbassato prima della
  pubblicazione. Il nuovo snapshot viene committato per primo, poi viene
  avanzato il watermark. Se quest'ultimo aggiornamento fallisce, il file
  pubblicato rimane valido e l'accesso successivo può avanzare il watermark,
  come per le scritture normali: non si presenta come fallita un'importazione
  già committata. Non è una transazione atomica fra due file.

Quattro regressioni aggiunte usano file e cifratura reali con dati sintetici:
file sostituito con cache/sessione precedente, importazione monotona riaperta e
record confrontato, contatore invalido/esaurito che preserva il vecchio vault,
rename fallita che conserva watermark e destinazione senza staging orfani.
Questi test fanno parte della compilazione finale completa, non del JSON
storico dei 78 test core. Hash del file consegnato per tale verifica:
`0da868ba9e40e3bcea510d7066517d86de3a15605db8aef756e6a4c9e45b1157`.

## Export nativo con password distinta e dialogo macOS

Sul candidato intermedio ARM64, il coordinatore ha esportato le 10.000 pratiche
sintetiche con una password del backup diversa dalla Master Password. La
verifica indipendente usa le funzioni crittografiche di produzione e conferma:
10.000 record JSON decifrati, nota salvata dalla UI presente, Master Password
del vault rifiutata e altra password errata rifiutata. La verifica è durata
1,41 s; questo tempo comprende tre derivazioni e la verifica del file, non è un
benchmark del dialogo. [Risultato e hash](COLLAUDO-2026-09-07-backup-nativo-password-distinta.json).

Il comando riproducibile del piccolo harness compilato è:

```sh
lexflow-backend-validation verify-native-export /percorso/backup-sintetico.lex 10000 --distinct-backup-password
```

L'opzione usa esclusivamente le password pubbliche della fixture: backup
`SYNTHETIC-Backup-Password-2026!`, Master Password
`SYNTHETIC-Validation-Password-2026!`, entrambe con prehash SHA-256 come nel
bridge UI. Non è un comando per aprire backup reali. Il risultato riguarda il
candidato intermedio ARM64 usato nella prova: non certifica gli installer
ricompilati successivamente e non esercita il dialogo nativo di importazione.

Durante questa prova, il pannello Salva mostrava inizialmente Salva e Nuova
cartella disabilitati. Il campione del processo dell'app delle 10:17:59 dura
circa due secondi: 1710/1713 osservazioni del thread principale sono nel normale
event loop AppKit e i worker Tokio risultano in attesa. Non mostra un blocco del
thread principale; non contiene stack attivi NSSavePanel o FileProvider. La
sola presenza di CloudDocs e FileProvider nell'elenco delle librerie caricate
non attribuisce l'anomalia a iCloud. Il coordinatore ha poi abilitato i pulsanti
interagendo con percorso, nome e focus del pannello, e il salvataggio è riuscito.
Questa sequenza è compatibile con una validazione del campo/focus durante
l'automazione, ma non basta a determinarne la causa. Non è stata applicata una
correzione al codice dell'app basata su questa osservazione.
