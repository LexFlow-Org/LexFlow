# Audit backend — 8 settembre 2026

La revisione ha individuato difetti concreti anche dopo i collaudi precedenti.
Le correzioni sono nei sorgenti; i quattro installer pubblicati 1.0.1 non sono
stati ricompilati durante questo audit. Le relative impronte sono invariate.
La nuova distribuzione dovrà distinguersi come 1.0.2 e incorporare questi sorgenti.

## Ambito e metodo

Revisione di tutti i moduli di `src-tauri/src`, del bridge Objective-C, della
registrazione IPC, delle capability/CSP e dei confini verso i programmi esterni.
Tre revisioni parallele hanno coperto archivio/crittografia/sessione,
file/backup/documenti e licenze/identità/migrazioni; le correzioni più delicate
sono state incrociate fra revisori. Controllato anche il generatore tramite i
suoi test sintetici e aggiornato il collegamento frontend per la prova licenza.

I test Rust eseguono il codice applicativo su questo Mac Apple Silicon con
archivi temporanei sintetici. I test frontend usano jsdom e IPC simulato.
Nessun archivio utente, password reale o chiave privata è stato usato. Nessuna
licenza reale è stata emessa o consumata. Le dipendenze pubbliche mancanti e il
database RustSec sono stati scaricati per il collaudo; il confronto delle
dipendenze avviene localmente, senza inviare documenti o il progetto.

La suite iniziale passava **437 test**, ma non copriva i casi qui sotto: il
superamento dei test preesistenti non dimostrava l'assenza di questi difetti.
Le prove e le impronte finali sono raccolte nelle
[evidenze](validation/2026-09-08-backend-audit/).

| Verifica conclusiva | Esito |
| --- | --- |
| Backend Rust sul Mac | 480 test distinti superati: 473 nel gruppo parallelo e 7 eseguiti singolarmente; nessun test ignorato |
| Frontend | 65 test superati in 13 file; build riuscita |
| Controllo statico | Clippy con `-D warnings` superato; lint frontend senza errori, 1 warning preesistente in AgendaPage |
| Configurazione di produzione Mac | `cargo check --lib --release` superato; non è la creazione di nuovi installer |
| Regole native e generatore | 10 test delle regole native e 19 test sintetici del generatore superati |
| Stabilità dei sorgenti | Impronte verificate prima/dopo gli ultimi controlli; quattro installer pubblicati invariati |

Due vecchi test di temporizzazione hanno superato le proprie soglie durante
esecuzioni parallele sotto carico: HMAC 28% di differenza e password 60,1% di
scostamento massimo. Gli esiti falliti restano nelle evidenze. La ripetizione
isolata HMAC ha misurato 0,1%. Per il controllo conclusivo i test con nomi
`timing`/`constant_time` sono eseguiti uno alla volta, dopo gli altri, senza
cambiare soglie, implementazione crittografica o disabilitare test. Il confronto
HMAC usa `verify_slice` di RustCrypto, che applica `ct_eq` a tag di uguale
lunghezza. Un test sul tempo trascorso può trovare anomalie ma non dimostrare
da solo l'assenza di canali temporali. Nell'esecuzione isolata conclusiva HMAC
ha misurato 5,0% e il test password 9,4%, entrambi entro le proprie soglie.
Qui i risultati sotto carico non sono stati interpretati come exploit dimostrati.

## Difetti risolti

| Area | Problema e conseguenza | Correzione e prova |
| --- | --- | --- |
| Licenza salvata — P1 | La cache `ed25519-burned` non conservava la prova firmata; dati locali ricostruibili dall'utente potevano autorizzare una licenza senza firma dell'emittente. Questo riguarda l'autorizzazione commerciale, non la decifrazione dei fascicoli. | Conservazione cifrata del token firmato e nuova verifica Ed25519 di firma, emittente, scadenza e vincoli ad ogni controllo. I campi cache non autorizzano più l'accesso. Test di token alterato, emittente errato e campi cache falsificati. |
| Aggiornamento licenze — P1/P2 | Una vecchia attivazione senza token non è autenticabile retroattivamente. Una licenza scaduta bloccava l'inserimento di un nuovo ID, mentre il generatore vieta di riemettere lo stesso ID. | Prova esplicita del codice originale, vincolata a ID, HMAC del token, emittente e dispositivo della precedente attivazione. Rinnovo con nuovo ID ammesso dopo scadenza firmata e periodo di tolleranza. La prova di una licenza scaduta non apre il frontend. |
| Attivazione interrotta — P1 | Un errore fra scrittura licenza, sentinel e registro delle chiavi consumate poteva lasciare l'installazione bloccata. | Journal cifrato e recupero idempotente prima dei controlli. Test di errore in ogni scrittura, ripresa e rifiuto di journal alterato o con firma errata. |
| Migrazione dei file di sicurezza — P1 | L'originale poteva essere cancellato anche dopo una copia fallita. | Copia persistita e confrontata prima della rimozione; un errore conserva la fonte. Test di destinazione esistente, fallimento e ripetizione. |
| Identità locale e orologio — P1/P2 | Un identificatore esistente corrotto poteva essere sostituito, rendendo illeggibili i metadati. Alcune letture di marker non avevano limiti e corruzioni venivano trattate come assenza. | Identità desktop/Android conservata in caso di errore, letture limitate e rifiuto esplicito dei marker corrotti. Se mancano entrambi i marker dell'orologio su un'installazione attivata serve la prova del codice originale. |
| Reset dell'archivio — P1 | Il contatore esterno delle scritture sopravviveva al reset e bloccava il nuovo archivio come presunto rollback. Gli errori di cancellazione erano ignorati. | Reset coerente del contatore, chiusura della sessione e segnalazione degli errori. Test completo creazione/salvataggio/blocco/sblocco/reset/nuova creazione/riapertura; licenze preservate. |
| Tentativi di accesso — P1 | Ordine inverso dei mutex poteva bloccare il processo; alla soglia di protezione potevano restare cache e versione dell'archivio attive. | Ordine dei lock coerente, serializzazione dei controlli, cancellazione congiunta di chiavi/cache/versione e contatore saturante. Test di contesa e soglia con deposito credenziali simulato. Eliminato il doppio conteggio del fallimento biometrico. |
| Registro attività — P1/P2 | Cercava la chiave del vecchio formato, mai impostata per gli archivi attuali; oltre 10.000 eventi la rimozione della prima voce rompeva la catena. Errori di parsing potevano azzerare la storia. | Accesso tramite DEK corrente, lettura rigorosa, originale conservato sugli errori, conservazione delle ultime 10.000 voci con nuova catena coerente. Test dell'effettivo stato V4, della soglia e della corruzione autenticata. |
| Registro e cambio archivio — P1/P2 | Attivare il registro richiedeva evitare lock ricorsivi in backup/import e preservarlo durante il cambio DEK. Un evento scritto dopo aver rilasciato il mutex poteva finire sull'archivio successivo. | Registrazione dentro la transazione già serializzata; chiave casuale propria del registro, protetta temporaneamente da entrambe le DEK prima del cambio. Test di interruzione prima/dopo commit e importazione con chiave diversa. |
| Esportazione CSV — P2 | Valori non numerici potevano finire integralmente nei log in chiaro. | Diagnostica limitata al nome fisso del campo, senza contenuto del record. Test con testo, oggetti e array riservati sintetici. |
| Esportazione PDF — P2 | Un errore di scrittura poteva lasciare il nome finale vuoto/parziale e impedire il tentativo successivo. | File temporaneo, sincronizzazione e pubblicazione senza sovrascrittura. Errore simulato dopo una scrittura parziale: nessun file finale, nuovo tentativo riuscito. |
| Ricerca — P2 | Risultati/cache potevano essere pubblicati dopo il cambio di sessione; la cache seguiva collegamenti simbolici in scrittura. | Ricontrollo della sessione prima della pubblicazione, breve mutex finale, DEK temporanea protetta, scrittura atomica della cache. Test di sessione terminata e destinazione simbolica. |
| Impostazioni e notifiche — P2 | Autolock negativo accettato; valori estremi nei promemoria potevano causare overflow. La disattivazione delle notifiche non era sempre rispettata e il contenuto poteva essere preparato prima del blocco. | Schema/intervalli validati, aritmetica controllata, preferenze e privacy ricontrollate all'invio, aggiornamento della coda dopo il salvataggio delle preferenze. Test sintetici degli estremi e delle impostazioni. |
| Briefing Android — P2 | Un avviso futuro poteva usare il giorno di riferimento sbagliato, in particolare la sera. | Data derivata dal giorno effettivo del briefing; test del giorno successivo e del cambio anno. Il test è della logica condivisa, non dell'invio su telefono. |
| Record, snapshot e contatori — P1/P2 | Scritture oltre i limiti del lettore potevano creare dati non riapribili; il contatore poteva traboccare; lo sblocco di recupero non applicava lo stesso controllo antiripristino della password. | Limiti simmetrici prima della pubblicazione, incremento controllato, controllo del contatore condiviso. Prove al limite con dimensioni ridotte, conservazione dell'originale e stesso rifiuto di rollback nei due percorsi. |

P1 indica rischio elevato di indisponibilità, perdita di integrità o aggiramento
dell'autorizzazione; P2 indica difetto concreto di riservatezza, robustezza o
comportamento. Le priorità non sono punteggi CVSS né una certificazione.

## Effetto sulle licenze già distribuite

La chiave privata e la chiave pubblica dell'emittente restano le stesse.
La prossima build chiederà **una volta il codice originale** per una vecchia
attivazione priva della firma conservata. La prova vale soltanto per la
corrispondente attivazione sullo stesso dispositivo. Non emette una nuova
licenza e non apre un secondo ciclo di attivazione del codice consumato.
Le attivazioni già convertite restano verificabili senza reinserimento.

Prima di distribuire questa correzione occorre verificare che il destinatario
conservi quel codice. Se lo ha perso, serve un recupero controllato dalla
documentazione dell'emissione; questo audit non ha aperto il registro reale né
ricostruito codici reali. La Master Password dell'archivio è una credenziale
separata. I quattro installer 1.0.1 attuali continuano ad avere il comportamento
precedente: questa modifica non viene applicata a distanza.

## Dipendenze e comportamento offline

Il lockfile corrente non presenta corrispondenze nella categoria
`vulnerabilities` del [database RustSec](https://rustsec.org/advisories/)
scaricato per questa revisione: 1.242 advisory, commit
`8a1eb4f933fb5821add5b4e98601ebd90b8b3538`.
Restano **18 avvisi di mancata manutenzione e 2 segnalazioni `unsound`**.
`glib 0.18.5` riguarda Linux; `rand 0.7.3` è transitivo nella generazione
`phf_codegen/selectors` in compilazione. La feature `log` interessata non è
attiva nell'albero Mac ricontrollato. Il confronto `--target all` non è stato
completato perché mancavano dipendenze Android nella cache; la scansione
RustSec del lockfile, invece, non applica un filtro di piattaforma.

I programmi locali identificati sono qpdf 12.4.1 e Typst 0.15.1, coerenti con
le rispettive [release qpdf](https://github.com/qpdf/qpdf/releases/tag/v12.4.1)
e [release Typst](https://github.com/typst/typst/releases/tag/v0.15.1).
Questa identificazione non equivale a fuzzing dei loro parser né alla verifica
di ogni libreria nativa interna.

Nei comandi Rust applicativi esaminati non è emerso un nuovo percorso di
comunicazione remota. CSP, navigazione limitata, capability senza apertura
arbitraria di shell/URL dal frontend e rimozione del permesso Internet Android
rimangono presenti. I test delle regole native sono sintetici. **Non è stata
eseguita una nuova cattura di rete durante questo audit**: le misure precedenti
restano riferite ai binari e agli scenari indicati nei rispettivi collaudi.

## Limiti che restano espliciti

- La monousabilità è registrata localmente. Computer scollegati non condividono
  un registro delle attivazioni; senza un vincolo firmato al dispositivo non
  si può garantire unicità globale del codice. Anche l'orologio locale non è
  una fonte di tempo indipendente da chi controlla il computer.
- Su Windows il nome del PC contribuisce ancora al legame dei metadati:
  rinominarlo può invalidare l'attivazione. Una migrazione a identità stabile
  richiede una procedura compatibile con i dati esistenti e collaudo Windows;
  non è stata introdotta alla cieca in questo audit.
- Un journal interrotto durante un futuro cambio di emittente richiederà una
  procedura di recupero che ne conservi la copia. Una firma revocata non viene
  accettata per sbloccare automaticamente il problema.
- Windows Error Reporting, copie del sistema, swap, backup del disco, screenshot
  e programmi già eseguiti nello stesso account richiedono protezioni e prove
  proprie del sistema operativo. `Drop` non viene eseguito in ogni tipo di
  arresto e la rimozione di file non garantisce cancellazione fisica su SSD.
- Il registro attività è locale, cifrato e limitato a 10.000 eventi; non è un
  registro notarizzato o un ancoraggio esterno contro cancellazione/rollback.
  Non costituisce una dichiarazione di conformità normativa.
- Il contatore delle scritture rileva alcuni ripristini accidentali a snapshot
  precedenti; metadati e contatore locali non costituiscono un contatore hardware
  resistente a un attaccante che possa ripristinare o manipolare tutti i file.
  Sono ora applicati limiti di 100 MiB al contenuto di un record, 100 MiB alla
  sua rappresentazione cifrata base64 e 500 MiB allo snapshot completo. Un
  salvataggio oltre limite restituisce un errore e conserva il file precedente.
- Non è stato eseguito collaudo nativo su Windows, Mac Intel o Android, né una
  prova fisica di perdita di alimentazione. Restano i limiti Android già
  documentati, inclusi il crash Wry osservato nell'emulatore precedente e la
  necessità di provare selezione file, backup/ripristino e notifiche su telefono.
- Mac e Android non acquistano nuove funzioni biometriche in questa revisione.
  Firma/notarizzazione dei pacchetti e test dei nuovi installer saranno parte
  della preparazione della distribuzione successiva.

## Riproduzione

```sh
cargo test --manifest-path src-tauri/Cargo.toml --lib --locked -- --test-threads=1
cargo clippy --manifest-path src-tauri/Cargo.toml --lib --locked -- -D warnings
npm --prefix client ci --no-audit --no-fund
npm --prefix client test
npm --prefix client run lint
npm --prefix client run build
python3 scripts/test-native-hardening.py
python3 scripts/test-license-generator.py
cargo audit --file src-tauri/Cargo.lock --json
```

Le evidenze indicano esattamente gli esiti eseguiti in questa sessione e le
impronte dei sorgenti. Un audit del codice e test superati riducono i rischi;
non permettono di dichiarare impossibili ulteriori difetti.
