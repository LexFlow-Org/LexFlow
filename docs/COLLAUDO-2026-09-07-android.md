# Collaudo Android — 7 settembre 2026

## Stato

L'APK originale è stato installato ed eseguito nell'emulatore. La prova ha individuato un difetto CSS che nascondeva il modulo password sui display stretti; la correzione è stata verificata in memoria e applicata ai sorgenti. Il nuovo APK corretto è stato compilato, firmato, installato come aggiornamento e riaperto quattro volte offline nell'emulatore. Il modulo password è visibile nella cattura ufficiale del display virtuale. Non è disponibile un telefono fisico. Questo documento distingue i controlli del pacchetto dalle osservazioni effettuate durante l'esecuzione e non certifica tutti i dispositivi Android.

## Pacchetto e isolamento

- APK originale consegnato: `releases/2026-09-06/Android/LexFlow-1.0.1-Android-arm64.apk`.
- Versione 1.0.1, codice Android 251, 13.007.417 byte.
- SHA256 ricontrollato: `913ef6f3c74b96828570a3a015b17e07f02e23a01717406d987e3c27d0113e8f`.
- APK originale conservato. Nessun accesso alle chiavi private di licenza né ai registri reali. Le correzioni ai sorgenti sono elencate più avanti; la modifica CSS in memoria nell'emulatore viene distinta dall'esecuzione del pacchetto originale.
- Ambiente di prova: `/private/tmp/lexflow-validation-2026-09-07/android`.
- Immagine AOSP Android 15/API 35 ARM64, revisione 2, senza Google Play o account Google.
- AVD dedicato `LexFlowValidation35`: 3 GiB RAM, 2 CPU virtuali, partizione dati da 2 GiB; camera e ingresso audio disattivati. Snapshot scaricabili e ripristino automatico da snapshot disattivati.
- `ANDROID_USER_HOME`, `ANDROID_AVD_HOME` e `ANDROID_EMULATOR_HOME` puntano alla cartella temporanea; `HOME` rimane invariata.

L'APK richiede un WebView compatibile con Chromium 111 o successivo. Dopo l'avvio è stata rilevata la versione `com.android.webview 124.0.6367.219`, compatibile con questo requisito. API 35 da sola non dimostra il requisito del browser, che deriva dal [supporto ufficiale di Tailwind CSS 4](https://tailwindcss.com/docs/compatibility#browser-support).

## Inventario e provenienza degli strumenti

All'inizio del collaudo non risultavano disponibili `adb`, `emulator`, `sdkmanager`, Android Studio, SDK globali nelle posizioni standard né AVD esistenti. L'inventario USB non mostrava un dispositivo Android. La toolchain temporanea delle build precedenti era stata rimossa.

Sono stati scaricati solo archivi ufficiali Google, con dimensione e SHA1 confrontati con i cataloghi ufficiali; è stata calcolata anche SHA256 per la ricevuta locale.

| Componente | Versione | Download, byte |
|---|---|---:|
| Platform Tools / ADB | 37.0.1 | 16.110.554 |
| Command-line Tools | 19.0 | 143.250.852 |
| Emulator Apple Silicon | 37.1.11, build 15917651 | 394.555.844 |
| AOSP API 35 ARM64 | revisione 2 | 769.099.654 |
| Totale | | 1.323.016.904 |

Gli ultimi tre archivi occupano 3.165.534.778 byte una volta estratti, prima di ADB e dei dati dell'AVD. Il computer disponeva di circa 79 GiB liberi. Per il solo emulatore è stato riutilizzato OpenJDK 25.0.2 già installato. La successiva compilazione usa invece un JDK 17 isolato, descritto sotto.

`emulator-check accel` è terminato con codice 0 e ha rilevato `Hypervisor.Framework OS X Version 26.6`. L'avvio è stato coordinato con il collaudo macOS. L'immagine avviata usa Android 15/API 35 ARM64, build `userdebug`, pagine di memoria da 4096 byte: non costituisce una prova runtime su kernel con pagine da 16 KB.

Cataloghi: [Android SDK](https://dl.google.com/android/repository/repository2-3.xml), [immagini AOSP](https://dl.google.com/android/repository/sys-img/android/sys-img2-3.xml). Le ricevute con URL e checksum sono `download-provenance.json` e `adb-provenance.json` nella cartella temporanea.

## Prove da completare

| Prova | Stato |
|---|---|
| Avvio AVD e verifica WebView/ABI/pagine memoria | Completata: API35, ARM64, WebView124, pagine4 KB |
| Installazione e apertura dell'APK originale | Installazione riuscita; Activity avviata; difetti osservati sotto |
| Attivazione con licenza sintetica e archivio sintetico | Licenza sintetica attivata; creazione archivio non ancora eseguita |
| Apertura, modifica, persistenza dopo chiusura forzata | In attesa |
| Funzionamento offline e osservazione del traffico del processo | In attesa |
| Esclusione backup, schermate protette e riapertura | Manifest e screenshot protetto verificati sul precedente APK; ripristino/riapertura completi in attesa |
| Tempi di avvio, memoria e risposta dell'interfaccia | In attesa |

Le istruzioni ufficiali descrivono la [gestione dell'emulatore da riga di comando](https://developer.android.com/studio/run/emulator-commandline) e [ADB](https://developer.android.com/tools/adb). I risultati di un emulatore saranno riportati come tali, senza attribuirli a un telefono reale.

## Evidenze dell'esecuzione e correzioni

1. **Modulo password invisibile sui display stretti.** Dopo l'attivazione la pagina conteneva il form nel DOM, ma il suo contenitore aveva `display: none`. La regola responsive di `client/src/index.css` nascondeva tutte le `.drag-region` sotto 1024 px, inclusa la schermata `LoginScreen`. Ora nasconde soltanto `.window-controls`; sulle aree trascinabili disattiva il trascinamento lasciando visibili i contenuti. Applicando la stessa correzione alla CSSOM dell'AVD, il valore è passato da `none` a `flex` e i testi del form sono tornati visibili. L'APK sul disco non è stato modificato da questa prova.
2. **CSP e stili dei messaggi.** La console della WebView ha registrato il rifiuto degli elementi style dinamici di `react-hot-toast`: il nonce aggiunto da Tauri al tag style inline rendeva inefficace `unsafe-inline`. Le regole critiche sono state spostate in `client/src/styles/bootstrap.css`, linkato prima del modulo bootstrap. La CSP non è stata allargata. La build frontend è riuscita; HTML sorgente e compilato non contengono tag style o script inline e conservano i limiti script/connect. Nel nuovo APK il modulo password è visibile; il collaudo specifico dei messaggi toast resta da completare.
3. **Diagnostica WebView nell'immagine userdebug.** Il pacchetto installato non aveva il flag `DEBUGGABLE`, ma la WebView dell'immagine AOSP userdebug esponeva un socket DevTools. È stato usato per leggere DOM, CSS e console e per l'input della licenza sintetica; non è stato abilitato durante la prova. Non si deduce da questo che il canale sia esposto su telefoni normali. Il nuovo hardener imposta esplicitamente `android:debuggable=false` nel manifest release e `WebView.setWebContentsDebuggingEnabled(false)` in `MainActivity` quando `BuildConfig.DEBUG` è falso. I dieci test dell'hardener sono passati; Il manifest e il bytecode del nuovo APK confermano entrambe le impostazioni; la particolarità userdebug è descritta sotto.
4. **Crash durante una riapertura.** Dopo l'interruzione dell'emulatore è stato osservato un SIGABRT: `wry 0.54.4`, `src/android/mod.rs:426`, `platform_webview_version`, `recv_timeout(...).unwrap()` con errore `Timeout`. Un successivo avvio è riuscito. La chiamata viene effettuata dall'inizializzazione del runtime Tauri; causa e riproducibilità devono essere isolate prima di attribuire una correzione a questo crash.
5. **Protezione screenshot.** Il comando `screencap` eseguito da Android ha prodotto una finestra nera con i soli controlli di sistema: `FLAG_SECURE` è attivo. La cattura del display effettuata dal controllore dell'emulatore può osservare i pixel virtuali e non è una prova di aggiramento su un telefono ordinario.

Installazione iniziale: circa 0,32 s; primo `am start -W`: `TotalTime 559 ms`. Sono osservazioni singole con avvio del sistema e richieste permessi, non benchmark rappresentativi. Nessun numero di prestazioni su telefono reale viene dichiarato.

Le prove iniziali non hanno creato un archivio: è stata usata soltanto una licenza sintetica di 48 ore, emessa fuori dal registro reale. Una successiva ripresa della diagnostica è stata rifiutata dal controllo automatico di approvazione per esaurimento quota; non sono stati usati percorsi alternativi per eseguire l'azione rifiutata. La nuova richiesta di rigenerazione degli installer ha consentito le operazioni distinte di download toolchain e compilazione.

## Rigenerazione dell'installer corretto

La nuova compilazione mantiene la versione applicativa 1.0.1 e porta il codice Android a 252, per consentire l'aggiornamento del precedente pacchetto 251. Riusa lo stesso certificato APK, distinto dalla chiave che firma le licenze. Il vecchio installer rimane conservato fino alla verifica del candidato.

La toolchain di compilazione è isolata nella cartella temporanea del collaudo: NDK r27c (`27.2.12479018`), piattaforma API36 revisione2, build-tools36.0.0 e Temurin17.0.20.1+1 ARM64. Questi quattro archivi ufficiali occupano 1.166.979.450 byte; dimensioni e checksum sono stati confrontati con il catalogo Google o la ricevuta ufficiale già verificata della precedente build. Gradle richiede anche build-tools35.0.0 e le relative licenze, gestiti dallo SDK temporaneo. Nessun JDK o SDK globale viene sostituito. La ricevuta è `build-toolchain-provenance.json` nella cartella temporanea.

Il progetto Android è stato rigenerato da Tauri e lo script `harden-android.py` applicato. La compilazione Rust e il confezionamento Gradle sono riusciti. Android lint segnala per impostazione predefinita anche `debuggable=false` esplicito: l'hardener esclude solo `HardcodedDebugMode` sull'elemento application del manifest release, lasciando attivi gli altri controlli. Dieci test passati. È stato rimosso un duplicato del collegamento generato `libapp_lib 2.so`, verificando che il pacchetto contenga esattamente una libreria nativa ARM64.

Il candidato è in `candidate/LexFlow-1.0.1-Android-arm64.apk` nella cartella temporanea, pesa 13.019.705 byte e ha SHA256 `06236e091912d55e0d4d9a6d5c9f90ea8f7eb33f4825ef5d7ea76fb57c7e73d6`. Il certificato SHA256 è `bab0ab7ef4395793afb278b688233d177c4545c4c49748a0a10409447544eaf5`, identico alla versione precedente. Firma, allineamento ZIP/ELF16 KB, assenza dei permessi di rete, debug/backup/cleartext disattivati, licenze incluse e nuova chiave pubblica delle licenze sono stati verificati. Gli 86 input sorgenti/configurazioni/risorse/frontend compilato sono rimasti invariati durante la build: impronta aggregata `b6fa29cadbc2348e1ca7fd95d3b12c14152e7d85dd1ee39c5d90d0552ce81a69`.

## Avvio del candidato finale

L'installazione come aggiornamento del pacchetto 251 è riuscita. Nell'AVD dedicato sono state disattivate Wi-Fi e dati mobili ed è stata attivata la modalità aereo tramite `cmd connectivity airplane-mode enable`. Quattro chiusure forzate e riaperture hanno restituito Activity `Status: ok` e processo ancora vivo dopo l'osservazione; il buffer dei crash è rimasto vuoto. I tempi singoli `am start -W` sono 898, 183, 426 e 375 ms, con altre compilazioni sul Mac: non sono un benchmark. Il crash Wry precedente non si è riprodotto in questa sequenza; la sua causa non viene dichiarata risolta.

UIAutomator non espone i nodi interni della WebView. Il comando ufficiale dell'emulatore `screenrecord screenshot` ha invece consentito di vedere il modulo con password, conferma e pulsante di creazione: il vecchio difetto CSS è corretto anche nel nuovo APK. La cattura con renderer automatico mostra bande bianche; il log contiene errori ANGLE di compilazione del programma grafico. Il confronto successivo con SwiftShader è stato eseguito e ha provocato un ANR di System UI durante l'avvio dell'AVD; nello stesso intervallo l'APK ha riprodotto SIGABRT in `wry0.54.4/src/android/mod.rs:426`, `recv_timeout(...).unwrap()` con `Timeout`. Le bande grafiche non sono state isolate in modo conclusivo e il crash non è corretto. La richiesta finale dell'utente di terminare ha chiuso le prove senza ulteriori modifiche. Non è stato disabilitato FLAG_SECURE e non sono stati usati DevTools/CDP per questo collaudo.

Nell'immagine AOSP userdebug il socket WebView rimane presente nonostante il bytecode dell'APK imposti esplicitamente false. Il [sorgente ufficiale Chromium](https://chromium.googlesource.com/chromium/src/%2B/3546854f59..2e285ebae2) documenta che `SharedStatics` ignora la disattivazione nelle build Android eng/userdebug, dove il debug è imposto dal sistema. Non è stata modificata l'immagine per aggirare questa scelta. Il test su un telefono con build di produzione resta da effettuare.

La creazione e modifica di un archivio sintetico, backup/ripristino tramite selettore Android SAF, le prestazioni e l'analisi dei PCAP rimangono non completate. Le sole riaperture offline non sostituiscono queste prove. Le ricevute del candidato riportano questi limiti.


## Chiusura e prove conservate

Emulatore dedicato e server ADB sulla porta5038 arrestati con i comandi ufficiali. Le chiavi ADB create dalla sessione non sono state eliminate: l'inventario attestava l'assenza iniziale ma non conteneva un'impronta, richiesta per la cancellazione finale. Nessun accesso o modifica alle chiavi private APK/licenze.

Le evidenze essenziali sono conservate in `docs/evidenze-android-2026-09-07/`: schermata del form nel candidato252, schermata ANR di sistema con SwiftShader, quattro avvii, estratto del crash Wry, firma e manifest. Il candidato resta in scratch per la pubblicazione coordinata dal task principale. Il collaudo non certifica ancora l'affidabilità operativa Android: il crash sotto carico e i flussi archivio/backup restano aperti.


## Aggiornamento finale degli interruttori — pacchetto253

Dopo le prove precedenti è stata richiesta un'ulteriore rigenerazione con la correzione della geometria degli interruttori nelle impostazioni e il comando diagnostico di disponibilità biometrica. Il nuovo pacchetto mantiene la versione 1.0.1 e il certificato APK, aumentando il codice Android a253. È stato prodotto con la toolchain isolata già presente e due processi Cargo.

Candidato: `/private/tmp/lexflow-validation-2026-09-07/android/candidate-toggle/LexFlow-1.0.1-Android-arm64.apk`, 13.019.705 byte; SHA256 `cc9d24a85cb40a5716a0fe45cea31d855092217b077a43538b769ab2736c2445`. Il certificato SHA256 resta `bab0ab7ef4395793afb278b688233d177c4545c4c49748a0a10409447544eaf5`.

Build riuscita, dieci test hardener passati; firma, manifest senza permessi Internet, backup/cleartext/debug disattivati, unica libreria ARM64, risorse di licenza e allineamento ZIP/ELF16 KB verificati. La chiave pubblica delle licenze è presente nella libreria nativa, il cui hash corrisponde all'output Rust appena compilato. Il DEX Android è identico a quello già ispezionato per FLAG_SECURE e disattivazione esplicita del debug WebView. L'impronta dei77 input è rimasta invariata prima e dopo la compilazione: `492e707912113aa41ed910333182f49f9da9f6e1705426736a60875070f7a52a`.

**Il pacchetto253 non è stato eseguito nell'emulatore né su un telefono.** Le quattro riaperture e le schermate descritte sopra appartengono al pacchetto252. Il crash Wry Timeout sotto carico, i difetti grafici osservati e il collaudo incompleto di archivio e backup Android restano dichiarati; questa rigenerazione non ne dimostra la correzione. Il vecchio candidato e le evidenze sono conservati separatamente. La ricevuta253 è salvata anche in `docs/evidenze-android-2026-09-07/apk253-verifica-pacchetto.json`.
