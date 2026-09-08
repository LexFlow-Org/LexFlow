# Scripts - LexFlow

## File disponibili

### Licenze: `generate-license.sh` e `generate_license_v2.py`

Su Mac puoi fare doppio clic su **`Crea licenza LexFlow.command`**, nella radice
del progetto. Apre il generatore in Terminale e lascia leggibile il risultato.
Il doppio clic usa la nuova chiave locale configurata per la versione **1.0.1**,
salvata fuori da iCloud in `~/Library/Application Support/LexFlow License Keys/`.
Il launcher non contiene segreti e resta nel progetto del proprietario, fuori
dai pacchetti da inviare all'amico. Chiede i dati del destinatario e la password
del registro; non occorre copiare o incollare la chiave privata.

Su macOS/Linux, dalla cartella del progetto:

```bash
./scripts/generate-license.sh generate --local-key
./scripts/generate-license.sh verify
./scripts/generate-license.sh --help
```

Il launcher funziona anche se avviato da un'altra directory. Non scarica software, non legge automaticamente `.env` e non crea log. Su Windows usare `py -3 scripts/generate_license_v2.py generate` (oppure `python` se configurato); la verifica usa lo stesso comando con `verify`.

Requisiti: Python 3 e `cryptography`, installabile con `python3 -m pip install cryptography`. Le prove qui usano cryptography 49.0.0. Senza `--local-key` o `--private-key-file`, il generatore chiede la chiave privata con input nascosto; la password del registro è sempre richiesta. Se il terminale non consente input nascosto, si ferma. Per una chiave PEM/PKCS8 è disponibile `generate --private-key-file /percorso/privato`; il contenuto non viene stampato.

La chiave pubblica derivata deve coincidere con **entrambe** le costanti pubbliche in `src-tauri/src/license.rs` e `src-tauri/build.rs`. La coppia è stata ruotata il 6 settembre 2026 su richiesta del proprietario. La versione **1.0.1** accetta solo il nuovo emittente e invalida le attivazioni firmate dall’emittente precedente: per quelle occorre una nuova licenza. Le successive ricompilazioni 1.0.1, inclusa la correzione delle Impostazioni del 7 settembre, mantengono lo stesso emittente e le licenze già valide: non richiedono una nuova emissione. Le vecchie copie offline devono essere aggiornate; non è possibile revocarle a distanza. Il generatore non ruota ulteriormente la coppia. Il destinatario deve usare una build corrispondente a queste costanti. La data scelta include la giornata indicata fino alle 23:59:59.999 UTC. Il token viene mostrato soltanto dopo il salvataggio del registro: inviare all'amico esclusivamente quella riga `LXFW.…`.

Comandi conservati:

| Comando | Comportamento |
|---|---|
| `generate` | Firma Ed25519, controllo della chiave pubblica, ID non duplicato e registro cifrato |
| `verify` | Verifica firma e scadenza senza leggere il registro; preferire il prompt al token negli argomenti |
| `list`, `stats` | Consulta i dati registrati localmente; non conosce le attivazioni sui computer dei destinatari |
| `burn ID` | Segna un ritiro nel registro locale conservando l'hash; **non revoca token su altri computer offline** |
| `export --output /percorso/file.csv` | CSV in chiaro, protezione dalle formule e rifiuto di sovrascrivere file |
| `nuke` | Dopo autenticazione e conferma, rimuove il registro corrente conservando un backup cifrato |

Il registro reale è `scripts/.lexflow-issued-keys.enc`. Il formato V3 usa AES-256-GCM e Scrypt con parametri invariati; scritture atomiche, permessi Unix `0600` e blocco fra processi proteggono la persistenza. I registri V2 con salt incorporato o separato sono prima autenticati e aggiornati al successivo salvataggio. Il vecchio salt resta disponibile perché può servire ai backup storici. Non usare il vecchio generatore per riaprire un registro migrato V3.

Registro, file salt, backup cifrati e chiavi private vanno conservati separatamente dai pacchetti distribuiti. Un registro perso non invalida la firma dei token: fa perdere la tracciabilità locale. Gli hash e la cancellazione di file non garantiscono eliminazione fisica da SSD, snapshot o backup. Senza ID dispositivo nel token, un'app offline non può impedire globalmente il suo uso su un altro computer.

Test soltanto sintetici:

```bash
python3 scripts/test-license-generator.py
```

### Controlli della distribuzione nativa

Il progetto Android generato non viene conservato nel repository. Dopo ogni
`npm run tauri -- android init`, eseguire:

```bash
python3 scripts/harden-android.py
```

Lo script mantiene il server Vite disponibile nelle build debug. Nelle build
release rimuove il permesso Internet anche durante la fusione dei manifest,
disabilita traffico HTTP, debugging e backup, esclude cloud e trasferimento tra
dispositivi e imposta `FLAG_SECURE` nell'Activity. La release disabilita inoltre
esplicitamente il debugging della WebView, anche quando il sistema Android di
collaudo usa una build `userdebug`. Interrompe l'esecuzione se il template
nativo non è riconosciuto. La pipeline applica lo script automaticamente e
controlla il manifest e l'allineamento ELF a 16 KB delle librerie native a
64 bit nell'APK realmente prodotto prima della firma. Il build Rust Android
imposta l'allineamento necessario anche con NDK r27; dopo la firma verificare
anche firma e allineamento ZIP con gli strumenti Android SDK:

```bash
python3 scripts/harden-android.py --verify-apk /percorso/app-release.apk --aapt /percorso/sdk/build-tools/versione/aapt
apksigner verify --verbose /percorso/app-release.apk
zipalign -c -P 16 4 /percorso/app-release.apk
python3 scripts/test-native-hardening.py
python3 scripts/verify-macos-sidecars.py
```

Il controllo macOS richiede binari Typst e qpdf con le architetture indicate
nel nome e senza librerie dinamiche esterne al sistema. I sidecar locali per
Apple Silicon, Intel e Universal sono stati verificati; il controllo resta
bloccante per ogni nuova distribuzione. La pipeline prepara le versioni
fissate con gli stessi script usabili localmente:

```bash
./scripts/fetch-macos-typst.sh
./scripts/build-macos-qpdf.sh --jobs 4
python3 scripts/verify-macos-sidecars.py
```

Typst **0.15.1**, qpdf **12.4.1** e libjpeg-turbo **3.2.0** provengono dai
repository ufficiali. Gli script controllano SHA256 fissati prima di estrarre
o eseguire codice; verificano tutte le architetture e le dipendenze dinamiche
prima di sostituire i tre binari corrispondenti. Il build qpdf usa libqpdf e
libjpeg statiche, crypto nativa, generatore casuale sicuro del sistema e target
macOS **11.0**. Le estensioni SIMD JPEG sono disabilitate per non richiedere
un assembler aggiuntivo. Il test automatico qpdf esegue una cifratura AES-256 e
la decifratura di un PDF sintetico sull'architettura del computer di build;
le altre architetture sono verificate strutturalmente.

Servono macOS, gli strumenti Xcode, Python **3.12+** e curl; per qpdf serve
anche CMake. `LEXFLOW_CMAKE` può indicarne il percorso. `--work-dir DIRECTORY`
o `LEXFLOW_BUILD_ROOT` scelgono la directory padre del lavoro temporaneo:
ciascuna esecuzione crea una nuova sottocartella, conserva lì originali, log
e `PROVENANCE.json`, e non legge archivi applicativi o chiavi. `--help` non
scarica né compila. Gli script copiano anche LICENSE/NOTICE upstream in
`src-tauri/licenses`, inclusi nei pacchetti dalla configurazione Tauri.

I quattro font Libertinus Serif già presenti dichiarano nei metadati la
versione **7.051** e il repository `alerque/libertinus`. La licenza in
`src-tauri/licenses/Libertinus-OFL.txt` è la copia integrale del
[OFL.txt ufficiale al tag v7.051](https://github.com/alerque/libertinus/blob/v7.051/OFL.txt),
senza modifiche ai font.

### DMG locale con firma ad hoc

Per preparare due pacchetti distinti da un'app universale già compilata,
eseguire dalla directory del progetto:

```bash
npx tauri build --target universal-apple-darwin --no-bundle
npx tauri bundle --target universal-apple-darwin --bundles app --no-sign
./scripts/package-macos-local.sh \
  --app src-tauri/target/universal-apple-darwin/release/bundle/macos/LexFlow.app \
  --arch arm64 \
  --output /percorso/esistente/LexFlow-macOS-Apple-Silicon.dmg
./scripts/package-macos-local.sh \
  --app src-tauri/target/universal-apple-darwin/release/bundle/macos/LexFlow.app \
  --arch x86_64 \
  --output /percorso/esistente/LexFlow-macOS-Intel.dmg
```

Servono macOS, Python **3.11+** e gli strumenti Xcode. Lo script copia il
bundle in una directory privata `.noindex` sotto `/private/tmp` con `ditto --norsrc
--noextattr --noacl`, normalizza i permessi dei file pubblici e rimuove gli
attributi estesi solo dalla copia. Questo evita che i metadati iCloud del
progetto impediscano la firma. Prima della copia verifica che tutti e tre gli
eseguibili contengano l'architettura richiesta, poi ne estrae la singola slice
con `lipo` e la ricontrolla prima e dopo la firma. Firma con identità ad hoc ed hardened runtime
i tre eseguibili e l'app, quindi verifica la firma completa. Il DMG UDZO
contiene l'app, il collegamento ad Applicazioni, un breve `LEGGIMI.txt` con
l'architettura e `.metadata_never_index` per evitare l'indicizzazione del volume.

Dopo `hdiutil verify`, il file viene pubblicato senza sostituire file o
collegamenti già esistenti, anche se compaiono durante il packaging. La
directory di destinazione deve esistere e supportare hard link; in caso
contrario scegliere una destinazione locale APFS/HFS+. I temporanei vengono
rimossi al termine. L'app sorgente resta invariata; lo script non compila,
non avvia e non installa l'app. Stampa il percorso finale e il suo SHA256.

Questa firma locale **non è una firma Developer ID e non è notarizzata**:
macOS può richiedere un'autorizzazione esplicita per aprire il pacchetto dopo
averne verificato la provenienza. Il percorso CI con eventuale certificato
Developer ID rimane gestito da Tauri e non usa questo script locale.

Le verifiche di dipendenze in CI sono bloccanti: `cargo audit` consulta il
database pubblico RustSec; `npm audit --omit=dev` invia al registry i metadati
delle dipendenze pubbliche. Non servono archivi legali o dati reali per questi
controlli. Il test delle schermate recenti, delle notifiche e della rete deve
essere completato su dispositivi e pacchetti release con dati sintetici.

## Sicurezza

1. **Chiave privata**: non committare mai la chiave privata Ed25519. Conservala in un password manager o HSM.
2. **Registro licenze**: conservare copie cifrate del registro e l'eventuale salt storico; nessuna pulizia automatica li elimina.
3. **Rotazione**: se la chiave privata viene compromessa, una nuova coppia richiede l'aggiornamento coerente di `license.rs` e `build.rs` e una nuova distribuzione; le vecchie installazioni offline continuano a fidarsi della vecchia chiave.
