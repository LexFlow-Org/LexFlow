# Audit delle dipendenze — 6 settembre 2026

Le dipendenze aggiornate non hanno corrispondenze con le vulnerabilità npm
o con la categoria `vulnerabilities` di RustSec presenti negli archivi
consultati. Restano 18 segnalazioni Rust di mancata manutenzione e due
segnalazioni `unsound`, descritte sotto. Questo risultato non certifica
l'assenza di vulnerabilità sconosciute o di errori nel codice applicativo.

## Metodo e riservatezza

Il controllo npm è stato eseguito interamente in locale: l'archivio OSV npm
completo era già stato scaricato, poi sono stati confrontati i due lockfile
senza richieste di rete e senza inviare il grafo delle dipendenze a servizi
esterni. Non sono stati usati fascicoli, documenti legali, password o chiavi.

`scripts/audit-npm-offline.py` esamina ogni percorso presente nei lockfile v2/v3,
incluse dipendenze annidate, opzionali e specifiche di altre piattaforme.
Indica separatamente le dipendenze marcate `dev` e la presenza fisica sul
computer di audit; un pacchetto opzionale non installato sul Mac non viene
escluso dal controllo dei pacchetti destinati a Windows o Android.

Gli intervalli OSV sono interpretati con la libreria `semver` già installata:
`introduced` incluso, `fixed` e `limit` esclusi, `last_affected` incluso,
intervalli aperti, versioni prerelease e rami di release distinti. Le versioni
esplicite sono considerate; gli advisory ritirati sono esclusi. Intervalli
sconosciuti producono un risultato incompleto e codice d'uscita 2, mai un
falso risultato pulito. Cinque test delle condizioni ai confini passano.

## Confronto verificato

Il punto iniziale è costituito dai lockfile di `HEAD` prima degli aggiornamenti
della sessione. Entrambi i confronti usano lo stesso archivio OSV.

| Misura | Prima | Dopo |
| --- | ---: | ---: |
| Percorsi npm nei due lockfile | 383 | 370 |
| Percorsi con almeno una corrispondenza OSV | 16 | 0 |
| Advisory npm distinti | 72 | 0 |
| Corrispondenze advisory/pacchetto/versione runtime | 34 | 0 |
| Corrispondenze advisory/pacchetto/versione sviluppo | 38 | 0 |
| Intervalli npm non valutati | 0 | 0 |
| Corrispondenze RustSec categoria `vulnerabilities` | 7 | 0 |

Gli advisory npm iniziali riguardavano cinque nomi di pacchetti runtime:
dompurify, fflate, jspdf, pdfjs-dist e react-router. I conteggi rappresentano
corrispondenze alle versioni, non 72 exploit dimostrati nell'applicazione.
L'ultimo advisory residuo di PDF.js richiedeva anche configurazioni specifiche
di scripting/CSP: la versione vulnerabile e il visualizzatore non più
raggiungibile sono stati rimossi insieme alla dipendenza, perché la funzione
di censura era stata disabilitata. [Advisory PDF.js](https://github.com/mozilla/pdf.js/security/advisories/GHSA-hq66-cqwq-w95j).

La successiva pulizia ha rimosso dal client tre plugin JavaScript senza import (dialog, log, opener) e la copia duplicata della CLI Tauri. Le funzionalità native Rust rimangono presenti. La scansione locale è stata ripetuta sui 370 percorsi finali, senza corrispondenze né intervalli non valutati.

Gli aggiornamenti Rust eliminano le corrispondenze per crossbeam-epoch,
lopdf, due versioni di quick-xml e rkyv. Il passaggio a lopdf 0.42 affronta
in particolare l'arresto del processo con PDF contenenti strutture
profondamente annidate. [Advisory lopdf](https://rustsec.org/advisories/RUSTSEC-2026-0187.html).

## Raggiungibilità dei residui Rust

`rkyv 0.7.46` era una dipendenza opzionale registrata nel lockfile tramite
`tauri-plugin-log → byte-unit 5.2 → rust_decimal 1.40`. La ricerca inversa
con `cargo tree --locked --offline --target all -i rkyv -e features` non
mostrava percorsi attivi. La dipendenza effettiva di rust_decimal usava solo
`std`. L'aggiornamento compatibile a rust_decimal 1.43 ha rimosso il vecchio
rkyv anche dal lockfile, senza attivare la sua serializzazione opzionale.

Il rapporto Rust finale conserva:

- **18 avvisi `unmaintained`**: soprattutto binding GTK3 per Linux e alcune
  librerie transitive. Sono un debito di manutenzione da seguire; non sono
  stati nascosti modificando il database o aggiungendo esclusioni generiche.
- **glib 0.18.5, RUSTSEC-2024-0429**: segnalazione di `unsoundness` nella
  dipendenza Linux; richiede revisione prima di distribuire una versione Linux.
  [Advisory glib](https://rustsec.org/advisories/RUSTSEC-2024-0429.html).
- **rand 0.7.3, RUSTSEC-2026-0097**: il percorso inverso verificato è
  `phf_generator → phf_codegen → build-dependencies di selectors → kuchikiki
  → tauri-utils`. È parte della generazione in compilazione. La feature
  `log`, richiesta dallo scenario dell'advisory, non compare tra le feature
  attive di questa versione. Gli altri rand vulnerabili sono stati aggiornati;
  questa versione transitoria resta da eliminare a monte e da ricontrollare
  se cambiano le feature. [Advisory rand](https://rustsec.org/advisories/RUSTSEC-2026-0097.html).

## Riproduzione e impronte

Eseguire dalla radice del progetto, fornendo l'archivio OSV già disponibile
localmente. Il programma non lo scarica autonomamente.

```bash
python3 scripts/audit-npm-offline.py --archive /percorso/osv-npm-all.zip --output /tmp/lexflow-npm-audit.json
python3 scripts/test-offline-audit.py
```

Il programma restituisce 0 senza corrispondenze, 1 con corrispondenze e 2
per analisi incompleta/errore. Il JSON riporta ogni percorso interessato,
versione, categoria dev/runtime, advisory e confini delle versioni corrette.
Questi confini possono appartenere a rami diversi: non sono suggerimenti
automatici di aggiornamento.

Snapshot finale npm: **2026-09-06 18:41 UTC**, 228.684 record JSON OSV letti,
214 advisory relativi ai nomi presenti esaminati, nessuna versione vulnerabile.

| Artefatto | SHA256 |
| --- | --- |
| Archivio OSV npm | `2b91963d5260533f103ff8d688cd8da4774d2007ecb2a4ab2d44ca2f5d2bed09` |
| package-lock.json | `9e3eff25b3f39be68974c78847ae7733146e9134ad40ab8e71caa0276c1b7bb9` |
| client/package-lock.json | `50405bf4a0e34334c5149b67c532f9b62d7896b73a37c94d1cfdfa5e30a80e24` |
| src-tauri/Cargo.lock | `f2817de2b0123f149c05344f127a71836fabe3397a6eb60cb383a8c54c25c529` |

Gli esiti sono definitivi per queste impronte. Qualunque ulteriore modifica
dei lockfile richiede una nuova scansione. I binari sidecar esterni, i motori
WebView del sistema operativo e le librerie native distribuite richiedono
verifiche separate: non sono coperti integralmente dai due lockfile.
