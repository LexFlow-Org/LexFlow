# Interruttori Impostazioni — collaudo del 7 settembre 2026

Esito: il difetto segnalato è riprodotto nella copia precedente e risolto nel componente aggiornato. Nel caso base a 360 px il pallino attivo precedente supera di 18 px il bordo destro. Nella versione corretta il margine minimo è 3 px, con pista 44 × 24 px e pallino 18 × 18 px.

Sono usati il vero componente `Toggle`, la vera pagina `SettingsPage` e il CSS completo compilato da Vite in modalità produzione. Le risposte native sono simulate con valori sintetici; il test non legge archivi, chiavi, registro delle licenze o Portachiavi. Il risultato riguarda il rendering Chromium, non un collaudo di WebKit macOS, Windows o hardware Android.

- 48 misure del componente aggiornato: ON/OFF, larghezze 360/768/1440 px, temi chiaro/scuro, font radice 16/20 px e zoom CSS 100/125%; pallino sempre contenuto.
- 24 configurazioni di interazione: click, spazio, invio e click sull’etichetta attivano il controllo esattamente una volta. Tab raggiunge il controllo e il focus ha contorno visibile. Area premibile minima 44 × 44 px.
- 12 configurazioni della pagina Impostazioni, 72 misure dei tre controlli ON/OFF: nome accessibile associato al testo visibile, geometria corretta e nessun overflow orizzontale dell’intera pagina.
- Il messaggio diagnostico che distingue Touch ID presente da firma dell’app mancante è visibile in tutte le 12 configurazioni, con risposta nativa simulata `build_not_authorized`. Questo non prova il funzionamento del Portachiavi sul Mac.
- Nessuna richiesta esterna e nessun errore JavaScript osservato nel collaudo.

`results.json` conserva tutte le misure, versioni browser e SHA-256 dei sorgenti provati. Gli screenshot sono stati ispezionati visivamente. Il confronto precedente è presente solo nell’harness sintetico e negli screenshot, non nel prodotto.

Per ripetere il test dalla radice del progetto, impostare `LEXFLOW_TOGGLE_DIR` a una cartella temporanea assoluta, `LEXFLOW_PLAYWRIGHT_MODULE` al modulo Playwright locale e `LEXFLOW_CHROMIUM_EXECUTABLE` al browser locale, quindi eseguire `node scripts/validation/toggle-visual.mjs`. L’opzione `LEXFLOW_TOGGLE_BEFORE` permette un confronto aggiuntivo con una copia precedente salvata del componente. Il server ascolta esclusivamente su 127.0.0.1 e le richieste del browser verso altri indirizzi sono bloccate. Il test non scarica dipendenze.
