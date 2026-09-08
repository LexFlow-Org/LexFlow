# Impostazioni, licenze e Touch ID — 7 settembre 2026

## Interruttori corretti

Il pallino assolutamente posizionato non aveva una coordinata orizzontale iniziale. Il centraggio del pulsante e la traslazione dello stato acceso lo portavano fuori dalla pista. La versione precedente supera il bordo destro di 18 px nel caso riprodotto.

Il controllo ora ha pista 44×24 px, pallino 18×18 px con origine esplicita a 3 px e spostamento di 20 px nello stato acceso. Il pallino mantiene almeno 3 px di margine. L'area premibile resta 44×44 px e i tre interruttori delle Impostazioni hanno nomi accessibili associati al testo visibile. Sono stati corretti anche restringimento e disposizione dei testi sulle finestre piccole.

[Collaudo visivo completo](validation/2026-09-07-settings-toggles/README.md): 120 misure geometriche, 24 configurazioni di interazione e 12 configurazioni della pagina reale, temi chiaro/scuro, larghezze 360/768/1440 px, font 16/20 px e zoom CSS 100/125%. Click, etichetta, spazio e invio attivano una sola volta il controllo; Tab e focus visibile funzionano. Nessun overflow, errore JavaScript o richiesta esterna nei campioni. Browser Chromium reale, IPC simulato: non è una prova dei sensori o del salvataggio nativo.

La suite frontend resta a 58 test superati; lint senza errori, un warning precedente in AgendaPage. Build frontend riuscita. La correzione non modifica cifratura, formati del vault, autorizzazioni di rete o emittente delle licenze.

## Licenze e registro

La chiave pubblica derivata dalla chiave privata locale coincide con progetto e installer: SHA-256 `4ff69b87240948576d916234273c2468e0906c1468e190f2b9a2ac3a5230672f`. Non è stata generata una nuova coppia e non sono state emesse o revocate licenze. Il generatore ha superato 19 test su dati sintetici.

Le licenze della precedente 1.0.1 con questo emittente restano utilizzabili, nei limiti delle loro scadenze e degli eventuali vincoli di dispositivo. La correzione grafica richiede l'installazione del nuovo pacchetto perché il frontend è incluso nell'app; non richiede una nuova attivazione solo perché cambia il frontend. Gli installer mantengono identificativo applicativo e cartella dei dati. L'aggiornamento su un PC Windows reale resta da collaudare.

Il registro reale è un file cifrato V3, regolare, di proprietà dell'utente, con permessi 0600; il suo hash è rimasto invariato durante il controllo. Non è stato decifrato: la password del registro è separata dalla chiave privata e non è disponibile all'agente. Quindi **il numero di emissioni e l'autenticità crittografica del contenuto reale non sono confermati**. Il comando `stats` del generatore autentica il registro e mostra i conteggi senza stampare nomi o token quando il proprietario inserisce localmente la password.

## Touch ID e firma dell'app

La verifica locale ha trovato l'app Mac firmata ad hoc, senza TeamIdentifier né entitlement del Portachiavi, e zero identità di firma valide disponibili. Questo non significa che il Mac non abbia un sensore Touch ID.

La nuova API `check_bio_status` restituisce separatamente disponibilità attuale del dispositivo e prerequisiti di firma dell'app. Settings mostra la causa `build_not_authorized` e, se LocalAuthentication conferma disponibilità, il testo “Touch ID è rilevato su questo Mac”. Un blocco temporaneo della biometria non viene descritto come assenza fisica del sensore. `check_bio` resta compatibile con i chiamanti esistenti.

Apple richiede il Data Protection Keychain per proteggere le credenziali mediante biometria; l'accesso dipende da entitlement di firma autorizzati. Occorrono firma e profilo Apple compatibili prima di collaudare enrollment e sblocco protetti. La notarizzazione riguarda separatamente la distribuzione. [Apple TN3137](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains).

La diagnosi usa solo `canEvaluatePolicy` e i permessi della propria app: non apre un prompt di autenticazione né legge credenziali. Otto test Rust mirati superati, inclusi quattro nuovi casi di diagnosi e le precedenti verifiche di autorizzazione, rifiuto ACL non protette e timeout. Nessun cambio di ACL, fallback non protetto, entitlement inventato o password salvata. **Touch ID resta indisponibile nei pacchetti ad hoc attuali** finché non è disponibile il materiale di firma richiesto.

## Verifica di sicurezza proporzionata

Per la geometria degli interruttori sono pertinenti il controllo del rendering, dell'accessibilità e delle chiamate singole ai callback. Per la diagnosi biometrica sono pertinenti i test dei casi di disponibilità e il mantenimento del rifiuto quando l'app non è autorizzata. Le verifiche di integrità, architettura e firma dei quattro pacchetti finali sono concluse e registrate nelle [ricevute della build finale](validation/2026-09-07-settings-toggles/build/); l'emittente delle licenze resta invariato.

Le prove precedenti di rete non vengono attribuite ai nuovi binari. Restano i limiti già documentati: nessun PC Windows o dispositivo Android fisico disponibile, import/export Android non completamente verificati, crash Wry per timeout riprodotto sul precedente APK 252 nell'emulatore durante la prova del renderer software e causa non corretta. L'APK finale 253 non è stato avviato e non dimostra la risoluzione del crash. Il collaudo grafico non costituisce una certificazione assoluta di sicurezza dell'app.


## Pacchetti finali e app installata

I quattro installer 1.0.1 aggiornati sono pronti in [releases/2026-09-07](../releases/2026-09-07/): DMG Apple Silicon e Intel separati, NSIS Windows x64 e APK Android ARM64 **versionCode 253**. Includono la correzione dei toggle e la nuova diagnostica biometrica. Versioni, dimensioni, impronte e limiti sono nell'[inventario finale](../releases/2026-09-07/pacchetti.json). Le ricevute precedenti restano conservate come evidenze storiche e non descrivono questi nuovi binari.

La suite completa Rust di **428 test superati precede i quattro nuovi test di `bio_status`**. Dopo le ultime modifiche è stata eseguita con successo la suite biometrica mirata di **8 test**, comprensiva dei quattro nuovi casi; non si dichiara una nuova suite completa di 432 test. Restano le 120 misure geometriche, 24 configurazioni di interazione e 12 configurazioni della pagina reale descritte sopra.

`/Applications/LexFlow.app` è stata aggiornata dal nuovo DMG Apple Silicon. L'eseguibile installato ha SHA-256 `84d3937fda76e98490ee51f7e0a86395490b01d9d3c10604fc2901ce3f6f5c80`; la verifica rigorosa della firma ad hoc è riuscita. **L'app non è stata avviata e il profilo utente e il registro delle licenze non sono stati modificati durante l'aggiornamento.** [Ricevuta locale](validation/2026-09-07-settings-toggles/installed-app-update.json).

Il confezionamento concluso non cambia i limiti del collaudo: Mac ad hoc e non notarizzato, Touch ID non autorizzato dalla firma attuale, Windows senza firma Authenticode e senza esecuzione nativa, nessuna prova su Mac Intel o Android fisici. L'APK 253 non è stato avviato; il crash Wry e gli artefatti di rendering osservati sul precedente emulatore restano irrisolti. Il conteggio del registro reale delle licenze resta non verificato.

## Pulizia conclusa

Eliminati gli ambienti temporanei di compilazione Mac/Windows/Android, le dipendenze e gli output rigenerabili del progetto, i profili sintetici ripristinati del collaudo e lo ZIP contenente il vecchio installer Windows. Restano esattamente quattro installer nella cartella di consegna. Sono conservati app Mac aggiornata, progetto, generatore, chiavi di firma, registro reale e dati dell’utente, compreso l’archivio creato durante il collaudo. I servizi iCloud e le cache condivise di altri strumenti non sono stati arrestati o cancellati. [Ricevuta della pulizia](validation/2026-09-07-settings-toggles/cleanup.json).
