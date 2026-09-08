# LexFlow 1.0.1 per Android

Il file da installare è **LexFlow-1.0.1-Android-arm64.apk**. È una build release firmata localmente, non pubblicata su Google Play.

## Aggiornamento e licenza

La versione 1.0.1 usa una nuova chiave pubblica per verificare le licenze: i token firmati con la vecchia chiave non vengono accettati da questa versione. Occorre una nuova licenza generata dal proprietario del progetto. Le copie precedenti già installate e offline mantengono il loro codice: questa modifica non può revocarle a distanza.

L'APK mantiene il certificato Android della versione 1.0.0 e aumenta il codice versione a 251. Su un dispositivo dove era installato quell'APK, installa il nuovo pacchetto come aggiornamento senza disinstallare prima l'applicazione. Il passaggio da una versione all'altra va verificato con dati fittizi prima dell'uso professionale.

## Requisiti e installazione

- Android 7.0 o successivo (API 24), dispositivo ARM64/arm64-v8a e Android System WebView con motore Chromium 111 o successivo. Il requisito Android indica il minimo per l'installazione: il vecchio WebView incluso in un telefono Android 7 non garantisce il corretto funzionamento dell'interfaccia. Questa build non supporta dispositivi esclusivamente a 32 bit né processori x86.
- Aggiorna il componente di sistema WebView alla versione compatibile più recente disponibile prima di usare il telefono offline. Se il telefono non può ricevere un WebView compatibile, usa un dispositivo più recente. LexFlow utilizza il componente già installato e non lo scarica.
- Copia l'APK sul telefono, aprilo dal gestore file e, se Android lo richiede, autorizza l'installazione per quel gestore file. Puoi revocare questa autorizzazione dopo l'installazione.
- Attiva LexFlow con la licenza destinata al dispositivo e crea la password personale dell'archivio. Conserva la chiave di recupero in un luogo privato.
- Prima di inserire documenti di lavoro, verifica apertura, salvataggio e riapertura con dati fittizi. Il pacchetto è stato compilato e verificato sul computer; non è stato collaudato su un telefono reale.

## Verifiche e limiti

Il requisito del motore grafico deriva dal supporto dichiarato di [Tailwind CSS 4](https://tailwindcss.com/docs/compatibility#browser-support), che richiede Chrome 111 o successivo; la compilazione JavaScript usa il target predefinito di [Vite 7](https://github.com/vitejs/vite/blob/v7.3.1/docs/guide/build.md#browser-compatibility). È un prerequisito della build, non una certificazione su tutti i modelli di telefono.

La firma dell'APK, l'allineamento ZIP e le librerie native per pagine di memoria da 16 KB sono stati verificati. Il manifest release non concede Internet e disabilita backup e trasferimento automatico dei dati. L'attività Android applica FLAG_SECURE per limitare screenshot e registrazione della finestra; il comportamento va verificato sul dispositivo.

L'accesso biometrico Android non è disponibile: questa versione usa la password. I programmi PDF esterni qpdf e Typst non sono inclusi nel pacchetto Android; le funzioni che dipendono da questi programmi richiedono la versione desktop. La censura PDF resta disabilitata.

L'archivio di LexFlow è cifrato; i file allegati esterni e i documenti esportati restano soggetti alle protezioni della loro cartella e alle altre applicazioni che li aprono. I selettori di file e le notifiche vanno verificati sul dispositivo utilizzato.

`SHA256SUMS-1.0.1.txt` contiene l'impronta del pacchetto. `CERTIFICATO-FIRMA-1.0.1.txt` identifica il certificato pubblico usato per questa release. La chiave privata di firma è conservata separatamente dal proprietario del progetto e non deve essere inviata insieme all'applicazione. Gli aggiornamenti Android devono mantenere lo stesso certificato.
