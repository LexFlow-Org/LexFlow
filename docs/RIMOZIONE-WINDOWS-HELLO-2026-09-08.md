# Rimozione Windows Hello — 8 settembre 2026

## Decisione

Il proprietario ha chiesto di interrompere l'ampliamento della biometria e rimuovere Windows Hello, privilegiando sicurezza e semplicità. L'accesso Windows usa la Master Password. Non sono introdotti nuovi sistemi biometrici su macOS o Android: i relativi pacchetti esistenti restano invariati e continuano a richiedere la password con la configurazione attuale.

## Motivo e modifica

La precedente implementazione Windows mostrava un prompt `UserConsentVerifier`, quindi leggeva separatamente il prehash della password da una credenziale generica. Il prompt non vincolava crittograficamente quella lettura: Microsoft documenta che `CredReadW` accede alle credenziali associate alla sessione di accesso del token corrente. Inoltre il backend Windows di keyring 3.6.3 usava `CRED_PERSIST_ENTERPRISE`, che può rendere disponibile una credenziale su altri computer con profili roaming. Non è stata osservata un'esfiltrazione; questo controllo ha individuato una protezione insufficiente rispetto al requisito di sblocco biometrico e di conservazione locale. Fonti: [Microsoft CredReadW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credreadw), [persistenza delle credenziali](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw), [keyring 3.6.3, sorgente Windows](https://raw.githubusercontent.com/hwchen/keyring-rs/v3.6.3/src/windows.rs).

Sono stati rimossi controllo hardware e prompt PowerShell di Windows Hello. I comandi Windows `check_bio` e `has_bio_saved` restituiscono falso; `save_bio` e `bio_login` rifiutano l'operazione senza leggere o salvare la credenziale. La pagina Impostazioni mostra “Accesso con Master Password” e non offre il pulsante biometrico. Un eventuale dialogo di configurazione già aperto non può riabilitare la funzione.

Durante l'avvio Windows viene tentata una sola cancellazione della credenziale del servizio `LexFlow_Bio` per l'utente corrente e del marker `.bio-enabled` del relativo archivio. L'operazione non legge il segreto, non modifica il vault cifrato o la licenza e non cancella credenziali di altri servizi o utenti. La credenziale assente è un esito valido. Se la cancellazione fallisce, il problema è indicato nelle Impostazioni e viene ritentato al successivo avvio; la biometria rimane comunque disabilitata. Anche la cancellazione esplicita e il cambio password tentano la stessa pulizia; il cambio password non risalva più il prehash nel deposito Windows.

## Conseguenza per l'aggiornamento

**Il destinatario deve conoscere la Master Password prima di installare il nuovo pacchetto.** Se dipendeva soltanto dal vecchio sblocco Hello e ha dimenticato la password, la rimozione della credenziale elimina quella possibilità di accesso. Il vault non viene cancellato, ma non viene introdotto un recupero che aggiri la cifratura.

La chiave privata delle licenze e la chiave pubblica incorporata restano invariate: non serve generare una nuova licenza per questa correzione. Il nuovo EXE deve essere installato sul PC per applicare la rimozione; non modifica a distanza le copie già distribuite. I pacchetti Mac Apple Silicon, Mac Intel e Android del 7 settembre non vengono ricompilati per questo cambiamento specifico di Windows.

## Prestazioni e verifiche

Installer Windows pubblicato in [releases/2026-09-07/Windows](../releases/2026-09-07/Windows/): `LexFlow_1.0.1_x64-setup.exe`, 305.812.232 byte, SHA-256 `e01d3ec44017e88808eafcfccf89b3df129444d6c519ea0c112a4bd604733405`. Integrità 7z ed estrazione riuscite; confrontati 573 file di risorse, inclusi 548 del runtime WebView2 e nove DLL qpdf. PE x64, versione 1.0.1.0 e chiave pubblica corrente verificati; le stringhe API specifiche del vecchio Hello risultano assenti dall’eseguibile. Questo controllo strutturale non è un collaudo su Windows reale.

Nessun nuovo servizio, polling o controllo biometrico all'avvio. Sono eliminate le due esecuzioni PowerShell dedicate a disponibilità e autenticazione Hello. La migrazione esegue una cancellazione locale per avvio; cifratura, KDF, ricerca e gestione dei documenti rimangono invariate. Senza un PC Windows non è possibile quantificare il tempo di avvio o la latenza della cancellazione sul dispositivo reale.

La suite frontend ha superato 60 test, compreso accesso con Master Password in presenza di un vecchio stato biometrico e rifiuto dell'enrollment da un dialogo obsoleto. Lint senza errori, un warning preesistente in AgendaPage. Build frontend riuscita. La suite Rust mirata ha superato 13 test in 13,60 s: sette nuovi casi di rimozione Windows e sei controlli esistenti della biometria Mac. Sono stati usati store sintetici, senza accesso a credenziali reali. Log e verifica del nuovo installer sono nelle [evidenze](validation/2026-09-07-no-windows-hello/).

La cancellazione del Credential Manager e l'aggiornamento dell'app sul PC richiedono ancora un collaudo Windows nativo. I test sintetici verificano isolamento della cancellazione, conservazione byte per byte del vault e della licenza, riapertura con la password originale, errori e tentativi successivi. Non dimostrano l'esecuzione di `CredDeleteW` su un PC reale. Le catture di rete precedenti non vengono attribuite a questo nuovo binario. Restano anche i limiti Android già descritti nel [collaudo precedente](COLLAUDO-2026-09-07-android.md).

Pulizia conclusa: eliminati toolchain e target temporanei, dipendenze e output rigenerabili di questa compilazione. Verificata la presenza dei soli quattro installer correnti; conservati progetto, generatore, chiavi, registro, app Mac installata e dati utente. [Ricevuta finale](validation/2026-09-07-no-windows-hello/final-verification.json).
