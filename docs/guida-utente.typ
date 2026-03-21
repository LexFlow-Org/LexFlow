// ══════════════════════════════════════════════════════════════════════════
// LexFlow — Guida Utente Completa
// ══════════════════════════════════════════════════════════════════════════

#let slate-900 = rgb("#0F172A")
#let slate-700 = rgb("#334155")
#let slate-500 = rgb("#475569")
#let slate-300 = rgb("#CBD5E1")
#let slate-100 = rgb("#F1F5F9")
#let divider   = rgb("#E2E8F0")
#let gold      = rgb("#b89520")

#set page(
  paper: "a4",
  margin: (top: 3cm, bottom: 2.5cm, left: 2.5cm, right: 2.5cm),
  footer: [
    #set text(8pt, fill: slate-500, font: "Libertinus Serif")
    #align(center)[
      #context {
        let current = counter(page).get().first()
        let total = counter(page).final().first()
        [#current / #total]
      }
    ]
  ],
)

#set text(font: "Libertinus Serif", size: 10.5pt, fill: slate-900, lang: "it")
#set par(justify: true, leading: 0.75em)
#set heading(numbering: "1.1")

// ── COPERTINA ──
#v(4cm)
#align(center)[
  #text(size: 28pt, weight: "bold", fill: slate-900, tracking: 1pt)[LexFlow]
  #v(4pt)
  #text(size: 12pt, fill: gold, tracking: 3pt, weight: "medium")[LAW SUITE]
  #v(2cm)
  #line(length: 40%, stroke: 0.5pt + slate-300)
  #v(1cm)
  #text(size: 18pt, weight: "bold", fill: slate-900)[Guida Utente]
  #v(8pt)
  #text(size: 11pt, fill: slate-500)[Manuale completo dell'applicazione]
  #v(4pt)
  #text(size: 10pt, fill: slate-500)[Versione 2.5.0 · Marzo 2026]
]

#pagebreak()
#outline(title: "Indice", indent: 1.5em)
#pagebreak()

// ══════════════════════════════════════════════════════════════════════════
= Introduzione

LexFlow è un gestionale completo per studi legali. Tutti i dati sono cifrati con crittografia di livello bancario (AES-256) e restano esclusivamente sul tuo dispositivo — nessun server esterno, nessun cloud, nessun accesso da parte di terzi.

L'applicazione è disponibile per *macOS*, *Windows* e *Android*.

== Primo Avvio

Al primo avvio, LexFlow ti chiede di creare una *Master Password*. Questa password è l'unica chiave per accedere ai tuoi dati:

- *Minimo 12 caratteri*, con almeno una maiuscola, un numero e un simbolo.
- *Non è recuperabile*: se la dimentichi, i dati sono persi (a meno che tu non abbia una Recovery Key).
- *Consiglio*: scegli una frase lunga e memorabile, es. `IlMioStudio2024!Avvocato`.

Dopo aver impostato la password, LexFlow crea il tuo vault crittografato e ti porta alla schermata principale.

== Sblocco con Biometria

Su dispositivi compatibili (Touch ID su Mac, Windows Hello, impronta digitale su Android), LexFlow attiva automaticamente lo sblocco biometrico. Dopo il primo sblocco con password, i successivi saranno istantanei tramite biometria.

#pagebreak()

// ══════════════════════════════════════════════════════════════════════════
= L'Interfaccia

La barra laterale sinistra contiene tutte le sezioni dell'app:

#table(
  columns: (auto, 1fr),
  stroke: 0.5pt + slate-300,
  inset: 8pt,
  [*Sezione*], [*Funzione*],
  [Agenda], [Calendario con appuntamenti, udienze, scadenze e promemoria.],
  [Scadenze], [Vista dedicata alle scadenze processuali e legali.],
  [Fascicoli], [Archivio completo delle pratiche con ricerca avanzata.],
  [Contatti & Conflitti], [Rubrica professionale con verifica conflitti di interesse.],
  [Gestione Ore], [Time tracking per la fatturazione a ore.],
  [Impostazioni], [Configurazione app, notifiche, sicurezza, import/export.],
)

In basso nella sidebar trovi il pulsante *Blocca Vault* per bloccare manualmente l'app.

#pagebreak()

// ══════════════════════════════════════════════════════════════════════════
= Fascicoli

== Creare un Fascicolo

1. Clicca su *Fascicoli* nella sidebar.
2. Clicca il pulsante *+ Nuovo Fascicolo* in alto a destra.
3. Compila i campi: numero, oggetto, cliente, controparte, giudice, note.
4. Il fascicolo viene salvato e cifrato automaticamente.

== Ricerca

La barra di ricerca in cima alla lista supporta:
- *Ricerca parziale*: digita "contrat" per trovare "contratto", "contrattuale", "contratti".
- *Ricerca fuzzy*: tollera errori di battitura.
- *Case-insensitive*: maiuscole e minuscole sono equivalenti.

I risultati sono ordinati per rilevanza (i fascicoli più pertinenti appaiono per primi).

== Esportazione PDF

Ogni fascicolo può essere esportato come PDF professionale:
1. Apri il fascicolo.
2. Clicca l'icona *PDF* in alto a destra.
3. Il PDF include: dati del fascicolo, diario, scadenze, note.

Il formato è lo stesso di questo documento — pulito, minimale, professionale.

#pagebreak()

// ══════════════════════════════════════════════════════════════════════════
= Agenda

== Vista Giornaliera, Settimanale e Mensile

L'agenda supporta tre modalità di visualizzazione, selezionabili con i tab in alto.

== Tipi di Evento

#table(
  columns: (auto, 1fr),
  stroke: 0.5pt + slate-300,
  inset: 8pt,
  [*Tipo*], [*Descrizione*],
  [Udienza], [Udienza in tribunale — alta priorità, notifica automatica.],
  [Scadenza], [Termine processuale — notifica anticipata configurabile.],
  [Riunione], [Incontri con clienti o colleghi.],
  [Personale], [Impegni personali.],
  [Altro], [Qualsiasi altro evento.],
)

== Notifiche

LexFlow invia notifiche per ogni evento dell'agenda:
- *Mattina, Pomeriggio, Sera*: briefing giornaliero configurabile.
- *Promemoria individuali*: prima di ogni evento, a intervalli configurabili.
- Funzionano anche quando l'app è chiusa (su Android) o minimizzata nella tray (su desktop).

#pagebreak()

// ══════════════════════════════════════════════════════════════════════════
= Contatti & Conflitti

== Gestione Contatti

La rubrica professionale include: nome, ruolo (cliente, avvocato, giudice, perito, controparte), contatti, note.

== Verifica Conflitti di Interesse

Quando crei un nuovo fascicolo, LexFlow verifica automaticamente se un contatto appare sia come cliente che come controparte in fascicoli diversi. In caso di conflitto, viene mostrato un avviso.

#pagebreak()

// ══════════════════════════════════════════════════════════════════════════
= Gestione Ore

Il time tracker integrato permette di registrare le ore lavorate per fascicolo:

1. Vai in *Gestione Ore*.
2. Seleziona il fascicolo.
3. Avvia il timer o inserisci manualmente le ore.
4. Aggiungi note sulla prestazione.

I dati sono cifrati come tutti gli altri contenuti del vault.

#pagebreak()

// ══════════════════════════════════════════════════════════════════════════
= Sicurezza

== Blocco Automatico

L'app si blocca automaticamente dopo un periodo di inattività configurabile (default: 5 minuti). Puoi modificarlo in *Impostazioni → Sicurezza*.

Quando l'app si blocca:
- Tutti i dati vengono cancellati dalla memoria.
- Il vault viene chiuso crittograficamente.
- Per riaprire serve la password o la biometria.

== Chiusura Finestra (X)

Cliccando la X, l'app non si chiude — si nasconde nella system tray (icona accanto all'orologio). Il vault si blocca automaticamente e le notifiche continuano a funzionare.

Per chiudere completamente: tasto destro sull'icona tray → *Chiudi LexFlow*.

== Recovery Key

Se hai configurato una Recovery Key alla creazione del vault, puoi usarla per sbloccare il vault anche se dimentichi la password. La chiave ha il formato `XXXX-XXXX-XXXX-XXXX` — conservala stampata in un luogo sicuro.

== Cambio Password

In *Impostazioni → Sicurezza → Cambia Password*. L'operazione è istantanea (meno di 1 secondo) grazie all'architettura envelope encryption.

== Factory Reset

In *Impostazioni → Avanzate → Reset Vault*. Cancella tutti i dati in modo irreversibile. Richiede la password attuale per conferma.

#pagebreak()

// ══════════════════════════════════════════════════════════════════════════
= Import / Export

== Esportare il Vault (Backup)

1. Vai in *Impostazioni → Backup*.
2. Clicca *Esporta Vault*.
3. Inserisci la password per conferma.
4. Scegli dove salvare il file `.lex`.

Il backup è un file cifrato autonomo — contiene tutti i fascicoli, l'agenda, i contatti e le ore. Può essere aperto su qualsiasi dispositivo con LexFlow.

== Importare un Vault (Ripristino)

1. Vai in *Impostazioni → Backup*.
2. Clicca *Importa Vault*.
3. Seleziona il file `.lex`.
4. Inserisci la password del backup.

L'importazione sovrascrive il vault attuale. Il vault corrente non viene salvato automaticamente — esporta prima se necessario.

#pagebreak()

// ══════════════════════════════════════════════════════════════════════════
= Installazione

== macOS

1. Scarica il file `LexFlow_x.x.x_universal.dmg`.
2. Apri il DMG e trascina LexFlow nella cartella Applicazioni.
3. Al primo avvio, vai in *Impostazioni di Sistema → Privacy e Sicurezza* e clicca *Apri comunque*.

== Windows

1. Scarica il file `LexFlow-vx.x.x-windows-x64.msi` (versione lite, 25 MB).
2. Se il PC non ha WebView2, scarica la versione *offline* (218 MB) che lo include.
3. Doppio click sull'MSI → segui il wizard di installazione.
4. SmartScreen potrebbe mostrare un avviso: clicca *Ulteriori informazioni → Esegui comunque*.

== Android

1. Scarica il file `LexFlow-vx.x.x-android.apk`.
2. Abilita *Installa da origini sconosciute* nelle impostazioni.
3. Apri l'APK e installa.
4. Google Play Protect potrebbe mostrare un avviso: clicca *Installa comunque*.

#v(2cm)
#align(center)[
  #text(size: 9pt, fill: slate-500)[
    LexFlow Guida Utente · v2.5.0 · Marzo 2026
  ]
]
