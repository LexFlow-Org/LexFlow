// ══════════════════════════════════════════════════════════════════════════
// LexFlow — Release Notes v2.0
// ══════════════════════════════════════════════════════════════════════════

#let slate-900 = rgb("#0F172A")
#let slate-700 = rgb("#334155")
#let slate-500 = rgb("#475569")
#let slate-300 = rgb("#CBD5E1")
#let divider   = rgb("#E2E8F0")
#let gold      = rgb("#b89520")
#let green     = rgb("#16a34a")

#set page(
  paper: "a4",
  margin: (top: 3cm, bottom: 2.5cm, left: 2.5cm, right: 2.5cm),
)

#set text(font: "Libertinus Serif", size: 10.5pt, fill: slate-900, lang: "it")
#set par(justify: true, leading: 0.75em)

// ── COPERTINA ──
#v(4cm)
#align(center)[
  #text(size: 28pt, weight: "bold", fill: slate-900, tracking: 1pt)[LexFlow]
  #v(4pt)
  #text(size: 12pt, fill: gold, tracking: 3pt, weight: "medium")[LAW SUITE]
  #v(2cm)
  #line(length: 40%, stroke: 0.5pt + slate-300)
  #v(1cm)
  #text(size: 18pt, weight: "bold", fill: slate-900)[Novità della Versione 2.0]
  #v(8pt)
  #text(size: 10pt, fill: slate-500)[Marzo 2026]
]

#v(3cm)

// ── HIGHLIGHTS ──

#text(size: 13pt, weight: "bold", fill: gold)[Cosa c'è di nuovo]

#v(0.5cm)

*Sicurezza potenziata*

La crittografia è stata completamente riprogettata con lo standard più avanzato disponibile. I tuoi fascicoli sono ora protetti da una doppia chiave di sicurezza: anche se qualcuno ottenesse il file del vault, senza la tua password i dati sono matematicamente impossibili da leggere.

#v(0.3cm)

*Cambio password istantaneo*

Cambiare la password ora richiede meno di un secondo, indipendentemente da quanti fascicoli hai. Prima richiedeva la ri-cifratura di tutti i dati — ora è immediato.

#v(0.3cm)

*Ricerca intelligente*

La nuova ricerca trova i fascicoli anche con parole parziali o con errori di battitura. Cerca "contrat" e troverà "contratto", "contrattuale", "contratti". I risultati sono ordinati per rilevanza.

#v(0.3cm)

*Chiave di recupero*

Se dimentichi la password, una chiave di emergenza (formato `XXXX-XXXX-XXXX-XXXX`) ti permette di riaprire il vault. Viene mostrata alla creazione — stampala e conservala in un luogo sicuro.

#v(0.3cm)

*Più veloce su Windows*

Effetti visivi ottimizzati per Windows. L'app si avvia più velocemente, la navigazione tra le pagine è istantanea, e il caricamento dei dati avviene in parallelo.

#v(0.3cm)

*Compressione dati*

I dati vengono compressi prima della cifratura: il vault occupa il 60–80% in meno di spazio su disco. Backup più leggeri e veloci.

#v(0.3cm)

*Notifiche migliorate*

Le notifiche funzionano anche quando l'app è chiusa (su Android) o minimizzata nella tray (su desktop). Briefing mattutino, pomeridiano e serale configurabili.

#v(0.3cm)

*Blocco automatico alla chiusura*

Cliccando la X, l'app si nasconde nella tray e il vault si blocca automaticamente. Le notifiche continuano a funzionare. Per chiudere completamente: tasto destro sulla tray → Chiudi.

#v(1cm)
#line(length: 100%, stroke: 0.3pt + divider)
#v(0.5cm)

#text(size: 10pt, fill: slate-500)[
  *Piattaforme supportate*: macOS (Apple Silicon + Intel), Windows 10/11, Android 7+. \
  *Requisiti*: 50 MB di spazio libero, 2 GB RAM.
]

#v(2cm)
#align(center)[
  #text(size: 9pt, fill: slate-500)[
    LexFlow Release Notes · v2.0 · Marzo 2026
  ]
]
