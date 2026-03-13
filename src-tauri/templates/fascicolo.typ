// ══════════════════════════════════════════════════════════════════════════
// LexFlow — Report Fascicolo (Typst)
// Design: Apple / Premium — pulito, minimale, tanto respiro
// ══════════════════════════════════════════════════════════════════════════

// ── Palette Premium (Tailwind Slate) ──
#let slate-900 = rgb("#0F172A")
#let slate-700 = rgb("#334155")
#let slate-500 = rgb("#475569")
#let slate-300 = rgb("#CBD5E1")
#let slate-100 = rgb("#F1F5F9")
#let slate-50  = rgb("#F8FAFC")
#let divider   = rgb("#E2E8F0")

// ── Impaginazione ──
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

// ══════════════════════════════════════════════════════════════════════════
//  HEADER — Studio + Meta
// ══════════════════════════════════════════════════════════════════════════
#grid(
  columns: (1fr, auto),
  align(left)[
    #if "__STUDIO_NAME__" != "" [
      #text(size: 15pt, weight: "bold", fill: slate-900, tracking: 0.3pt)[__STUDIO_NAME__]
      #v(2pt)
    ]
    #if "__LAWYER_NAME__" != "" [
      #text(size: 9.5pt, fill: slate-500)[Avv. __LAWYER_NAME__]
    ]
  ],
  align(right)[
    #text(size: 10pt, weight: "light", fill: slate-500, tracking: 2pt)[REPORT FASCICOLO]
    #v(4pt)
    #text(size: 8.5pt, fill: slate-500)[Aggiornato al __DATE_GENERATED__]
  ],
)

#v(0.5cm)
#line(length: 100%, stroke: 0.5pt + slate-300)
#v(1cm)

// ══════════════════════════════════════════════════════════════════════════
//  CARD CLIENTE
// ══════════════════════════════════════════════════════════════════════════
#rect(
  width: 100%,
  fill: slate-50,
  stroke: 0.5pt + slate-300,
  radius: 8pt,
  inset: 16pt,
)[
  #text(size: 8pt, weight: "bold", fill: slate-500, tracking: 1.5pt)[CLIENTE / ASSISTITO]
  #v(5pt)
  #text(size: 18pt, weight: "bold", fill: slate-900)[__CLIENT__]
  #if "__OBJECT__" != "" and "__OBJECT__" != "—" [
    #v(3pt)
    #text(size: 10.5pt, fill: slate-500)[__OBJECT__]
  ]
]

#v(1.2cm)

// ══════════════════════════════════════════════════════════════════════════
//  DATI DEL FASCICOLO (include Tipo e Stato come righe normali)
// ══════════════════════════════════════════════════════════════════════════
#text(size: 13pt, weight: "bold", fill: slate-900, tracking: 0.3pt)[Dati del Fascicolo]
#v(0.2cm)
#line(length: 100%, stroke: 0.5pt + slate-300)
#v(0.4cm)

#table(
  columns: (30%, 70%),
  stroke: (x, y) => if y == 0 { (bottom: 1pt + slate-300) } else { (bottom: 0.5pt + divider) },
  inset: 8pt,
  block(fill: slate-100, width: 100%, inset: 8pt)[
    #text(size: 8.5pt, weight: "bold", fill: slate-500, tracking: 1pt)[CAMPO]
  ],
  block(fill: slate-100, width: 100%, inset: 8pt)[
    #text(size: 8.5pt, weight: "bold", fill: slate-500, tracking: 1pt)[DETTAGLIO]
  ],
  block(inset: 8pt)[#text(fill: slate-500, weight: "bold")[Tipo Pratica]],
  block(inset: 8pt)[#text(fill: slate-900)[__TYPE_LABEL__]],
  block(inset: 8pt)[#text(fill: slate-500, weight: "bold")[Stato]],
  block(inset: 8pt)[#text(fill: slate-900)[__STATUS_LABEL__]],
  block(inset: 8pt)[#text(fill: slate-500, weight: "bold")[__COUNTERPARTY_LABEL__]],
  block(inset: 8pt)[#text(fill: slate-900)[__COUNTERPARTY__]],
  block(inset: 8pt)[#text(fill: slate-500, weight: "bold")[__COURT_LABEL__]],
  block(inset: 8pt)[#text(fill: slate-900)[__COURT__]],
  block(inset: 8pt)[#text(fill: slate-500, weight: "bold")[__CODE_LABEL__]],
  block(inset: 8pt)[#text(fill: slate-900)[__CODE__]],
  ..if "__DESCRIPTION__" != "" and "__DESCRIPTION__" != "—" {
    (
      block(inset: 8pt)[#text(fill: slate-500, weight: "bold")[Descrizione]],
      block(inset: 8pt)[#text(fill: slate-900)[__DESCRIPTION__]],
    )
  },
)

// ══════════════════════════════════════════════════════════════════════════
//  SEZIONI DINAMICHE (scadenze, diario — solo se presenti)
// ══════════════════════════════════════════════════════════════════════════
__DEADLINES_CONTENT__

__DIARY_CONTENT__
