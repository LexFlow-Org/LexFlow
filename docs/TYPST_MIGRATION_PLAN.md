# 🖋️ Piano Migrazione PDF: da jsPDF a Typst (Sidecar)

> **STATO: ✅ FASE 2 COMPLETATA** — Typst attivo con fallback jsPDF

## Architettura Target

```
┌─────────────────────┐     invoke('genera_pdf_typst')     ┌──────────────────┐
│  React Frontend     │ ──────────────────────────────────► │  Rust Backend    │
│  (form UI)          │                                     │  (Tauri Command) │
└─────────────────────┘                                     └────────┬─────────┘
                                                                     │
                                                            Scrive temp.typ
                                                            Lancia Sidecar
                                                                     │
                                                                     ▼
                                                            ┌──────────────────┐
                                                            │  Typst Engine    │
                                                            │  (bin/typst)     │
                                                            └────────┬─────────┘
                                                                     │
                                                              Output PDF
                                                                     ▼
                                                            ┌──────────────────┐
                                                            │  Documenti/      │
                                                            │  LexFlow_*.pdf   │
                                                            └──────────────────┘
```

## Vantaggi rispetto a jsPDF

| Aspetto           | jsPDF (attuale)           | Typst (target)                    |
|--------------------|--------------------------|-----------------------------------|
| Tipografia         | Approssimativa           | Professionale (kerning, legature) |
| Font               | Helvetica base            | Libertinus Serif + Cinzel         |
| Sillabazione       | Nessuna                  | Automatica multilingua (IT)       |
| Giustificazione    | Basilare                 | Algoritmo TeX-grade               |
| Manutenibilità     | JS procedurale           | Template dichiarativo `.typ`      |
| Velocità           | ~200ms                   | ~50ms (Rust native)               |

## Fase 1: Preparazione Sidecar

### 1.1 Scarica binari Typst

Da https://github.com/typst/typst/releases scaricare:
- `typst-aarch64-apple-darwin` (Mac Apple Silicon)
- `typst-x86_64-apple-darwin` (Mac Intel)
- `typst-x86_64-pc-windows-msvc.exe` (Windows)

Mettere in `src-tauri/bin/`

### 1.2 Configurare `tauri.conf.json`

```json
{
  "bundle": {
    "externalBin": ["bin/typst"]
  }
}
```

### 1.3 Template Typst: `src-tauri/templates/fascicolo.typ`

```typst
#let impagina_fascicolo(
  nome_studio: "",
  nome_avvocato: "",
  tipo_pratica: "Civile",
  foro: "",
  numero_rg: "",
  titolo_atto: "",
  contenuto: []
) = {
  set page(
    paper: "a4",
    margin: (top: 3.5cm, bottom: 3cm, left: 3.5cm, right: 3.5cm),
    header: [
      #set text(8pt, fill: luma(150), font: "Libertinus Serif")
      #align(right)[Foro di #foro -- RG #numero_rg]
    ],
    footer: [
      #set text(8pt, fill: luma(150), font: "Libertinus Serif")
      #align(center)[
        #line(length: 100%, stroke: 0.3pt + luma(200))
        #v(3pt)
        Pagina #counter(page).display("1 di 1", both: true)
      ]
    ]
  )
  
  set text(font: "Libertinus Serif", size: 11.5pt, lang: "it")
  set par(justify: true, leading: 1.2em, first-line-indent: 1em)

  let colore_accento = if tipo_pratica.lower() == "penale" {
    rgb("#8B0000")
  } else if tipo_pratica.lower() == "amministrativo" {
    rgb("#004B23")
  } else {
    rgb("#003366")
  }

  align(center)[
    #text(font: "Cinzel", size: 18pt, tracking: 2pt, weight: "bold")[#nome_studio] \
    #v(4pt)
    #text(size: 10pt, fill: luma(100), tracking: 1pt)[AVV. #upper(nome_avvocato)]
  ]
  
  v(1cm)
  
  align(right)[
    #block(
      fill: luma(250), 
      stroke: (left: 2pt + colore_accento),
      inset: 10pt,
      radius: (right: 4pt),
      width: 60%
    )[
      #set align(left)
      #text(weight: "bold", fill: colore_accento)[FASCICOLO #upper(tipo_pratica)] \
      #v(2pt)
      #text(size: 9.5pt)[
        *Tribunale:* #foro \
        *Procedimento N:* #numero_rg
      ]
    ]
  ]

  v(1.5cm)

  align(center)[
    #text(size: 15pt, weight: "bold", tracking: 0.5pt)[#upper(titolo_atto)]
  ]
  
  v(1cm)

  contenuto
}
```

### 1.4 Comando Rust (Sidecar)

```rust
use tauri::api::process::Command as TauriCommand;

#[tauri::command]
fn genera_pdf_typst(dati: DatiFascicolo) -> Result<String, String> {
    let documento = format!(
        r#"
        #import "fascicolo.typ": impagina_fascicolo
        #show: impagina_fascicolo.with(
          nome_studio: "{}",
          nome_avvocato: "{}",
          tipo_pratica: "{}",
          foro: "{}",
          numero_rg: "{}",
          titolo_atto: "{}"
        )

        {}
        "#,
        dati.nome_studio, dati.nome_avvocato, dati.tipo_pratica,
        dati.foro, dati.numero_rg, dati.titolo_atto, dati.contenuto_testo
    );

    let temp_dir = std::env::temp_dir();
    let file_typst = temp_dir.join("temp.typ");
    let safe_rg = dati.numero_rg.replace("/", "_");
    let file_pdf = dirs::document_dir()
        .ok_or("Impossibile trovare Documenti")?
        .join(format!("Fascicolo_{}_{}.pdf", dati.tipo_pratica, safe_rg));

    std::fs::write(&file_typst, documento).map_err(|e| e.to_string())?;

    let (mut _rx, child) = TauriCommand::new_sidecar("typst")
        .expect("Sidecar typst non trovato")
        .args(&["compile", &file_typst.to_string_lossy(), &file_pdf.to_string_lossy()])
        .spawn()
        .expect("Impossibile avviare Typst");

    // Attendere completamento...
    
    Ok(file_pdf.to_string_lossy().into_owned())
}
```

## Fase 2: Coesistenza

Durante la transizione, il sistema jsPDF attuale (`pdfGenerator.js`) rimane come fallback.
Il nuovo export Typst viene aggiunto come opzione separata nella UI delle impostazioni.

## Fase 3: Migrazione completa

Una volta validato Typst su tutte le piattaforme target (macOS, Windows),
rimuovere `jspdf` e `jspdf-autotable` da `package.json` e eliminare `pdfGenerator.js`.

## Font richiesti

- **Libertinus Serif** — Standard accademico/giuridico (open source, OFL)
- **Cinzel** — Iscrizioni romane classiche (Google Fonts, OFL)

Includere i file `.ttf` in `src-tauri/fonts/` e referenziarli nel template Typst.

## Colori per tipo pratica

| Tipo            | Hex       | Significato               |
|-----------------|-----------|---------------------------|
| Civile          | `#003366` | Blu Savoia                |
| Penale          | `#8B0000` | Rosso Giurisprudenza      |
| Amministrativo  | `#004B23` | Verde Istituzionale       |
| Stragiudiziale  | `#d4a940` | Gold LexFlow              |
