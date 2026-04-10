import { useState, useEffect } from 'react';
import {
  FileText, Merge, Split, Scissors, RotateCw,
  Minimize2, Stamp, FileOutput, Type, Images,
  Upload, Download, Check, AlertCircle, Loader2, X, Info,
  ArrowUpDown, Hash, EyeOff, Shield, Unlock, Clock
} from 'lucide-react';
import * as api from '../tauri-api';

const TOOLS = [
  {
    id: 'merge',
    label: 'Unisci PDF',
    icon: Merge,
    description: 'Combina più PDF in un unico documento',
    multiFile: true,
    accept: '.pdf',
  },
  {
    id: 'split',
    label: 'Dividi PDF',
    icon: Split,
    description: 'Dividi un PDF in pagine singole',
    multiFile: false,
    accept: '.pdf',
  },
  {
    id: 'remove',
    label: 'Rimuovi Pagine',
    icon: Scissors,
    description: 'Elimina pagine specifiche da un PDF',
    multiFile: false,
    accept: '.pdf',
    needsPages: true,
  },
  {
    id: 'extract',
    label: 'Estrai Pagine',
    icon: FileOutput,
    description: 'Estrai solo le pagine che ti servono',
    multiFile: false,
    accept: '.pdf',
    needsPages: true,
  },
  {
    id: 'rotate',
    label: 'Ruota Pagine',
    icon: RotateCw,
    description: 'Ruota le pagine di 90°, 180° o 270°',
    multiFile: false,
    accept: '.pdf',
    needsRotation: true,
  },
  {
    id: 'compress',
    label: 'Comprimi PDF',
    icon: Minimize2,
    description: 'Riduci la dimensione del PDF per PEC',
    multiFile: false,
    accept: '.pdf',
  },
  {
    id: 'watermark',
    label: 'Watermark',
    icon: Stamp,
    description: 'Aggiungi BOZZA, RISERVATO, COPIA CONFORME',
    multiFile: false,
    accept: '.pdf',
    needsWatermark: true,
  },
  {
    id: 'text',
    label: 'Estrai Testo',
    icon: Type,
    description: 'Estrai il testo da un PDF',
    multiFile: false,
    accept: '.pdf',
  },
  {
    id: 'images2pdf',
    label: 'Immagini → PDF',
    icon: Images,
    description: 'Converti immagini in un unico PDF',
    multiFile: true,
    accept: '.png,.jpg,.jpeg,.webp,.bmp,.tiff,.gif',
  },
  {
    id: 'reorder',
    label: 'Organizza PDF',
    icon: ArrowUpDown,
    description: 'Riordina le pagine nel tuo PDF',
    multiFile: false,
    accept: '.pdf',
    needsReorder: true,
  },
  {
    id: 'pagenumbers',
    label: 'Numeri di Pagina',
    icon: Hash,
    description: 'Aggiungi numerazione pagine per atti e fascicoli',
    multiFile: false,
    accept: '.pdf',
    needsPageNumbers: true,
  },
  {
    id: 'redact',
    label: 'Censura PDF',
    icon: EyeOff,
    description: 'Oscura dati sensibili con barre nere (GDPR)',
    multiFile: false,
    accept: '.pdf',
    needsRedact: true,
  },
  {
    id: 'secure',
    label: 'Proteggi PDF',
    icon: Shield,
    description: 'Blocca copia, stampa, modifica e condivisione',
    multiFile: false,
    accept: '.pdf',
    needsSecure: true,
  },
  {
    id: 'unsecure',
    label: 'Rimuovi Protezione',
    icon: Unlock,
    description: 'Rimuovi restrizioni da un PDF protetto',
    multiFile: false,
    accept: '.pdf',
    needsUnsecurePassword: true,
  },
];

const WATERMARK_PRESETS = ['BOZZA', 'RISERVATO', 'COPIA CONFORME', 'CONFIDENZIALE', 'URGENTE'];
const ROTATION_OPTIONS = [
  { value: 90, label: '90° orario' },
  { value: 180, label: '180°' },
  { value: 270, label: '270° (90° antiorario)' },
];

export default function DocumentToolsPage() {
  const [activeTool, setActiveTool] = useState(null);
  const [files, setFiles] = useState([]);
  const [pdfInfo, setPdfInfo] = useState(null);
  const [processing, setProcessing] = useState(false);
  const [result, setResult] = useState(null);
  const [extractedText, setExtractedText] = useState(null);

  // Tool-specific state
  const [pageInput, setPageInput] = useState('');
  const [rotation, setRotation] = useState(90);
  const [watermarkText, setWatermarkText] = useState('BOZZA');
  const [watermarkOpacity, setWatermarkOpacity] = useState(0.15);

  // Page numbers state
  const [pageNumPosition, setPageNumPosition] = useState('bottom-center');
  const [pageNumFormat, setPageNumFormat] = useState('Pag. {n} di {total}');
  const [pageNumStart, setPageNumStart] = useState(1);

  // Reorder state
  const [reorderList, setReorderList] = useState([]); // array of page numbers in current order
  const [dragIdx, setDragIdx] = useState(null);

  // Redact state
  const [redactAreas, setRedactAreas] = useState([{ page: 1, x: 50, y: 750, width: 200, height: 20 }]);

  // Secure PDF state
  const [secNoCopy, setSecNoCopy] = useState(true);
  const [secNoPrint, setSecNoPrint] = useState(true);
  const [secNoModify, setSecNoModify] = useState(true);
  const [secWatermark, setSecWatermark] = useState(true);
  const [secPassword, setSecPassword] = useState('');

  // Unsecure password
  const [unsecurePassword, setUnsecurePassword] = useState('');

  // History
  const [history, setHistory] = useState([]);
  useEffect(() => {
    try { setHistory(JSON.parse(localStorage.getItem('lexflow_pdf_history') || '[]')); } catch { setHistory([]); }
  }, []);

  const resetState = () => {
    setFiles([]);
    setPdfInfo(null);
    setResult(null);
    setExtractedText(null);
    setPageInput('');
    setProcessing(false);
    setReorderList([]);
    setDragIdx(null);
    setRedactAreas([{ page: 1, x: 50, y: 750, width: 200, height: 20 }]);
    setPageNumPosition('bottom-center');
    setPageNumFormat('Pag. {n} di {total}');
    setPageNumStart(1);
    setSecNoCopy(true); setSecNoPrint(true); setSecNoModify(true); setSecWatermark(true); setSecPassword('');
    setUnsecurePassword('');
  };

  const addToHistory = (tool, inputName, outputPath) => {
    const entry = { tool, input: inputName, output: outputPath, date: new Date().toISOString() };
    const updated = [entry, ...history].slice(0, 50);
    setHistory(updated);
    try { localStorage.setItem('lexflow_pdf_history', JSON.stringify(updated)); } catch { /* ignore */ }
  };

  const selectTool = (tool) => {
    setActiveTool(tool);
    resetState();
  };

  /** Extract a plain path string from selectFile result (which returns {name, path} or string). */
  const toPath = (result) => {
    if (!result) return null;
    if (typeof result === 'string') return result;
    if (result.path) return result.path;
    return null;
  };

  const handleFileSelect = async () => {
    const tool = TOOLS.find(t => t.id === activeTool);
    if (!tool) return;

    if (tool.multiFile) {
      // Native multi-file picker: select many files at once
      const exts = tool.accept.split(',').map(e => e.replace('.', '').trim());
      const paths = await api.selectFiles(exts);
      if (paths && paths.length > 0) {
        // Deduplicate against already-selected files
        setFiles(prev => {
          const existing = new Set(prev);
          const newPaths = paths.filter(p => !existing.has(p));
          return [...prev, ...newPaths];
        });
        // Load info for the last PDF
        if (tool.accept.includes('.pdf')) {
          try {
            const info = await api.pdfInfo(paths[paths.length - 1]);
            setPdfInfo(info);
          } catch { /* ignore */ }
        }
      }
    } else {
      const result = await api.selectFile();
      const path = toPath(result);
      if (path) {
        setFiles([path]);
        if (tool.accept.includes('.pdf')) {
          try {
            const info = await api.pdfInfo(path);
            setPdfInfo(info);
            if (tool.needsReorder && info?.pages) {
              setReorderList(Array.from({ length: info.pages }, (_, i) => i + 1));
            }
          } catch { /* ignore */ }
        }
      }
    }
  };

  const removeFile = (idx) => {
    setFiles(prev => prev.filter((_, i) => i !== idx));
  };

  const parsePages = (input, total) => {
    const pages = [];
    for (const part of input.split(',')) {
      const trimmed = part.trim();
      if (trimmed.includes('-')) {
        const [a, b] = trimmed.split('-').map(Number);
        if (!isNaN(a) && !isNaN(b)) {
          for (let i = Math.max(1, a); i <= Math.min(total, b); i++) pages.push(i);
        }
      } else {
        const n = parseInt(trimmed);
        if (!isNaN(n) && n >= 1 && n <= total) pages.push(n);
      }
    }
    return [...new Set(pages)].sort((a, b) => a - b);
  };

  const executeTool = async () => {
    if (files.length === 0) return;
    setProcessing(true);
    setResult(null);
    setExtractedText(null);

    try {
      let res;

      switch (activeTool) {
        case 'merge': {
          if (files.length < 2) { setResult({ success: false, message: 'Servono almeno 2 file.' }); break; }
          const out = await api.selectSavePath('unione.pdf');
          if (!out) break;
          res = await api.mergePdfs(files, out);
          setResult(res);
          break;
        }
        case 'split': {
          const dir = await api.selectFolder();
          if (!dir) break;
          res = await api.splitPdf(files[0], dir);
          setResult(res);
          break;
        }
        case 'remove': {
          if (!pdfInfo || !pageInput) break;
          const pages = parsePages(pageInput, pdfInfo.pages);
          if (pages.length === 0) { setResult({ success: false, message: 'Nessuna pagina valida.' }); break; }
          const out = await api.selectSavePath('modificato.pdf');
          if (!out) break;
          res = await api.removePages(files[0], out, pages);
          setResult(res);
          break;
        }
        case 'extract': {
          if (!pdfInfo || !pageInput) break;
          const pages = parsePages(pageInput, pdfInfo.pages);
          if (pages.length === 0) { setResult({ success: false, message: 'Nessuna pagina valida.' }); break; }
          const out = await api.selectSavePath('estratto.pdf');
          if (!out) break;
          res = await api.extractPages(files[0], out, pages);
          setResult(res);
          break;
        }
        case 'rotate': {
          const out = await api.selectSavePath('ruotato.pdf');
          if (!out) break;
          res = await api.rotatePdf(files[0], out, rotation, null);
          setResult(res);
          break;
        }
        case 'compress': {
          const out = await api.selectSavePath('compresso.pdf');
          if (!out) break;
          res = await api.compressPdf(files[0], out);
          setResult(res);
          break;
        }
        case 'watermark': {
          const out = await api.selectSavePath('watermark.pdf');
          if (!out) break;
          res = await api.addWatermark(files[0], out, watermarkText, watermarkOpacity, null);
          setResult(res);
          break;
        }
        case 'text': {
          const text = await api.pdfToText(files[0]);
          setExtractedText(text);
          setResult({ success: true, message: 'Testo estratto con successo.' });
          break;
        }
        case 'images2pdf': {
          const out = await api.selectSavePath('immagini.pdf');
          if (!out) break;
          res = await api.imagesToPdf(files, out);
          setResult(res);
          break;
        }
        case 'reorder': {
          if (reorderList.length === 0) { setResult({ success: false, message: 'Nessun ordine specificato.' }); break; }
          const out = await api.selectSavePath('riordinato.pdf');
          if (!out) break;
          res = await api.reorderPages(files[0], out, reorderList);
          setResult(res);
          break;
        }
        case 'pagenumbers': {
          const out = await api.selectSavePath('numerato.pdf');
          if (!out) break;
          res = await api.addPageNumbers(files[0], out, pageNumPosition, pageNumFormat, pageNumStart, null);
          setResult(res);
          break;
        }
        case 'redact': {
          if (redactAreas.length === 0) { setResult({ success: false, message: 'Nessuna area da censurare.' }); break; }
          const out = await api.selectSavePath('censurato.pdf');
          if (!out) break;
          res = await api.redactPdf(files[0], out, redactAreas);
          setResult(res);
          break;
        }
        case 'secure': {
          const out = await api.selectSavePath('protetto.pdf');
          if (!out) break;
          res = await api.securePdf(files[0], out, {
            noCopy: secNoCopy,
            noPrint: secNoPrint,
            noModify: secNoModify,
            watermark: secWatermark ? 'RISERVATO' : null,
            ownerPassword: secPassword || null,
          });
          setResult(res);
          break;
        }
        case 'unsecure': {
          const out = await api.selectSavePath('sbloccato.pdf');
          if (!out) break;
          res = await api.unsecurePdf(files[0], out, unsecurePassword || null);
          setResult(res);
          break;
        }
      }
      // Save to history if successful
      if (res?.success && res?.output_path) {
        const inputName = (typeof files[0] === 'string' ? files[0] : '').split('/').pop() || 'file';
        addToHistory(activeTool, inputName, res.output_path);
      }
    } catch (err) {
      setResult({ success: false, message: err?.message || String(err) });
    } finally {
      setProcessing(false);
    }
  };

  const currentTool = TOOLS.find(t => t.id === activeTool);

  // ─── Tool Grid (no tool selected) ────────────────────────
  if (!activeTool) {
    return (
      <div className="max-w-5xl mx-auto space-y-6 pb-12">
        {/* Header */}
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 bg-primary/10 rounded-2xl flex items-center justify-center border border-primary/20">
            <FileText size={28} className="text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-text tracking-tight">Strumenti PDF</h1>
            <p className="text-text-dim text-sm mt-0.5">Unisci, dividi, comprimi e modifica documenti PDF</p>
          </div>
        </div>

        {/* Tool Cards Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {TOOLS.map(tool => {
            const Icon = tool.icon;
            return (
              <button
                key={tool.id}
                onClick={() => selectTool(tool.id)}
                className="glass-card p-6 text-left hover:border-primary/30 transition-all duration-200 group cursor-pointer"
              >
                <div className="flex items-start gap-4">
                  <div className="w-11 h-11 bg-primary/10 rounded-xl flex items-center justify-center border border-primary/20 group-hover:bg-primary/20 transition-colors">
                    <Icon size={20} className="text-primary" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <h3 className="text-sm font-bold text-text">{tool.label}</h3>
                    <p className="text-xs text-text-dim mt-1 leading-relaxed">{tool.description}</p>
                  </div>
                </div>
              </button>
            );
          })}
        </div>

        {/* History */}
        {history.length > 0 && (
          <div className="mt-8">
            <div className="flex items-center gap-2 mb-3">
              <Clock size={14} className="text-text-dim" />
              <h3 className="text-2xs font-black text-text-dim uppercase tracking-label">Ultimi file modificati</h3>
            </div>
            <div className="space-y-1.5">
              {history.slice(0, 10).map((h, i) => (
                <div key={i} className="glass-card p-3 flex items-center gap-3 text-xs">
                  <span className="text-primary font-bold uppercase w-20 truncate">{h.tool}</span>
                  <span className="text-text truncate flex-1">{h.input}</span>
                  <span className="text-text-dim text-2xs shrink-0">{new Date(h.date).toLocaleDateString('it-IT', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })}</span>
                  {h.output && (
                    <button onClick={() => api.openPath(h.output)} className="text-primary hover:underline text-2xs font-bold shrink-0">Apri</button>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  // ─── Active Tool View ─────────────────────────────────────
  const Icon = currentTool.icon;
  return (
    <div className="max-w-3xl mx-auto space-y-6 pb-12">
      {/* Header with Back */}
      <div className="flex items-center gap-4">
        <button
          onClick={() => { setActiveTool(null); resetState(); }}
          className="w-10 h-10 rounded-xl bg-card hover:bg-card-hover flex items-center justify-center transition-colors border border-border/30"
        >
          <X size={18} className="text-text-dim" />
        </button>
        <div className="w-12 h-12 bg-primary/10 rounded-2xl flex items-center justify-center border border-primary/20">
          <Icon size={24} className="text-primary" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-text">{currentTool.label}</h1>
          <p className="text-xs text-text-dim">{currentTool.description}</p>
        </div>
      </div>

      {/* File Selection */}
      <div className="glass-card p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-text">
            {currentTool.multiFile ? 'Seleziona file' : 'Seleziona file'}
          </h3>
          <button
            onClick={handleFileSelect}
            className="btn-primary px-5 py-2.5 text-xs font-bold uppercase tracking-widest flex items-center gap-2"
          >
            <Upload size={14} /> Sfoglia
          </button>
        </div>

        {/* File List */}
        {files.length > 0 && (
          <div className="space-y-2">
            {files.map((f, i) => (
              <div key={i} className="flex items-center gap-3 bg-card rounded-xl px-4 py-3 border border-border/20">
                <FileText size={16} className="text-primary flex-shrink-0" />
                <span className="text-xs text-text truncate flex-1">{(typeof f === 'string' ? f : f?.path || f?.name || '').split('/').pop()}</span>
                {currentTool.multiFile && (
                  <button onClick={() => removeFile(i)} className="text-text-dim hover:text-danger transition-colors">
                    <X size={14} />
                  </button>
                )}
              </div>
            ))}
          </div>
        )}

        {/* PDF Info */}
        {pdfInfo && (
          <div className="flex items-center gap-4 text-xs text-text-dim bg-card rounded-xl px-4 py-3 border border-border/20">
            <Info size={14} className="text-primary flex-shrink-0" />
            <span>{pdfInfo.pages} pagine</span>
            <span className="opacity-40">|</span>
            <span>{pdfInfo.file_size_label}</span>
            {pdfInfo.encrypted && (
              <>
                <span className="opacity-40">|</span>
                <span className="text-warning">Protetto</span>
              </>
            )}
          </div>
        )}

        {/* Tool-specific Options */}
        {(currentTool.needsPages) && pdfInfo && (
          <div className="space-y-2">
            <label className="text-xs font-bold text-text-dim uppercase tracking-widest">
              Pagine ({activeTool === 'remove' ? 'da rimuovere' : 'da estrarre'})
            </label>
            <input
              type="text"
              value={pageInput}
              onChange={e => setPageInput(e.target.value)}
              placeholder="Es: 1,3,5-8,12"
              className="input-field w-full px-4 py-3 rounded-xl bg-input border-border text-text text-sm"
            />
            <p className="text-2xs text-text-dim">Usa virgole per singole pagine, trattino per intervalli. Totale: {pdfInfo.pages} pagine.</p>
          </div>
        )}

        {currentTool.needsRotation && (
          <div className="space-y-2">
            <label className="text-xs font-bold text-text-dim uppercase tracking-widest">Rotazione</label>
            <div className="flex gap-2">
              {ROTATION_OPTIONS.map(opt => (
                <button
                  key={opt.value}
                  onClick={() => setRotation(opt.value)}
                  className={`px-4 py-2.5 rounded-xl text-xs font-bold transition-colors border ${
                    rotation === opt.value
                      ? 'bg-primary/20 border-primary/40 text-primary'
                      : 'bg-card border-border/20 text-text-dim hover:border-primary/20'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
        )}

        {currentTool.needsWatermark && (
          <div className="space-y-3">
            <div className="space-y-2">
              <label className="text-xs font-bold text-text-dim uppercase tracking-widest">Testo watermark</label>
              <div className="flex gap-2 flex-wrap">
                {WATERMARK_PRESETS.map(preset => (
                  <button
                    key={preset}
                    onClick={() => setWatermarkText(preset)}
                    className={`px-3 py-2 rounded-lg text-xs font-bold transition-colors border ${
                      watermarkText === preset
                        ? 'bg-primary/20 border-primary/40 text-primary'
                        : 'bg-card border-border/20 text-text-dim hover:border-primary/20'
                    }`}
                  >
                    {preset}
                  </button>
                ))}
              </div>
              <input
                type="text"
                value={watermarkText}
                onChange={e => setWatermarkText(e.target.value)}
                placeholder="Testo personalizzato..."
                className="input-field w-full px-4 py-3 rounded-xl bg-input border-border text-text text-sm"
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs font-bold text-text-dim uppercase tracking-widest">
                Opacità: {Math.round(watermarkOpacity * 100)}%
              </label>
              <input
                type="range"
                min="0.05"
                max="0.5"
                step="0.05"
                value={watermarkOpacity}
                onChange={e => setWatermarkOpacity(parseFloat(e.target.value))}
                className="w-full accent-primary"
              />
            </div>
          </div>
        )}

        {/* Reorder Options */}
        {currentTool.needsReorder && pdfInfo && reorderList.length > 0 && (
          <div className="space-y-2">
            <label className="text-xs font-bold text-text-dim uppercase tracking-widest">
              Ordine pagine (trascina per riordinare)
            </label>
            <div className="flex flex-wrap gap-2">
              {reorderList.map((pageNum, idx) => (
                <div
                  key={idx}
                  draggable
                  onDragStart={() => setDragIdx(idx)}
                  onDragOver={e => e.preventDefault()}
                  onDrop={() => {
                    if (dragIdx === null || dragIdx === idx) return;
                    const next = [...reorderList];
                    const [moved] = next.splice(dragIdx, 1);
                    next.splice(idx, 0, moved);
                    setReorderList(next);
                    setDragIdx(null);
                  }}
                  className={`w-12 h-12 rounded-xl flex items-center justify-center text-sm font-bold border cursor-grab active:cursor-grabbing transition-colors ${
                    dragIdx === idx ? 'bg-primary/30 border-primary text-primary' : 'bg-card border-border/20 text-text hover:border-primary/30'
                  }`}
                >
                  {pageNum}
                </div>
              ))}
            </div>
            <p className="text-2xs text-text-dim">Trascina i numeri per cambiare l'ordine. Totale: {pdfInfo.pages} pagine.</p>
          </div>
        )}

        {/* Page Numbers Options */}
        {currentTool.needsPageNumbers && pdfInfo && (
          <div className="space-y-3">
            <div className="space-y-2">
              <label className="text-xs font-bold text-text-dim uppercase tracking-widest">Posizione</label>
              <div className="flex flex-wrap gap-2">
                {[
                  { v: 'bottom-center', l: 'Basso centro' },
                  { v: 'bottom-right', l: 'Basso destra' },
                  { v: 'bottom-left', l: 'Basso sinistra' },
                  { v: 'top-center', l: 'Alto centro' },
                  { v: 'top-right', l: 'Alto destra' },
                  { v: 'top-left', l: 'Alto sinistra' },
                ].map(opt => (
                  <button
                    key={opt.v}
                    onClick={() => setPageNumPosition(opt.v)}
                    className={`px-3 py-2 rounded-lg text-xs font-bold transition-colors border ${
                      pageNumPosition === opt.v
                        ? 'bg-primary/20 border-primary/40 text-primary'
                        : 'bg-card border-border/20 text-text-dim hover:border-primary/20'
                    }`}
                  >
                    {opt.l}
                  </button>
                ))}
              </div>
            </div>
            <div className="space-y-2">
              <label className="text-xs font-bold text-text-dim uppercase tracking-widest">Formato</label>
              <div className="flex flex-wrap gap-2">
                {[
                  { v: '{n}', l: '1, 2, 3...' },
                  { v: 'Pag. {n}', l: 'Pag. 1' },
                  { v: 'Pag. {n} di {total}', l: 'Pag. 1 di 10' },
                  { v: '- {n} -', l: '- 1 -' },
                ].map(opt => (
                  <button
                    key={opt.v}
                    onClick={() => setPageNumFormat(opt.v)}
                    className={`px-3 py-2 rounded-lg text-xs font-bold transition-colors border ${
                      pageNumFormat === opt.v
                        ? 'bg-primary/20 border-primary/40 text-primary'
                        : 'bg-card border-border/20 text-text-dim hover:border-primary/20'
                    }`}
                  >
                    {opt.l}
                  </button>
                ))}
              </div>
            </div>
            <div className="space-y-2">
              <label className="text-xs font-bold text-text-dim uppercase tracking-widest">Inizia da</label>
              <input
                type="number"
                min="1"
                value={pageNumStart}
                onChange={e => setPageNumStart(Math.max(1, parseInt(e.target.value) || 1))}
                className="input-field w-24 px-4 py-3 rounded-xl bg-input border-border text-text text-sm"
              />
            </div>
          </div>
        )}

        {/* Redact Options */}
        {currentTool.needsRedact && pdfInfo && (
          <div className="space-y-3">
            <label className="text-xs font-bold text-text-dim uppercase tracking-widest">
              Aree da censurare (coordinate PDF: origine in basso a sinistra)
            </label>
            {redactAreas.map((area, idx) => (
              <div key={idx} className="flex items-center gap-2 flex-wrap bg-card rounded-xl px-3 py-2 border border-border/20">
                <span className="text-2xs text-text-dim w-8">#{idx + 1}</span>
                <label className="text-2xs text-text-dim">Pag</label>
                <input type="number" min="1" max={pdfInfo.pages} value={area.page}
                  onChange={e => { const n = [...redactAreas]; n[idx] = { ...n[idx], page: parseInt(e.target.value) || 1 }; setRedactAreas(n); }}
                  className="input-field w-16 px-2 py-1.5 rounded-lg bg-input border-border text-text text-xs" />
                <label className="text-2xs text-text-dim">X</label>
                <input type="number" value={area.x}
                  onChange={e => { const n = [...redactAreas]; n[idx] = { ...n[idx], x: parseFloat(e.target.value) || 0 }; setRedactAreas(n); }}
                  className="input-field w-16 px-2 py-1.5 rounded-lg bg-input border-border text-text text-xs" />
                <label className="text-2xs text-text-dim">Y</label>
                <input type="number" value={area.y}
                  onChange={e => { const n = [...redactAreas]; n[idx] = { ...n[idx], y: parseFloat(e.target.value) || 0 }; setRedactAreas(n); }}
                  className="input-field w-16 px-2 py-1.5 rounded-lg bg-input border-border text-text text-xs" />
                <label className="text-2xs text-text-dim">L</label>
                <input type="number" value={area.width}
                  onChange={e => { const n = [...redactAreas]; n[idx] = { ...n[idx], width: parseFloat(e.target.value) || 0 }; setRedactAreas(n); }}
                  className="input-field w-16 px-2 py-1.5 rounded-lg bg-input border-border text-text text-xs" />
                <label className="text-2xs text-text-dim">A</label>
                <input type="number" value={area.height}
                  onChange={e => { const n = [...redactAreas]; n[idx] = { ...n[idx], height: parseFloat(e.target.value) || 0 }; setRedactAreas(n); }}
                  className="input-field w-16 px-2 py-1.5 rounded-lg bg-input border-border text-text text-xs" />
                {redactAreas.length > 1 && (
                  <button onClick={() => setRedactAreas(redactAreas.filter((_, i) => i !== idx))}
                    className="text-text-dim hover:text-danger transition-colors ml-auto">
                    <X size={14} />
                  </button>
                )}
              </div>
            ))}
            <button
              onClick={() => setRedactAreas([...redactAreas, { page: 1, x: 50, y: 700, width: 200, height: 20 }])}
              className="text-xs text-primary hover:underline font-bold"
            >
              + Aggiungi area
            </button>
            <p className="text-2xs text-text-dim">Le coordinate usano il sistema PDF: X da sinistra, Y dal basso. L = larghezza, A = altezza in punti.</p>
          </div>
        )}

        {/* Secure PDF Options */}
        {currentTool.needsSecure && pdfInfo && (
          <div className="space-y-3">
            <label className="text-xs font-bold text-text-dim uppercase tracking-widest">Protezioni</label>
            <div className="space-y-2">
              {[
                { key: 'noCopy', label: 'Blocca copia/incolla testo', val: secNoCopy, set: setSecNoCopy },
                { key: 'noPrint', label: 'Blocca stampa', val: secNoPrint, set: setSecNoPrint },
                { key: 'noModify', label: 'Blocca modifica', val: secNoModify, set: setSecNoModify },
                { key: 'watermark', label: 'Watermark RISERVATO', val: secWatermark, set: setSecWatermark },
              ].map(opt => (
                <label key={opt.key} className="flex items-center gap-3 cursor-pointer py-1">
                  <input type="checkbox" checked={opt.val} onChange={e => opt.set(e.target.checked)}
                    className="w-4 h-4 rounded border-border accent-primary" />
                  <span className="text-sm text-text">{opt.label}</span>
                </label>
              ))}
            </div>
            <div className="space-y-2">
              <label className="text-xs font-bold text-text-dim uppercase tracking-widest">Password proprietario (opzionale)</label>
              <input type="password" value={secPassword} onChange={e => setSecPassword(e.target.value)}
                placeholder="Lascia vuoto per generare automaticamente"
                className="input-field w-full px-4 py-3 rounded-xl bg-input border-border text-text text-sm" />
            </div>
          </div>
        )}

        {/* Unsecure Password */}
        {currentTool.needsUnsecurePassword && pdfInfo && (
          <div className="space-y-2">
            <label className="text-xs font-bold text-text-dim uppercase tracking-widest">Password (se il PDF ne ha una)</label>
            <input type="password" value={unsecurePassword} onChange={e => setUnsecurePassword(e.target.value)}
              placeholder="Lascia vuoto se il PDF non ha password"
              className="input-field w-full px-4 py-3 rounded-xl bg-input border-border text-text text-sm" />
          </div>
        )}

        {/* Execute Button */}
        <button
          onClick={executeTool}
          disabled={files.length === 0 || processing}
          className="btn-primary w-full py-4 rounded-xl text-xs font-bold uppercase tracking-widest flex items-center justify-center gap-3 disabled:opacity-40"
        >
          {processing ? (
            <>
              <Loader2 size={16} className="animate-spin" />
              Elaborazione...
            </>
          ) : (
            <>
              <Download size={16} />
              {activeTool === 'text' ? 'Estrai Testo' : 'Esegui'}
            </>
          )}
        </button>
      </div>

      {/* Result */}
      {result && (
        <div className={`glass-card p-5 flex items-start gap-4 border ${
          result.success ? 'border-success/30' : 'border-danger/30'
        }`}>
          {result.success ? (
            <Check size={20} className="text-success flex-shrink-0 mt-0.5" />
          ) : (
            <AlertCircle size={20} className="text-danger flex-shrink-0 mt-0.5" />
          )}
          <div className="flex-1 min-w-0">
            <p className={`text-sm font-semibold ${result.success ? 'text-success' : 'text-danger'}`}>
              {result.message}
            </p>
            {result.output_path && (
              <button
                onClick={() => api.openPath(result.output_path)}
                className="text-xs text-primary hover:underline mt-1"
              >
                Apri risultato
              </button>
            )}
            {result.details?.saved_percent > 0 && (
              <p className="text-xs text-text-dim mt-1">
                Risparmiato {result.details.saved_percent}% ({(result.details.saved_bytes / 1024).toFixed(0)} KB)
              </p>
            )}
          </div>
        </div>
      )}

      {/* Extracted Text */}
      {extractedText && (
        <div className="glass-card p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-text">Testo estratto</h3>
            <button
              onClick={() => navigator.clipboard.writeText(extractedText)}
              className="text-xs text-primary hover:underline font-bold"
            >
              Copia tutto
            </button>
          </div>
          <pre className="text-xs text-text-dim bg-card rounded-xl p-4 border border-border/20 overflow-auto max-h-96 whitespace-pre-wrap font-mono">
            {extractedText}
          </pre>
        </div>
      )}
    </div>
  );
}
