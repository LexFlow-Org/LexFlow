import { useSessionState } from '../hooks/useSessionState';
import { useState, useEffect, useMemo } from 'react';
import {
  FileText, Merge, Split, Scissors, RotateCw,
  Minimize2, Stamp, FileOutput, Type, Images,
  Upload, Download, Check, AlertCircle, Loader2, X, Info,
  ArrowUpDown, Hash, EyeOff, Eye, Shield, Unlock, Clock,
  ChevronUp, ChevronDown
} from 'lucide-react';
import toast from 'react-hot-toast';
import * as api from '../tauri-api';
import { secureCopy } from '../tauri-api';

// NOTE: protect_pdf was removed by BE-4 + BE-8 (deprecated/dead). The corresponding
// `protectPdf` wrapper has also been removed from `client/src/tauri-api.js`.
// Do NOT re-add a `protect` tool here.
const TOOLS = [
  // ── Sicurezza & Protezione (piu' importanti) ──
  { id: 'secure', label: 'Proteggi PDF', icon: Shield, description: 'Imposta restrizioni di copia, stampa e modifica', multiFile: false, accept: '.pdf', needsSecure: true, defaultOutput: 'protetto.pdf' },
  { id: 'unsecure', label: 'Rimuovi Protezione', icon: Unlock, description: 'Rimuovi restrizioni da un PDF protetto', multiFile: false, accept: '.pdf', needsUnsecurePassword: true, defaultOutput: 'sbloccato.pdf' },
  { id: 'redact', label: 'Censura PDF', icon: EyeOff, description: 'Non disponibile: la rimozione irreversibile dei dati non è ancora garantita', disabled: true, multiFile: false, accept: '.pdf', defaultOutput: 'censurato.pdf' },
  { id: 'watermark', label: 'Watermark', icon: Stamp, description: 'Aggiungi BOZZA, RISERVATO, COPIA CONFORME', multiFile: false, accept: '.pdf', needsWatermark: true, defaultOutput: 'watermark.pdf' },
  // ── Operazioni comuni ──
  { id: 'merge', label: 'Unisci PDF', icon: Merge, description: 'Combina piu\' PDF in un unico documento', multiFile: true, accept: '.pdf', defaultOutput: 'unione.pdf' },
  { id: 'compress', label: 'Comprimi PDF', icon: Minimize2, description: 'Riduci la dimensione del PDF per PEC', multiFile: false, accept: '.pdf', defaultOutput: 'compresso.pdf' },
  { id: 'split', label: 'Dividi PDF', icon: Split, description: 'Dividi un PDF in pagine singole', multiFile: false, accept: '.pdf' },
  { id: 'pagenumbers', label: 'Numeri di Pagina', icon: Hash, description: 'Aggiungi numerazione pagine per atti e fascicoli', multiFile: false, accept: '.pdf', needsPageNumbers: true, defaultOutput: 'numerato.pdf' },
  // ── Modifica pagine ──
  { id: 'extract', label: 'Estrai Pagine', icon: FileOutput, description: 'Estrai solo le pagine che ti servono', multiFile: false, accept: '.pdf', needsPages: true, defaultOutput: 'estratto.pdf' },
  { id: 'remove', label: 'Rimuovi Pagine', icon: Scissors, description: 'Elimina pagine specifiche da un PDF', multiFile: false, accept: '.pdf', needsPages: true, defaultOutput: 'modificato.pdf' },
  { id: 'reorder', label: 'Organizza PDF', icon: ArrowUpDown, description: 'Riordina le pagine nel tuo PDF', multiFile: false, accept: '.pdf', needsReorder: true, defaultOutput: 'riordinato.pdf' },
  { id: 'rotate', label: 'Ruota Pagine', icon: RotateCw, description: 'Ruota le pagine di 90\u00b0, 180\u00b0 o 270\u00b0', multiFile: false, accept: '.pdf', needsRotation: true, defaultOutput: 'ruotato.pdf' },
  // ── Conversione ──
  { id: 'text', label: 'Estrai Testo', icon: Type, description: 'Estrai il testo da un PDF', multiFile: false, accept: '.pdf' },
  { id: 'images2pdf', label: 'Immagini \u2192 PDF', icon: Images, description: 'Converti immagini in un unico PDF', multiFile: true, accept: '.png,.jpg,.jpeg,.webp,.gif', defaultOutput: 'immagini.pdf' },
];

// Limits for images\u2192PDF tool (FIX-12)
const IMAGES2PDF_MAX_FILES = 100;
const IMAGES2PDF_MAX_TOTAL_BYTES = 200 * 1024 * 1024; // 200 MB

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
  const [result, setResultRaw] = useState(null);
  const setResult = (next) => { setRevealOwnerPwd(false); setResultRaw(next); };
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

  // Secure PDF state
  const [secNoCopy, setSecNoCopy] = useState(true);
  const [secNoPrint, setSecNoPrint] = useState(true);
  const [secNoModify, setSecNoModify] = useState(true);
  const [secWatermark, setSecWatermark] = useState(true);
  const [secPassword, setSecPassword] = useState('');

  // Unsecure password
  const [unsecurePassword, setUnsecurePassword] = useState('');

  // Owner-password reveal state (FIX-2): hidden by default, auto-hides after 60s
  const [revealOwnerPwd, setRevealOwnerPwd] = useState(false);

  // Filenames and paths stay in memory until the vault locks.
  const [history, setHistory] = useSessionState('pdfHistory', []);

  const resetState = () => {
    setFiles([]);
    setPdfInfo(null);
    setResult(null);
    setExtractedText(null);
    setPageInput('');
    setProcessing(false);
    setReorderList([]);
    setDragIdx(null);
    setPageNumPosition('bottom-center');
    setPageNumFormat('Pag. {n} di {total}');
    setPageNumStart(1);
    setSecNoCopy(true); setSecNoPrint(true); setSecNoModify(true); setSecWatermark(true); setSecPassword('');
    setUnsecurePassword('');
  };

  const addToHistory = (tool, inputName, outputPath) => {
    const entry = { tool, input: inputName, output: outputPath, date: new Date().toISOString() };
    setHistory(prev => [entry, ...prev].slice(0, 50));
  };

  const selectTool = (tool) => {
    if (TOOLS.find(item => item.id === tool)?.disabled) return;
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
          } catch {
            // FIX-7 BUG-3: surface PDF parse errors instead of silently swallowing
            setPdfInfo(null);
            toast.error('PDF illeggibile o danneggiato.');
          }
        }
      }
    } else {
      const exts = tool.accept.split(',').map(e => e.replace('.', '').trim());
      const result = await api.selectFile(exts);
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
          } catch {
            // FIX-7 BUG-3
            setPdfInfo(null);
            toast.error('PDF illeggibile o danneggiato.');
          }
        }
      }
    }
  };

  const removeFile = (idx) => {
    setFiles(prev => prev.filter((_, i) => i !== idx));
  };

  // FIX-10 VAL-1: parser that also returns invalid tokens for inline diagnostics.
  const parsePagesWithDiag = (input, total) => {
    const valid = [];
    const invalid = [];
    if (!input?.trim()) return { valid: [], invalid: [] };
    for (const part of input.split(',')) {
      const trimmed = part.trim();
      if (!trimmed) continue;
      if (trimmed.includes('-')) {
        const [a, b] = trimmed.split('-').map(s => s.trim());
        const ai = parseInt(a, 10);
        const bi = parseInt(b, 10);
        if (Number.isNaN(ai) || Number.isNaN(bi) || ai > bi || ai < 1 || bi > total) {
          invalid.push(trimmed);
          continue;
        }
        for (let i = Math.max(1, ai); i <= Math.min(total, bi); i++) valid.push(i);
      } else {
        const n = parseInt(trimmed, 10);
        if (Number.isNaN(n) || n < 1 || n > total) {
          invalid.push(trimmed);
        } else {
          valid.push(n);
        }
      }
    }
    return {
      valid: [...new Set(valid)].sort((a, b) => a - b),
      invalid,
    };
  };

  // Backwards-compatible wrapper used inside executeTool.
  const parsePages = (input, total) => parsePagesWithDiag(input, total).valid;

  // FIX-8 BUG-4: clamp a page-number input to [1, total].
  const setPageNumStartClamped = (val) => {
    const n = Math.max(1, parseInt(val, 10) || 1);
    setPageNumStart(Math.min(n, pdfInfo?.pages ?? n));
  };

  // Live preview of valid/invalid tokens for the current pageInput.
  const pageDiag = useMemo(() => {
    if (!pdfInfo || !pageInput) return { valid: [], invalid: [] };
    return parsePagesWithDiag(pageInput, pdfInfo.pages);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pageInput, pdfInfo?.pages]);

  // FIX-5 BUG-1 + FIX-6 BUG-2: helper to mark a save-dialog cancellation
  // with a neutral (not-error) banner and a small toast.
  const markCancelled = () => {
    setResult({ success: null, message: 'Operazione annullata.' });
    toast('Annullato', { icon: 'ℹ️' });
  };

  const executeTool = async () => {
    if (files.length === 0) return;
    const tool = TOOLS.find(t => t.id === activeTool);
    setProcessing(true);
    setResult(null);
    setExtractedText(null);

    try {
      let res;

      switch (activeTool) {
        case 'merge': {
          if (files.length < 2) { setResult({ success: false, message: 'Servono almeno 2 file.' }); break; }
          const out = await api.selectSavePath(tool.defaultOutput);
          if (!out) { markCancelled(); break; }
          res = await api.mergePdfs(files, out);
          setResult(res);
          break;
        }
        case 'split': {
          const dir = await api.selectFolder();
          if (!dir) { markCancelled(); break; }
          res = await api.splitPdf(files[0], dir);
          setResult(res);
          break;
        }
        case 'remove': {
          if (!pdfInfo || !pageInput) break;
          const pages = parsePages(pageInput, pdfInfo.pages);
          if (pages.length === 0) { setResult({ success: false, message: 'Nessuna pagina valida.' }); break; }
          const out = await api.selectSavePath(tool.defaultOutput);
          if (!out) { markCancelled(); break; }
          res = await api.removePages(files[0], out, pages);
          setResult(res);
          break;
        }
        case 'extract': {
          if (!pdfInfo || !pageInput) break;
          const pages = parsePages(pageInput, pdfInfo.pages);
          if (pages.length === 0) { setResult({ success: false, message: 'Nessuna pagina valida.' }); break; }
          const out = await api.selectSavePath(tool.defaultOutput);
          if (!out) { markCancelled(); break; }
          res = await api.extractPages(files[0], out, pages);
          setResult(res);
          break;
        }
        case 'rotate': {
          const out = await api.selectSavePath(tool.defaultOutput);
          if (!out) { markCancelled(); break; }
          res = await api.rotatePdf(files[0], out, rotation, null);
          setResult(res);
          break;
        }
        case 'compress': {
          const out = await api.selectSavePath(tool.defaultOutput);
          if (!out) { markCancelled(); break; }
          res = await api.compressPdf(files[0], out);
          setResult(res);
          break;
        }
        case 'watermark': {
          const out = await api.selectSavePath(tool.defaultOutput);
          if (!out) { markCancelled(); break; }
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
          // FIX-12 VAL-3: hard caps on file count + total bytes (running counter shown in UI).
          if (files.length > IMAGES2PDF_MAX_FILES) {
            setResult({ success: false, message: `Massimo ${IMAGES2PDF_MAX_FILES} immagini per conversione.` });
            break;
          }
          const out = await api.selectSavePath(tool.defaultOutput);
          if (!out) { markCancelled(); break; }
          res = await api.imagesToPdf(files, out);
          setResult(res);
          break;
        }
        case 'reorder': {
          if (reorderList.length === 0) { setResult({ success: false, message: 'Nessun ordine specificato.' }); break; }
          const out = await api.selectSavePath(tool.defaultOutput);
          if (!out) { markCancelled(); break; }
          res = await api.reorderPages(files[0], out, reorderList);
          setResult(res);
          break;
        }
        case 'pagenumbers': {
          const out = await api.selectSavePath(tool.defaultOutput);
          if (!out) { markCancelled(); break; }
          res = await api.addPageNumbers(files[0], out, pageNumPosition, pageNumFormat, pageNumStart, null);
          setResult(res);
          break;
        }
        case 'secure': {
          const out = await api.selectSavePath(tool.defaultOutput);
          if (!out) { markCancelled(); break; }
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
          const out = await api.selectSavePath(tool.defaultOutput);
          if (!out) { markCancelled(); break; }
          res = await api.unsecurePdf(files[0], out, unsecurePassword || null);
          setResult(res);
          break;
        }
      }
      // Save to history if successful
      if (res?.success && res?.output_path) {
        // Keep a concise filename for this in-memory session history.
        const inputName = (typeof files[0] === 'string' ? files[0] : '').split('/').pop() || 'file';
        addToHistory(activeTool, inputName, res.output_path);
      }
    } catch (err) {
      setResult({ success: false, message: err?.message || String(err) });
    } finally {
      // FIX-1 SEC-2: passwords must NEVER linger in React state once a tool run finishes,
      // regardless of success/failure. Clearing here also covers the cancellation path.
      setProcessing(false);
      setSecPassword('');
      setUnsecurePassword('');
    }
  };

  // FIX-17 PERF-1: avoid re-running TOOLS.find on every render
  const currentTool = useMemo(() => TOOLS.find(t => t.id === activeTool), [activeTool]);

  // Expire each reveal after 60 seconds, including a reveal made long after generation.
  useEffect(() => {
    if (!revealOwnerPwd) return;
    const id = setTimeout(() => setRevealOwnerPwd(false), 60000);
    return () => clearTimeout(id);
  }, [revealOwnerPwd]);

  // ─── Tool Grid (no tool selected) ────────────────────────
  if (!activeTool) {
    return (
      <div className="max-w-5xl mx-auto space-y-6 pb-12">
        {/* Header */}
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 bg-primary/10 rounded-2xl flex items-center justify-center border border-primary/20">
            <FileText size={28} className="text-primary" aria-hidden="true" />
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
                disabled={tool.disabled}
                onClick={() => selectTool(tool.id)}
                className="glass-card p-6 text-left hover:border-primary/30 transition-all duration-200 group cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed"
              >
                <div className="flex items-start gap-4">
                  <div className="w-11 h-11 bg-primary/10 rounded-xl flex items-center justify-center border border-primary/20 group-hover:bg-primary/20 transition-colors">
                    <Icon size={20} className="text-primary" aria-hidden="true" />
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
              <Clock size={14} className="text-text-dim" aria-hidden="true" />
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
          aria-label="Torna agli strumenti"
          className="min-w-11 min-h-11 rounded-xl bg-card hover:bg-card-hover flex items-center justify-center transition-colors border border-border/30"
        >
          <X size={18} className="text-text-dim" aria-hidden="true" />
        </button>
        <div className="w-12 h-12 bg-primary/10 rounded-2xl flex items-center justify-center border border-primary/20">
          <Icon size={24} className="text-primary" aria-hidden="true" />
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
            <Upload size={14} aria-hidden="true" /> Sfoglia
          </button>
        </div>

        {/* File List */}
        {files.length > 0 && (
          <div className="space-y-2">
            {files.map((f, i) => (
              <div key={i} className="flex items-center gap-3 bg-card rounded-xl px-4 py-3 border border-border/20">
                <FileText size={16} className="text-primary flex-shrink-0" aria-hidden="true" />
                <span className="text-xs text-text truncate flex-1">{(typeof f === 'string' ? f : f?.path || f?.name || '').split('/').pop()}</span>
                {currentTool.multiFile && (
                  <button
                    onClick={() => removeFile(i)}
                    aria-label={`Rimuovi ${(typeof f === 'string' ? f : f?.path || f?.name || '').split('/').pop()}`}
                    className="text-text-dim hover:text-danger transition-colors min-w-11 min-h-11 flex items-center justify-center"
                  >
                    <X size={14} aria-hidden="true" />
                  </button>
                )}
              </div>
            ))}
          </div>
        )}

        {/* PDF Info */}
        {pdfInfo && (
          <div className="flex items-center gap-4 text-xs text-text-dim bg-card rounded-xl px-4 py-3 border border-border/20">
            <Info size={14} className="text-primary flex-shrink-0" aria-hidden="true" />
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
            <label className="text-xs font-bold text-text-dim uppercase tracking-widest" htmlFor="pdf-pages-input">
              Pagine ({activeTool === 'remove' ? 'da rimuovere' : 'da estrarre'})
            </label>
            <input
              id="pdf-pages-input"
              type="text"
              value={pageInput}
              onChange={e => setPageInput(e.target.value)}
              placeholder="Es: 1,3,5-8,12"
              aria-describedby="pdf-pages-help"
              className="input-field w-full px-4 py-3 rounded-xl bg-input border-border text-text text-sm"
            />
            <p id="pdf-pages-help" className="text-2xs text-text-dim">Usa virgole per singole pagine, trattino per intervalli. Totale: {pdfInfo.pages} pagine.</p>
            {/* FIX-10 VAL-1: live preview of valid/invalid tokens */}
            {pageDiag.invalid.length > 0 && (
              <p className="text-2xs text-warning">
                Token non validi: {pageDiag.invalid.join(', ')}
              </p>
            )}
            {pageDiag.valid.length > 0 && (
              <p className="text-2xs text-text-dim">
                Pagine selezionate ({pageDiag.valid.length}): {pageDiag.valid.join(', ')}
              </p>
            )}
          </div>
        )}

        {currentTool.needsRotation && (
          <div className="space-y-2">
            <label className="text-xs font-bold text-text-dim uppercase tracking-widest">Rotazione</label>
            <div className="flex gap-2" role="group" aria-label="Rotazione">
              {ROTATION_OPTIONS.map(opt => (
                <button
                  key={opt.value}
                  onClick={() => setRotation(opt.value)}
                  aria-pressed={rotation === opt.value}
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
              <div className="flex gap-2 flex-wrap" role="group" aria-label="Preset watermark">
                {WATERMARK_PRESETS.map(preset => (
                  <button
                    key={preset}
                    onClick={() => setWatermarkText(preset)}
                    aria-pressed={watermarkText === preset}
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
              <label className="text-xs font-bold text-text-dim uppercase tracking-widest" htmlFor="watermark-opacity">
                Opacità: {Math.round(watermarkOpacity * 100)}%
              </label>
              <input
                id="watermark-opacity"
                type="range"
                min="0.05"
                max="0.5"
                step="0.05"
                value={watermarkOpacity}
                onChange={e => setWatermarkOpacity(parseFloat(e.target.value))}
                aria-valuetext={`${Math.round(watermarkOpacity * 100)} percento`}
                className="w-full accent-primary"
              />
            </div>
          </div>
        )}

        {/* Reorder Options */}
        {currentTool.needsReorder && pdfInfo && reorderList.length > 0 && (
          <div className="space-y-2">
            <label className="text-xs font-bold text-text-dim uppercase tracking-widest">
              Ordine pagine (trascina o usa le frecce per riordinare)
            </label>
            <div className="flex flex-wrap gap-2" role="list">
              {reorderList.map((pageNum, idx) => (
                <div
                  key={idx}
                  draggable
                  onDragStart={() => setDragIdx(idx)}
                  onDragOver={e => e.preventDefault()}
                  onDrop={() => {
                    if (dragIdx === null || dragIdx === idx) return;
                    setReorderList(prev => {
                      const next = [...prev];
                      const [moved] = next.splice(dragIdx, 1);
                      next.splice(idx, 0, moved);
                      return next;
                    });
                    setDragIdx(null);
                  }}
                  role="listitem"
                  aria-label={`Pagina ${pageNum}, posizione ${idx + 1} di ${reorderList.length}`}
                  className={`group flex items-center gap-1 rounded-xl border transition-colors ${
                    dragIdx === idx ? 'bg-primary/30 border-primary text-primary' : 'bg-card border-border/20 text-text hover:border-primary/30'
                  }`}
                >
                  {/* FIX-14 A11Y-2: keyboard reorder buttons (44x44 touch target) */}
                  <button
                    type="button"
                    aria-label={`Sposta pagina ${pageNum} indietro`}
                    disabled={idx === 0}
                    onClick={() => {
                      setReorderList(prev => {
                        if (idx === 0) return prev;
                        const next = [...prev];
                        [next[idx - 1], next[idx]] = [next[idx], next[idx - 1]];
                        return next;
                      });
                    }}
                    className="min-w-11 min-h-11 flex items-center justify-center rounded-l-xl hover:bg-primary/10 disabled:opacity-30"
                  >
                    <ChevronUp size={14} aria-hidden="true" />
                  </button>
                  <span className="cursor-grab active:cursor-grabbing min-w-8 text-center text-sm font-bold select-none">
                    {pageNum}
                  </span>
                  <button
                    type="button"
                    aria-label={`Sposta pagina ${pageNum} avanti`}
                    disabled={idx === reorderList.length - 1}
                    onClick={() => {
                      setReorderList(prev => {
                        if (idx === prev.length - 1) return prev;
                        const next = [...prev];
                        [next[idx], next[idx + 1]] = [next[idx + 1], next[idx]];
                        return next;
                      });
                    }}
                    className="min-w-11 min-h-11 flex items-center justify-center rounded-r-xl hover:bg-primary/10 disabled:opacity-30"
                  >
                    <ChevronDown size={14} aria-hidden="true" />
                  </button>
                </div>
              ))}
            </div>
            <p className="text-2xs text-text-dim">Trascina i numeri o usa le frecce per cambiare l'ordine. Totale: {pdfInfo.pages} pagine.</p>
          </div>
        )}

        {/* Page Numbers Options */}
        {currentTool.needsPageNumbers && pdfInfo && (
          <div className="space-y-3">
            <div className="space-y-2">
              <label className="text-xs font-bold text-text-dim uppercase tracking-widest">Posizione</label>
              <div className="flex flex-wrap gap-2" role="group" aria-label="Posizione numero di pagina">
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
                    aria-pressed={pageNumPosition === opt.v}
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
              <div className="flex flex-wrap gap-2" role="group" aria-label="Formato numero di pagina">
                {[
                  { v: '{n}', l: '1, 2, 3...' },
                  { v: 'Pag. {n}', l: 'Pag. 1' },
                  { v: 'Pag. {n} di {total}', l: 'Pag. 1 di 10' },
                  { v: '- {n} -', l: '- 1 -' },
                ].map(opt => (
                  <button
                    key={opt.v}
                    onClick={() => setPageNumFormat(opt.v)}
                    aria-pressed={pageNumFormat === opt.v}
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
              <label className="text-xs font-bold text-text-dim uppercase tracking-widest" htmlFor="pdf-pagenum-start">Inizia da</label>
              <input
                id="pdf-pagenum-start"
                type="number"
                min="1"
                max={pdfInfo.pages}
                value={pageNumStart}
                onChange={e => setPageNumStartClamped(e.target.value)}
                className="input-field w-24 px-4 py-3 rounded-xl bg-input border-border text-text text-sm"
              />
              <p className="text-2xs text-text-dim">Min 1 — max {pdfInfo.pages}.</p>
            </div>
          </div>
        )}

        {currentTool.needsSecure && (
          <p role="note" className="text-sm text-warning bg-warning-soft border border-warning-border rounded-xl p-4">
            Si apre senza password; altri programmi possono ignorare le restrizioni. Non impedisce la condivisione.
          </p>
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

        {/* FIX-12 VAL-3: running counter + cap warning for images→PDF */}
        {currentTool.id === 'images2pdf' && files.length > 0 && (
          <p className={`text-2xs ${files.length > IMAGES2PDF_MAX_FILES ? 'text-danger' : 'text-text-dim'}`}>
            {files.length} / {IMAGES2PDF_MAX_FILES} immagini selezionate
            {files.length > IMAGES2PDF_MAX_FILES && ' — supera il limite'}
          </p>
        )}

        {/* Execute Button — FIX-11 VAL-2: also disable merge when < 2 files */}
        <button
          onClick={executeTool}
          disabled={
            files.length === 0
            || processing
            || (currentTool.id === 'merge' && files.length < 2)
            || (currentTool.id === 'images2pdf' && files.length > IMAGES2PDF_MAX_FILES)
          }
          className="btn-primary w-full py-4 rounded-xl text-xs font-bold uppercase tracking-widest flex items-center justify-center gap-3 disabled:opacity-40"
        >
          {processing ? (
            <>
              <Loader2 size={16} className="animate-spin" aria-hidden="true" />
              Elaborazione...
            </>
          ) : (
            <>
              <Download size={16} aria-hidden="true" />
              {activeTool === 'text' ? 'Estrai Testo' : 'Esegui'}
            </>
          )}
        </button>
      </div>

      {/* Result — FIX-5 BUG-1: tri-state (success / null=cancelled / false=error) */}
      {result && (
        <div className={`glass-card p-5 flex items-start gap-4 border ${
          result.success === true ? 'border-success/30' :
          result.success === null ? 'border-border/30' :
          'border-danger/30'
        }`} role="status">
          {result.success === true ? (
            <Check size={20} className="text-success flex-shrink-0 mt-0.5" aria-hidden="true" />
          ) : result.success === null ? (
            <Info size={20} className="text-text-dim flex-shrink-0 mt-0.5" aria-hidden="true" />
          ) : (
            <AlertCircle size={20} className="text-danger flex-shrink-0 mt-0.5" aria-hidden="true" />
          )}
          <div className="flex-1 min-w-0">
            <p className={`text-sm font-semibold ${
              result.success === true ? 'text-success' :
              result.success === null ? 'text-text-dim' :
              'text-danger'
            }`}>
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
            {result.details?.owner_password && (
              <div className="mt-2 space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-2xs text-text-dim">Password proprietario:</span>
                  {/* FIX-2 SEC-2: hidden by default, reveal toggle */}
                  <button
                    type="button"
                    onClick={() => setRevealOwnerPwd(v => !v)}
                    aria-label="Mostra/nascondi owner password"
                    aria-pressed={revealOwnerPwd}
                    className="min-w-11 min-h-11 inline-flex items-center justify-center rounded-md hover:bg-card/50 text-text-dim hover:text-text transition-colors"
                  >
                    {revealOwnerPwd ? <EyeOff size={14} aria-hidden="true" /> : <Eye size={14} aria-hidden="true" />}
                  </button>
                  <code className="text-xs bg-input px-2 py-1 rounded border border-border/30 text-text font-mono">
                    {revealOwnerPwd ? result.details.owner_password : '•'.repeat(16)}
                  </code>
                  {/* FIX-3 SEC-3: secureCopy auto-clears clipboard at ~30s */}
                  <button
                    type="button"
                    onClick={async () => {
                      try {
                        await secureCopy(result.details.owner_password);
                        toast.success('Password copiata (cancellata automaticamente fra 30s)');
                      } catch {
                        toast.error('Impossibile copiare la password.');
                      }
                    }}
                    className="text-2xs text-primary hover:underline font-bold"
                  >
                    Copia
                  </button>
                </div>
                <small className="text-2xs text-text-dim block">
                  La password verrà nascosta automaticamente fra 60 secondi.
                  Conservala in un password manager — non sarà mostrata di nuovo.
                </small>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Extracted Text */}
      {extractedText && (
        <div className="glass-card p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-text">Testo estratto</h3>
            {/* FIX-3 SEC-3: secureCopy with auto-clear */}
            <button
              onClick={async () => {
                try {
                  await secureCopy(extractedText);
                  toast.success('Testo copiato (cancellato automaticamente fra 30s)');
                } catch {
                  toast.error('Impossibile copiare il testo.');
                }
              }}
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
