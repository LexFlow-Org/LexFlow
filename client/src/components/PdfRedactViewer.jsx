import { useState, useEffect, useRef, useCallback } from 'react';
import { ChevronLeft, ChevronRight, Trash2, Loader2 } from 'lucide-react';
import * as api from '../tauri-api';

// PDF.js setup — use legacy build for broader compat
import * as pdfjsLib from 'pdfjs-dist';
import pdfjsWorker from 'pdfjs-dist/build/pdf.worker.mjs?url';
pdfjsLib.GlobalWorkerOptions.workerSrc = pdfjsWorker;

/**
 * PdfRedactViewer — Visual PDF redaction component.
 *
 * Props:
 *   filePath: string        — absolute path to the PDF file
 *   redactAreas: array      — [{page, x, y, width, height}, ...]  (PDF coords, origin bottom-left)
 *   onRedactAreasChange: fn — called with updated areas array
 *   totalPages: number      — total pages in the PDF (from pdfInfo)
 */
export default function PdfRedactViewer({ filePath, redactAreas, onRedactAreasChange, totalPages }) {
  const [pdfDoc, setPdfDoc] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [pageInfo, setPageInfo] = useState(null); // {width, height} in PDF points
  const [scale, setScale] = useState(1);

  // Drawing state
  const [drawing, setDrawing] = useState(false);
  const [drawStart, setDrawStart] = useState(null);
  const [drawCurrent, setDrawCurrent] = useState(null);

  // Currently selected redaction area (for keyboard delete)
  const [selectedAreaIdx, setSelectedAreaIdx] = useState(null);

  const canvasRef = useRef(null);
  const overlayRef = useRef(null);
  const containerRef = useRef(null);

  // Load PDF document
  useEffect(() => {
    if (!filePath) return;
    let cancelled = false;
    setLoading(true);

    (async () => {
      try {
        const b64 = await api.readFileBase64(filePath);
        const raw = atob(b64);
        const bytes = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);

        const doc = await pdfjsLib.getDocument({ data: bytes }).promise;
        if (!cancelled) {
          setPdfDoc(doc);
          setCurrentPage(1);
        }
      } catch (err) {
        console.error('PDF load error:', err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => { cancelled = true; };
  }, [filePath]);

  // Render current page
  useEffect(() => {
    if (!pdfDoc || !canvasRef.current) return;
    let cancelled = false;
    let renderTask = null;

    (async () => {
      const page = await pdfDoc.getPage(currentPage);
      const viewport = page.getViewport({ scale: 1 });

      // Fit to container width
      const containerWidth = containerRef.current?.clientWidth || 600;
      const fitScale = Math.min((containerWidth - 32) / viewport.width, 1.5);
      const scaledViewport = page.getViewport({ scale: fitScale });

      if (cancelled) return;
      setScale(fitScale);
      setPageInfo({ width: viewport.width, height: viewport.height });

      const dpr = window.devicePixelRatio || 1;
      const canvas = canvasRef.current;
      const ctx = canvas.getContext('2d');

      // Render at native resolution for Retina sharpness
      canvas.width = scaledViewport.width * dpr;
      canvas.height = scaledViewport.height * dpr;
      canvas.style.width = scaledViewport.width + 'px';
      canvas.style.height = scaledViewport.height + 'px';
      ctx.scale(dpr, dpr);

      // Size overlay to match CSS dimensions (mouse coords are CSS-space)
      if (overlayRef.current) {
        overlayRef.current.width = scaledViewport.width * dpr;
        overlayRef.current.height = scaledViewport.height * dpr;
        overlayRef.current.style.width = scaledViewport.width + 'px';
        overlayRef.current.style.height = scaledViewport.height + 'px';
      }

      try {
        renderTask = page.render({ canvasContext: ctx, viewport: scaledViewport });
        await renderTask.promise;
      } catch (err) {
        // Cancellation is expected when navigating quickly; only log other errors
        if (err?.name !== 'RenderingCancelledException') {
          console.error('Page render error:', err);
        }
      }
      // Overlay redraw is handled by the dedicated useEffect on `[drawOverlay]`
    })();

    return () => {
      cancelled = true;
      try { renderTask?.cancel?.(); } catch { /* ignore */ }
    };
  }, [pdfDoc, currentPage]);

  // Convert screen coords (relative to canvas) to PDF coords (origin bottom-left)
  const screenToPdf = useCallback((sx, sy) => {
    if (!pageInfo) return { x: 0, y: 0 };
    const x = sx / scale;
    const y = pageInfo.height - (sy / scale); // flip Y axis
    return { x, y };
  }, [scale, pageInfo]);

  // Convert PDF coords to screen coords
  const pdfToScreen = useCallback((px, py, pw, ph) => {
    if (!pageInfo) return { x: 0, y: 0, w: 0, h: 0 };
    const x = px * scale;
    const y = (pageInfo.height - py - ph) * scale; // flip Y: PDF origin is bottom-left
    const w = pw * scale;
    const h = ph * scale;
    return { x, y, w, h };
  }, [scale, pageInfo]);

  // Draw overlay: existing redaction areas + current drawing
  const drawOverlay = useCallback(() => {
    const canvas = overlayRef.current;
    if (!canvas || !pageInfo) return;
    const dpr = window.devicePixelRatio || 1;
    const ctx = canvas.getContext('2d');
    ctx.setTransform(1, 0, 0, 1, 0, 0); // reset transform
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.scale(dpr, dpr); // scale for Retina

    // Draw existing areas for current page
    const pageAreas = redactAreas.filter(a => a.page === currentPage);
    ctx.fillStyle = 'rgba(0, 0, 0, 0.6)';
    ctx.strokeStyle = 'rgba(239, 68, 68, 0.8)';
    ctx.lineWidth = 2;

    for (const area of pageAreas) {
      const { x, y, w, h } = pdfToScreen(area.x, area.y, area.width, area.height);
      ctx.fillRect(x, y, w, h);
      ctx.strokeRect(x, y, w, h);
    }

    // Draw current selection
    if (drawing && drawStart && drawCurrent) {
      const x = Math.min(drawStart.sx, drawCurrent.sx);
      const y = Math.min(drawStart.sy, drawCurrent.sy);
      const w = Math.abs(drawCurrent.sx - drawStart.sx);
      const h = Math.abs(drawCurrent.sy - drawStart.sy);

      ctx.fillStyle = 'rgba(239, 68, 68, 0.3)';
      ctx.strokeStyle = 'rgba(239, 68, 68, 1)';
      ctx.lineWidth = 2;
      ctx.setLineDash([5, 3]);
      ctx.fillRect(x, y, w, h);
      ctx.strokeRect(x, y, w, h);
      ctx.setLineDash([]);
    }
  }, [redactAreas, currentPage, pageInfo, pdfToScreen, drawing, drawStart, drawCurrent]);

  // Re-draw overlay when areas or drawing state change
  useEffect(() => {
    drawOverlay();
  }, [drawOverlay]);

  // Pointer handlers — use setPointerCapture so we keep receiving move/up events
  // even if the cursor briefly leaves the canvas during a drag.
  const dragRectRef = useRef(null); // cached getBoundingClientRect for the active drag

  const getCanvasCoordsFromRect = (e, rect) => ({
    sx: e.clientX - rect.left,
    sy: e.clientY - rect.top,
  });

  const handlePointerDown = (e) => {
    if (e.button !== 0) return; // left click / primary touch only
    try { e.currentTarget.setPointerCapture?.(e.pointerId); } catch { /* ignore */ }
    // Cache the bounding rect for the entire drag — avoids layout reads on every move
    dragRectRef.current = overlayRef.current.getBoundingClientRect();
    const coords = getCanvasCoordsFromRect(e, dragRectRef.current);
    setDrawing(true);
    setDrawStart(coords);
    setDrawCurrent(coords);
  };

  const handlePointerMove = (e) => {
    if (!drawing || !dragRectRef.current) return;
    setDrawCurrent(getCanvasCoordsFromRect(e, dragRectRef.current));
  };

  const handlePointerUp = (e) => {
    try { e.currentTarget.releasePointerCapture?.(e.pointerId); } catch { /* ignore */ }
    if (!drawing || !drawStart || !drawCurrent) {
      setDrawing(false);
      dragRectRef.current = null;
      return;
    }

    // Calculate screen-space rectangle
    const x1 = Math.min(drawStart.sx, drawCurrent.sx);
    const y1 = Math.min(drawStart.sy, drawCurrent.sy);
    const x2 = Math.max(drawStart.sx, drawCurrent.sx);
    const y2 = Math.max(drawStart.sy, drawCurrent.sy);

    // Convert screen corners to PDF coords
    // screenToPdf flips Y: screen-top (y1) → PDF high-y, screen-bottom (y2) → PDF low-y
    const pdfTL = screenToPdf(x1, y1); // PDF: x=left, y=high (top of rect)
    const pdfBR = screenToPdf(x2, y2); // PDF: x=right, y=low (bottom of rect)

    const pdfWidth = Math.abs(pdfBR.x - pdfTL.x);
    const pdfHeight = Math.abs(pdfTL.y - pdfBR.y);

    // Minimum size in PDF points (≈ 3pt = 1mm). Scale-independent.
    if (pdfWidth >= 3 && pdfHeight >= 3) {
      // PDF rect origin = bottom-left corner = (smallest x, smallest y)
      const area = {
        page: currentPage,
        x: Math.round(Math.min(pdfTL.x, pdfBR.x) * 100) / 100,
        y: Math.round(Math.min(pdfTL.y, pdfBR.y) * 100) / 100,
        width: Math.round(pdfWidth * 100) / 100,
        height: Math.round(pdfHeight * 100) / 100,
      };

      onRedactAreasChange([...redactAreas, area]);
    }

    setDrawing(false);
    setDrawStart(null);
    setDrawCurrent(null);
    dragRectRef.current = null;
  };

  const removeArea = (idx) => {
    onRedactAreasChange(redactAreas.filter((_, i) => i !== idx));
    if (selectedAreaIdx === idx) setSelectedAreaIdx(null);
  };

  // Keyboard navigation: ←/→ change page, Delete removes selected area, Cmd/Ctrl-Z undo last
  useEffect(() => {
    const onKey = (e) => {
      // Ignore when user is typing in an input/textarea
      const tag = e.target?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || e.target?.isContentEditable) return;

      if (e.key === 'ArrowLeft') {
        setCurrentPage(p => Math.max(1, p - 1));
      } else if (e.key === 'ArrowRight') {
        setCurrentPage(p => Math.min(pdfDoc?.numPages || totalPages || 1, p + 1));
      } else if (e.key === 'Delete' || e.key === 'Backspace') {
        if (selectedAreaIdx !== null && redactAreas[selectedAreaIdx]) {
          e.preventDefault();
          removeArea(selectedAreaIdx);
        }
      } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'z' && !e.shiftKey) {
        if (redactAreas.length > 0) {
          e.preventDefault();
          onRedactAreasChange(redactAreas.slice(0, -1));
          setSelectedAreaIdx(null);
        }
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pdfDoc, totalPages, selectedAreaIdx, redactAreas]);

  const pageCount = pdfDoc?.numPages || totalPages || 1;
  const areasOnPage = redactAreas.filter(a => a.page === currentPage);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 size={24} className="animate-spin text-primary" />
        <span className="ml-2 text-sm text-text-dim">Caricamento PDF...</span>
      </div>
    );
  }

  if (!pdfDoc) return null;

  return (
    <div className="space-y-3">
      {/* Page navigation */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
            disabled={currentPage <= 1}
            aria-label="Pagina precedente"
            className="min-w-11 min-h-11 rounded-lg bg-card hover:bg-card-hover flex items-center justify-center transition-colors border border-border/30 disabled:opacity-30"
          >
            <ChevronLeft size={16} aria-hidden="true" />
          </button>
          <span className="text-xs text-text font-bold min-w-[80px] text-center" aria-live="polite">
            Pagina {currentPage} / {pageCount}
          </span>
          <button
            onClick={() => setCurrentPage(p => Math.min(pageCount, p + 1))}
            disabled={currentPage >= pageCount}
            aria-label="Pagina successiva"
            className="min-w-11 min-h-11 rounded-lg bg-card hover:bg-card-hover flex items-center justify-center transition-colors border border-border/30 disabled:opacity-30"
          >
            <ChevronRight size={16} aria-hidden="true" />
          </button>
        </div>
        <span className="text-2xs text-text-dim">
          {redactAreas.length} {redactAreas.length === 1 ? 'area' : 'aree'} totali
        </span>
      </div>

      {/* Honest warning about redaction limits */}
      <div className="rounded-md p-3 text-sm border" style={{ background: 'var(--warning-soft, rgba(234, 179, 8, 0.08))', borderColor: 'var(--warning, #eab308)' }}>
        <strong>⚠️ ATTENZIONE — limite della redazione</strong>
        <p className="mt-1 text-xs leading-relaxed">
          La redazione attuale è <strong>visiva</strong>: rimuove il testo dalle pagine
          selezionate ma non offre garanzie crittografiche di rimozione totale.{' '}
          <strong>NON usare questa funzione per documenti che devono essere
          consegnati a controparti contenenti dati protetti dal segreto professionale.</strong>
        </p>
        <p className="mt-2 text-xs leading-relaxed">
          Per documenti riservati: stampa il PDF, redigi a mano con pennarello nero
          permanente, ri-scansiona, e usa la versione scansionata.
        </p>
      </div>

      {/* PDF canvas + overlay */}
      <div ref={containerRef} className="relative border border-border/30 rounded-xl overflow-hidden bg-white">
        <canvas ref={canvasRef} className="block" aria-hidden="true" />
        <canvas
          ref={overlayRef}
          className="absolute top-0 left-0 cursor-crosshair touch-none"
          onPointerDown={handlePointerDown}
          onPointerMove={handlePointerMove}
          onPointerUp={handlePointerUp}
          onPointerCancel={handlePointerUp}
          role="application"
          aria-label="Disegna le aree da censurare trascinando il puntatore"
        />
      </div>

      <p className="text-2xs text-text-dim">
        Trascina il mouse per selezionare le aree da censurare.
        Tasti rapidi: ← → per cambiare pagina, Canc per eliminare l'area selezionata, ⌘/Ctrl+Z per annullare.
      </p>

      {/* Area list for current page */}
      {areasOnPage.length > 0 && (
        <div className="space-y-1.5">
          <label className="text-2xs font-bold text-text-dim uppercase tracking-widest">
            Aree su pagina {currentPage}
          </label>
          {areasOnPage.map((area, localIdx) => {
            const globalIdx = redactAreas.indexOf(area);
            const isSelected = selectedAreaIdx === globalIdx;
            return (
              <div
                key={globalIdx}
                onClick={() => setSelectedAreaIdx(isSelected ? null : globalIdx)}
                className={`flex items-center gap-3 rounded-lg px-3 py-2 border text-xs cursor-pointer transition-colors ${
                  isSelected
                    ? 'bg-primary/10 border-primary/50'
                    : 'bg-card border-border/20 hover:border-primary/30'
                }`}
                aria-selected={isSelected}
                role="option"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    setSelectedAreaIdx(isSelected ? null : globalIdx);
                  }
                }}
              >
                <span className="text-text-dim">#{localIdx + 1}</span>
                <span className="text-text">
                  x:{Math.round(area.x)} y:{Math.round(area.y)} {Math.round(area.width)}x{Math.round(area.height)}
                </span>
                <button
                  onClick={(e) => { e.stopPropagation(); removeArea(globalIdx); }}
                  aria-label={`Rimuovi area #${localIdx + 1}`}
                  className="ml-auto text-text-dim hover:text-danger transition-colors min-w-11 min-h-11 flex items-center justify-center"
                >
                  <Trash2 size={14} aria-hidden="true" />
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
