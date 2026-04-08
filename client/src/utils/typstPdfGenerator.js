/**
 * ══════════════════════════════════════════════════════════════════════════
 * LexFlow — Typst PDF Generator
 * Genera PDF professionali usando il motore Typst (sidecar)
 * Tipografia TeX-grade con Libertinus Serif + Cinzel
 * ══════════════════════════════════════════════════════════════════════════
 */
import { exportTypstPdf, checkLicense } from '../tauri-api';

const TYPE_LABELS = {
  civile: 'Civile',
  penale: 'Penale',
  amm: 'Amministrativo',
  stra: 'Stragiudiziale',
  lavoro: 'Lavoro',
  soc: 'Societario',
};

const STATUS_LABELS = {
  active: 'Attivo',
  archived: 'Archiviato',
};

const FIELD_LABELS = {
  civile:  { counterparty: 'Controparte',     court: 'Tribunale',   code: 'N. R.G.' },
  penale:  { counterparty: 'Parte Offesa',    court: 'Tribunale',   code: 'N. R.G.N.R.' },
  amm:     { counterparty: 'Amministrazione', court: 'TAR / CdS',  code: 'N. Ricorso' },
  stra:    { counterparty: 'Controparte',     court: 'Sede',        code: 'Rif. Pratica' },
  lavoro:  { counterparty: 'Controparte',     court: 'Tribunale',   code: 'N. R.G.' },
  soc:     { counterparty: 'Controparte',     court: 'Camera Comm.', code: 'N. REA / P.IVA' },
};

/** Safe date formatter — returns fallback on invalid dates */
function safeDateIT(dateStr) {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleDateString('it-IT');
}

/**
 * Export a practice as a professional Typst-rendered PDF.
 * This is the drop-in replacement for exportPracticePDF from pdfGenerator.js.
 */
export async function exportPracticeTypstPDF(practice) {
  try {
    // 0. Load studio/lawyer info from license
    let lawyerName = '', studioName = '', lawyerTitle = 'Avv.';
    try {
      const license = await checkLicense() || {};
      if (license.activated) {
        // Strip any title prefix from name (e.g. "Avv. Pietro Longo" → "Pietro Longo")
        lawyerName = (license.lawyerName || '').replace(/^(Avv\.|Avv|Avvocato|Praticante)\.?\s+/i, '').trim();
        studioName = license.studioName || '';
        lawyerTitle = license.lawyerTitle || 'Avv.';
      }
    } catch { /* fallback vuoto */ }

    // Override lawyerTitle from settings if user changed it
    try {
      const settings = await (await import('../tauri-api')).getSettings() || {};
      if (settings.lawyerTitle) lawyerTitle = settings.lawyerTitle;
    } catch { /* fallback */ }

    const labels = FIELD_LABELS[practice.type] || FIELD_LABELS.civile;

    // 1. Build the data payload for Rust
    const practiceData = {
      client: practice.client || '—',
      object: practice.object || null,
      type: practice.type || 'civile',
      typeLabel: TYPE_LABELS[practice.type] || practice.type || 'Civile',
      statusLabel: STATUS_LABELS[practice.status] || practice.status || 'Attivo',
      counterparty: practice.counterparty || null,
      court: practice.court || null,
      code: practice.code || null,
      description: practice.description || null,
      counterpartyLabel: labels.counterparty,
      courtLabel: labels.court,
      codeLabel: labels.code,
      lawyerName: lawyerName || null,
      lawyerTitle: lawyerTitle || null,
      studioName: studioName || null,
      deadlines: practice.deadlines?.filter(d => d.date || d.label).map(d => ({
        date: safeDateIT(d.date),
        label: d.label || '—',
      })) || null,
      diary: practice.diary?.filter(d => d.date || d.text).map(d => ({
        date: safeDateIT(d.date),
        text: d.text || '—',
      })) || null,
    };

    // 2. Build clean file name
    const clientSafe = (practice.client || 'fascicolo')
      .replaceAll(/[^a-zA-Z0-9àèéìòù ]/g, '')
      .trim()
      .replaceAll(/\s+/g, '_');
    const defaultName = `LexFlow_${clientSafe}_${new Date().toISOString().split('T')[0]}.pdf`;

    // 3. Generate & save via Rust sidecar
    const result = await exportTypstPdf(practiceData, defaultName);

    return result; // { success, path } or { success: false, cancelled: true }
  } catch (error) {
    console.error('Errore export Typst PDF:', error);
    return { success: false, error };
  }
}
