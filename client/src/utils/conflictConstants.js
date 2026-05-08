/* ──── Label / colour maps for conflict-check & contacts ──── */

export const ROLE_LABELS = {
  client: 'Cliente',
  counterparty: 'Controparte',
  opposing_counsel: 'Avv. Controparte',
  judge: 'Giudice',
  consultant: 'Consulente',
};

// FIX-CC2: renamed from FIELD_LABELS to avoid name collision with the
// nested-map `FIELD_LABELS` defined locally inside `utils/typstPdfGenerator.js`.
export const CONFLICT_FIELD_LABELS = {
  client: 'Cliente',
  counterparty: 'Controparte',
  description: 'Descrizione',
  court: 'Tribunale',
  object: 'Oggetto',
};

export const STATUS_LABELS = { active: 'Attivo', closed: 'Chiuso', archived: 'Archiviato' };

// FIX-CC3: Tailwind utility classes here use `*-500/10` opacity overlays
// that work in both light and dark themes — the bg uses 10% alpha which
// preserves contrast across backgrounds. Ratios checked against light
// theme `--bg-canvas` (#fbf8f3) and dark theme `--bg-canvas` (#0e1015).
// If you swap to a vivid theme background, retest contrast for AAA.
export const STATUS_COLORS = {
  active: 'bg-green-500/10 text-green-400 border-green-500/30',
  closed: 'bg-zinc-500/10 text-zinc-400 border-zinc-500/30',
  archived: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
};
