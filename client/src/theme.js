/** CSS category classes and JavaScript-only display colors. */

// ── Classi CSS per le categorie — queste vanno usate nei componenti ──
/** Classe CSS per il pallino (dot) della categoria */
export const catDotClass = (cat) => `cat-dot-${cat || 'altro'}`;
/** Classe CSS per la pill (badge) della categoria */
export const catPillClass = (cat) => `cat-pill-${cat || 'altro'}`;
/** Classe CSS per la barra (progress/accent) della categoria */
export const catBarClass = (cat) => `cat-bar-${cat || 'altro'}`;
/** Classe CSS per l'event block (calendar) della categoria */
export const evBgClass = (cat) => `ev-bg-${cat || 'altro'}`;

// ── Etichette Categoria ──────────────────────────────────
export const CAT_LABELS = {
  udienza:   'Udienza',
  scadenza:  'Scadenza',
  riunione:  'Riunione',
  personale: 'Personale',
  altro:     'Altro',
};

// ── Premium Pills (per Tailwind className) — classi CSS senza glow inline ──
export const CAT_PILL_STYLES = {
  udienza:   'cat-pill-udienza border',
  scadenza:  'cat-pill-scadenza border',
  riunione:  'cat-pill-riunione border',
  personale: 'cat-pill-personale border',
  altro:     'cat-pill-altro border',
};

// ── Colori Semantici (da usare solo quando serve JS) ─────
// Per la UI, preferire sempre le classi Tailwind:
//   text-primary, bg-surface, border-border, text-text, ecc.
// Contrasti misurati su bg dark #16171e e light #d0d1d5 — WCAG 2.1 AAA = 7:1.
export const SEMANTIC = { success: '#22c55e', danger: '#ef4444' };

// ── Colori Hero Dashboard — 3 fasce orarie ──────────────
// Colore unico per tema chiaro e scuro — IDENTICO in entrambi i temi.
// Solo 3 colori: mattina / pomeriggio / sera.
const HERO_COLORS = {
  morning:   '#96623E',   // Cuoio caldo — luce mattutina
  afternoon: '#6B5040',   // Siena scuro — calore pomeridiano
  evening:   '#4A5A8A',   // Blu notte chiaro — sera
};

/** Determina la fascia oraria (mattina dalle 5, notte 0-4 = sera) */
function getTimeOfDay(hour = new Date().getHours()) {
  if (hour >= 5 && hour < 13) return 'morning';
  if (hour >= 13 && hour < 18) return 'afternoon';
  return 'evening';
}

/**
 * Ottiene il colore hero per fascia oraria, adattato al tema.
 */
export function getHeroColor() {
  const timeOfDay = getTimeOfDay();
  const background = HERO_COLORS[timeOfDay] || HERO_COLORS.morning;

  return {
    background,
    timeOfDay,
  };
}
