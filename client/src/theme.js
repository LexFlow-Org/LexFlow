/**
 * LexFlow Design Tokens — Single Source of Truth
 * ================================================
 * Tutti i colori dell'app sono definiti QUI.
 * Nessun hex hardcoded nei componenti.
 *
 * Uso:  import { COLORS, CAT, GRADIENTS } from '../theme';
 */

// ── Colori Categoria Agenda ──────────────────────────────
// ★ I colori sono definiti SOLO in index.css (--cat-*).
//   Queste costanti servono SOLO come backup / per chart libraries.
export const CAT_COLORS = {
  udienza:   '#A78FD8',
  scadenza:  '#E06060',
  riunione:  '#5A9DAD',
  personale: '#4BA88E',
  altro:     '#8891A5',
};

/** Colore categoria con fallback — USARE SOLO per chart/canvas, MAI per inline style */
export const catColor = (cat) => CAT_COLORS[cat] || CAT_COLORS.altro;

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

// ── Premium Glow Pills (per Tailwind className) — ORA USANO CLASSI CSS ──
export const CAT_PILL_STYLES = {
  udienza:   'cat-pill-udienza border shadow-[0_0_8px_rgba(167,143,216,0.15)]',
  scadenza:  'cat-pill-scadenza border shadow-[0_0_8px_rgba(224,96,96,0.15)]',
  riunione:  'cat-pill-riunione border shadow-[0_0_8px_rgba(90,157,173,0.15)]',
  personale: 'cat-pill-personale border shadow-[0_0_8px_rgba(75,168,142,0.15)]',
  altro:     'cat-pill-altro border shadow-[0_0_8px_rgba(136,145,165,0.15)]',
};

export const catPill = (cat) => CAT_PILL_STYLES[cat] || CAT_PILL_STYLES.altro;

// ── Colori Semantici (da usare solo quando serve JS) ─────
// Per la UI, preferire sempre le classi Tailwind:
//   text-primary, bg-surface, border-border, text-text, ecc.
// ★ WCAG AAA: tutti i testi ≥ 7:1 su bg #16171e (dark) o #f4f5f8 (light)
export const SEMANTIC = {
  primary:      '#d4a940',
  primaryHover: '#c29735',
  success:      '#22c55e',
  successDark:  '#16a34a',
  danger:       '#ef4444',
  dangerDark:   '#dc2626',
  warning:      '#f59e0b',
  info:         '#60a5fa',
  // Text toni (dark mode) — AAA ≥ 7:1 su #16171e
  text:         '#edeef6',   // 14.8:1 ✅ AAA
  textMuted:    '#b8bcd4',   //  7.2:1 ✅ AAA
  textDim:      '#A8ADCC',   //  5.9→7.0:1 ✅ AAA (era #9AA0C0 = 4.5:1)
  textSubtle:   '#B0B6D0',   //  6.5→7.2:1 ✅ AAA (era #A0A8C0 = 5.1:1)
  // Backgrounds (dark mode)
  bg:           '#16171e',
  bgCard:       '#1e1f28',
  bgSurface:    '#22232e',
  bgSidebar:    '#14151c',
  bgDeep:       '#08090f',
  bgError:      '#0c0d14',
  // Borders
  border:       '#32374f',
};

// ── Colori Hero Dashboard — Stagionali & Dinamici ────────
// Colore unico per tema chiaro e scuro — medio, elegante, leggibile.
// 12 combinazioni: 4 stagioni × 3 momenti del giorno
export const HERO_COLORS = {
  // 🌿 PRIMAVERA — toni caldi dorati, no verdi
  spring: {
    morning:   '#8C7A50',   // Sabbia calda — mattina primaverile
    afternoon: '#8C7848',   // Ocra dorato — pomeriggio di sole
    evening:   '#6B6888',   // Lavanda grigia — sera di primavera
  },
  // ☀️ ESTATE — palette calda e solare
  summer: {
    morning:   '#8C8050',   // Grano dorato — mattina d'estate
    afternoon: '#8C6458',   // Terracotta — pomeriggio rovente
    evening:   '#585878',   // Indaco caldo — notte estiva
  },
  // 🍂 AUTUNNO — terra, ambra, vino
  autumn: {
    morning:   '#8C7040',   // Ambra — prima luce d'autunno
    afternoon: '#7C5860',   // Borgogna — pomeriggio tra le vigne
    evening:   '#6C5848',   // Noce — sera autunnale
  },
  // ❄️ INVERNO — toni freddi, pietra e acciaio
  winter: {
    morning:   '#6C6C74',   // Pietra — nebbia mattutina
    afternoon: '#5C6C74',   // Acciaio — cielo invernale
    evening:   '#505058',   // Antracite — notte gelida
  },
};

/** Determina la stagione dall'emisfero nord (Italia) */
export function getSeason(month = new Date().getMonth()) {
  if (month >= 2 && month <= 4) return 'spring';   // Mar-Mag
  if (month >= 5 && month <= 7) return 'summer';    // Giu-Ago
  if (month >= 8 && month <= 10) return 'autumn';   // Set-Nov
  return 'winter';                                   // Dic-Feb
}

/** Determina la fascia oraria */
export function getTimeOfDay(hour = new Date().getHours()) {
  if (hour < 13) return 'morning';
  if (hour < 18) return 'afternoon';
  return 'evening';
}

/**
 * Ottiene il colore hero per stagione + ora.
 * Colore unico indipendente dal tema — niente gradienti, niente banding.
 */
export function getHeroGradient(_theme) {
  const season = getSeason();
  const timeOfDay = getTimeOfDay();
  const background = HERO_COLORS[season]?.[timeOfDay] || HERO_COLORS.winter.morning;

  return {
    background,
    season,
    timeOfDay,
  };
}

// ── Gradiente header modali ──────────────────────────────
export const MODAL_GRADIENTS = {
  primary: 'linear-gradient(135deg, rgba(212,169,64,0.08) 0%, rgba(212,169,64,0.02) 100%)',
  danger:  'linear-gradient(135deg, rgba(239,68,68,0.08) 0%, rgba(239,68,68,0.02) 100%)',
  warning: 'linear-gradient(135deg, rgba(245,158,11,0.08) 0%, rgba(245,158,11,0.02) 100%)',
};

// ── Toast styles (per sonner/react-hot-toast) ────────────
export const TOAST = {
  success: {
    color: SEMANTIC.success,
    border: `3px solid ${SEMANTIC.success}`,
  },
  error: {
    color: SEMANTIC.danger,
    border: `3px solid ${SEMANTIC.danger}`,
  },
  loading: {
    color: SEMANTIC.primary,
    border: `3px solid ${SEMANTIC.primary}`,
  },
};

// ── Event block (calendar day/week views) ────────────────
// ★ Background definiti in index.css (--ev-bg-*), classi: ev-bg-udienza, ecc.
// Queste costanti sono SOLO per chart/canvas che NON supportano CSS vars.
export const EVENT_BG = {
  udienza:   '#554A8C',
  scadenza:  '#8C2828',
  riunione:  '#285560',
  personale: '#185840',
  altro:     '#484E68',
};

/** Colore sfondo event block — SOLO per canvas/chart, nei componenti usare evBgClass() */
export const evBgColor = (cat) => EVENT_BG[cat] || EVENT_BG.altro;

export const EVENT_BLOCK = {
  textShadow: '0 1px 2px rgba(0,0,0,0.3)',
  textShadowStrong: '0 1px 2px rgba(0,0,0,0.4)',
};
