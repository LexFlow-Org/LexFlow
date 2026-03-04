/**
 * Shared utility helpers — consolidated from duplicated functions across the codebase.
 */

/**
 * Generate a unique ID with optional prefix.
 * Uses crypto.getRandomValues for collision-resistant IDs.
 */
export function genId(prefix = '') {
  const a = new Uint8Array(4);
  crypto.getRandomValues(a);
  return prefix + Date.now().toString(36) + Array.from(a, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert a Date to YYYY-MM-DD string.
 */
export function toDateStr(d) {
  return d.toISOString().split('T')[0];
}

/**
 * Safe Italian date formatter — returns fallback on invalid / missing dates.
 * @param {string|null|undefined} dateStr
 * @param {string} [fallback='—']
 * @returns {string}
 */
export function formatDateIT(dateStr, fallback = '—') {
  if (!dateStr) return fallback;
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return fallback;
  return d.toLocaleDateString('it-IT', { day: '2-digit', month: 'short', year: 'numeric' });
}
