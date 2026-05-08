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
 * Convert a Date (or date-string) to YYYY-MM-DD using LOCAL time.
 *
 * Bug-fix: `Date#toISOString()` returns UTC, which silently shifts the date
 * by 1 day for users east of GMT in evening hours and west of GMT in morning
 * hours. Italian users in CET/CEST were seeing "tomorrow" entries leak into
 * "today" near midnight. Always derive YMD from local fields.
 *
 * @param {Date|string|number} d
 * @returns {string} YYYY-MM-DD
 */
export function toDateStr(d) {
  const date = d instanceof Date ? d : new Date(d);
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

/**
 * Parse a YYYY-MM-DD string as a LOCAL midnight Date.
 *
 * Bug-fix: `new Date("YYYY-MM-DD")` is parsed as UTC midnight, which becomes
 * the previous day in local time for negative-offset zones (and shifts hour
 * fields elsewhere). Use this whenever you compare dates for "today / past /
 * future" semantics.
 *
 * @param {string} ymd "YYYY-MM-DD"
 * @returns {Date} local-midnight Date, or Invalid Date if malformed
 */
export function parseLocalYMD(ymd) {
  if (typeof ymd !== 'string') return new Date(NaN);
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(ymd);
  if (!m) return new Date(NaN);
  const y = Number(m[1]);
  const mo = Number(m[2]);
  const d = Number(m[3]);
  return new Date(y, mo - 1, d);
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

/**
 * Map agenda events to notification-schedule items.
 * Filters out completed / no-time events and coerces remindMinutes.
 * @param {Array} events
 * @param {number} defaultPreavviso
 * @returns {Array<{id,date,time,title,remindMinutes,customRemindTime}>}
 */
export function mapAgendaToScheduleItems(events, defaultPreavviso = 30) {
  return (events || [])
    .filter(e => !e.completed && e.timeStart)
    .map(e => ({
      id: e.id,
      date: e.date,
      time: e.timeStart,
      title: e.title,
      category: e.category || '',
      remindMinutes: (() => {
        if (typeof e.remindMinutes === 'number') return e.remindMinutes;
        if (e.remindMinutes === 'custom') return 0;
        return Number.parseInt(e.remindMinutes, 10) || defaultPreavviso;
      })(),
      customRemindTime: e.customRemindTime || null,
    }));
}
