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
      remindMinutes: (() => {
        if (typeof e.remindMinutes === 'number') return e.remindMinutes;
        if (e.remindMinutes === 'custom') return 0;
        return Number.parseInt(e.remindMinutes, 10) || defaultPreavviso;
      })(),
      customRemindTime: e.customRemindTime || null,
    }));
}
