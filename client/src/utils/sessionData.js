// Sensitive UI state belongs to the unlocked session, never WebView storage.
// JavaScript cannot guarantee physical memory erasure; clearing drops references.
const values = new Map();
let generation = 0;

export const getSessionGeneration = () => generation;
export const readSessionData = (key, fallback) => values.has(key) ? values.get(key) : fallback;
export function writeSessionData(key, value, expectedGeneration) {
  if (expectedGeneration !== generation) return;
  if (value == null || value === '') values.delete(key);
  else values.set(key, value);
}

export function clearSessionData() {
  generation += 1;
  values.clear();
  // Remove plaintext remnants left by older versions, including after a crash.
  for (const [storageName, keys] of [
    ['localStorage', ['lexflow_notifications', 'lexflow_pdf_history']],
    ['sessionStorage', ['lexflow_pending_recovery', 'lexflow_active_timer', 'agenda_scroll_time']],
  ]) {
    for (const key of keys) {
      try { globalThis[storageName]?.removeItem(key); } catch { /* storage unavailable */ }
    }
  }
}
