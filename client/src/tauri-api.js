/* LexFlow — Tauri API Bridge v3.6.0 (ESM) */
// SECURITY: Pure ES module — no window.api global.
// withGlobalTauri=false + CSP script-src 'self' = XSS cannot access invoke().
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { isPermissionGranted as notifPermGranted } from '@tauri-apps/plugin-notification';

function safeInvoke(cmd, args = {}) {
  return invoke(cmd, args).catch(err => {
    if (import.meta.env.PROD) {
      console.warn(`[LexFlow] Command failed: ${cmd}`);
    } else {
      console.error(`[LexFlow] ${cmd} failed:`, err);
    }
    // SECURITY FIX (Gemini Audit Chunk 01): always throw an Error instance
    // so frontend toast/catch handlers never show "[object Object]"
    if (err instanceof Error) throw err;
    const message = typeof err === 'string' ? err : (err?.message || JSON.stringify(err));
    const error = new Error(message);
    error.raw = err;
    throw error;
  });
}

// Vault / Auth
export const vaultExists = () => safeInvoke('vault_exists');
export const unlockVault = (pwd) => safeInvoke('unlock_vault', { password: pwd });
export const lockVault = () => safeInvoke('lock_vault');
export const resetVault = (password) => safeInvoke('reset_vault', { password });
export const exportVault = (pwd) => safeInvoke('export_vault', { pwd });
export const importVault = (pwd) => safeInvoke('import_vault', { pwd });
export const changePassword = (currentPassword, newPassword) =>
  safeInvoke('change_password', { currentPassword, newPassword });
export const verifyVaultPassword = (pwd) => safeInvoke('verify_vault_password', { pwd });
export const getAuditLog = () => safeInvoke('get_audit_log');

// Biometrics
export const checkBio = () => safeInvoke('check_bio');
export const hasBioSaved = () => safeInvoke('has_bio_saved');
export const saveBio = (pwd) => safeInvoke('save_bio', { pwd });
export const clearBio = () => safeInvoke('clear_bio');
// SECURITY FIX (Gemini Audit Chunk 01): wrap in try/catch so callers
// get null on bio failure instead of an unhandled throw from safeInvoke
// FOCUS GUARD: never trigger system biometric prompt when LexFlow window
// doesn't have focus — prevents Touch ID appearing over other apps
export const bioLogin = async () => {
  // If the window is not focused, skip biometric entirely
  if (!document.hasFocus()) {
    console.debug('[LexFlow] bioLogin skipped — window not focused');
    return null;
  }
  try {
    const res = await safeInvoke('bio_login');
    return (res?.success) ? { success: true } : null;
  } catch {
    return null;
  }
};
export const loginBio = bioLogin;

// Files / Folders
export const listFolderContents = (path) => safeInvoke('list_folder_contents', { path });
export const warmSwift = () => safeInvoke('warm_swift');

// Data
export const loadPractices = () => safeInvoke('load_practices');
export const savePractices = (list) => safeInvoke('save_practices', { list });
export const loadAgenda = () => safeInvoke('load_agenda');
export const saveAgenda = (agenda) => safeInvoke('save_agenda', { agenda });
export const getSummary = () => safeInvoke('get_summary');

// Conflict Check
export const checkConflict = (name) => safeInvoke('check_conflict', { name });

// Time Tracking
export const loadTimeLogs = () => safeInvoke('load_time_logs');
export const saveTimeLogs = (logs) => safeInvoke('save_time_logs', { logs });

// Invoices / Billing
export const loadInvoices = () => safeInvoke('load_invoices');
export const saveInvoices = (invoices) => safeInvoke('save_invoices', { invoices });

// Contacts Registry
export const loadContacts = () => safeInvoke('load_contacts');
export const saveContacts = (contacts) => safeInvoke('save_contacts', { contacts });

// Settings
export const getSettings = () => safeInvoke('get_settings');
export const saveSettings = (settings) => safeInvoke('save_settings', { settings });

// Files
export const selectFile = async () => (await safeInvoke('select_file')) || null;
export const selectFolder = async () => (await safeInvoke('select_folder')) || null;
export const openPath = (path) => safeInvoke('open_path', { path });

// PDF export — uses Rust command to bypass FS plugin scope (restricted to $APPDATA)
export const exportPDF = async (arrayBuffer, defaultName) => {
  // SECURITY FIX (Gemini Audit Chunk 01): validate buffer before writing
  if (!arrayBuffer || arrayBuffer.byteLength === 0) {
    throw new Error('Cannot export an empty PDF');
  }
  const savePath = await safeInvoke('select_pdf_save_path', { defaultName });
  if (savePath) {
    // Convert ArrayBuffer to plain Array<u8> for Tauri command serialization
    const data = Array.from(new Uint8Array(arrayBuffer));
    await safeInvoke('write_pdf_to_path', { path: savePath, data });
    return { success: true, path: savePath };
  }
  return { success: false, cancelled: true };
};

// Notifications
export const sendNotification = ({ title, body }) =>
  safeInvoke('send_notification', { title, body });
export const syncNotificationSchedule = (schedule) =>
  safeInvoke('sync_notification_schedule', { schedule });
export const testNotification = () => safeInvoke('test_notification');

// Licensing
export const checkLicense = () => safeInvoke('check_license');
// SECURITY FIX (Audit 2026-03-11 I3): verifyLicense now accepts a token string parameter.
// The Rust command verify_license(key_string: String) requires a token.
// Previously this bridge passed no arguments, making it unusable.
export const verifyLicense = (keyString) => safeInvoke('verify_license', { keyString });
export const activateLicense = (key) => safeInvoke('activate_license', { key });
export const getMachineFingerprint = () => safeInvoke('get_machine_fingerprint');

// Platform / App
export const isMac = () => safeInvoke('is_mac');
export const getAppVersion = () => safeInvoke('get_app_version');
export const getPlatform = () => safeInvoke('get_platform');

// Window controls
export const windowMinimize = () => safeInvoke('window_minimize');
export const windowMaximize = () => safeInvoke('window_maximize');
export const windowClose = () => safeInvoke('window_close');
export const showMainWindow = () => safeInvoke('show_main_window');

// Security & Content Protection
export const setContentProtection = (enabled) =>
  safeInvoke('set_content_protection', { enabled });
export const pingActivity = () => safeInvoke('ping_activity');
export const setAutolockMinutes = (minutes) =>
  safeInvoke('set_autolock_minutes', { minutes });
export const getAutolockMinutes = () => safeInvoke('get_autolock_minutes');

// Listeners (return unsubscribe fn)
export const onBlur = (cb) => {
  const p = listen('lf-blur', e => cb(e.payload === true || e.payload === undefined)).catch(() => null);
  return () => { p.then(fn => fn?.()); };
};
export const onLock = (cb) => {
  const p = listen('lf-lock', () => cb()).catch(() => null);
  return () => { p.then(fn => fn?.()); };
};
export const onVaultLocked = (cb) => {
  const p = listen('lf-vault-locked', () => cb()).catch(() => null);
  return () => { p.then(fn => fn?.()); };
};
export const onVaultWarning = (cb) => {
  const p = listen('lf-vault-warning', () => cb()).catch(() => null);
  return () => { p.then(fn => fn?.()); };
};
// SECURITY FIX (Audit 2026-03-04): listen for backend settings-corrupted event.
// Fired when get_settings() detects a corrupted settings file and falls back to {}.
// payload: { backup_path: string, timestamp: string }
export const onSettingsCorrupted = (cb) => {
  const p = listen('settings-corrupted', (e) => cb(e.payload)).catch(() => null);
  return () => { p.then(fn => fn?.()); };
};

// SECURITY FIX (Audit 2026-03-11): listen for notification-permission-denied event.
// Fired by setup_notification_permissions when the OS has denied notification permission.
// The frontend can use this to show an in-app banner guiding the user to System Settings.
export const onNotificationPermissionDenied = (cb) => {
  const p = listen('notification-permission-denied', () => cb()).catch(() => null);
  return () => { p.then(fn => fn?.()); };
};

// Notification fallback listener (top-level await — Vite ESM)
try {
  await listen('show-notification', async (event) => {
    try {
      try {
        const granted = await notifPermGranted();
        if (granted) return;
      } catch { console.debug('[tauri-api] Not in Tauri runtime'); }
      if (globalThis.Notification) {
        if (Notification.permission === 'granted') {
          new Notification(event.payload.title, { body: event.payload.body });
        } else if (Notification.permission !== 'denied') {
          const p = await Notification.requestPermission();
          if (p === 'granted') new Notification(event.payload.title, { body: event.payload.body });
        }
      }
    } catch { console.warn('Notification fallback error'); }
  });
} catch { /* listen unavailable outside Tauri */ }
