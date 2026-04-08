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

// SECURITY: Pre-hash passwords in the frontend before sending over IPC.
// This ensures the plaintext password never crosses the Tauri bridge —
// only the SHA-256 hash is sent. The backend uses this hash as input to
// Argon2id (which accepts any byte string). This mitigates the serde
// deserialization copy issue where plaintext lingers in heap memory.
async function hashPwd(pwd) {
  const encoder = new TextEncoder();
  const data = encoder.encode(pwd);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  // Clear the original encoded data (best-effort in JS)
  data.fill(0);
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Vault / Auth
export const vaultExists = () => safeInvoke('vault_exists');
export const unlockVault = async (pwd) => safeInvoke('unlock_vault', { password: await hashPwd(pwd) });
export const lockVault = () => safeInvoke('lock_vault');
export const resetVault = async (password) => safeInvoke('reset_vault', { password: await hashPwd(password) });
export const exportVault = async (pwd) => safeInvoke('export_vault', { pwd: await hashPwd(pwd) });
export const importVault = async (pwd) => safeInvoke('import_vault', { pwd: await hashPwd(pwd) });
export const changePassword = async (currentPassword, newPassword) =>
  safeInvoke('change_password', { currentPassword: await hashPwd(currentPassword), newPassword: await hashPwd(newPassword) });
export const verifyVaultPassword = async (pwd) => safeInvoke('verify_vault_password', { pwd: await hashPwd(pwd) });

// Biometrics — saveBio stores the HASHED password in keychain
export const checkBio = () => safeInvoke('check_bio');
export const hasBioSaved = () => safeInvoke('has_bio_saved');
export const saveBio = async (pwd) => safeInvoke('save_bio', { pwd: await hashPwd(pwd) });
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
export const warmSwift = () => safeInvoke('warm_swift');

// Vault Health (v4)
export const getVaultHealth = () => safeInvoke('get_vault_health');

// PERF: Index-only reads (v4) — instant list rendering without decrypting records
export const getVaultIndex = () => safeInvoke('get_vault_index');
export const loadRecordDetail = (recordId) => safeInvoke('load_record_detail', { recordId });
export const loadRecordHistory = (recordId) => safeInvoke('load_record_history', { recordId });

// Full-text search (v4 — trigram fuzzy + BM25 ranking)
export const searchVault = (query, limit = 50) => safeInvoke('search_vault', { query, limit });
export const rebuildSearchIndex = () => safeInvoke('rebuild_search_index');

// Audit log
export const getAuditLog = () => safeInvoke('get_audit_log');

// Backup
export const triggerBackup = () => safeInvoke('trigger_backup');
export const getBackupList = () => safeInvoke('get_backup_list');

// CSV Export
export const exportTimeLogsCsv = () => safeInvoke('export_time_logs_csv');
export const exportInvoicesCsv = () => safeInvoke('export_invoices_csv');

// Data
export const loadPractices = () => safeInvoke('load_practices');
export const savePractices = (list) => safeInvoke('save_practices', { list });
export const loadAgenda = () => safeInvoke('load_agenda');
export const saveAgenda = (agenda) => safeInvoke('save_agenda', { agenda });
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
export const selectFiles = async (extensions) => (await safeInvoke('select_files', { extensions })) || [];
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

// Typst PDF generation — sends practice data to Rust, Typst sidecar compiles to PDF
export const generateTypstPdf = async (practiceData) => {
  const pdfBytes = await safeInvoke('generate_typst_pdf', { data: practiceData });
  if (!pdfBytes || pdfBytes.length === 0) {
    throw new Error('Typst ha generato un PDF vuoto');
  }
  return new Uint8Array(pdfBytes);
};

// Full Typst export pipeline: generate + save dialog
export const exportTypstPdf = async (practiceData, defaultName) => {
  const pdfBytes = await generateTypstPdf(practiceData);
  const savePath = await safeInvoke('select_pdf_save_path', { defaultName });
  if (savePath) {
    const data = Array.from(pdfBytes);
    await safeInvoke('write_pdf_to_path', { path: savePath, data });
    return { success: true, path: savePath };
  }
  return { success: false, cancelled: true };
};

// Notifications
export const syncNotificationSchedule = (schedule) =>
  safeInvoke('sync_notification_schedule', { schedule });

// Licensing
export const checkLicense = () => safeInvoke('check_license');
export const activateLicense = (key) => safeInvoke('activate_license', { key });

// Save dialog (generic)
export const selectSavePath = (defaultName) => safeInvoke('select_pdf_save_path', { defaultName });

// Document Tools
export const pdfInfo = (path) => safeInvoke('pdf_info', { path });
export const mergePdfs = (inputPaths, outputPath) => safeInvoke('merge_pdfs', { inputPaths, outputPath });
export const splitPdf = (inputPath, outputDir) => safeInvoke('split_pdf', { inputPath, outputDir });
export const removePages = (inputPath, outputPath, pagesToRemove) => safeInvoke('remove_pages', { inputPath, outputPath, pagesToRemove });
export const extractPages = (inputPath, outputPath, pagesToExtract) => safeInvoke('extract_pages', { inputPath, outputPath, pagesToExtract });
export const compressPdf = (inputPath, outputPath) => safeInvoke('compress_pdf', { inputPath, outputPath });
export const addWatermark = (inputPath, outputPath, text, opacity, fontSize) => safeInvoke('add_watermark', { inputPath, outputPath, text, opacity, fontSize });
export const rotatePdf = (inputPath, outputPath, rotation, pagesToRotate) => safeInvoke('rotate_pdf', { inputPath, outputPath, rotation, pagesToRotate });
export const pdfToText = (inputPath) => safeInvoke('pdf_to_text', { inputPath });
export const imagesToPdf = (imagePaths, outputPath) => safeInvoke('images_to_pdf', { imagePaths, outputPath });
export const reorderPages = (inputPath, outputPath, newOrder) => safeInvoke('reorder_pages', { inputPath, outputPath, newOrder });
export const addPageNumbers = (inputPath, outputPath, position, formatStr, startFrom, fontSize) => safeInvoke('add_page_numbers', { inputPath, outputPath, position, formatStr, startFrom, fontSize });
export const redactPdf = (inputPath, outputPath, redactions) => safeInvoke('redact_pdf', { inputPath, outputPath, redactions });

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

// Recovery key
export const generateRecoveryKey = () => safeInvoke('generate_recovery_key');
export const unlockWithRecovery = (recoveryKey) => safeInvoke('unlock_with_recovery', { recoveryKey });

// SECURITY: Clipboard with auto-clear after 30 seconds
let clipboardTimer = null;
export const secureCopy = (text) => {
  navigator.clipboard.writeText(text).catch(() => {});
  if (clipboardTimer) clearTimeout(clipboardTimer);
  clipboardTimer = setTimeout(() => {
    navigator.clipboard.writeText('').catch(() => {});
    clipboardTimer = null;
  }, 30000); // 30 seconds
  return true;
};

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

// macOS TCC location warning: fired when the app is running from a non-standard
// path (Downloads, DMG, AppTranslocation).  The frontend shows a dismissable
// banner guiding the user to move the app to /Applications.
export const onTccLocationWarning = (cb) => {
  const p = listen('lf-tcc-location-warning', (e) => cb(e.payload)).catch(() => null);
  return () => { p.then(fn => fn?.()); };
};

// GOD TIER: Actionable notification callback.
// Fired when the backend sends a notification with action buttons (Windows) or
// when the cron job fires a reminder. The frontend can show in-app action UI.
export const onNotificationAction = (cb) => {
  const p = listen('notification-action', (e) => cb(e.payload)).catch(() => null);
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
