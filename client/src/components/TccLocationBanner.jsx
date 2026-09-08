import { useState, useEffect } from 'react';
import { AlertCircle, X } from 'lucide-react';
import * as api from '../tauri-api';

const STORAGE_KEY = 'tcc-warning-dismissed';

/**
 * macOS TCC Location Warning Banner
 *
 * Shown when the app detects it's running from a non-standard location
 * (Downloads, mounted DMG, AppTranslocation sandbox).  TCC permissions
 * granted here may NOT persist when the app is moved to /Applications.
 *
 * The banner is dismissable — power users can ignore it.  The dismissed
 * state is stored in localStorage so it persists across reload/sessions.
 */
export default function TccLocationBanner() {
  const [warning, setWarning] = useState(null);
  const [dismissed, setDismissed] = useState(
    () => {
      try {
        return localStorage.getItem(STORAGE_KEY) === '1';
      } catch {
        return false;
      }
    }
  );

  useEffect(() => {
    if (dismissed) return;

    const unsub = api.onTccLocationWarning?.((payload) => {
      setWarning(payload);
    });

    return () => {
      if (typeof unsub === 'function') unsub();
    };
  }, [dismissed]);

  if (!warning || dismissed) return null;

  const handleDismiss = () => {
    setDismissed(true);
    try {
      localStorage.setItem(STORAGE_KEY, '1');
    } catch {
      /* storage unavailable — silent fail */
    }
  };

  return (
    <div
      role="status"
      aria-live="polite"
      className="flex items-center gap-3 px-4 py-2.5 text-sm
                 bg-warning-soft border-b border-warning-border
                 text-warning dark:text-warning select-none"
    >
      <AlertCircle className="w-4 h-4 shrink-0 text-warning" aria-hidden="true" />
      <span className="flex-1">
        <strong>Posizione non standard</strong> — Per mantenere i permessi di sistema
        (notifiche, accesso ai file), sposta LexFlow nella cartella <strong>Applicazioni</strong>.
      </span>
      <button
        onClick={handleDismiss}
        className="p-1 rounded hover:bg-warning-soft transition-colors min-h-11 min-w-11 flex items-center justify-center"
        aria-label="Chiudi avviso"
      >
        <X className="w-3.5 h-3.5" aria-hidden="true" />
      </button>
    </div>
  );
}
