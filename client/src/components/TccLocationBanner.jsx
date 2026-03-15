import { useState, useEffect } from 'react';
import { AlertCircle, X } from 'lucide-react';
import * as api from '../tauri-api';

/**
 * macOS TCC Location Warning Banner
 * 
 * Shown when the app detects it's running from a non-standard location
 * (Downloads, mounted DMG, AppTranslocation sandbox).  TCC permissions
 * granted here may NOT persist when the app is moved to /Applications.
 * 
 * The banner is dismissable — power users can ignore it.  The dismissed
 * state is stored in sessionStorage so it only appears once per session.
 */
export default function TccLocationBanner() {
  const [warning, setWarning] = useState(null);
  const [dismissed, setDismissed] = useState(
    () => sessionStorage.getItem('tcc-warning-dismissed') === '1'
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
    sessionStorage.setItem('tcc-warning-dismissed', '1');
  };

  return (
    <div className="flex items-center gap-3 px-4 py-2.5 text-sm
                    bg-warning-soft border-b border-warning-border
                    text-warning dark:text-warning select-none">
      <AlertCircle className="w-4 h-4 shrink-0 text-warning" />
      <span className="flex-1">
        <strong>Posizione non standard</strong> — Per mantenere i permessi di sistema
        (notifiche, accesso ai file), sposta LexFlow nella cartella <strong>Applicazioni</strong>.
      </span>
      <button
        onClick={handleDismiss}
        className="p-1 rounded hover:bg-warning-soft transition-colors"
        aria-label="Chiudi avviso"
      >
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}
