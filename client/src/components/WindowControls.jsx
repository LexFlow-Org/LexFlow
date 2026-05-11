import { useState, useEffect } from 'react';
import { Minus, Square, Copy, X } from 'lucide-react';
import * as api from '../tauri-api';

const logWarn = (label, err) => {
  if (!import.meta.env.PROD) {
    console.warn(`[WindowControls] ${label}:`, err);
  }
};

export default function WindowControls() {
  const [isMac, setIsMac] = useState(true);
  const [isMaximized, setIsMaximized] = useState(false);

  useEffect(() => {
    // Usiamo ?. per evitare il crash se l'api non è ancora pronta
    api.isMac?.().then(setIsMac).catch((e) => {
      logWarn('isMac failed', e);
      setIsMac(true);
    });
  }, []);

  // Su Mac i controlli sono a sinistra e gestiti dal sistema (semaforo)
  if (isMac) return null;

  const handleMinimize = () => {
    api.windowMinimize().catch((e) => logWarn('minimize failed', e));
  };

  const handleMaximize = () => {
    api.windowMaximize()
      .then(() => setIsMaximized((v) => !v))
      .catch((e) => logWarn('maximize failed', e));
  };

  const handleClose = () => {
    api.windowClose().catch((e) => logWarn('close failed', e));
  };

  return (
    <div className="window-controls no-drag">
      <button
        className="wc-btn"
        onClick={handleMinimize}
        aria-label="Riduci a icona finestra"
      >
        <Minus size={15} />
      </button>
      <button
        className="wc-btn"
        onClick={handleMaximize}
        aria-label={isMaximized ? 'Ripristina dimensioni finestra' : 'Massimizza finestra'}
      >
        {isMaximized ? <Copy size={12} /> : <Square size={12} />}
      </button>
      <button
        className="wc-btn wc-close"
        onClick={handleClose}
        aria-label="Chiudi finestra"
      >
        <X size={15} />
      </button>
    </div>
  );
}
