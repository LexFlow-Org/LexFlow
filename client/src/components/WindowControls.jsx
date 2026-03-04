import { useState, useEffect } from 'react';
import { Minus, Square, X } from 'lucide-react';
import * as api from '../tauri-api';

export default function WindowControls() {
  const [isMac, setIsMac] = useState(true);

  useEffect(() => {
    // Usiamo ?. per evitare il crash se l'api non è ancora pronta
    api.isMac?.().then(setIsMac).catch(() => setIsMac(true));
  }, []);

  // Su Mac i controlli sono a sinistra e gestiti dal sistema (semaforo)
  if (isMac) return null;

  return (
    <div className="window-controls no-drag">
      <button className="wc-btn" onClick={() => api.windowMinimize().catch(() => {})}>
        <Minus size={15} />
      </button>
      <button className="wc-btn" onClick={() => api.windowMaximize().catch(() => {})}>
        <Square size={12} />
      </button>
      <button className="wc-btn wc-close" onClick={() => api.windowClose().catch(() => {})}>
        <X size={15} />
      </button>
    </div>
  );
}