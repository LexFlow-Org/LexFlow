import { useEffect, useRef, useState } from 'react';
import PropTypes from 'prop-types';
import { ShieldAlert, X } from 'lucide-react';
import ModalOverlay from './ModalOverlay';

const SUPPRESS_KEY = 'lexflow_export_warning_suppressed';

/**
 * ExportWarningModal
 *
 * Shown before any PDF export to inform the user that the generated file
 * will be stored unencrypted on disk and may be indexed by the OS.
 * Satisfies the legal/professional duty-of-care requirement to document
 * that the user was warned before unencrypted data left the vault.
 *
 * Props:
 *   isOpen    – boolean: controls visibility
 *   onClose   – fn(): called when the user cancels
 *   onConfirm – fn(): called when the user confirms and export should proceed
 */
export default function ExportWarningModal({ isOpen, onClose, onConfirm }) {
  const cancelRef = useRef(null);
  const [dontShowAgain, setDontShowAgain] = useState(false);

  useEffect(() => {
    if (!isOpen) return;
    setDontShowAgain(false);
    const id = setTimeout(() => cancelRef.current?.focus(), 0);
    return () => clearTimeout(id);
  }, [isOpen]);

  if (!isOpen) return null;

  const handleConfirm = () => {
    if (dontShowAgain) {
      try {
        localStorage.setItem(SUPPRESS_KEY, '1');
      } catch {
        /* storage unavailable — ignore */
      }
    }
    onConfirm?.();
  };

  return (
    <ModalOverlay onClose={onClose} labelledBy="export-warning-title" zIndex={9999} focusTrap role="alertdialog">
      <div className="modal-card modal-card-md">

        {/* Header */}
        <div className="modal-header-gradient modal-header-gradient-warning">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-warning-soft rounded-2xl flex items-center justify-center border border-warning-border">
                <ShieldAlert size={22} className="text-warning" aria-hidden="true" />
              </div>
              <div>
                <h2 id="export-warning-title" className="text-xl font-bold text-text">Avviso di Sicurezza</h2>
                <p className="text-xs text-text-dim mt-0.5">Esportazione Documento — Leggere prima di procedere</p>
              </div>
            </div>
            <button onClick={onClose} className="p-2 hover:bg-card-hover rounded-xl text-text-dim transition-colors group" aria-label="Chiudi">
              <X size={20} className="group-hover:rotate-90 transition-transform" aria-hidden="true" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="px-8 py-6 space-y-3 text-sm text-text-muted leading-relaxed">
          <p>
            Il documento PDF che stai per generare verrà salvato <span className="text-text font-medium">in chiaro</span> sul disco.
            Una volta esportato, il file non sarà più protetto dalla crittografia isolata di LexFlow.
          </p>
          <p>
            Al fine di preservare il segreto professionale e la conformità normativa, si raccomanda di salvare
            il documento esclusivamente su volumi protetti da crittografia di sistema
            (<span className="text-text-dim font-medium">Windows BitLocker</span> o{' '}
            <span className="text-text-dim font-medium">macOS FileVault</span>).
          </p>
          <p>
            Evitare il salvataggio su cartelle cloud sincronizzate non sicure, desktop condivisi o
            dispositivi di archiviazione rimovibili non cifrati.
          </p>

          <label className="flex items-center gap-2 pt-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={dontShowAgain}
              onChange={(e) => setDontShowAgain(e.target.checked)}
              className="w-4 h-4 accent-[var(--primary)]"
            />
            <span className="text-xs text-text-dim">Non mostrare più questo avviso</span>
          </label>
        </div>

        {/* Actions */}
        <div className="modal-footer">
          <button ref={cancelRef} onClick={onClose} className="btn-cancel">
            Annulla
          </button>
          <button onClick={handleConfirm} className="btn-primary px-6 py-3 text-xs font-bold uppercase tracking-widest">
            Comprendo — Procedi
          </button>
        </div>
      </div>
    </ModalOverlay>
  );
}

ExportWarningModal.propTypes = {
  isOpen: PropTypes.bool,
  onClose: PropTypes.func,
  onConfirm: PropTypes.func,
};

// Helper interni: permettono di saltare la dialog se l'utente ha cliccato
// "Non mostrare più". (Esportati come default-only per fast-refresh.)
// eslint-disable-next-line react-refresh/only-export-components
export function isExportWarningSuppressed() {
  try {
    return localStorage.getItem(SUPPRESS_KEY) === '1';
  } catch {
    return false;
  }
}

// eslint-disable-next-line react-refresh/only-export-components
export function resetExportWarningSuppression() {
  try {
    localStorage.removeItem(SUPPRESS_KEY);
  } catch {
    /* ignore */
  }
}
