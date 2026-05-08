import { useEffect, useRef } from 'react';
import PropTypes from 'prop-types';
import { AlertTriangle, X } from 'lucide-react';
import ModalOverlay from './ModalOverlay';
/**
 * Modale di conferma — sostituisce window.confirm()
 * Stile unificato: rounded-[32px], bg-card, gradient header, footer bg-surface
 *
 * Default focus: Cancel (più sicuro per conferme distruttive).
 */
export default function ConfirmDialog({ open, title, message, confirmLabel = 'Conferma', cancelLabel = 'Annulla', onConfirm, onCancel }) {
  const cancelRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    // Auto-focus Cancel after the dialog mounts (small delay so ModalOverlay's
    // own dialog focus has already run).
    const id = setTimeout(() => cancelRef.current?.focus(), 0);
    return () => clearTimeout(id);
  }, [open]);

  if (!open) return null;

  return (
    <ModalOverlay onClose={onCancel} labelledBy="confirm-dialog-title" zIndex={9999} focusTrap role="alertdialog">
      <div className="modal-card modal-card-sm mx-4">
        <div className="modal-header-gradient modal-header-gradient-primary">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-warning-soft rounded-2xl flex items-center justify-center border border-warning-border">
                <AlertTriangle size={22} className="text-warning" aria-hidden="true" />
              </div>
              <div>
                <h3 id="confirm-dialog-title" className="text-xl font-bold text-text">{title}</h3>
              </div>
            </div>
            <button onClick={onCancel} className="p-2 hover:bg-card-hover rounded-xl text-text-dim transition-colors group" aria-label="Chiudi">
              <X size={20} className="group-hover:rotate-90 transition-transform" aria-hidden="true" />
            </button>
          </div>
        </div>
        <div className="px-8 py-6">
          <p className="text-text-muted text-sm leading-relaxed">{message}</p>
        </div>
        <div className="modal-footer">
          <button ref={cancelRef} onClick={onCancel} className="btn-cancel">
            {cancelLabel}
          </button>
          <button onClick={onConfirm} className="btn-primary px-6 py-3 text-xs font-bold uppercase tracking-widest">
            {confirmLabel}
          </button>
        </div>
      </div>
    </ModalOverlay>
  );
}

ConfirmDialog.propTypes = {
  open: PropTypes.bool,
  title: PropTypes.string,
  message: PropTypes.string,
  confirmLabel: PropTypes.string,
  cancelLabel: PropTypes.string,
  onConfirm: PropTypes.func,
  onCancel: PropTypes.func,
};
