import PropTypes from 'prop-types';
import { AlertTriangle, X } from 'lucide-react';
import ModalOverlay from './ModalOverlay';

/**
 * Modale di conferma — sostituisce window.confirm()
 * Stile unificato: rounded-[32px], bg-[#0f1016], gradient header, footer bg-[#14151d]
 */
export default function ConfirmDialog({ open, title, message, confirmLabel = 'Conferma', cancelLabel = 'Annulla', onConfirm, onCancel }) {
  if (!open) return null;

  return (
    <ModalOverlay onClose={onCancel} labelledBy="confirm-dialog-title" zIndex={9999} focusTrap>
      <div className="bg-[#0f1016] border border-white/10 rounded-[32px] shadow-2xl w-full max-w-md mx-4 overflow-hidden">
        <div className="px-8 pt-8 pb-5" style={{ background: 'linear-gradient(135deg, rgba(212,169,64,0.08) 0%, rgba(212,169,64,0.02) 100%)' }}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-amber-500/10 rounded-2xl flex items-center justify-center border border-amber-500/20">
                <AlertTriangle size={22} className="text-amber-400" />
              </div>
              <div>
                <h3 id="confirm-dialog-title" className="text-xl font-bold text-white">{title}</h3>
              </div>
            </div>
            <button onClick={onCancel} className="p-2 hover:bg-white/10 rounded-xl text-text-dim transition-all group">
              <X size={20} className="group-hover:rotate-90 transition-transform" />
            </button>
          </div>
        </div>
        <div className="px-8 py-6">
          <p className="text-text-muted text-sm leading-relaxed">{message}</p>
        </div>
        <div className="flex justify-end gap-3 px-8 py-5 bg-[#14151d] border-t border-white/5">
          <button onClick={onCancel} className="px-6 py-3 rounded-2xl text-text-dim hover:text-white hover:bg-white/5 transition-all text-xs font-bold uppercase tracking-widest">
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
