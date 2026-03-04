import PropTypes from 'prop-types';
import { ShieldAlert, X } from 'lucide-react';
import ModalOverlay from './ModalOverlay';

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
  if (!isOpen) return null;

  return (
    <ModalOverlay onClose={onClose} labelledBy="export-warning-title" zIndex={9999} focusTrap role="alertdialog">
      <div className="w-full max-w-lg bg-[#0f1016] border border-white/10 rounded-[32px] shadow-2xl overflow-hidden">

        {/* Header */}
        <div className="px-8 pt-8 pb-5" style={{ background: 'linear-gradient(135deg, rgba(245,158,11,0.08) 0%, rgba(245,158,11,0.02) 100%)' }}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-amber-500/10 rounded-2xl flex items-center justify-center border border-amber-500/20">
                <ShieldAlert size={22} className="text-amber-400" />
              </div>
              <div>
                <h2 id="export-warning-title" className="text-xl font-bold text-white">Avviso di Sicurezza</h2>
                <p className="text-xs text-text-dim mt-0.5">Esportazione Documento — Leggere prima di procedere</p>
              </div>
            </div>
            <button onClick={onClose} className="p-2 hover:bg-white/10 rounded-xl text-text-dim transition-all group">
              <X size={20} className="group-hover:rotate-90 transition-transform" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="px-8 py-6 space-y-3 text-sm text-text-muted leading-relaxed">
          <p>
            Il documento PDF che stai per generare verrà salvato <span className="text-white font-medium">in chiaro</span> sul disco.
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
        </div>

        {/* Actions */}
        <div className="flex justify-end gap-3 px-8 py-5 bg-[#14151d] border-t border-white/5">
          <button onClick={onClose} className="px-6 py-3 rounded-2xl text-text-dim hover:text-white hover:bg-white/5 transition-all text-xs font-bold uppercase tracking-widest">
            Annulla
          </button>
          <button onClick={onConfirm} className="btn-primary px-6 py-3 text-xs font-bold uppercase tracking-widest">
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
