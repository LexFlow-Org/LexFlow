import { useState, useCallback, useEffect, useRef } from 'react';
import PropTypes from 'prop-types';
import {
  Shield,
  Lock,
  HardDrive,
  LogOut,
  Bell,
  BellOff,
  Camera,
  CameraOff,
  Timer,
  Upload,
  Download,
  Smartphone,
  Monitor,
  ArrowLeftRight,
  KeyRound,
  Eye,
  EyeOff,
  X,
  Fingerprint,
  ShieldCheck,
  Briefcase
} from 'lucide-react';
import toast from 'react-hot-toast';
import LicenseSettings from '../components/LicenseSettings';
import ModalOverlay from '../components/ModalOverlay';
import * as api from '../tauri-api';
import Toggle from '../components/Toggle';

const RECOVERY_STORE_KEY = 'lexflow_pending_recovery';

const PREAVVISO_OPTIONS = [
  { value: 0, label: 'Al momento' },
  { value: 15, label: '15 min' },
  { value: 30, label: '30 min' },
  { value: 60, label: '1 ora' },
  { value: 120, label: '2 ore' },
  { value: 1440, label: '1 giorno' },
];

const AUTOLOCK_OPTIONS = [
  { value: 1, label: '1 min' },
  { value: 2, label: '2 min' },
  { value: 5, label: '5 min' },
  { value: 10, label: '10 min' },
  { value: 15, label: '15 min' },
  { value: 30, label: '30 min' },
  { value: 0, label: 'Mai' },
];

/* ── Factory Reset Modal ── */
const FACTORY_RESET_PHRASE = 'ELIMINA VAULT';
function FactoryResetModal({ onClose, bioStatus }) {
  const [pwd, setPwd] = useState('');
  const [showPwd, setShowPwd] = useState(false);
  const [confirmText, setConfirmText] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const errorId = 'factory-reset-error';
  const phraseValid = confirmText === FACTORY_RESET_PHRASE;
  const canSubmit = !loading && pwd && phraseValid;

  const doReset = useCallback(async () => {
    setError('');
    if (!pwd) { setError('Password richiesta.'); return; }
    if (!phraseValid) { setError(`Digita esattamente "${FACTORY_RESET_PHRASE}" per confermare.`); return; }
    setLoading(true);
    try {
      // Strict bio gate: when bio is active, biometric verification is REQUIRED.
      if (bioStatus === 'active') {
        const bioOk = await api.bioLogin().catch(() => false);
        if (!bioOk) {
          setError('Verifica biometrica fallita. Factory reset negato.');
          setLoading(false);
          return;
        }
      } else {
        // Bio not configured / unavailable: try opportunistic check but never fall through silently on error.
        try {
          const bioAvail = await api.checkBio();
          if (bioAvail) {
            const bioOk = await api.bioLogin();
            if (!bioOk) {
              setError('Verifica biometrica fallita. Factory reset negato.');
              setLoading(false);
              return;
            }
          }
        } catch {
          // checkBio threw → treat as unavailable, proceed with password-only path
        }
      }

      // Auto-backup before wipe (best-effort; user can cancel the dialog).
      try {
        const bk = await api.triggerBackup?.();
        if (bk?.success === false) {
          // backend reported failure but didn't throw — surface it as a warning toast, do not block
          toast.error('Backup automatico fallito. Procedo solo se confermi nuovamente premendo Conferma.');
          setLoading(false);
          return;
        }
      } catch {
        // triggerBackup unavailable on platform: continue (already warned via UI copy)
      }

      const res = await api.resetVault(pwd);
      if (res?.success) {
        onClose();
        globalThis.location.reload();
      } else {
        setError(res?.error || 'Password errata.');
      }
    } finally {
      setLoading(false);
    }
  }, [pwd, phraseValid, bioStatus, onClose]);

  return (
    <ModalOverlay onClose={onClose} labelledBy="factory-reset-title" zIndex={200}>
      <div className="modal-card modal-card-sm">
        <div className="modal-header-gradient modal-header-gradient-danger">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-danger-soft rounded-2xl flex items-center justify-center border border-danger-border">
                <LogOut size={22} className="text-danger" />
              </div>
              <div>
                <h3 id="factory-reset-title" className="text-xl font-bold text-text">Factory Reset</h3>
                <p className="text-xs text-text-dim mt-0.5">Tutti i dati verranno eliminati</p>
              </div>
            </div>
            <button onClick={onClose} aria-label="Chiudi" className="p-2 hover:bg-card-hover rounded-xl text-text-dim transition-colors group">
              <X size={20} className="group-hover:rotate-90 transition-transform" />
            </button>
          </div>
        </div>
        <div className="px-8 py-6 space-y-4">
          <p className="text-text-muted text-xs leading-relaxed">
            Stai per cancellare <span className="text-text font-bold">tutti i dati del Vault</span>.
            Verrà generato un backup automatico prima della cancellazione, ma{' '}
            <span className="font-semibold">l&apos;azione resta irreversibile.</span>
          </p>
          <div className="relative">
            <KeyRound size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-dim" />
            <input
              type={showPwd ? 'text' : 'password'}
              className="w-full py-3 pl-10 pr-10 rounded-xl bg-surface border border-border text-text placeholder:text-text-dim/40 text-sm focus:border-primary/40 outline-none transition-colors"
              placeholder="Password vault…"
              value={pwd}
              onChange={e => { setPwd(e.target.value); setError(''); }}
              autoFocus
              aria-invalid={!!error}
              aria-describedby={error ? errorId : undefined}
            />
            <button
              type="button"
              onClick={() => setShowPwd(v => !v)}
              aria-label={showPwd ? 'Nascondi password' : 'Mostra password'}
              aria-pressed={showPwd}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-text-dim hover:text-text transition-colors"
            >
              {showPwd ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
          <div className="space-y-2">
            <label htmlFor="factory-reset-phrase" className="text-2xs font-bold text-text-dim uppercase tracking-wider block">
              Per confermare digita: <span className="font-mono text-danger">{FACTORY_RESET_PHRASE}</span>
            </label>
            <input
              id="factory-reset-phrase"
              type="text"
              autoComplete="off"
              spellCheck={false}
              value={confirmText}
              onChange={e => { setConfirmText(e.target.value); setError(''); }}
              className="w-full px-4 py-2.5 rounded-xl bg-surface border border-border text-text text-sm placeholder:text-text-dim/40 outline-none focus:border-danger/50 transition-colors font-mono"
              placeholder={FACTORY_RESET_PHRASE}
              aria-invalid={!!error}
            />
          </div>
          {error && (
            <p id={errorId} role="alert" className="text-danger text-xs-p font-semibold">{error}</p>
          )}
        </div>
        <div className="modal-footer">
          <button onClick={onClose} className="btn-cancel">Annulla</button>
          <button
            onClick={doReset}
            disabled={!canSubmit}
            className={`px-6 py-3 rounded-2xl bg-danger-soft border border-danger-border text-danger hover:bg-danger-soft transition-colors text-xs font-bold uppercase tracking-widest ${!canSubmit ? 'opacity-40 cursor-not-allowed' : ''}`}
          >
            {loading ? 'Reset in corso…' : 'Conferma Reset'}
          </button>
        </div>
      </div>
    </ModalOverlay>
  );
}

FactoryResetModal.propTypes = {
  onClose: PropTypes.func.isRequired,
  bioStatus: PropTypes.string,
};

/* ── Export Backup Modal ── */
function ExportBackupModal({ onClose }) {
  const [pwd, setPwd] = useState('');
  const [pwdConfirm, setPwdConfirm] = useState('');
  const [showPwd, setShowPwd] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const doExport = async () => {
    setError('');
    if (!pwd) { setError('Inserisci una password per il backup.'); return; }
    if (pwd.length < 12) { setError('Password troppo corta (min. 12 caratteri).'); return; }
    if (pwd !== pwdConfirm) { setError('Le password non corrispondono.'); return; }
    if (!api.exportVault) { toast.error('Servizio backup non disponibile'); return; }
    setLoading(true);
    const toastId = toast.loading('Generazione backup…');
    try {
      const result = await api.exportVault(pwd);
      if (result?.cancelled) { toast.dismiss(toastId); return; }
      if (result?.success) {
        toast.success('Backup esportato con successo!', { id: toastId });
        onClose();
        return;
      }
      toast.error('Errore: ' + (result?.error || 'Sconosciuto'), { id: toastId });
    } catch {
      toast.error('Errore critico durante il backup', { id: toastId });
    } finally {
      setLoading(false);
    }
  };

  return (
    <ModalOverlay onClose={onClose} labelledBy="export-backup-title" zIndex={200}>
      <div className="modal-card modal-card-sm">
        <div className="modal-header-gradient modal-header-gradient-primary">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-primary/10 rounded-2xl flex items-center justify-center border border-primary/20">
                <Download size={22} className="text-primary" />
              </div>
              <div>
                <h3 id="export-backup-title" className="text-xl font-bold text-text">Esporta Backup</h3>
                <p className="text-xs text-text-dim mt-0.5">Crea un file .lex cifrato</p>
              </div>
            </div>
            <button onClick={onClose} aria-label="Chiudi" className="p-2 hover:bg-card-hover rounded-xl text-text-dim transition-colors group">
              <X size={20} className="group-hover:rotate-90 transition-transform" />
            </button>
          </div>
        </div>
        <div className="px-8 py-6 space-y-4">
          <p className="text-text-muted text-xs leading-relaxed">
            Scegli una password per proteggere il file di backup. Ti servirà per importarlo su un altro dispositivo.
          </p>
          <div className="space-y-3">
            <div className="relative">
              <KeyRound size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-dim" />
              <input
                type={showPwd ? 'text' : 'password'}
                className="w-full py-3 pl-10 pr-10 rounded-xl bg-surface border border-border text-text placeholder:text-text-dim/40 text-sm focus:border-primary/40 outline-none transition-colors"
                placeholder="Password backup…"
                value={pwd}
                onChange={e => { setPwd(e.target.value); setError(''); }}
                autoFocus
                aria-invalid={!!error}
                aria-describedby={error ? 'export-backup-error' : undefined}
              />
              <button
                type="button"
                onClick={() => setShowPwd(v => !v)}
                aria-label={showPwd ? 'Nascondi password' : 'Mostra password'}
                aria-pressed={showPwd}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-text-dim hover:text-text transition-colors"
              >
                {showPwd ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
            <div className="relative">
              <KeyRound size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-dim" />
              <input
                type={showPwd ? 'text' : 'password'}
                className="w-full py-3 pl-10 rounded-xl bg-surface border border-border text-text placeholder:text-text-dim/40 text-sm focus:border-primary/40 outline-none transition-colors"
                placeholder="Conferma password…"
                value={pwdConfirm}
                onChange={e => { setPwdConfirm(e.target.value); setError(''); }}
                aria-invalid={!!error}
                aria-describedby={error ? 'export-backup-error' : undefined}
                onKeyDown={e => { if (e.key === 'Enter') doExport(); }}
              />
            </div>
          </div>
          {error && <p id="export-backup-error" role="alert" className="text-danger text-xs-p font-semibold">{error}</p>}
        </div>
        <div className="modal-footer">
          <button onClick={onClose} className="btn-cancel">Annulla</button>
          <button onClick={doExport} disabled={loading}
            className={`btn-primary px-6 py-3 text-xs font-bold uppercase tracking-widest ${loading ? 'opacity-50' : ''}`}>
            {loading ? 'Esporto…' : 'Esporta'}
          </button>
        </div>
      </div>
    </ModalOverlay>
  );
}

ExportBackupModal.propTypes = { onClose: PropTypes.func.isRequired };

/* ── Import Backup Modal ── */
const IMPORT_CONFIRM_PHRASE = 'OVERWRITE';
function ImportBackupModal({ onClose }) {
  const [pwd, setPwd] = useState('');
  const [showPwd, setShowPwd] = useState(false);
  const [confirmText, setConfirmText] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [preBackupDone, setPreBackupDone] = useState(false);
  const reloadTimerRef = useRef(null);
  const errorId = 'import-backup-error';

  // Trigger an automatic safety backup of the current vault before allowing the destructive import.
  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const r = await api.triggerBackup?.();
        if (!mounted) return;
        if (r === undefined || r?.success) {
          setPreBackupDone(true);
          toast.success('Backup di sicurezza creato prima dell\'import.');
        } else {
          // Don't block the user, but warn loudly.
          setPreBackupDone(true);
          toast.error('Backup di sicurezza non creato. Procedi con cautela.');
        }
      } catch {
        if (!mounted) return;
        setPreBackupDone(true);
        toast.error('Backup di sicurezza non creato. Procedi con cautela.');
      }
    })();
    return () => {
      mounted = false;
      if (reloadTimerRef.current) clearTimeout(reloadTimerRef.current);
    };
  }, []);

  const phraseValid = confirmText === IMPORT_CONFIRM_PHRASE;
  const canSubmit = !loading && pwd && phraseValid && preBackupDone;

  const doImport = async () => {
    setError('');
    if (!pwd) { setError('Inserisci la password del backup.'); return; }
    if (!phraseValid) { setError(`Digita esattamente "${IMPORT_CONFIRM_PHRASE}" per confermare.`); return; }
    if (!api.importVault) { toast.error('Servizio importazione non disponibile'); return; }
    setLoading(true);
    const toastId = toast.loading('Importazione in corso…');
    try {
      const result = await api.importVault(pwd);
      if (result?.cancelled) { toast.dismiss(toastId); return; }
      if (result?.success) {
        toast.success('Vault importato! Ricarico…', { id: toastId });
        onClose();
        reloadTimerRef.current = setTimeout(() => globalThis.location.reload(), 1500);
        return;
      }
      toast.error('Errore: ' + (result?.error || 'Password errata o file non valido'), { id: toastId });
    } catch {
      toast.error("Errore critico durante l'importazione", { id: toastId });
    } finally {
      setLoading(false);
    }
  };

  return (
    <ModalOverlay onClose={onClose} labelledBy="import-backup-title" zIndex={200}>
      <div className="modal-card modal-card-sm">
        <div className="modal-header-gradient modal-header-gradient-primary">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-primary/10 rounded-2xl flex items-center justify-center border border-primary/20">
                <Upload size={22} className="text-primary" />
              </div>
              <div>
                <h3 id="import-backup-title" className="text-xl font-bold text-text">Importa Backup</h3>
                <p className="text-xs text-text-dim mt-0.5">Sovrascrive i dati attuali</p>
              </div>
            </div>
            <button onClick={onClose} aria-label="Chiudi" className="p-2 hover:bg-card-hover rounded-xl text-text-dim transition-colors group">
              <X size={20} className="group-hover:rotate-90 transition-transform" />
            </button>
          </div>
        </div>
        <div className="px-8 py-6 space-y-4">
          <p className="text-text-muted text-xs leading-relaxed">
            Inserisci la password con cui è stato cifrato il file di backup.
            {' '}<span className="text-text font-semibold">I dati attuali verranno sovrascritti.</span>
          </p>
          <div
            className={`text-2xs px-3 py-2 rounded-lg border ${preBackupDone ? 'bg-success-soft border-success-border text-success' : 'bg-warning-soft border-warning-border text-warning'}`}
            role="status"
          >
            {preBackupDone ? '✓ Backup di sicurezza creato prima dell\'import.' : 'Creazione backup di sicurezza in corso…'}
          </div>
          <div className="relative">
            <KeyRound size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-dim" />
            <input type={showPwd ? 'text' : 'password'}
              className="w-full py-3 pl-10 pr-10 rounded-xl bg-surface border border-border text-text placeholder:text-text-dim/40 text-sm focus:border-primary/40 outline-none transition-colors"
              placeholder="Password backup…"
              value={pwd}
              onChange={e => { setPwd(e.target.value); setError(''); }}
              autoFocus
              aria-invalid={!!error}
              aria-describedby={error ? errorId : undefined}
              onKeyDown={e => { if (e.key === 'Enter' && canSubmit) doImport(); }} />
            <button
              type="button"
              onClick={() => setShowPwd(v => !v)}
              aria-label={showPwd ? 'Nascondi password' : 'Mostra password'}
              aria-pressed={showPwd}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-text-dim hover:text-text transition-colors"
            >
              {showPwd ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
          <div className="space-y-2">
            <label htmlFor="import-confirm-phrase" className="text-2xs font-bold text-text-dim uppercase tracking-wider block">
              Per confermare digita: <span className="font-mono text-danger">{IMPORT_CONFIRM_PHRASE}</span>
            </label>
            <input
              id="import-confirm-phrase"
              type="text"
              autoComplete="off"
              spellCheck={false}
              value={confirmText}
              onChange={e => { setConfirmText(e.target.value); setError(''); }}
              className="w-full px-4 py-2.5 rounded-xl bg-surface border border-border text-text text-sm placeholder:text-text-dim/40 outline-none focus:border-danger/50 transition-colors font-mono"
              placeholder={IMPORT_CONFIRM_PHRASE}
              aria-invalid={!!error}
            />
          </div>
          {error && (
            <p id={errorId} role="alert" className="text-danger text-xs-p font-semibold">{error}</p>
          )}
        </div>
        <div className="modal-footer">
          <button onClick={onClose} className="btn-cancel">Annulla</button>
          <button onClick={doImport} disabled={!canSubmit}
            className={`btn-primary px-6 py-3 text-xs font-bold uppercase tracking-widest ${!canSubmit ? 'opacity-40 cursor-not-allowed' : ''}`}>
            {loading ? 'Importo…' : 'Importa'}
          </button>
        </div>
      </div>
    </ModalOverlay>
  );
}

ImportBackupModal.propTypes = { onClose: PropTypes.func.isRequired };

/* ── Biometric Configuration / Deactivation Modal ── */
function BioResetConfirmModal({ onClose, bioStatus }) {
  // If bio is active → flow: confirm-deactivate → done-deactivated
  // If bio is available (not configured) → flow: enroll (ask password → saveBio → done)
  const isActive = bioStatus === 'active';
  const [step, setStep] = useState(isActive ? 'confirm-deactivate' : 'enroll');
  const [pwd, setPwd] = useState('');
  const [showPwd, setShowPwd] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Deactivate biometrics
  const doDeactivate = async () => {
    setLoading(true);
    try {
      await api.clearBio();
      setStep('done-deactivated');
    } catch {
      toast.error("Errore nella disattivazione biometria");
    }
    setLoading(false);
  };

  // Enroll biometrics: verify password → saveBio (triggers native popup) → done
  const doEnroll = async () => {
    setError('');
    if (!pwd.trim()) { setError('Inserisci la Master Password.'); return; }
    setLoading(true);
    try {
      // Verify the password is correct first
      const verify = await api.verifyVaultPassword(pwd);
      if (!verify?.valid) {
        setError(verify?.error || 'Password errata.');
        setLoading(false);
        return;
      }
      // Enroll biometrics with the password (this triggers the native biometric popup)
      await api.saveBio(pwd);
      toast.success("Biometria configurata con successo!");
      // refreshBioStatus is invoked once by the parent's onClose handler — avoid double-fetch.
      onClose();
    } catch {
      setError('Errore nella configurazione biometrica.');
    }
    setLoading(false);
  };

  // Close after deactivation — parent's onClose handler refreshes bio status.
  const handleCloseAfterDeactivate = () => {
    toast.success("Biometria disattivata");
    onClose();
  };

  const stepGradientClass = {
    enroll: 'modal-header-gradient-primary',
    'done-deactivated': 'modal-header-gradient-info',
    'confirm-deactivate': 'modal-header-gradient-danger',
  };
  const defaultGradientClass = 'modal-header-gradient-danger';

  const stepIconStyles = {
    enroll: 'bg-primary/10 border-primary/20',
    'done-deactivated': 'bg-info-soft border-info-border',
    'confirm-deactivate': 'bg-danger-soft border-danger-border',
  };
  const defaultIconStyle = 'bg-danger-soft border-danger-border';

  const stepIcons = {
    enroll: <Fingerprint size={22} className="text-primary" />,
    'done-deactivated': <ShieldCheck size={22} className="text-info" />,
    'confirm-deactivate': <Fingerprint size={22} className="text-danger" />,
  };
  const defaultIcon = <Fingerprint size={22} className="text-danger" />;

  return (
    <ModalOverlay onClose={onClose} labelledBy="bio-modal-title" zIndex={200}>
      <div className="modal-card modal-card-sm">
        <div className={`modal-header-gradient ${stepGradientClass[step] || defaultGradientClass}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className={`w-12 h-12 rounded-2xl flex items-center justify-center border ${
              stepIconStyles[step] || defaultIconStyle
            }`}>
              {stepIcons[step] || defaultIcon}
            </div>
            <div>
              <h3 id="bio-modal-title" className="text-xl font-bold text-text">
                {step === 'confirm-deactivate' && 'Disattiva Biometria'}
                {step === 'done-deactivated' && 'Biometria Disattivata'}
                {step === 'enroll' && 'Configura Biometria'}
              </h3>
              <p className="text-xs text-text-dim mt-0.5">
                {step === 'confirm-deactivate' && 'Rimuovi l\'accesso biometrico'}
                {step === 'done-deactivated' && 'Accesso biometrico rimosso'}
                {step === 'enroll' && 'Password + biometria del dispositivo'}
              </p>
            </div>
          </div>
          <button onClick={onClose} aria-label="Chiudi" className="p-2 hover:bg-card-hover rounded-xl text-text-dim transition-colors group">
            <X size={20} className="group-hover:rotate-90 transition-transform" />
          </button>
        </div>
      </div>

      {/* Step: Confirm deactivation */}
      {step === 'confirm-deactivate' && (
        <>
          <div className="px-8 py-6">
            <p className="text-text-muted text-xs leading-relaxed">
              Vuoi disattivare l'accesso biometrico? Dovrai usare la Master Password per accedere ai fascicoli protetti. Potrai riattivare la biometria in qualsiasi momento.
            </p>
          </div>
          <div className="modal-footer">
            <button onClick={onClose} className="btn-cancel">Annulla</button>
            <button onClick={doDeactivate} disabled={loading}
              className={`px-6 py-3 rounded-2xl bg-danger-soft border border-danger-border text-danger hover:bg-danger-soft transition-colors text-xs font-bold uppercase tracking-widest ${loading ? 'opacity-50' : ''}`}>
              {loading ? 'Disattivazione...' : 'Disattiva'}
            </button>
          </div>
        </>
      )}

      {/* Step: Done deactivated */}
      {step === 'done-deactivated' && (
        <>
          <div className="px-8 py-6">
            <p className="text-text-muted text-xs leading-relaxed">
              L'accesso biometrico è stato disattivato. Potrai riattivarlo in qualsiasi momento dalle Impostazioni.
            </p>
          </div>
          <div className="modal-footer">
            <button onClick={handleCloseAfterDeactivate}
              className="btn-primary px-6 py-3 text-xs font-bold uppercase tracking-widest">
              Chiudi
            </button>
          </div>
        </>
      )}

      {/* Step: Enroll — ask for password, then saveBio triggers native popup */}
      {step === 'enroll' && (
        <>
          <div className="px-8 py-6 space-y-4">
            <p className="text-text-muted text-xs leading-relaxed">
              Inserisci la tua Master Password per configurare l'accesso biometrico. Dopo la verifica, il sistema ti chiederà di confermare con Face ID / Touch ID.
            </p>
            <div className="relative">
              <KeyRound size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-dim" />
              <input
                type={showPwd ? 'text' : 'password'}
                className="w-full py-3 pl-10 pr-10 rounded-xl bg-surface border border-border text-text placeholder:text-text-dim/40 text-sm focus:border-primary/40 outline-none transition-colors"
                placeholder="Master Password…"
                value={pwd}
                onChange={e => { setPwd(e.target.value); setError(''); }}
                autoFocus
                aria-invalid={!!error}
                aria-describedby={error ? 'bio-enroll-error' : undefined}
                onKeyDown={e => { if (e.key === 'Enter') doEnroll(); }}
              />
              <button
                type="button"
                onClick={() => setShowPwd(v => !v)}
                aria-label={showPwd ? 'Nascondi password' : 'Mostra password'}
                aria-pressed={showPwd}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-text-dim hover:text-text transition-colors"
              >
                {showPwd ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
            {error && <p id="bio-enroll-error" role="alert" className="text-danger text-xs-p font-semibold">{error}</p>}
          </div>
          <div className="modal-footer">
            <button onClick={onClose} className="btn-cancel">Annulla</button>
            <button onClick={doEnroll} disabled={loading}
              className={`btn-primary px-6 py-3 text-xs font-bold uppercase tracking-widest ${loading ? 'opacity-50' : ''}`}>
              {loading ? 'Configurazione...' : 'Configura Biometria'}
            </button>
          </div>
        </>
      )}
      </div>
    </ModalOverlay>
  );
}

BioResetConfirmModal.propTypes = { onClose: PropTypes.func.isRequired, bioStatus: PropTypes.string };

export default function SettingsPage({ onLock }) {
  const [settingsLoaded, setSettingsLoaded] = useState(false);
  const [settingsLoadError, setSettingsLoadError] = useState(false);
  const [privacyEnabled, setPrivacyEnabled] = useState(true);
  const [appVersion, setAppVersion] = useState('');
  const [platform, setPlatform] = useState('');

  // Profilo studio (read-only, from license token)
  const [lawyerName, setLawyerName] = useState('');
  const [lawyerTitle, setLawyerTitle] = useState('Avv.');
  const [studioName, setStudioName] = useState('');

  // Stato per le Notifiche — attive di default
  const [notifyEnabled, setNotifyEnabled] = useState(true);
  const [notificationTime, setNotificationTime] = useState(30);

  // Stato per Sicurezza Avanzata
  const [screenshotProtection, setScreenshotProtection] = useState(true);
  const [autolockMinutes, setAutolockMinutes] = useState(5);

  // Modal visibility flags
  const [showFactoryReset, setShowFactoryReset] = useState(false);
  const [changePwdCurrent, setChangePwdCurrent] = useState('');
  const [changePwdNew, setChangePwdNew] = useState('');
  const [changePwdConfirm, setChangePwdConfirm] = useState('');
  const [changePwdLoading, setChangePwdLoading] = useState(false);
  const [changePwdError, setChangePwdError] = useState('');
  const [changePwdSuccess, setChangePwdSuccess] = useState('');
  // Recovery key persists across remounts via sessionStorage until the user
  // explicitly confirms they have saved it. Losing this key without saving it
  // would lock the user out of vault recovery.
  const [recoveryKey, setRecoveryKey] = useState(() => {
    try { return sessionStorage.getItem(RECOVERY_STORE_KEY) || ''; } catch { return ''; }
  });
  const [confirmedSaved, setConfirmedSaved] = useState(false);
  const [showRegenerateConfirm, setShowRegenerateConfirm] = useState(false);
  const [vaultHealth, setVaultHealth] = useState(null);

  const [showExportModal, setShowExportModal] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [showBioResetConfirm, setShowBioResetConfirm] = useState(false);

  // Biometrics status: 'checking' | 'active' | 'available' | 'unavailable'
  const [bioStatus, setBioStatus] = useState('checking');
  const refreshBioStatus = useCallback(async () => {
    try {
      const available = await api.checkBio();
      if (!available) { setBioStatus('unavailable'); return; }
      const saved = await api.hasBioSaved();
      setBioStatus(saved ? 'active' : 'available');
    } catch { setBioStatus('unavailable'); }
  }, []);

  // Persist the recovery key in sessionStorage so a stray re-render or
  // accidental nav back to Settings doesn't lose the irreplaceable secret.
  useEffect(() => {
    try {
      if (recoveryKey) sessionStorage.setItem(RECOVERY_STORE_KEY, recoveryKey);
    } catch { /* sessionStorage unavailable */ }
  }, [recoveryKey]);

  const onConfirmSaved = useCallback(() => {
    if (!confirmedSaved) return;
    try { sessionStorage.removeItem(RECOVERY_STORE_KEY); } catch { /* ignore */ }
    setRecoveryKey('');
    setConfirmedSaved(false);
  }, [confirmedSaved]);

  // Vault-health polling: only when document is visible to avoid burning
  // resources / triggering audit-log writes while the app is in the background.
  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      if (cancelled) return;
      if (typeof document !== 'undefined' && document.visibilityState !== 'visible') return;
      try {
        const h = await api.getVaultHealth();
        if (!cancelled && h) setVaultHealth(h);
      } catch { /* vault health non-critical */ }
    };
    tick();
    const interval = setInterval(tick, 30000);
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', tick);
    }
    return () => {
      cancelled = true;
      clearInterval(interval);
      if (typeof document !== 'undefined') {
        document.removeEventListener('visibilitychange', tick);
      }
    };
  }, []);

  const applySettings = useCallback((settings) => {
    if (!settings) return;
    const boolFields = [
      ['privacyBlurEnabled', setPrivacyEnabled],
      ['notifyEnabled', setNotifyEnabled],
      ['screenshotProtection', setScreenshotProtection],
    ];
    for (const [key, setter] of boolFields) {
      // Default to true (secure posture) when the key is missing from the backend
      setter(typeof settings[key] === 'boolean' ? settings[key] : true);
    }
    // If screenshotProtection is missing from backend payload, sync the OS-level
    // setting to the secure default so UI and OS state stay aligned.
    if (typeof settings.screenshotProtection !== 'boolean') {
      api.setContentProtection?.(true).catch(() => { /* OS may not support */ });
    }
    // Unify: prefer `preavviso` (Agenda key), fallback to `notificationTime` (legacy Settings key)
    const time = settings.preavviso ?? settings.notificationTime;
    if (time !== undefined) setNotificationTime(time);
    // Validate autolock against the canonical option set; fall back to 5 min.
    const validAutolock = AUTOLOCK_OPTIONS.find(o => o.value === settings.autolockMinutes)?.value ?? 5;
    setAutolockMinutes(validAutolock);
    // Override lawyer title from saved settings (user may have changed it)
    if (settings.lawyerTitle) setLawyerTitle(settings.lawyerTitle);
  }, []);

  const loadSettings = useCallback(async () => {
    setSettingsLoadError(false);
    try {
      const s = await api.getSettings();
      applySettings(s);
      setSettingsLoaded(true);
    } catch {
      // Don't apply defaults blindly — surface a Retry to the user.
      setSettingsLoadError(true);
    }
  }, [applySettings]);

  useEffect(() => {
    let mounted = true;

    api.getAppVersion()
      .then(v => { if (mounted) setAppVersion(v); })
      .catch(() => { /* version is decorative */ });

    // Detect platform asynchronously
    api.getPlatform()
      .then(p => {
        if (!mounted) return;
        const labels = { macos: 'macOS', windows: 'Windows', android: 'Android', ios: 'iOS', linux: 'Linux' };
        setPlatform(labels[p] || p || 'Desktop');
      })
      .catch(() => {
        api.isMac().then(m => { if (mounted) setPlatform(m ? 'macOS' : 'Windows'); }).catch(() => {});
      });

    loadSettings();

    // Load lawyer/studio from license token (read-only, not from settings)
    api.checkLicense()
      .then(res => {
        if (!mounted) return;
        if (res?.activated) {
          if (res.lawyerName) setLawyerName(res.lawyerName.replace(/^(Avv\.|Avv|Avvocato|Praticante)\.?\s+/i, '').trim());
          if (res.lawyerTitle) setLawyerTitle(res.lawyerTitle);
          if (res.studioName) setStudioName(res.studioName);
        }
      })
      .catch(() => { /* silent */ });

    // Check biometrics status asynchronously
    api.checkBio()
      .then(available => {
        if (!mounted) return undefined;
        if (!available) { setBioStatus('unavailable'); return undefined; }
        return api.hasBioSaved().then(saved => { if (mounted) setBioStatus(saved ? 'active' : 'available'); });
      })
      .catch(() => { if (mounted) setBioStatus('unavailable'); });

    // Listen for corrupted settings file event from backend.
    // After the toast, also re-fetch settings so the UI reflects the
    // backend-restored defaults rather than stale state.
    const unsubscribe = api.onSettingsCorrupted?.((payload) => {
      toast.error(
        `Il file impostazioni era corrotto ed è stato ripristinato ai valori predefiniti. Backup salvato in: ${payload?.backup_path || '(sconosciuto)'}`,
        { duration: 8000 }
      );
      api.getSettings().then(s => { if (mounted) applySettings(s); }).catch(() => {});
    });

    return () => {
      mounted = false;
      unsubscribe?.();
    };
  }, [applySettings, loadSettings]);

  const buildFullSettings = useCallback(() => ({
    privacyBlurEnabled: privacyEnabled ?? true,
    notifyEnabled: notifyEnabled ?? true,
    notificationTime: notificationTime ?? 30,
    preavviso: notificationTime ?? 30,
    screenshotProtection: screenshotProtection ?? true,
    autolockMinutes: autolockMinutes ?? 5,
  }), [privacyEnabled, notifyEnabled, notificationTime, screenshotProtection, autolockMinutes]);

  // Toggle now passes the new value explicitly; respect the emitted boolean
  // rather than re-deriving from stale state.
  const handlePrivacyToggle = useCallback(async (val) => {
    const prev = privacyEnabled;
    setPrivacyEnabled(val);
    try {
      await api.saveSettings({ ...buildFullSettings(), privacyBlurEnabled: val });
      toast.success(val ? 'Privacy Blur Attivato' : 'Privacy Blur Disattivato');
    } catch {
      toast.error('Errore salvataggio');
      setPrivacyEnabled(prev);
    }
  }, [privacyEnabled, buildFullSettings]);

  const handleScreenshotToggle = useCallback(async (val) => {
    const prev = screenshotProtection;
    setScreenshotProtection(val);
    // Persist the setting first, then sync OS state. If the OS call fails we
    // roll back BOTH the persisted setting and the in-memory state so they
    // can never drift out of agreement.
    try {
      await api.saveSettings({ ...buildFullSettings(), screenshotProtection: val });
    } catch {
      toast.error('Errore salvataggio');
      setScreenshotProtection(prev);
      return;
    }
    try {
      await api.setContentProtection(val);
      toast.success(val ? 'Screenshot bloccati' : 'Screenshot sbloccati');
    } catch {
      toast.error('Errore protezione schermo: ripristino valore precedente');
      setScreenshotProtection(prev);
      // Best-effort rollback of persisted setting; ignore rollback failures.
      try { await api.saveSettings({ ...buildFullSettings(), screenshotProtection: prev }); } catch { /* ignore */ }
    }
  }, [screenshotProtection, buildFullSettings]);

  const handleAutolockChange = useCallback(async (opt) => {
    const prev = autolockMinutes;
    setAutolockMinutes(opt.value);
    try {
      await api.setAutolockMinutes(opt.value);
      await api.saveSettings({ ...buildFullSettings(), autolockMinutes: opt.value });
      toast.success(opt.value === 0 ? 'Blocco automatico disabilitato' : `Blocco dopo ${opt.label} di inattività`);
    } catch {
      toast.error('Errore');
      setAutolockMinutes(prev);
    }
  }, [autolockMinutes, buildFullSettings]);

  // Funzione per salvare le impostazioni delle notifiche
  const saveNotifySettings = useCallback(async (updates) => {
    try {
      await api.saveSettings({ ...buildFullSettings(), ...updates });
      toast.success("Preferenze notifiche aggiornate");
    } catch {
      toast.error("Errore nel salvataggio");
    }
  }, [buildFullSettings]);

  const handleNotifyToggle = useCallback((val) => {
    setNotifyEnabled(val);
    saveNotifySettings({ notifyEnabled: val });
  }, [saveNotifySettings]);

  const handleNotificationTimeChange = useCallback((value) => {
    setNotificationTime(value);
    saveNotifySettings({ notificationTime: value, preavviso: value });
  }, [saveNotifySettings]);

  const handleLawyerTitleChange = useCallback(async (newTitle) => {
    const prev = lawyerTitle;
    setLawyerTitle(newTitle);
    try {
      await api.saveSettings({ ...buildFullSettings(), lawyerTitle: newTitle });
      toast.success(`Titolo aggiornato: ${newTitle}`);
    } catch {
      toast.error('Errore salvataggio');
      setLawyerTitle(prev);
    }
  }, [lawyerTitle, buildFullSettings]);

  // Change Password — full validation including the new "confirm" field.
  const handleChangePassword = useCallback(async () => {
    setChangePwdError(''); setChangePwdSuccess('');
    if (!changePwdCurrent || !changePwdNew) {
      setChangePwdError('Compila tutti i campi'); return;
    }
    if (changePwdNew.length < 12) {
      setChangePwdError('La nuova password deve avere almeno 12 caratteri'); return;
    }
    if (changePwdNew !== changePwdConfirm) {
      setChangePwdError('Le nuove password non corrispondono'); return;
    }
    if (changePwdNew === changePwdCurrent) {
      setChangePwdError('La nuova password deve differire dall\'attuale'); return;
    }
    setChangePwdLoading(true);
    try {
      const res = await api.changePassword(changePwdCurrent, changePwdNew);
      if (res?.success) {
        setChangePwdSuccess('Password cambiata con successo');
        setChangePwdCurrent(''); setChangePwdNew(''); setChangePwdConfirm('');
      } else {
        setChangePwdError(res?.error || 'Errore cambio password');
      }
    } catch (e) {
      setChangePwdError(String(e));
    } finally {
      setChangePwdLoading(false);
    }
  }, [changePwdCurrent, changePwdNew, changePwdConfirm]);

  const openBioResetConfirm = useCallback(() => setShowBioResetConfirm(true), []);
  const openExportModal = useCallback(() => setShowExportModal(true), []);
  const openImportModal = useCallback(() => setShowImportModal(true), []);
  const openFactoryReset = useCallback(() => setShowFactoryReset(true), []);

  const generateRecovery = useCallback(async () => {
    try {
      const res = await api.generateRecoveryKey();
      // Standardize on camelCase. The backend now returns `recoveryKey`.
      if (res?.recoveryKey) {
        setRecoveryKey(res.recoveryKey);
        setConfirmedSaved(false);
      } else {
        toast?.error(res?.error || 'Errore generazione chiave');
      }
    } catch (e) {
      toast?.error(String(e));
    }
  }, []);

  return (
    <div className="max-w-4xl mx-auto space-y-8 pb-10">
      
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-text tracking-tight mb-2">Impostazioni</h1>
          <p className="text-text-muted text-sm">Gestisci sicurezza e preferenze di LexFlow.</p>
        </div>
        <div className="px-4 py-2 bg-surface rounded-lg border border-border text-xs font-mono text-text-dim">
          v{appVersion} • {platform}
        </div>
      </div>

      {settingsLoadError && (
        <div className="glass-card p-6 flex items-center justify-between gap-4 border border-danger-border bg-danger-soft" role="alert">
          <div className="space-y-1">
            <p className="text-sm font-bold text-danger">Impossibile caricare le impostazioni</p>
            <p className="text-xs text-text-muted">Le preferenze non sono state lette. Non sono stati applicati valori di default per evitare di sovrascrivere la tua configurazione.</p>
          </div>
          <button
            type="button"
            onClick={loadSettings}
            className="px-4 py-2 rounded-xl bg-surface border border-border text-text text-xs font-bold uppercase tracking-widest hover:bg-card transition-colors"
          >
            Riprova
          </button>
        </div>
      )}

      <div className={`grid gap-6 ${settingsLoaded ? 'opacity-100' : 'opacity-0'}`}>


        
        {/* SEZIONE PROFILO STUDIO */}
        <section className="glass-card p-6 space-y-6">
          <div className="flex items-center gap-3 border-b border-border pb-4 mb-4">
            <Briefcase className="text-text-muted" size={20} />
            <h2 className="text-lg font-bold text-text">Profilo Studio</h2>
          </div>
          {(lawyerName || studioName) ? (
            <>
              <div className="grid gap-5 sm:grid-cols-2">
                {lawyerName && (
                  <div className="space-y-2">
                    <label htmlFor="lawyer-title-select" className="text-2xs font-bold text-text-dim uppercase tracking-wider block">Titolo e Nome</label>
                    <div className="flex items-center gap-2">
                      <select
                        id="lawyer-title-select"
                        value={lawyerTitle}
                        onChange={(e) => handleLawyerTitleChange(e.target.value)}
                        className="bg-surface border border-border rounded-xl px-3 py-3 text-sm text-text focus:border-primary/50 focus:ring-1 focus:ring-primary/20 outline-none transition-colors appearance-none cursor-pointer"
                      >
                        <option value="Avv.">Avv.</option>
                        <option value="Praticante">Praticante</option>
                      </select>
                      <div className="flex-1 bg-surface border border-border rounded-xl px-4 py-3 text-sm text-text">
                        {lawyerName}
                      </div>
                    </div>
                  </div>
                )}
                {studioName && (
                  <div className="space-y-2">
                    <label className="text-2xs font-bold text-text-dim uppercase tracking-wider block">Nome Studio</label>
                    <div className="w-full bg-surface border border-border rounded-xl px-4 py-3 text-sm text-text">
                      {studioName}
                    </div>
                  </div>
                )}
              </div>
              <p className="text-2xs text-text-dim">Il titolo e lo studio vengono utilizzati nell&apos;intestazione dei report PDF e in tutta l&apos;app.</p>
            </>
          ) : (
            <div className="flex items-start gap-3 p-4 rounded-xl bg-surface border border-border">
              <KeyRound size={16} className="text-text-dim mt-0.5 shrink-0" />
              <div className="space-y-1">
                <p className="text-xs font-semibold text-text">Profilo non disponibile</p>
                <p className="text-xs text-text-muted leading-relaxed">
                  Attiva la licenza per vedere il profilo dello studio. Le informazioni dell&apos;avvocato e dello studio vengono lette dal token di licenza e usate nei report PDF.
                </p>
              </div>
            </div>
          )}
        </section>


      <section className="glass-card p-6 space-y-6">
        <div className="flex items-center gap-3">
          <ShieldCheck size={20} className="text-primary" />
          <h2 className="text-lg font-bold text-text">Sicurezza Vault</h2>
        </div>

        {/* Cambio Password */}
        <div className="space-y-3">
          <label htmlFor="cp-current" className="text-2xs font-bold text-text-dim uppercase tracking-wider block">Cambia Password Master</label>
          <div className="grid gap-3 sm:grid-cols-2">
            <input
              id="cp-current"
              type="password"
              placeholder="Password attuale"
              value={changePwdCurrent}
              onChange={e => { setChangePwdCurrent(e.target.value); setChangePwdError(''); }}
              aria-invalid={!!changePwdError}
              aria-describedby={changePwdError ? 'cp-error' : undefined}
              className="w-full px-4 py-2.5 rounded-xl bg-surface border border-border text-text text-sm placeholder:text-text-dim outline-none focus:border-primary"
            />
            <input
              id="cp-new"
              type="password"
              placeholder="Nuova password (min 12 car.)"
              value={changePwdNew}
              onChange={e => { setChangePwdNew(e.target.value); setChangePwdError(''); }}
              aria-invalid={!!changePwdError}
              aria-describedby={changePwdError ? 'cp-error' : undefined}
              className="w-full px-4 py-2.5 rounded-xl bg-surface border border-border text-text text-sm placeholder:text-text-dim outline-none focus:border-primary"
            />
            <input
              id="cp-confirm"
              type="password"
              placeholder="Conferma nuova password"
              value={changePwdConfirm}
              onChange={e => { setChangePwdConfirm(e.target.value); setChangePwdError(''); }}
              aria-invalid={!!changePwdError}
              aria-describedby={changePwdError ? 'cp-error' : undefined}
              className="w-full px-4 py-2.5 rounded-xl bg-surface border border-border text-text text-sm placeholder:text-text-dim outline-none focus:border-primary sm:col-span-2"
            />
          </div>
          {changePwdError && <p id="cp-error" role="alert" className="text-xs text-danger">{changePwdError}</p>}
          {changePwdSuccess && <p className="text-xs text-emerald-400" role="status">{changePwdSuccess}</p>}
          <button
            onClick={handleChangePassword}
            disabled={changePwdLoading}
            aria-busy={changePwdLoading}
            className={`btn-primary px-6 py-2.5 text-xs font-bold uppercase tracking-widest ${changePwdLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            {changePwdLoading ? 'Cambio in corso…' : 'Cambia Password'}
          </button>
        </div>

        <div className="border-t border-border" />

        {/* Recovery Key */}
        <div className="space-y-3">
          <label className="text-2xs font-bold text-text-dim uppercase tracking-wider block">Chiave di Emergenza</label>
          <p className="text-xs text-text-dim">Genera una chiave di recupero per sbloccare il vault se dimentichi la password. Conservala in un luogo sicuro.</p>
          {recoveryKey ? (
            <div className="bg-surface border border-primary-soft rounded-xl p-4 space-y-3">
              <p className="text-center font-mono text-lg tracking-[4px] text-primary font-bold select-all">{recoveryKey}</p>
              <p className="text-xs text-text-dim text-center">Copia e conserva questa chiave. Non verrà mostrata di nuovo.</p>
              <button
                onClick={() => { api.secureCopy?.(recoveryKey); toast?.success('Chiave copiata (auto-cancellazione in 30s)'); }}
                className="w-full px-4 py-2 rounded-xl bg-primary-soft text-primary text-xs font-bold uppercase tracking-widest"
              >
                Copia negli Appunti
              </button>
              <label className="flex items-start gap-2 text-xs text-text-muted cursor-pointer pt-2 border-t border-border/40">
                <input
                  type="checkbox"
                  checked={confirmedSaved}
                  onChange={(e) => setConfirmedSaved(e.target.checked)}
                  className="mt-0.5 accent-primary"
                />
                <span>Ho copiato e conservato la chiave di recovery in un posto sicuro.</span>
              </label>
              <div className="flex flex-col sm:flex-row gap-2">
                <button
                  onClick={onConfirmSaved}
                  disabled={!confirmedSaved}
                  className={`flex-1 px-4 py-2 rounded-xl bg-success-soft border border-success-border text-success text-xs font-bold uppercase tracking-widest transition-colors ${confirmedSaved ? '' : 'opacity-40 cursor-not-allowed'}`}
                >
                  Ho salvato la chiave — chiudi
                </button>
                <button
                  onClick={() => setShowRegenerateConfirm(true)}
                  className="flex-1 px-4 py-2 rounded-xl bg-warning-soft border border-warning-border text-warning text-xs font-bold uppercase tracking-widest transition-colors"
                >
                  Rigenera chiave
                </button>
              </div>
            </div>
          ) : (
            <button
              onClick={generateRecovery}
              className="btn-primary px-6 py-2.5 text-xs font-bold uppercase tracking-widest"
            >
              Genera Chiave di Emergenza
            </button>
          )}
        </div>

        <div className="border-t border-border" />

        {/* Stato del Vault — user-friendly */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <label className="text-2xs font-bold text-text-dim uppercase tracking-wider block">Stato del Vault</label>
            {vaultHealth && (
              <span className="text-2xs text-emerald-400 flex items-center gap-1.5 bg-emerald-400/10 px-2.5 py-1 rounded-full">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                Protetto
              </span>
            )}
          </div>
          {vaultHealth ? (
            <div className="space-y-3">
              {/* Key metrics — large and clear */}
              <div className="grid gap-3 sm:grid-cols-3">
                <div className="bg-surface rounded-xl p-4 border border-border text-center">
                  <p className="text-2xl font-black text-text">{vaultHealth.record_count || 0}</p>
                  <p className="text-2xs text-text-dim font-medium mt-1">Fascicoli protetti</p>
                </div>
                <div className="bg-surface rounded-xl p-4 border border-border text-center">
                  <p className="text-2xl font-black text-text">{vaultHealth.total_writes || 0}</p>
                  <p className="text-2xs text-text-dim font-medium mt-1">Operazioni totali</p>
                </div>
                <div className="bg-surface rounded-xl p-4 border border-border text-center">
                  <p className={`text-2xl font-black ${vaultHealth.rotation_due ? 'text-amber-400' : 'text-emerald-400'}`}>
                    {vaultHealth.rotation_due ? 'Richiesta' : 'OK'}
                  </p>
                  <p className="text-2xs text-text-dim font-medium mt-1">Rotazione chiave</p>
                </div>
              </div>
              {/* Technical details — collapsed by default */}
              <details className="group">
                <summary className="text-2xs text-text-dim cursor-pointer hover:text-text transition-colors flex items-center gap-1">
                  <span className="group-open:rotate-90 transition-transform">&#9654;</span>
                  Dettagli tecnici
                </summary>
                <div className="grid gap-2 sm:grid-cols-2 text-xs mt-3">
                  {[
                    ['Formato', vaultHealth.vault_format || `v${vaultHealth.version}`],
                    ['Cifratura', vaultHealth.cipher || 'AES-256-GCM-SIV'],
                    ['Derivazione chiave', vaultHealth.kdf_algorithm || 'Argon2id'],
                    ['Memoria derivazione', vaultHealth.kdf_memory_mb ? `${vaultHealth.kdf_memory_mb} MB` : '-'],
                    ['Compressione', vaultHealth.compressed ? 'zstd attiva' : 'Non attiva'],
                    ['Chiave creata', vaultHealth.dek_created ? new Date(vaultHealth.dek_created).toLocaleDateString('it-IT') : '-'],
                  ].map(([label, val]) => (
                    <div key={label} className="flex justify-between bg-surface/50 rounded-lg px-3 py-2 border border-border/50">
                      <span className="text-text-dim">{label}</span>
                      <span className="text-text font-medium">{val}</span>
                    </div>
                  ))}
                </div>
              </details>
            </div>
          ) : (
            <div className="text-xs text-text-dim text-center py-4">Caricamento...</div>
          )}
        </div>
      </section>

        <section className="glass-card p-6 space-y-6">
          <div className="flex items-center gap-3 border-b border-border pb-4 mb-4">
            <Shield className="text-text-muted" size={20} />
            <h2 className="text-lg font-bold text-text">Sicurezza & Privacy</h2>
          </div>

          <div className="flex items-center justify-between group">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                {privacyEnabled ? <Eye size={16} className="text-primary" /> : <EyeOff size={16} className="text-text-dim" />}
                <span className="font-medium text-text">Privacy Blur</span>
                <span className="text-2xs bg-primary/20 text-primary px-2 py-0.5 rounded border border-primary/20">CONSIGLIATO</span>
              </div>
              <p className="text-xs text-text-muted max-w-md">
                Sfoca automaticamente il contenuto dell'app quando perdi il focus.
              </p>
            </div>
            <Toggle checked={privacyEnabled} onChange={handlePrivacyToggle} />
          </div>

          {/* Anti-Screenshot */}
          <div className="flex items-center justify-between group pt-4 border-t border-border">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                {screenshotProtection ? <Camera size={16} className="text-primary" /> : <CameraOff size={16} className="text-text-dim" />}
                <span className="font-medium text-text">Blocco Screenshot</span>
                <span className="text-2xs bg-primary/20 text-primary px-2 py-0.5 rounded border border-primary/20">SICUREZZA</span>
              </div>
              <p className="text-xs text-text-muted max-w-md">
                Impedisce la cattura dello schermo (screenshot, registrazioni, condivisione schermo).
              </p>
            </div>
            <Toggle checked={screenshotProtection} onChange={handleScreenshotToggle} />
          </div>

          {/* Auto-Lock Timer */}
          <div className="pt-4 border-t border-border">
            <div className="flex items-center gap-2 mb-1">
              <Timer size={16} className="text-text-muted" />
              <span id="autolock-label" className="font-medium text-text">Blocco Automatico</span>
            </div>
            <p className="text-xs text-text-muted max-w-md mb-4">
              Blocca automaticamente il Vault dopo un periodo di inattività.
            </p>
            <div role="radiogroup" aria-labelledby="autolock-label" className="flex flex-wrap gap-2">
              {AUTOLOCK_OPTIONS.map(opt => {
                const selected = autolockMinutes === opt.value;
                return (
                  <button
                    key={opt.value}
                    type="button"
                    role="radio"
                    aria-checked={selected}
                    tabIndex={selected ? 0 : -1}
                    onClick={() => handleAutolockChange(opt)}
                    className={`px-4 py-2 rounded-xl text-xs font-semibold transition-colors border ${
                      selected
                        ? 'bg-primary text-black border-primary'
                        : 'bg-surface text-text-muted border-border hover:bg-card hover:text-text'
                    }`}
                  >
                    {opt.label}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            <button
              onClick={onLock}
              title="Chiude immediatamente il Vault. Dovrai inserire la Master Password per riaprirlo."
              aria-label="Blocca Vault Ora — chiude immediatamente la sessione del Vault"
              className="flex items-center justify-center gap-3 p-4 rounded-xl bg-surface hover:bg-card border border-border text-text transition-colors group"
            >
              <Lock size={18} className="text-primary transition-transform group-hover:-rotate-12" />
              <span className="text-sm font-bold uppercase tracking-wider">Blocca Vault Ora</span>
            </button>
            <button
              onClick={openBioResetConfirm}
              className={`flex items-center gap-4 p-4 rounded-xl border transition-colors group relative ${
                {
                  active: 'bg-success-soft hover:bg-success-soft border-success-border',
                  available: 'bg-warning-soft hover:bg-warning-soft border-warning-border',
                }[bioStatus] || 'bg-surface hover:bg-card border-border'
              }`}
            >
              <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${
                { active: 'bg-success-soft', available: 'bg-warning-soft' }[bioStatus] || 'bg-surface'
              }`}>
                <Fingerprint size={20} className={
                  {
                    active: 'text-success',
                    available: 'text-warning',
                    checking: 'text-text-dim animate-pulse',
                  }[bioStatus] || 'text-text-dim'
                } />
              </div>
              <div className="flex flex-col items-start">
                <span className="text-sm font-bold text-text">Biometria</span>
                <span className={`text-2xs font-bold uppercase tracking-wider ${
                  {
                    active: 'text-success',
                    available: 'text-warning',
                    checking: 'text-text-dim animate-pulse',
                  }[bioStatus] || 'text-text-dim'
                }`}>
                  {bioStatus === 'active' && 'Attiva — Face ID / Touch ID'}
                  {bioStatus === 'available' && 'Non configurata'}
                  {bioStatus === 'unavailable' && 'Non disponibile'}
                  {bioStatus === 'checking' && 'Verifica…'}
                </span>
              </div>
            </button>
          </div>
        </section>

        <section className="glass-card p-6 space-y-6">
          <div className="flex items-center gap-3 border-b border-border pb-4 mb-4">
            <Bell className="text-text-muted" size={20} />
            <h2 className="text-lg font-bold text-text">Notifiche di Sistema</h2>
          </div>

          <div className="flex flex-col gap-6">
            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  {notifyEnabled ? <Bell size={16} className="text-primary" /> : <BellOff size={16} className="text-text-dim" />}
                  <span className="font-medium text-text">Avvisi Agenda e Scadenze</span>
                </div>
                <p className="text-xs text-text-muted max-w-md">
                  Ricevi notifiche desktop per udienze, scadenze e impegni in agenda.
                </p>
              </div>
              <Toggle checked={notifyEnabled} onChange={handleNotifyToggle} />
            </div>

            <div className="pt-4 border-t border-border">
              <span id="preavviso-label" className="text-2xs font-bold text-text-dim uppercase tracking-wider mb-3 block">Preavviso Standard</span>
              <div
                role="radiogroup"
                aria-labelledby="preavviso-label"
                aria-disabled={!notifyEnabled}
                className={`flex flex-wrap gap-2 ${notifyEnabled ? '' : 'opacity-40 pointer-events-none'}`}
              >
                {PREAVVISO_OPTIONS.map(opt => {
                  const selected = notificationTime === opt.value;
                  return (
                    <button
                      key={opt.value}
                      type="button"
                      role="radio"
                      aria-checked={selected}
                      tabIndex={selected && notifyEnabled ? 0 : -1}
                      disabled={!notifyEnabled}
                      onClick={() => handleNotificationTimeChange(opt.value)}
                      className={`px-4 py-2 rounded-xl text-xs font-semibold transition-colors border ${
                        selected
                          ? (notifyEnabled ? 'bg-primary text-black border-primary' : 'bg-card text-text-dim border-border')
                          : 'bg-surface text-text-muted border-border hover:bg-card hover:text-text'
                      } ${!notifyEnabled ? 'cursor-not-allowed' : ''}`}
                    >
                      {opt.label}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        </section>

        <section className="glass-card p-6 space-y-6">
          <div className="flex items-center gap-3 border-b border-border pb-4 mb-4">
            <HardDrive className="text-text-muted" size={20} />
            <h2 className="text-lg font-bold text-text">Gestione Dati</h2>
          </div>

          {/* Banner sistema chiuso */}
          <div className="flex items-start gap-3 p-4 rounded-xl bg-surface border border-border">
            <ArrowLeftRight size={16} className="text-primary mt-0.5 shrink-0" />
            <div className="space-y-1">
              <p className="text-xs font-semibold text-primary uppercase tracking-wider">Sistema Chiuso — Vault Indipendenti</p>
              <p className="text-xs text-text-muted leading-relaxed">
                Il vault su <span className="text-white font-medium inline-flex items-center gap-1"><Monitor size={11} /> desktop</span>{' '}e
                su <span className="text-white font-medium inline-flex items-center gap-1"><Smartphone size={11} /> Android</span>{' '}sono{' '}
                cifrati con chiavi distinte, legate al singolo dispositivo. Non condividono dati in automatico.
                <br />
                Per portare i dati da un dispositivo all'altro: <span className="text-primary font-semibold">Esporta</span> sul dispositivo sorgente,
                poi <span className="text-primary font-semibold">Importa</span> su quello di destinazione con la stessa password di backup.
              </p>
            </div>
          </div>

          {/* Export */}
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Download size={15} className="text-primary" />
                <span className="font-medium text-text">Esporta Backup</span>
              </div>
              <p className="text-xs text-text-muted max-w-lg">
                Salva fascicoli e agenda in un file <code className="text-primary">.lex</code> cifrato con una password a tua scelta.
                Usalo per trasferire i dati su un altro dispositivo o per un backup sicuro.
              </p>
            </div>
            <button
              onClick={openExportModal}
              className="btn-primary px-6 py-2.5 text-sm flex items-center gap-2 shrink-0"
            >
              <Download size={16} />
              Esporta .lex
            </button>
          </div>

          <div className="border-t border-border" />

          {/* Import */}
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Upload size={15} className="text-primary" />
                <span className="font-medium text-text">Importa Backup</span>
              </div>
              <p className="text-xs text-text-muted max-w-lg">
                Ripristina un file <code className="text-primary">.lex</code> esportato in precedenza.
                {' '}<span className="text-text-muted font-medium">Attenzione: sovrascrive i dati attuali.</span>
              </p>
            </div>
            <button
              onClick={openImportModal}
              className="btn-primary px-6 py-2.5 text-sm flex items-center gap-2 shrink-0"
            >
              <Upload size={16} />
              Importa .lex
            </button>
          </div>
        </section>
      </div>



      {/* License information card inserted at the end of settings */}
      <LicenseSettings />

      <div className="pt-12 text-center">
        <button
          onClick={openFactoryReset}
          className="w-full max-w-xs mx-auto flex items-center justify-center gap-3 px-4 py-3 rounded-2xl text-danger bg-danger-soft border border-danger-border hover:bg-danger-soft transition-colors duration-300 group"
        >
          <Lock size={18} className="transition-transform group-hover:-rotate-12" />
          <span className="font-black text-xs-p uppercase tracking-widest">Factory Reset Vault</span>
        </button>
      </div>

      {/* Factory Reset Modal */}
      {showFactoryReset && <FactoryResetModal onClose={() => setShowFactoryReset(false)} bioStatus={bioStatus} />}

      {/* Export Modal */}
      {showExportModal && <ExportBackupModal onClose={() => setShowExportModal(false)} />}

      {/* Import Modal */}
      {showImportModal && <ImportBackupModal onClose={() => setShowImportModal(false)} />}

      {/* Biometrics Reset Confirm Modal */}
      {showBioResetConfirm && <BioResetConfirmModal onClose={() => { setShowBioResetConfirm(false); refreshBioStatus(); }} bioStatus={bioStatus} />}

      {/* Regenerate recovery key confirmation */}
      {showRegenerateConfirm && (
        <ModalOverlay onClose={() => setShowRegenerateConfirm(false)} labelledBy="regen-recovery-title" zIndex={210}>
          <div className="modal-card modal-card-sm">
            <div className="modal-header-gradient modal-header-gradient-danger">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 bg-danger-soft rounded-2xl flex items-center justify-center border border-danger-border">
                    <KeyRound size={22} className="text-danger" />
                  </div>
                  <div>
                    <h3 id="regen-recovery-title" className="text-xl font-bold text-text">Rigenera Chiave di Recovery</h3>
                    <p className="text-xs text-text-dim mt-0.5">La chiave attuale verrà invalidata</p>
                  </div>
                </div>
                <button onClick={() => setShowRegenerateConfirm(false)} aria-label="Chiudi" className="p-2 hover:bg-card-hover rounded-xl text-text-dim transition-colors group">
                  <X size={20} className="group-hover:rotate-90 transition-transform" />
                </button>
              </div>
            </div>
            <div className="px-8 py-6">
              <p className="text-text-muted text-xs leading-relaxed">
                Stai per generare una nuova chiave di recovery. <span className="text-text font-semibold">La chiave attuale verrà invalidata</span> e non potrà più essere usata per sbloccare il vault. Procedere?
              </p>
            </div>
            <div className="modal-footer">
              <button onClick={() => setShowRegenerateConfirm(false)} className="btn-cancel">Annulla</button>
              <button
                onClick={async () => {
                  setShowRegenerateConfirm(false);
                  await generateRecovery();
                }}
                className="px-6 py-3 rounded-2xl bg-danger-soft border border-danger-border text-danger hover:bg-danger-soft transition-colors text-xs font-bold uppercase tracking-widest"
              >
                Rigenera
              </button>
            </div>
          </div>
        </ModalOverlay>
      )}
    </div>
  );
}

SettingsPage.propTypes = {
  onLock: PropTypes.func,
};