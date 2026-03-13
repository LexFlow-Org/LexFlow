import { useState, useCallback, useEffect } from 'react';
import PropTypes from 'prop-types';
import { 
  Shield, 
  Lock, 
  HardDrive, 
  LogOut,
  RefreshCw,
  Bell,
  Camera,
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
function FactoryResetModal({ onClose }) {
  const [pwd, setPwd] = useState('');
  const [error, setError] = useState('');
  const [showPwd, setShowPwd] = useState(false);

  const doReset = async () => {
    if (!pwd) { setError('Password richiesta.'); return; }
    // Extra security: trigger system biometric before factory reset
    try {
      const bioAvail = await api.checkBio();
      if (bioAvail) {
        const bioResult = await api.bioLogin();
        if (!bioResult) {
          setError('Verifica biometrica fallita. Factory reset negato.');
          return;
        }
      }
    } catch { /* bio unavailable — proceed with password only */ }
    const res = await api.resetVault(pwd);
    if (res?.success) { onClose(); globalThis.location.reload(); }
    else { setError(res?.error || 'Password errata.'); }
  };

  return (
    <ModalOverlay onClose={onClose} labelledBy="factory-reset-title" zIndex={200}>
      <div className="modal-card modal-card-sm">
        <div className="modal-header-gradient modal-header-gradient-danger">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-red-500/10 rounded-2xl flex items-center justify-center border border-red-500/20">
                <LogOut size={22} className="text-red-400" />
              </div>
              <div>
                <h3 id="factory-reset-title" className="text-xl font-bold text-text">Factory Reset</h3>
                <p className="text-xs text-text-dim mt-0.5">Tutti i dati verranno eliminati</p>
              </div>
            </div>
            <button onClick={onClose} className="p-2 hover:bg-white/10 rounded-xl text-text-dim transition-all group">
              <X size={20} className="group-hover:rotate-90 transition-transform" />
            </button>
          </div>
        </div>
        <div className="px-8 py-6 space-y-4">
          <p className="text-text-muted text-xs leading-relaxed">
            Stai per cancellare <span className="text-text font-bold">tutti i dati del Vault</span>.
            Inserisci la password per confermare. <span className="font-semibold">Azione irreversibile.</span>
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
              onKeyDown={async (e) => { if (e.key === 'Enter' && pwd) doReset(); }}
            />
            <button type="button" onClick={() => setShowPwd(v => !v)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-text-dim hover:text-text transition-colors">
              {showPwd ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
          {error && <p className="text-red-400 text-[11px] font-semibold">{error}</p>}
        </div>
        <div className="modal-footer">
          <button onClick={onClose} className="btn-cancel">Annulla</button>
          <button onClick={doReset} className="px-6 py-3 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-all text-xs font-bold uppercase tracking-widest">Conferma Reset</button>
        </div>
      </div>
    </ModalOverlay>
  );
}

FactoryResetModal.propTypes = { onClose: PropTypes.func.isRequired };

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
    if (pwd.length < 8) { setError('Password troppo corta (min. 8 caratteri).'); return; }
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
            <button onClick={onClose} className="p-2 hover:bg-white/10 rounded-xl text-text-dim transition-all group">
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
              <input type={showPwd ? 'text' : 'password'}
                className="w-full py-3 pl-10 pr-10 rounded-xl bg-surface border border-border text-text placeholder:text-text-dim/40 text-sm focus:border-primary/40 outline-none transition-colors"
                placeholder="Password backup…"
                value={pwd}
                onChange={e => { setPwd(e.target.value); setError(''); }}
                autoFocus />
              <button type="button" onClick={() => setShowPwd(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-text-dim hover:text-text transition-colors">
                {showPwd ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
            <div className="relative">
              <KeyRound size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-dim" />
              <input type={showPwd ? 'text' : 'password'}
                className="w-full py-3 pl-10 rounded-xl bg-surface border border-border text-text placeholder:text-text-dim/40 text-sm focus:border-primary/40 outline-none transition-colors"
                placeholder="Conferma password…"
                value={pwdConfirm}
                onChange={e => { setPwdConfirm(e.target.value); setError(''); }}
                onKeyDown={e => { if (e.key === 'Enter') doExport(); }} />
            </div>
          </div>
          {error && <p className="text-red-400 text-[11px] font-semibold">{error}</p>}
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
function ImportBackupModal({ onClose }) {
  const [pwd, setPwd] = useState('');
  const [showPwd, setShowPwd] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const doImport = async () => {
    setError('');
    if (!pwd) { setError('Inserisci la password del backup.'); return; }
    if (!api.importVault) { toast.error('Servizio importazione non disponibile'); return; }
    setLoading(true);
    const toastId = toast.loading('Importazione in corso…');
    try {
      const result = await api.importVault(pwd);
      if (result?.cancelled) { toast.dismiss(toastId); return; }
      if (result?.success) {
        toast.success('Vault importato! Ricarico…', { id: toastId });
        onClose();
        setTimeout(() => globalThis.location.reload(), 1500);
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
            <button onClick={onClose} className="p-2 hover:bg-white/10 rounded-xl text-text-dim transition-all group">
              <X size={20} className="group-hover:rotate-90 transition-transform" />
            </button>
          </div>
        </div>
        <div className="px-8 py-6 space-y-4">
          <p className="text-text-muted text-xs leading-relaxed">
            Inserisci la password con cui è stato cifrato il file di backup.
            {' '}<span className="text-text font-semibold">I dati attuali verranno sovrascritti.</span>
          </p>
          <div className="relative">
            <KeyRound size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-dim" />
            <input type={showPwd ? 'text' : 'password'}
              className="w-full py-3 pl-10 pr-10 rounded-xl bg-surface border border-border text-text placeholder:text-text-dim/40 text-sm focus:border-primary/40 outline-none transition-colors"
              placeholder="Password backup…"
              value={pwd}
              onChange={e => { setPwd(e.target.value); setError(''); }}
              autoFocus
              onKeyDown={e => { if (e.key === 'Enter') doImport(); }} />
            <button type="button" onClick={() => setShowPwd(v => !v)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-text-dim hover:text-text transition-colors">
              {showPwd ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
          {error && <p className="text-red-400 text-[11px] font-semibold">{error}</p>}
        </div>
        <div className="modal-footer">
          <button onClick={onClose} className="btn-cancel">Annulla</button>
          <button onClick={doImport} disabled={loading}
            className={`btn-primary px-6 py-3 text-xs font-bold uppercase tracking-widest ${loading ? 'opacity-50' : ''}`}>
            {loading ? 'Importo…' : 'Importa'}
          </button>
        </div>
      </div>
    </ModalOverlay>
  );
}

ImportBackupModal.propTypes = { onClose: PropTypes.func.isRequired };

/* ── Biometric Configuration / Deactivation Modal ── */
function BioResetConfirmModal({ onClose, bioStatus, refreshBioStatus }) {
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
      refreshBioStatus();
      onClose();
    } catch {
      setError('Errore nella configurazione biometrica.');
    }
    setLoading(false);
  };

  // Close after deactivation — refresh status
  const handleCloseAfterDeactivate = () => {
    toast.success("Biometria disattivata");
    refreshBioStatus();
    onClose();
  };

  const stepGradientClass = {
    enroll: 'modal-header-gradient-primary',
    'done-deactivated': 'modal-header-gradient-info',
  };
  const defaultGradientClass = 'modal-header-gradient-danger';

  const stepIconStyles = {
    enroll: 'bg-primary/10 border-primary/20',
    'done-deactivated': 'bg-blue-500/10 border-blue-500/20',
  };
  const defaultIconStyle = 'bg-red-500/10 border-red-500/20';

  const stepIcons = {
    enroll: <Fingerprint size={22} className="text-primary" />,
    'done-deactivated': <ShieldCheck size={22} className="text-blue-400" />,
  };
  const defaultIcon = <RefreshCw size={22} className="text-red-400" />;

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
          <button onClick={onClose} className="p-2 hover:bg-white/10 rounded-xl text-text-dim transition-all group">
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
              className={`px-6 py-3 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-all text-xs font-bold uppercase tracking-widest ${loading ? 'opacity-50' : ''}`}>
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
              <input type={showPwd ? 'text' : 'password'}
                className="w-full py-3 pl-10 pr-10 rounded-xl bg-surface border border-border text-text placeholder:text-text-dim/40 text-sm focus:border-primary/40 outline-none transition-colors"
                placeholder="Master Password…"
                value={pwd}
                onChange={e => { setPwd(e.target.value); setError(''); }}
                autoFocus
                onKeyDown={e => { if (e.key === 'Enter') doEnroll(); }} />
              <button type="button" onClick={() => setShowPwd(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-text-dim hover:text-text transition-colors">
                {showPwd ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
            {error && <p className="text-red-400 text-[11px] font-semibold">{error}</p>}
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

BioResetConfirmModal.propTypes = { onClose: PropTypes.func.isRequired, bioStatus: PropTypes.string, refreshBioStatus: PropTypes.func };

export default function SettingsPage({ onLock }) {
  const [settingsLoaded, setSettingsLoaded] = useState(false);
  const [privacyEnabled, setPrivacyEnabled] = useState(null);
  const [appVersion, setAppVersion] = useState('');
  const [platform, setPlatform] = useState('');

  // Profilo studio (read-only, from license token)
  const [lawyerName, setLawyerName] = useState('');
  const [studioName, setStudioName] = useState('');

  // Stato per le Notifiche
  const [notifyEnabled, setNotifyEnabled] = useState(null);
  const [notificationTime, setNotificationTime] = useState(null);

  // Stato per Sicurezza Avanzata
  const [screenshotProtection, setScreenshotProtection] = useState(null);
  const [autolockMinutes, setAutolockMinutes] = useState(null);
  
  // Modal visibility flags
  const [showFactoryReset, setShowFactoryReset] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [showBioResetConfirm, setShowBioResetConfirm] = useState(false);

  // Biometrics status: 'checking' | 'active' | 'available' | 'unavailable'
  const [bioStatus, setBioStatus] = useState('checking');
  const refreshBioStatus = async () => {
    try {
      const available = await api.checkBio();
      if (!available) { setBioStatus('unavailable'); return; }
      const saved = await api.hasBioSaved();
      setBioStatus(saved ? 'active' : 'available');
    } catch { setBioStatus('unavailable'); }
  };

  const applySettings = (settings) => {
    if (!settings) return;
    const boolFields = [
      ['privacyBlurEnabled', setPrivacyEnabled],
      ['notifyEnabled', setNotifyEnabled],
      ['screenshotProtection', setScreenshotProtection],
    ];
    for (const [key, setter] of boolFields) {
      if (typeof settings[key] === 'boolean') setter(settings[key]);
    }
    // Unify: prefer `preavviso` (Agenda key), fallback to `notificationTime` (legacy Settings key)
    const time = settings.preavviso ?? settings.notificationTime;
    if (time !== undefined) setNotificationTime(time);
    if (settings.autolockMinutes !== undefined) setAutolockMinutes(settings.autolockMinutes);
  };

  const initPlatform = async () => {
    try {
      const p = await api.getPlatform();
      const labels = { macos: 'macOS', windows: 'Windows', android: 'Android', ios: 'iOS', linux: 'Linux' };
      setPlatform(labels[p] || p || 'Desktop');
    } catch {
      const m = await api.isMac();
      setPlatform(m ? 'macOS' : 'Windows');
    }
  };

  useEffect(() => {
    api.getAppVersion().then(setAppVersion);
    initPlatform();
    api.getSettings().then((s) => { applySettings(s); setSettingsLoaded(true); });
    // Load lawyer/studio from license token (read-only, not from settings)
    api.checkLicense().then(res => {
      if (res?.activated) {
        if (res.lawyerName) setLawyerName(res.lawyerName);
        if (res.studioName) setStudioName(res.studioName);
      }
    }).catch(() => { /* silent */ });
    refreshBioStatus();
    // Listen for corrupted settings file event from backend
    const unsubscribe = api.onSettingsCorrupted?.((payload) => {
      toast.error(
        `⚠️ Il file impostazioni era corrotto ed è stato ripristinato ai valori predefiniti. Backup salvato in: ${payload?.backup_path || '(sconosciuto)'}`,
        { duration: 8000 }
      );
    });
    return () => { unsubscribe?.(); };
  }, []);

  const buildFullSettings = useCallback(() => ({
    privacyBlurEnabled: privacyEnabled ?? true,
    notifyEnabled: notifyEnabled ?? true,
    notificationTime: notificationTime ?? 30,
    preavviso: notificationTime ?? 30,
    screenshotProtection: screenshotProtection ?? true,
    autolockMinutes: autolockMinutes ?? 5,
  }), [privacyEnabled, notifyEnabled, notificationTime, screenshotProtection, autolockMinutes]);

  const handlePrivacyToggle = async () => {
    const newValue = !privacyEnabled;
    setPrivacyEnabled(newValue);
    try {
      await api.saveSettings({ ...buildFullSettings(), privacyBlurEnabled: newValue });
      toast.success(newValue ? 'Privacy Blur Attivato' : 'Privacy Blur Disattivato');
    } catch {
      toast.error('Errore salvataggio');
      setPrivacyEnabled(!newValue); 
    }
  };

  const handleScreenshotToggle = async () => {
    const val = !screenshotProtection;
    setScreenshotProtection(val);
    try {
      await api.setContentProtection(val);
      await api.saveSettings({ ...buildFullSettings(), screenshotProtection: val });
      toast.success(val ? 'Screenshot bloccati' : 'Screenshot sbloccati');
    } catch {
      toast.error('Errore');
      setScreenshotProtection(!val);
    }
  };

  const handleAutolockChange = async (opt) => {
    setAutolockMinutes(opt.value);
    try {
      await api.setAutolockMinutes(opt.value);
      await api.saveSettings({ ...buildFullSettings(), autolockMinutes: opt.value });
      toast.success(opt.value === 0 ? 'Blocco automatico disabilitato' : `Blocco dopo ${opt.label} di inattività`);
    } catch {
      toast.error('Errore');
    }
  };

  // Funzione per salvare le impostazioni delle notifiche
  const saveNotifySettings = async (updates) => {
    try {
      await api.saveSettings({ ...buildFullSettings(), ...updates });
      toast.success("Preferenze notifiche aggiornate");
    } catch {
      toast.error("Errore nel salvataggio");
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8 pb-10">
      
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-text tracking-tight mb-2">Impostazioni</h1>
          <p className="text-text-muted text-sm">Gestisci sicurezza e preferenze di LexFlow.</p>
        </div>
        <div className="px-4 py-2 bg-white/5 rounded-lg border border-border text-xs font-mono text-text-dim">
          v{appVersion} • {platform}
        </div>
      </div>

      <div className={`grid gap-6 transition-opacity duration-300 ${settingsLoaded ? 'opacity-100' : 'opacity-0'}`}>
        
        {/* SEZIONE PROFILO STUDIO */}
        {(lawyerName || studioName) && (
        <section className="glass-card p-6 space-y-6">
          <div className="flex items-center gap-3 border-b border-border pb-4 mb-4">
            <Briefcase className="text-primary" size={20} />
            <h2 className="text-lg font-bold text-text">Profilo Studio</h2>
          </div>
          <div className="grid gap-5 sm:grid-cols-2">
            {lawyerName && (
            <div className="space-y-2">
              <label className="text-[10px] font-bold text-text-dim uppercase tracking-wider block">Nome Avvocato</label>
              <div className="w-full bg-white/3 border border-border rounded-xl px-4 py-3 text-sm text-text">
                Avv. {lawyerName}
              </div>
            </div>
            )}
            {studioName && (
            <div className="space-y-2">
              <label className="text-[10px] font-bold text-text-dim uppercase tracking-wider block">Nome Studio</label>
              <div className="w-full bg-white/3 border border-border rounded-xl px-4 py-3 text-sm text-text">
                {studioName}
              </div>
            </div>
            )}
          </div>
          <p className="text-[10px] text-text-dim">Questi dati provengono dalla licenza e vengono utilizzati nell'intestazione dei report PDF.</p>
        </section>
        )}

        {/* SEZIONE NOTIFICHE (AGGIUNTA) */}
        <section className="glass-card p-6 space-y-6">
          <div className="flex items-center gap-3 border-b border-border pb-4 mb-4">
            <Bell className="text-primary" size={20} />
            <h2 className="text-lg font-bold text-text">Notifiche di Sistema</h2>
          </div>

          <div className="flex flex-col gap-6">
            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <span className="font-medium text-text">Avvisi Agenda e Scadenze</span>
                <p className="text-xs text-text-muted max-w-md">
                  Ricevi notifiche desktop per udienze, scadenze e impegni in agenda.
                </p>
              </div>
              <button 
                onClick={() => {
                  const val = !notifyEnabled;
                  setNotifyEnabled(val);
                  saveNotifySettings({ notifyEnabled: val });
                }}
                className={`w-12 h-6 rounded-full transition-colors relative ${notifyEnabled ? 'bg-primary' : 'bg-white/10'}`}
              >
                <div className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform ${notifyEnabled ? 'left-7' : 'left-1'}`} />
              </button>
            </div>

            {notifyEnabled && (
              <div className="pt-4 border-t border-border">
                <span className="text-[10px] font-bold text-text-dim uppercase tracking-wider mb-3 block">Preavviso Standard</span>
                <div className="flex flex-wrap gap-2">
                  {PREAVVISO_OPTIONS.map(opt => (
                    <button
                      key={opt.value}
                      type="button"
                      onClick={() => {
                        setNotificationTime(opt.value);
                        saveNotifySettings({ notificationTime: opt.value, preavviso: opt.value });
                      }}
                      className={`px-4 py-2 rounded-xl text-xs font-semibold transition-all border ${
                        notificationTime === opt.value
                          ? 'bg-primary text-black border-primary shadow-[0_0_12px_rgba(212,169,64,0.3)]'
                          : 'bg-white/[0.04] text-text-muted border-border hover:bg-white/[0.08] hover:text-text'
                      }`}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </section>

        {/* Sezione Sicurezza */}
        <section className="glass-card p-6 space-y-6">
          <div className="flex items-center gap-3 border-b border-border pb-4 mb-4">
            <Shield className="text-primary" size={20} />
            <h2 className="text-lg font-bold text-text">Sicurezza & Privacy</h2>
          </div>

          <div className="flex items-center justify-between group">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="font-medium text-text">Privacy Blur</span>
                <span className="text-[10px] bg-primary/20 text-primary px-2 py-0.5 rounded border border-primary/20">CONSIGLIATO</span>
              </div>
              <p className="text-xs text-text-muted max-w-md">
                Sfoca automaticamente il contenuto dell'app quando perdi il focus.
              </p>
            </div>
            <button 
              onClick={handlePrivacyToggle}
              className={`w-12 h-6 rounded-full transition-colors relative ${privacyEnabled ? 'bg-primary' : 'bg-white/10'}`}
            >
              <div className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform duration-200 ${privacyEnabled ? 'left-7' : 'left-1'}`} />
            </button>
          </div>

          {/* Anti-Screenshot */}
          <div className="flex items-center justify-between group pt-4 border-t border-border">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Camera size={16} className="text-primary" />
                <span className="font-medium text-text">Blocco Screenshot</span>
                <span className="text-[10px] bg-primary/10 text-primary px-2 py-0.5 rounded border border-primary/20">SICUREZZA</span>
              </div>
              <p className="text-xs text-text-muted max-w-md">
                Impedisce la cattura dello schermo (screenshot, registrazioni, condivisione schermo).
              </p>
            </div>
            <button 
              onClick={handleScreenshotToggle}
              className={`w-12 h-6 rounded-full transition-colors relative ${screenshotProtection ? 'bg-primary' : 'bg-white/10'}`}
            >
              <div className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform duration-200 ${screenshotProtection ? 'left-7' : 'left-1'}`} />
            </button>
          </div>

          {/* Auto-Lock Timer */}
          <div className="pt-4 border-t border-border">
            <div className="flex items-center gap-2 mb-1">
              <Timer size={16} className="text-primary" />
              <span className="font-medium text-text">Blocco Automatico</span>
            </div>
            <p className="text-xs text-text-muted max-w-md mb-4">
              Blocca automaticamente il Vault dopo un periodo di inattività.
            </p>
            <div className="flex flex-wrap gap-2">
              {AUTOLOCK_OPTIONS.map(opt => (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => handleAutolockChange(opt)}
                  className={`px-4 py-2 rounded-xl text-xs font-semibold transition-all border ${
                    autolockMinutes === opt.value
                      ? 'bg-primary text-black border-primary shadow-[0_0_12px_rgba(212,169,64,0.3)]'
                      : 'bg-white/[0.04] text-text-muted border-border hover:bg-white/[0.08] hover:text-text'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            <button 
              onClick={onLock}
              className="flex items-center justify-center gap-3 p-4 rounded-xl bg-white/5 hover:bg-white/10 border border-border text-text transition-all group"
            >
              <Lock size={18} className="text-primary transition-transform group-hover:-rotate-12" />
              <span className="text-sm font-bold uppercase tracking-wider">Blocca Vault Ora</span>
            </button>
            <button 
              onClick={() => setShowBioResetConfirm(true)}
              className={`flex items-center gap-4 p-4 rounded-xl border transition-all group relative ${
                {
                  active: 'bg-emerald-500/5 hover:bg-emerald-500/10 border-emerald-500/20',
                  available: 'bg-amber-500/5 hover:bg-amber-500/10 border-amber-500/20',
                }[bioStatus] || 'bg-white/5 hover:bg-white/10 border-white/10'
              }`}
            >
              <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${
                { active: 'bg-emerald-500/15', available: 'bg-amber-500/15' }[bioStatus] || 'bg-white/5'
              }`}>
                <Fingerprint size={20} className={
                  {
                    active: 'text-emerald-400',
                    available: 'text-amber-400',
                    checking: 'text-text-dim animate-pulse',
                  }[bioStatus] || 'text-text-dim'
                } />
              </div>
              <div className="flex flex-col items-start">
                <span className="text-sm font-bold text-text">Biometria</span>
                <span className={`text-[10px] font-bold uppercase tracking-wider ${
                  {
                    active: 'text-emerald-400',
                    available: 'text-amber-400',
                    checking: 'text-text-dim animate-pulse',
                  }[bioStatus] || 'text-text-dim'
                }`}>
                  {bioStatus === 'active' && '✓ Attiva — Face ID / Touch ID'}
                  {bioStatus === 'available' && '○ Non configurata'}
                  {bioStatus === 'unavailable' && '✕ Non disponibile'}
                  {bioStatus === 'checking' && 'Verifica…'}
                </span>
              </div>
            </button>
          </div>
        </section>

        {/* Sezione Dati */}
        <section className="glass-card p-6 space-y-6">
          <div className="flex items-center gap-3 border-b border-border pb-4 mb-4">
            <HardDrive className="text-primary" size={20} />
            <h2 className="text-lg font-bold text-text">Gestione Dati</h2>
          </div>

          {/* Banner sistema chiuso */}
          <div className="flex items-start gap-3 p-4 rounded-xl bg-white/[0.03] border border-border">
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
              onClick={() => setShowExportModal(true)}
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
              onClick={() => setShowImportModal(true)}
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
          onClick={() => setShowFactoryReset(true)}
          className="w-full max-w-xs mx-auto flex items-center justify-center gap-3 px-4 py-3 rounded-2xl text-red-500 bg-red-500/10 border border-red-500/20 hover:bg-red-500/20 transition-all duration-300 group"
        >
          <Lock size={18} className="transition-transform group-hover:-rotate-12" />
          <span className="font-black text-[11px] uppercase tracking-widest">Factory Reset Vault</span>
        </button>
      </div>

      {/* Factory Reset Modal */}
      {showFactoryReset && <FactoryResetModal onClose={() => setShowFactoryReset(false)} />}

      {/* Export Modal */}
      {showExportModal && <ExportBackupModal onClose={() => setShowExportModal(false)} />}

      {/* Import Modal */}
      {showImportModal && <ImportBackupModal onClose={() => setShowImportModal(false)} />}

      {/* Biometrics Reset Confirm Modal */}
      {showBioResetConfirm && <BioResetConfirmModal onClose={() => { setShowBioResetConfirm(false); refreshBioStatus(); }} bioStatus={bioStatus} refreshBioStatus={refreshBioStatus} />}
    </div>
  );
}

SettingsPage.propTypes = {
  onLock: PropTypes.func,
};