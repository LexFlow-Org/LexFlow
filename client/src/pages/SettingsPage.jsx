import { useState, useCallback } from 'react';
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
  X
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

/* ── Shared Modal Sub-Components ── */

/** Header gradient bar with icon, title, subtitle, close button */
function ModalHeader({ id, icon: Icon, iconBg, iconBorder, iconColor, title, subtitle, onClose }) {
  const gradient = iconColor === 'text-red-400'
    ? 'linear-gradient(135deg, rgba(239,68,68,0.08) 0%, rgba(239,68,68,0.02) 100%)'
    : 'linear-gradient(135deg, rgba(212,169,64,0.08) 0%, rgba(212,169,64,0.02) 100%)';
  return (
    <div className="px-8 pt-8 pb-5" style={{ background: gradient }}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className={`w-12 h-12 ${iconBg} rounded-2xl flex items-center justify-center border ${iconBorder}`}>
            <Icon size={22} className={iconColor} />
          </div>
          <div>
            <h3 id={id} className="text-xl font-bold text-white">{title}</h3>
            <p className="text-xs text-text-dim mt-0.5">{subtitle}</p>
          </div>
        </div>
        <button onClick={onClose} className="p-2 hover:bg-white/10 rounded-xl text-text-dim transition-all group">
          <X size={20} className="group-hover:rotate-90 transition-transform" />
        </button>
      </div>
    </div>
  );
}


ModalHeader.propTypes = {
  id: PropTypes.string.isRequired,
  icon: PropTypes.elementType.isRequired,
  iconBg: PropTypes.string.isRequired,
  iconBorder: PropTypes.string.isRequired,
  iconColor: PropTypes.string.isRequired,
  title: PropTypes.string.isRequired,
  subtitle: PropTypes.string.isRequired,
  onClose: PropTypes.func.isRequired,
};
/** Password input with KeyRound icon and show/hide toggle */
function PasswordField({ value, onChange, showPwd, onToggle, placeholder = 'Password…', autoFocus = false, onKeyDown }) {
  return (
    <div className="relative">
      <KeyRound size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-dim" />
      <input
        type={showPwd ? 'text' : 'password'}
        className="w-full py-3 pl-10 pr-10 rounded-xl bg-white/5 border border-white/10 text-white placeholder:text-white/20 text-sm focus:border-primary/40 outline-none transition-colors"
        placeholder={placeholder}
        value={value}
        onChange={onChange}
        autoFocus={autoFocus}
        onKeyDown={onKeyDown}
      />
      <button type="button" onClick={onToggle}
        className="absolute right-3 top-1/2 -translate-y-1/2 text-text-dim hover:text-white transition-colors">
        {showPwd ? <EyeOff size={16} /> : <Eye size={16} />}
      </button>
    </div>
  );
}

PasswordField.propTypes = {
  value: PropTypes.string.isRequired,
  onChange: PropTypes.func.isRequired,
  showPwd: PropTypes.bool.isRequired,
  onToggle: PropTypes.func.isRequired,
  placeholder: PropTypes.string,
  autoFocus: PropTypes.bool,
  onKeyDown: PropTypes.func,
};

/** Standard footer: Annulla + action button */
function ModalFooter({ onClose, onAction, actionLabel, actionClass, disabled }) {
  return (
    <div className="flex justify-end gap-3 px-8 py-5 bg-[#14151d] border-t border-white/5">
      <button onClick={onClose} className="px-6 py-3 rounded-2xl text-text-dim hover:text-white hover:bg-white/5 transition-all text-xs font-bold uppercase tracking-widest">Annulla</button>
      <button onClick={onAction} disabled={disabled}
        className={`px-6 py-3 text-xs font-bold uppercase tracking-widest ${actionClass || 'btn-primary'} ${disabled ? 'opacity-50' : ''}`}>
        {actionLabel}
      </button>
    </div>
  );
}


ModalFooter.propTypes = {
  onClose: PropTypes.func.isRequired,
  onAction: PropTypes.func.isRequired,
  actionLabel: PropTypes.string.isRequired,
  actionClass: PropTypes.string,
  disabled: PropTypes.bool,
};
/* ── Factory Reset Modal ── */
function FactoryResetModal({ onClose }) {
  const [pwd, setPwd] = useState('');
  const [error, setError] = useState('');
  const [showPwd, setShowPwd] = useState(false);

  const doReset = async () => {
    if (!pwd) { setError('Password richiesta.'); return; }
    const res = await api.resetVault(pwd);
    if (res?.success) { onClose(); globalThis.location.reload(); }
    else { setError(res?.error || 'Password errata.'); }
  };

  return (
    <ModalOverlay onClose={onClose} labelledBy="factory-reset-title" zIndex={200}>
      <div className="bg-[#0f1016] border border-white/10 rounded-[32px] max-w-md w-full shadow-2xl overflow-hidden">
        <ModalHeader id="factory-reset-title" icon={LogOut} iconBg="bg-red-500/10" iconBorder="border-red-500/20" iconColor="text-red-400"
          title="Factory Reset" subtitle="Tutti i dati verranno eliminati" onClose={onClose} />
        <div className="px-8 py-6 space-y-4">
          <p className="text-text-muted text-xs leading-relaxed">
            Stai per cancellare <span className="text-white font-bold">tutti i dati del Vault</span>.
            Inserisci la password per confermare. <span className="font-semibold">Azione irreversibile.</span>
          </p>
          <PasswordField value={pwd} onChange={e => { setPwd(e.target.value); setError(''); }}
            showPwd={showPwd} onToggle={() => setShowPwd(v => !v)} placeholder="Password vault…" autoFocus
            onKeyDown={async (e) => { if (e.key === 'Enter' && pwd) doReset(); }} />
          {error && <p className="text-red-400 text-[11px] font-semibold">{error}</p>}
        </div>
        <ModalFooter onClose={onClose} onAction={doReset} actionLabel="Conferma Reset"
          actionClass="rounded-2xl bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-all" />
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
      <div className="bg-[#0f1016] border border-white/10 rounded-[32px] max-w-md w-full shadow-2xl overflow-hidden">
        <ModalHeader id="export-backup-title" icon={Download} iconBg="bg-primary/10" iconBorder="border-primary/20" iconColor="text-primary"
          title="Esporta Backup" subtitle="Crea un file .lex cifrato" onClose={onClose} />
        <div className="px-8 py-6 space-y-4">
          <p className="text-text-muted text-xs leading-relaxed">
            Scegli una password per proteggere il file di backup. Ti servirà per importarlo su un altro dispositivo.
          </p>
          <div className="space-y-3">
            <PasswordField value={pwd} onChange={e => { setPwd(e.target.value); setError(''); }}
              showPwd={showPwd} onToggle={() => setShowPwd(v => !v)} placeholder="Password backup…" autoFocus />
            <div className="relative">
              <KeyRound size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-dim" />
              <input type={showPwd ? 'text' : 'password'}
                className="w-full py-3 pl-10 rounded-xl bg-white/5 border border-white/10 text-white placeholder:text-white/20 text-sm focus:border-primary/40 outline-none transition-colors"
                placeholder="Conferma password…"
                value={pwdConfirm}
                onChange={e => { setPwdConfirm(e.target.value); setError(''); }}
                onKeyDown={e => { if (e.key === 'Enter') doExport(); }} />
            </div>
          </div>
          {error && <p className="text-red-400 text-[11px] font-semibold">{error}</p>}
        </div>
        <ModalFooter onClose={onClose} onAction={doExport} actionLabel={loading ? 'Esporto…' : 'Esporta'} disabled={loading} />
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
      <div className="bg-[#0f1016] border border-white/10 rounded-[32px] max-w-md w-full shadow-2xl overflow-hidden">
        <ModalHeader id="import-backup-title" icon={Upload} iconBg="bg-primary/10" iconBorder="border-primary/20" iconColor="text-primary"
          title="Importa Backup" subtitle="Sovrascrive i dati attuali" onClose={onClose} />
        <div className="px-8 py-6 space-y-4">
          <p className="text-text-muted text-xs leading-relaxed">
            Inserisci la password con cui è stato cifrato il file di backup.
            {' '}<span className="text-white font-semibold">I dati attuali verranno sovrascritti.</span>
          </p>
          <PasswordField value={pwd} onChange={e => { setPwd(e.target.value); setError(''); }}
            showPwd={showPwd} onToggle={() => setShowPwd(v => !v)} placeholder="Password backup…" autoFocus
            onKeyDown={e => { if (e.key === 'Enter') doImport(); }} />
          {error && <p className="text-red-400 text-[11px] font-semibold">{error}</p>}
        </div>
        <ModalFooter onClose={onClose} onAction={doImport} actionLabel={loading ? 'Importo…' : 'Importa'} disabled={loading} />
      </div>
    </ModalOverlay>
  );
}

ImportBackupModal.propTypes = { onClose: PropTypes.func.isRequired };

/* ── Biometric Reset Confirm Modal ── */
function BioResetConfirmModal({ onClose }) {
  const handleConfirm = () => {
    onClose();
    api.clearBio()
      .then(() => toast.success("Biometria resettata"))
      .catch(() => toast.error("Errore nel reset biometria"));
  };

  return (
    <ModalOverlay onClose={onClose} labelledBy="bio-reset-title" zIndex={200}>
      <div className="bg-[#0f1016] border border-white/10 rounded-[32px] max-w-md w-full shadow-2xl overflow-hidden">
        <ModalHeader id="bio-reset-title" icon={RefreshCw} iconBg="bg-red-500/10" iconBorder="border-red-500/20" iconColor="text-red-400"
          title="Resetta Biometria" subtitle="Azione irreversibile" onClose={onClose} />
        <div className="px-8 py-6">
          <p className="text-text-muted text-xs leading-relaxed">
            Cancellare le credenziali biometriche salvate? Dovrai reinserire la password e riconfigurare la biometria.
          </p>
        </div>
        <ModalFooter onClose={onClose} onAction={handleConfirm} actionLabel="Conferma"
          actionClass="rounded-2xl bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-all" />
      </div>
    </ModalOverlay>
  );
}

BioResetConfirmModal.propTypes = { onClose: PropTypes.func.isRequired };

export default function SettingsPage({ onLock }) {
  const [privacyEnabled, setPrivacyEnabled] = useState(true);
  const [appVersion, setAppVersion] = useState('');
  const [platform, setPlatform] = useState('');

  // Stato per le Notifiche
  const [notifyEnabled, setNotifyEnabled] = useState(true);
  const [notificationTime, setNotificationTime] = useState(30);

  // Stato per Sicurezza Avanzata
  const [screenshotProtection, setScreenshotProtection] = useState(true);
  const [autolockMinutes, setAutolockMinutes] = useState(5);
  
  // Modal visibility flags
  const [showFactoryReset, setShowFactoryReset] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [showImportModal, setShowImportModal] = useState(false);
  const [showBioResetConfirm, setShowBioResetConfirm] = useState(false);

  const applySettings = (settings) => {
    if (!settings) return;
    if (typeof settings.privacyBlurEnabled === 'boolean') setPrivacyEnabled(settings.privacyBlurEnabled);
    if (typeof settings.notifyEnabled === 'boolean') setNotifyEnabled(settings.notifyEnabled);
    if (settings.notificationTime) setNotificationTime(settings.notificationTime);
    if (typeof settings.screenshotProtection === 'boolean') setScreenshotProtection(settings.screenshotProtection);
    if (settings.autolockMinutes !== undefined) setAutolockMinutes(settings.autolockMinutes);
  };

  useEffect(() => {
    api.getAppVersion().then(setAppVersion);
    api.isMac().then(isMac => setPlatform(isMac ? 'macOS' : 'Windows'));
    api.getSettings().then(applySettings);
  }, []);

  const buildFullSettings = useCallback(() => ({
    privacyBlurEnabled: privacyEnabled,
    notifyEnabled,
    notificationTime,
    screenshotProtection,
    autolockMinutes,
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
          <h1 className="text-3xl font-bold text-white tracking-tight mb-2">Impostazioni</h1>
          <p className="text-text-muted text-sm">Gestisci sicurezza e preferenze di LexFlow.</p>
        </div>
        <div className="px-4 py-2 bg-white/5 rounded-lg border border-white/10 text-xs font-mono text-text-dim">
          v{appVersion} • {platform}
        </div>
      </div>

      <div className="grid gap-6">
        
        {/* SEZIONE NOTIFICHE (AGGIUNTA) */}
        <section className="glass-card p-6 space-y-6">
          <div className="flex items-center gap-3 border-b border-white/5 pb-4 mb-4">
            <Bell className="text-primary" size={20} />
            <h2 className="text-lg font-bold text-white">Notifiche di Sistema</h2>
          </div>

          <div className="flex flex-col gap-6">
            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <span className="font-medium text-white">Avvisi Agenda e Scadenze</span>
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
              <div className="pt-4 border-t border-white/5">
                <span className="text-[10px] font-bold text-text-dim uppercase tracking-wider mb-3 block">Preavviso Standard</span>
                <div className="flex flex-wrap gap-2">
                  {PREAVVISO_OPTIONS.map(opt => (
                    <button
                      key={opt.value}
                      type="button"
                      onClick={() => {
                        setNotificationTime(opt.value);
                        saveNotifySettings({ notificationTime: opt.value });
                      }}
                      className={`px-4 py-2 rounded-xl text-xs font-semibold transition-all border ${
                        notificationTime === opt.value
                          ? 'bg-primary text-black border-primary shadow-[0_0_12px_rgba(212,169,64,0.3)]'
                          : 'bg-white/[0.04] text-text-muted border-white/5 hover:bg-white/[0.08] hover:text-white'
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
          <div className="flex items-center gap-3 border-b border-white/5 pb-4 mb-4">
            <Shield className="text-primary" size={20} />
            <h2 className="text-lg font-bold text-white">Sicurezza & Privacy</h2>
          </div>

          <div className="flex items-center justify-between group">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="font-medium text-white">Privacy Blur</span>
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
          <div className="flex items-center justify-between group pt-4 border-t border-white/5">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Camera size={16} className="text-primary" />
                <span className="font-medium text-white">Blocco Screenshot</span>
                <span className="text-[10px] bg-primary/10 text-primary px-2 py-0.5 rounded border border-primary/20">SICUREZZA</span>
              </div>
              <p className="text-xs text-text-muted max-w-md">
                Impedisce la cattura dello schermo (screenshot, registrazioni, condivisione schermo).
              </p>
            </div>
            <button 
              onClick={async () => {
                const val = !screenshotProtection;
                setScreenshotProtection(val);
                try {
                  await api.setContentProtection(val);
                  await api.saveSettings({ ...buildFullSettings(), screenshotProtection: val });
                  toast.success(val ? 'Blocco Screenshot Attivato' : 'Blocco Screenshot Disattivato');
                } catch {
                  toast.error('Errore');
                  setScreenshotProtection(!val);
                }
              }}
              className={`w-12 h-6 rounded-full transition-colors relative ${screenshotProtection ? 'bg-primary' : 'bg-white/10'}`}
            >
              <div className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform duration-200 ${screenshotProtection ? 'left-7' : 'left-1'}`} />
            </button>
          </div>

          {/* Auto-Lock Timer */}
          <div className="pt-4 border-t border-white/5">
            <div className="flex items-center gap-2 mb-1">
              <Timer size={16} className="text-primary" />
              <span className="font-medium text-white">Blocco Automatico</span>
            </div>
            <p className="text-xs text-text-muted max-w-md mb-4">
              Blocca automaticamente il Vault dopo un periodo di inattività.
            </p>
            <div className="flex flex-wrap gap-2">
              {AUTOLOCK_OPTIONS.map(opt => (
                <button
                  key={opt.value}
                  type="button"
                  onClick={async () => {
                    setAutolockMinutes(opt.value);
                    try {
                      await api.setAutolockMinutes(opt.value);
                      await api.saveSettings({ ...buildFullSettings(), autolockMinutes: opt.value });
                      toast.success(opt.value === 0 ? 'Blocco automatico disabilitato' : `Blocco dopo ${opt.label} di inattività`);
                    } catch {
                      toast.error('Errore');
                    }
                  }}
                  className={`px-4 py-2 rounded-xl text-xs font-semibold transition-all border ${
                    autolockMinutes === opt.value
                      ? 'bg-primary text-black border-primary shadow-[0_0_12px_rgba(212,169,64,0.3)]'
                      : 'bg-white/[0.04] text-text-muted border-white/5 hover:bg-white/[0.08] hover:text-white'
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
              className="flex items-center justify-center gap-3 p-4 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-white transition-all group"
            >
              <Lock size={18} className="text-primary transition-transform group-hover:-rotate-12" />
              <span className="text-sm font-bold uppercase tracking-wider">Blocca Vault Ora</span>
            </button>
            <button 
              onClick={() => setShowBioResetConfirm(true)}
              className="flex items-center justify-center gap-3 p-4 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-white transition-all group"
            >
              <RefreshCw size={18} className="text-text-dim group-hover:rotate-180 transition-transform duration-500" />
              <span className="text-sm font-medium">Resetta Biometria</span>
            </button>
          </div>
        </section>

        {/* Sezione Dati */}
        <section className="glass-card p-6 space-y-6">
          <div className="flex items-center gap-3 border-b border-white/5 pb-4 mb-4">
            <HardDrive className="text-primary" size={20} />
            <h2 className="text-lg font-bold text-white">Gestione Dati</h2>
          </div>

          {/* Banner sistema chiuso */}
          <div className="flex items-start gap-3 p-4 rounded-xl bg-white/[0.03] border border-white/10">
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
                <span className="font-medium text-white">Esporta Backup</span>
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

          <div className="border-t border-white/5" />

          {/* Import */}
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Upload size={15} className="text-primary" />
                <span className="font-medium text-white">Importa Backup</span>
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
          className="text-[10px] font-black text-red-500/30 hover:text-red-500 uppercase tracking-[4px] transition-all flex items-center justify-center gap-3 mx-auto py-4 border border-transparent hover:border-red-500/10 rounded-full px-8"
        >
          <LogOut size={14} />
          Factory Reset Vault
        </button>
      </div>

      {/* Factory Reset Modal */}
      {showFactoryReset && <FactoryResetModal onClose={() => setShowFactoryReset(false)} />}

      {/* Export Modal */}
      {showExportModal && <ExportBackupModal onClose={() => setShowExportModal(false)} />}

      {/* Import Modal */}
      {showImportModal && <ImportBackupModal onClose={() => setShowImportModal(false)} />}

      {/* Biometrics Reset Confirm Modal */}
      {showBioResetConfirm && <BioResetConfirmModal onClose={() => setShowBioResetConfirm(false)} />}
    </div>
  );
}

SettingsPage.propTypes = {
  onLock: PropTypes.func,
};