import { useState, useRef, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import { 
  Eye, 
  EyeOff, 
  ShieldCheck, 
  Fingerprint, 
  KeyRound, 
  ShieldAlert, 
  CheckCircle2,
  Timer,
  X
} from 'lucide-react';
import logoSrc from '../assets/logo.png';
import * as api from '../tauri-api';
import ConfirmDialog from './ConfirmDialog';

export default function LoginScreen({ onUnlock, autoLocked = false }) {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadingText, setLoadingText] = useState('Sblocco...');
  const [isNew, setIsNew] = useState(null);
  const [showPwd, setShowPwd] = useState(false);
  
  // Brute-force lockout countdown
  const [lockoutSeconds, setLockoutSeconds] = useState(0);
  const lockoutTimer = useRef(null);
  
  // Stati per la Biometria
  const [bioAvailable, setBioAvailable] = useState(false);
  const [bioSaved, setBioSaved] = useState(false);
  const [bioFailed, setBioFailed] = useState(0);
  const [showPasswordField, setShowPasswordField] = useState(false);
  
  // Modal per Reset Vault (sostituisce window.prompt -- non mostra password in chiaro)
  const [showResetModal, setShowResetModal] = useState(false);
  const [resetPassword, setResetPassword] = useState('');
  const [resetError, setResetError] = useState('');

  const executeReset = useCallback(async () => {
    if (!resetPassword) { setResetError('Password richiesta.'); return; }
    const result = await api.resetVault(resetPassword);
    if (result?.success) {
      setShowResetModal(false);
      setIsNew(true); setPassword(''); setConfirm(''); setError(''); setBioSaved(false);
    } else {
      setResetError(result?.error || 'Password errata.');
    }
  }, [resetPassword]);

  // Modal per consenso biometria (sostituisce window.confirm)
  const [showBioConsent, setShowBioConsent] = useState(false);
  const bioConsentPasswordRef = useRef('');
  
  const bioTriggered = useRef(false);
  const bioAutoTriggeredOnReturn = useRef(false);
  // Track if a bio login attempt is currently in-flight to prevent double-triggers
  const bioInFlight = useRef(false);
  const MAX_BIO_ATTEMPTS = 3;

  // ─── Biometric login handler (defined as ref to avoid stale closures in effects) ──
  const handleBioLoginRef = useRef(null);

  /** Complete a successful biometric unlock */
  const completeBioUnlock = () => {
    setPassword('');
    setShowPasswordField(false);
    setLoading(false);
    onUnlock();
  };

  /** Handle biometric login error */
  const handleBioError = (err, isAutomatic) => {
    const errMsg = err?.message || String(err);
    const isAndroidHandoff = errMsg.includes('android-bio-use-frontend');

    console.warn("Login bio fallito:", isAndroidHandoff ? "(Android handoff)" : err);

    const nextFailed = bioFailed + (isAndroidHandoff ? 0 : 1);
    if (!isAndroidHandoff) setBioFailed(prev => prev + 1);

    setShowPasswordField(true);

    if (nextFailed >= MAX_BIO_ATTEMPTS) {
      setError('Troppi tentativi falliti. Usa la password.');
    } else if (!isAutomatic && !isAndroidHandoff) {
      setError('Riconoscimento fallito o annullato.');
    }
  };

  const handleBioLogin = async (isAutomatic = false) => {
    if (bioInFlight.current) return;
    bioInFlight.current = true;

    setError('');
    setLoading(true);
    setLoadingText('Autenticazione...');
    let unlocked = false;

    try {
      if (!api) throw new Error("API non disponibile");

      const bioResult = await api.loginBio();
      if (!bioResult) throw new Error("Autenticazione annullata o fallita");

      if (typeof bioResult === 'object' && bioResult.success) {
        unlocked = true;
        completeBioUnlock();
        return;
      }

      const savedPassword = typeof bioResult === 'string' ? bioResult : JSON.stringify(bioResult);
      const result = await api.unlockVault(savedPassword);
      if (result.success) {
        unlocked = true;
        completeBioUnlock();
        return;
      }
      throw new Error(result.error || "Errore decifratura vault");
    } catch (err) {
      handleBioError(err, isAutomatic);
    } finally {
      bioInFlight.current = false;
      if (!unlocked) setLoading(false);
    }
  };

  // Keep the ref up-to-date so effects always call the latest version
  handleBioLoginRef.current = handleBioLogin;

  /** Initialize biometric state after vault existence is confirmed */
  const initBiometrics = async () => {
    try {
      const available = await api.checkBio();
      setBioAvailable(available);
      if (!available) { setShowPasswordField(true); return; }

      const saved = await api.hasBioSaved();
      setBioSaved(saved);
      if (!saved) { setShowPasswordField(true); return; }

      if (!bioTriggered.current) {
        bioTriggered.current = true;
        setShowPasswordField(false);
        // Only auto-trigger biometric if the window actually has focus
        // to avoid Touch ID appearing over other apps
        const triggerBioNow = () => {
          if (handleBioLoginRef.current) handleBioLoginRef.current(true);
        };
        const onWindowFocus = () => {
          window.removeEventListener('focus', onWindowFocus);
          setTimeout(triggerBioNow, 300);
        };
        const triggerWhenFocused = () => {
          if (document.hasFocus()) {
            triggerBioNow();
          } else {
            window.addEventListener('focus', onWindowFocus);
          }
        };
        setTimeout(triggerWhenFocused, 400);
      }
    } catch (err) {
      console.warn("Errore inizializzazione bio:", err);
      setShowPasswordField(true);
    }
  };

  useEffect(() => {
    const init = async () => {
      try {
        const exists = await api.vaultExists();
        setIsNew(!exists);
        if (!exists) { setShowPasswordField(true); return; }
        await initBiometrics();
      } catch (err) {
        console.error("Errore inizializzazione vault:", err);
        setError("Errore critico di sistema");
      }
    };

    init();
  }, []);

  // ─── Auto-trigger biometria quando l'utente torna sulla finestra (autolock) ──
  useEffect(() => {
    // Solo se: autoLocked + biometria disponibile e salvata + pochi tentativi falliti
    if (!autoLocked || !bioAvailable || !bioSaved || bioFailed >= MAX_BIO_ATTEMPTS) return;
    if (isNew) return;

    const triggerBio = () => {
      // Only trigger if the window actually has OS-level focus
      if (!document.hasFocus()) return;
      // Always call the latest version via ref — avoids stale closure bugs
      if (handleBioLoginRef.current) handleBioLoginRef.current(true);
    };

    const handleVisibility = () => {
      // document.visibilityState === 'visible' → l'utente è tornato su LexFlow
      // Also require hasFocus() to avoid triggering over other apps
      if (document.visibilityState === 'visible' && document.hasFocus() && !bioAutoTriggeredOnReturn.current && !showPasswordField) {
        bioAutoTriggeredOnReturn.current = true;
        // Breve delay per dare tempo al focus della finestra
        setTimeout(triggerBio, 300);
      }
    };

    // Se la finestra è già visibile E focused (l'utente è davanti a LexFlow), triggera subito
    if (document.visibilityState === 'visible' && document.hasFocus() && !bioAutoTriggeredOnReturn.current && !showPasswordField) {
      bioAutoTriggeredOnReturn.current = true;
      setTimeout(triggerBio, 600);
    }

    document.addEventListener('visibilitychange', handleVisibility);
    // Anche su focus della finestra (più affidabile su macOS con Tauri)
    const handleFocus = () => {
      if (!bioAutoTriggeredOnReturn.current && !showPasswordField) {
        bioAutoTriggeredOnReturn.current = true;
        setTimeout(triggerBio, 300);
      }
    };
    window.addEventListener('focus', handleFocus);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibility);
      window.removeEventListener('focus', handleFocus);
    };
  }, [autoLocked, bioAvailable, bioSaved, bioFailed, isNew, showPasswordField]);

  // ─── Countdown timer per lockout brute-force ───────────────────────────────
  const isLockedOut = lockoutSeconds > 0;
  useEffect(() => {
    if (!isLockedOut) {
      if (lockoutTimer.current) clearInterval(lockoutTimer.current);
      return;
    }
    lockoutTimer.current = setInterval(() => {
      setLockoutSeconds(prev => {
        if (prev <= 1) {
          clearInterval(lockoutTimer.current);
          lockoutTimer.current = null;
          setError('');
          return 0;
        }
        const next = prev - 1;
        const mm = String(Math.floor(next / 60)).padStart(2, '0');
        const ss = String(next % 60).padStart(2, '0');
        setError(`Troppi tentativi falliti. Riprova tra ${mm}:${ss}`);
        return next;
      });
    }, 1000);
    return () => { if (lockoutTimer.current) clearInterval(lockoutTimer.current); };
  }, [isLockedOut]); // re-trigger only on transition 0→positive

  const getStrength = (pwd) => {
    if (!pwd) return { label: '', color: 'bg-white/10', text: 'text-white/10', pct: 0, segments: 0 };
    let score = 0;
    if (pwd.length >= 8) score++;
    if (pwd.length >= 12) score++;
    if (/[A-Z]/.test(pwd)) score++;
    if (/[a-z]/.test(pwd)) score++;
    if (/\d/.test(pwd)) score++;
    if (/[^A-Za-z0-9]/.test(pwd)) score++;
    // 6 criteri → 6 segmenti. "Eccellente" (6/6) = isPasswordStrong soddisfatto
    if (score <= 1) return { label: 'Debole', color: 'bg-red-500', text: 'text-red-500', pct: 17, segments: 1 };
    if (score <= 2) return { label: 'Insufficiente', color: 'bg-orange-500', text: 'text-orange-500', pct: 33, segments: 2 };
    if (score <= 3) return { label: 'Sufficiente', color: 'bg-yellow-500', text: 'text-yellow-500', pct: 50, segments: 3 };
    if (score <= 4) return { label: 'Buona', color: 'bg-amber-400', text: 'text-amber-400', pct: 67, segments: 4 };
    if (score <= 5) return { label: 'Forte', color: 'bg-primary', text: 'text-primary', pct: 83, segments: 5 };
    return { label: 'Eccellente', color: 'bg-emerald-500', text: 'text-emerald-500', pct: 100, segments: 6 };
  };

  const isPasswordStrong = (pwd) => {
    return pwd.length >= 12 && /[A-Z]/.test(pwd) && /[a-z]/.test(pwd) && /\d/.test(pwd) && /[!@#$%^&*()\-_=+[\]{};':"\\|,.<>/?]/.test(pwd);
  };

  /** Handle unlock failure — sets error and lockout state */
  const handleUnlockFailure = (result) => {
    if (result.locked && result.remaining) {
      const secs = Math.ceil(Number(result.remaining));
      setLockoutSeconds(secs);
      const mm = String(Math.floor(secs / 60)).padStart(2, '0');
      const ss = String(secs % 60).padStart(2, '0');
      setError(`Troppi tentativi falliti. Riprova tra ${mm}:${ss}`);
    } else {
      setError(result.error || 'Password errata');
    }
    setLoading(false);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (lockoutSeconds > 0) return; // bloccato dal countdown
    setError('');

    if (isNew) {
      if (!isPasswordStrong(password)) {
        setError('Usa almeno 12 caratteri, una maiuscola, un numero e un simbolo.');
        return;
      }
      if (password !== confirm) { setError('Le password non corrispondono'); return; }
    }

    setLoading(true);
    setLoadingText(isNew ? 'Creazione database sicuro...' : 'Verifica crittografica...');

    try {
      const providedPwd = password;
      const result = await api.unlockVault(providedPwd);

      if (!result.success) {
        handleUnlockFailure(result);
        return;
      }

      // If this is a new vault and user wants biometrics, save with the original provided password
      if (result.isNew && bioAvailable && !bioSaved) {
        bioConsentPasswordRef.current = providedPwd;
        setShowBioConsent(true);
        setLoading(false);
        return;
      }

      setPassword('');
      setConfirm('');
      onUnlock();
    } catch (err) {
      console.error(err);
      setError('Errore di sistema durante lo sblocco');
      setLoading(false);
    }
  };

  // Loading Iniziale
  if (isNew === null) return (
    <div className="flex items-center justify-center min-h-screen bg-background">
      <div className="animate-pulse flex flex-col items-center gap-4">
        <div className="w-12 h-12 bg-primary/10 rounded-2xl flex items-center justify-center border border-primary/20">
          <ShieldCheck className="text-primary animate-spin-slow" size={24} />
        </div>
        <div className="text-text-muted text-xs font-medium tracking-widest uppercase">Initializing Secure Environment</div>
      </div>
    </div>
  );

  const strength = getStrength(password);

  return (
    <div className="flex items-center justify-center min-h-screen bg-background relative drag-region overflow-hidden">
      
      {/* Background Decor — no blur-[120px] che killava la GPU su Android */}
      <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-primary/5 rounded-full opacity-30" />
      <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-primary/5 rounded-full opacity-30" />

      {/* Login / Setup Card */}
      <div className="glass-card p-10 w-full max-w-[440px] mx-4 relative z-10 no-drag animate-slide-up shadow-2xl border-white/10">
        
        <div className="flex flex-col items-center mb-10">
          <div className="relative mb-6">
            <div className="absolute inset-0 bg-primary/20 blur-2xl rounded-full" />
            <img src={logoSrc} alt="LexFlow" className="w-20 h-20 object-contain relative z-10" draggable={false} />
          </div>
          
          <h1 className="text-2xl font-black text-white tracking-tight">LexFlow</h1>
          
          {isNew ? (
            <div className="text-center mt-3 space-y-2">
              <div className="px-3 py-1 bg-primary/10 border border-primary/20 rounded-full inline-block">
                <span className="text-[10px] font-bold text-primary uppercase tracking-[2px]">Configurazione Iniziale</span>
              </div>
              <p className="text-text-muted text-sm max-w-[280px]">Proteggi il tuo studio con una cifratura di grado militare.</p>
            </div>
          ) : (
            <p className="text-text-muted text-sm mt-2 font-medium uppercase tracking-widest opacity-60">
              {showPasswordField ? 'Accesso Protetto' : 'Autenticazione...'}
            </p>
          )}
        </div>

        {/* Pulsante Biometria (Visibile solo se configurata e non in modalità password forzata) */}
        {!isNew && bioAvailable && bioSaved && bioFailed < MAX_BIO_ATTEMPTS && !showPasswordField && (
          <div className="space-y-4">
            <button 
              type="button" 
              onClick={() => handleBioLogin(false)} 
              disabled={loading} 
              className="w-full py-4 bg-primary text-white rounded-2xl flex items-center justify-center gap-3 transition-all hover:scale-[1.02] shadow-xl shadow-primary/20 font-bold"
            >
              <Fingerprint size={24} />
              Accedi con Biometria
            </button>
            <button 
              onClick={() => setShowPasswordField(true)} 
              className="w-full text-text-dim hover:text-white text-xs font-semibold transition-colors py-2"
            >
              Usa invece la Master Password
            </button>
          </div>
        )}

        {/* Form Password (Setup o Fallback) */}
        {(isNew || showPasswordField) && (
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="space-y-4">
            <div className="relative group">
              <label htmlFor="login-master-pwd" className="text-[10px] font-bold text-text-dim uppercase tracking-[2px] ml-1 mb-2 block">Master Password</label>
              <div className="relative">
                <KeyRound size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-text-dim group-focus-within:text-primary transition-colors" />
                <input 
                  id="login-master-pwd"
                  type={showPwd ? 'text' : 'password'} 
                  className="input-field pl-12 pr-12 py-4 rounded-2xl bg-white/5 border-white/10 hover:border-white/20 transition-all text-white placeholder:text-white/20" 
                  placeholder="Inserisci la password..." 
                  value={password} 
                  onChange={e => setPassword(e.target.value)} 
                  autoFocus 
                />
                <button type="button" className="absolute right-4 top-1/2 -translate-y-1/2 text-text-dim hover:text-white transition-colors" onClick={() => setShowPwd(!showPwd)}>
                  {showPwd ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            {isNew && password && (
              <div className="space-y-2 px-1">
                <div className="flex justify-between items-end">
                  <span className="text-[10px] font-bold uppercase tracking-widest opacity-50">Sicurezza</span>
                  <span className={`text-xs font-bold ${strength.text}`}>
                    {strength.label}
                  </span>
                </div>
                <div className="flex gap-1.5 h-1.5">
                  {[1, 2, 3, 4, 5, 6].map((s) => (
                    <div 
                      key={s} 
                      className={`h-full flex-1 rounded-full transition-all duration-500 ${s <= strength.segments ? strength.color : 'bg-white/10'}`} 
                    />
                  ))}
                </div>
              </div>
            )}

            {isNew && (
              <div className="relative animate-fade-in">
                <label htmlFor="login-confirm-pwd" className="text-[10px] font-bold text-text-dim uppercase tracking-[2px] ml-1 mb-2 block">Conferma Password</label>
                <div className="relative">
                  <ShieldCheck size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-text-dim" />
                  <input 
                    id="login-confirm-pwd"
                    type={showPwd ? 'text' : 'password'} 
                    className="input-field pl-12 py-4 rounded-2xl bg-white/5 border-white/10 text-white placeholder:text-white/20" 
                    placeholder="Ripeti la password..." 
                    value={confirm} 
                    onChange={e => setConfirm(e.target.value)} 
                  />
                </div>
              </div>
            )}
          </div>

          {error && (
            <div className={`${lockoutSeconds > 0 ? 'bg-amber-500/10 border-amber-500/20' : 'bg-red-500/10 border-red-500/20'} border p-3 rounded-xl flex items-center gap-2 animate-shake`}>
              {lockoutSeconds > 0 ? (
                <Timer size={16} className="text-amber-500 flex-shrink-0 animate-pulse" />
              ) : (
                <ShieldAlert size={16} className="text-red-500 flex-shrink-0" />
              )}
              <p className={`${lockoutSeconds > 0 ? 'text-amber-500' : 'text-red-500'} text-[11px] font-semibold leading-tight`}>{error}</p>
            </div>
          )}

          <button 
            type="submit" 
            disabled={loading || lockoutSeconds > 0} 
            className="btn-primary w-full py-4 rounded-2xl justify-center font-bold text-sm tracking-widest shadow-xl shadow-primary/20 hover:scale-[1.02] active:scale-[0.98] transition-all disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:scale-100"
          >
            {(() => {
              if (loading) {
                return (
                  <span className="flex items-center gap-3">
                    <div className="w-5 h-5 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                    <span className="uppercase">{loadingText}</span>
                  </span>
                );
              }
              if (lockoutSeconds > 0) {
                return (
                  <span className="flex items-center gap-3 opacity-60">
                    <Timer size={18} className="animate-pulse" />
                    <span className="uppercase">Bloccato {String(Math.floor(lockoutSeconds / 60)).padStart(2, '0')}:{String(lockoutSeconds % 60).padStart(2, '0')}</span>
                  </span>
                );
              }
              return <span className="uppercase">{isNew ? 'Crea il mio Studio Digitale' : 'Accedi al Vault'}</span>;
            })()}
          </button>
        </form>
        )}

        <div className="mt-8 pt-6 border-t border-white/5 flex flex-col items-center gap-4">
          {!isNew && (
            <button 
              type="button" 
              onClick={() => { setShowResetModal(true); setResetPassword(''); setResetError(''); }}
              className="text-text-dim hover:text-red-500 text-[10px] font-bold uppercase tracking-widest transition-colors"
            >
              Password dimenticata? Reset Vault
            </button>
          )}

          <div className="flex items-center gap-4 opacity-40">
            <div className="flex items-center gap-1.5 text-[9px] font-bold text-text-dim uppercase tracking-widest">
              <CheckCircle2 size={12} className="text-emerald-500" />
              AES-256 GCM
            </div>
            <div className="w-1 h-1 bg-text-dim rounded-full" />
            <div className="flex items-center gap-1.5 text-[9px] font-bold text-text-dim uppercase tracking-widest">
              <CheckCircle2 size={12} className="text-emerald-500" />
              Zero-Knowledge
            </div>
          </div>
        </div>
      </div>

      {/* Reset Vault Modal -- sostituisce window.prompt (no password in chiaro nel UI) */}
      {showResetModal && (
        <div className="fixed inset-0 z-[200] bg-black/80 backdrop-blur-xl flex items-center justify-center p-4 animate-fade-in">
          <button type="button" className="absolute inset-0 cursor-default" aria-label="Chiudi" onClick={() => setShowResetModal(false)} tabIndex={-1} />
          <div className="relative z-10 bg-[#0f1016] border border-white/10 rounded-[32px] max-w-md w-full shadow-2xl overflow-hidden no-drag">
            <div className="px-8 pt-8 pb-5" style={{ background: 'linear-gradient(135deg, rgba(239,68,68,0.08) 0%, rgba(239,68,68,0.02) 100%)' }}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 bg-red-500/10 rounded-2xl flex items-center justify-center border border-red-500/20">
                    <ShieldAlert size={22} className="text-red-400" />
                  </div>
                  <div>
                    <h3 className="text-xl font-bold text-white">Factory Reset</h3>
                    <p className="text-xs text-text-dim mt-0.5">Tutti i dati verranno eliminati</p>
                  </div>
                </div>
                <button onClick={() => setShowResetModal(false)} className="p-2 hover:bg-white/10 rounded-xl text-text-dim transition-all group">
                  <X size={20} className="group-hover:rotate-90 transition-transform" />
                </button>
              </div>
            </div>
            <div className="px-8 py-6 space-y-4">
              <p className="text-text-muted text-xs leading-relaxed">
                Inserisci la password attuale per confermare il reset completo del Vault.{' '}
                <span className="text-red-400 font-semibold">Questa azione è irreversibile.</span>
              </p>
              <div className="relative">
                <input 
                  type="password"
                  className="input-field w-full py-3 px-4 rounded-xl bg-white/5 border-white/10 text-white placeholder:text-white/20 text-sm"
                  placeholder="Password attuale..."
                  value={resetPassword}
                  onChange={e => setResetPassword(e.target.value)}
                  autoFocus
                  onKeyDown={async (e) => {
                    if (e.key === 'Enter' && resetPassword) {
                      await executeReset();
                    }
                  }}
                />
              </div>
              {resetError && (
                <div className="bg-red-500/10 border border-red-500/20 p-2 rounded-lg">
                  <p className="text-red-400 text-[11px] font-semibold">{resetError}</p>
                </div>
              )}
            </div>
            <div className="flex justify-end gap-3 px-8 py-5 bg-[#14151d] border-t border-white/5">
              <button onClick={() => setShowResetModal(false)} className="px-6 py-3 rounded-2xl text-text-dim hover:text-white hover:bg-white/5 transition-all text-xs font-bold uppercase tracking-widest">Annulla</button>
              <button
                onClick={executeReset}
                className="px-6 py-3 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-all text-xs font-bold uppercase tracking-widest"
              >
                Conferma Reset
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Consenso Biometria -- sostituisce window.confirm */}
      <ConfirmDialog
        open={showBioConsent}
        title="Accesso Biometrico"
        message="Vuoi abilitare l'accesso biometrico (Face ID / Touch ID / impronta) per accedere piu velocemente?"
        confirmLabel="Abilita"
        cancelLabel="No, grazie"
        onConfirm={async () => {
          setShowBioConsent(false);
          try { await api.saveBio(bioConsentPasswordRef.current); } catch (e) { console.error(e); }
          bioConsentPasswordRef.current = '';
          setPassword('');
          setConfirm('');
          onUnlock();
        }}
        onCancel={() => {
          setShowBioConsent(false);
          bioConsentPasswordRef.current = '';
          setPassword('');
          setConfirm('');
          onUnlock();
        }}
      />
    </div>
  );
}

LoginScreen.propTypes = {
  onUnlock: PropTypes.func,
  autoLocked: PropTypes.bool,
};