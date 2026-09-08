// TODO(audit:LOW-STYLE): split LoginScreen into ResetVaultModal, RecoveryKeyModal, useBiometricAutoTrigger, useLockoutCountdown to comply with FE <250 LOC guideline
import { useState, useRef, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import {
  Eye,
  EyeOff,
  ShieldCheck,
  Fingerprint,
  KeyRound,
  ShieldAlert,
  Timer,
  X
} from 'lucide-react';
import logoSrc from '../assets/logo.svg';
import * as api from '../tauri-api';

// Common dictionary of weak / common passwords to reject outright in setup
const COMMON_PASSWORDS = new Set([
  'password', 'password1', 'password123', '12345678', '123456789', '1234567890',
  'qwerty', 'qwerty123', 'qwertyuiop', 'abc12345', 'admin', 'admin123',
  'letmein', 'welcome', 'welcome1', 'iloveyou', 'monkey', 'dragon',
  'master', 'login', 'starwars', 'football', 'baseball', 'sunshine',
  'princess', 'changeme', 'passw0rd', 'p@ssw0rd', 'p@ssword',
]);

const isDev = !import.meta.env.PROD;
const devLog = (...args) => { if (isDev) console.debug(...args); };
const devWarn = (...args) => { if (isDev) console.warn(...args); };
const devError = (...args) => { if (isDev) console.error(...args); };

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
  const [resetConfirmText, setResetConfirmText] = useState('');
  const [resetCooldown, setResetCooldown] = useState(5);
  const [showRecovery, setShowRecovery] = useState(false);
  const [recoveryInput, setRecoveryInput] = useState('');
  const [recoveryError, setRecoveryError] = useState('');
  const [showRecoveryKey, setShowRecoveryKey] = useState(false);
  const [resetError, setResetError] = useState('');
  const [showResetPwd, setShowResetPwd] = useState(false);

  const closeResetModal = useCallback(() => {
    setShowResetModal(false);
    setResetPassword('');
    setResetConfirmText('');
    setResetError('');
    setShowResetPwd(false);
  }, []);

  const closeRecoveryModal = useCallback(() => {
    setShowRecovery(false);
    setRecoveryInput('');
    setRecoveryError('');
    setShowRecoveryKey(false);
  }, []);

  // Reset modal cooldown — gates the destructive action behind a 5s delay
  useEffect(() => {
    if (!showResetModal) return;
    const id = setInterval(() => {
      setResetCooldown(c => Math.max(0, c - 1));
    }, 1000);
    return () => clearInterval(id);
  }, [showResetModal]);

  const canConfirmReset = resetConfirmText === 'RESET' && resetCooldown === 0 && !!resetPassword;

  const executeReset = useCallback(async () => {
    if (!canConfirmReset) return;
    try {
      const result = await api.resetVault(resetPassword);
      if (result?.success) {
        setIsNew(true);
        setPassword('');
        setConfirm('');
        setError('');
        setBioSaved(false);
        closeResetModal();
      } else {
        setResetError(result?.error || 'Password non corretta.');
      }
    } catch (err) {
      devWarn('Reset vault error:', err);
      setResetError('Errore di sistema durante il reset.');
    }
  }, [canConfirmReset, resetPassword, closeResetModal]);

  const bioTriggered = useRef(false);
  const bioAutoTriggeredOnReturn = useRef(false);
  // Track if a bio login attempt is currently in-flight to prevent double-triggers.
  // Ownership: only handleBioLogin's `finally` block resets this to false to avoid
  // a TOCTOU window where the autoLocked-effect could clear the flag mid-call.
  const bioInFlight = useRef(false);
  const MAX_BIO_ATTEMPTS = 3;

  // Reset bio refs when LoginScreen appears (autoLocked changes or component mounts)
  // This ensures biometrics re-triggers after every lock cycle.
  // We DO NOT touch bioInFlight here — handleBioLogin's finally owns it.
  useEffect(() => {
    bioTriggered.current = false;
    bioAutoTriggeredOnReturn.current = false;
  }, [autoLocked]);

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

    devLog("Login bio fallito:", isAndroidHandoff ? "(Android handoff)" : err);

    setShowPasswordField(true);

    if (isAndroidHandoff) {
      // Don't bump the counter — UI message handled below
      return;
    }

    // Single functional updater: derive state from prior value to avoid races
    setBioFailed(prev => {
      const next = prev + 1;
      if (next >= MAX_BIO_ATTEMPTS) {
        setError('Troppi tentativi biometrici falliti. Inserisci la password manualmente.');
      } else if (!isAutomatic) {
        setError('Riconoscimento biometrico non riuscito. Riprova o usa la password.');
      }
      return next;
    });
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
  useEffect(() => { handleBioLoginRef.current = handleBioLogin; });

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
          if (!document.hasFocus()) return;
          if (handleBioLoginRef.current) handleBioLoginRef.current(true);
        };
        // Poll for focus: Tauri windows may not have OS focus immediately at startup.
        // The 'focus' event won't fire if the window already has focus when the listener
        // is added, so we poll as a robust fallback.
        let pollCount = 0;
        const MAX_POLLS = 10;
        const pollForFocus = () => {
          if (document.hasFocus()) {
            triggerBioNow();
          } else if (++pollCount < MAX_POLLS) {
            setTimeout(pollForFocus, 500);
          }
        };
        setTimeout(pollForFocus, 400);
      }
    } catch (err) {
      devWarn("Errore inizializzazione bio:", err);
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
        devError("Errore inizializzazione vault:", err);
        setError("Si è verificato un errore di sistema. Riavvia l'applicazione.");
      }
    };

    init();
  }, []);

  // ─── Auto-trigger biometria quando l'utente torna sulla finestra (autolock) ──
  useEffect(() => {
    // Solo se: biometria disponibile e salvata + pochi tentativi falliti
    if (!bioAvailable || !bioSaved || bioFailed >= MAX_BIO_ATTEMPTS) return;
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

  const isCommonPassword = (pwd) => {
    if (!pwd) return false;
    const lower = pwd.toLowerCase();
    if (COMMON_PASSWORDS.has(lower)) return true;
    // Reject simple sequential patterns and repeated chars
    if (/^(.)\1+$/.test(pwd)) return true; // aaaaaaaa
    if (/^(0123456789|123456789|abcdefgh|qwertyui|asdfghjk)/i.test(pwd)) return true;
    return false;
  };

  const getStrength = (pwd) => {
    if (!pwd) return { label: '', color: 'bg-surface', text: 'text-text-dim', pct: 0, segments: 0 };
    if (isCommonPassword(pwd)) {
      return { label: 'Comune (vietata)', color: 'bg-danger', text: 'text-danger', pct: 8, segments: 1 };
    }
    let score = 0;
    if (pwd.length >= 8) score++;
    if (pwd.length >= 12) score++;
    if (/[A-Z]/.test(pwd)) score++;
    if (/[a-z]/.test(pwd)) score++;
    if (/\d/.test(pwd)) score++;
    if (/[^A-Za-z0-9]/.test(pwd)) score++;
    // 6 criteri → 6 segmenti. "Eccellente" (6/6) = isPasswordStrong soddisfatto
    if (score <= 1) return { label: 'Debole', color: 'bg-danger', text: 'text-danger', pct: 17, segments: 1 };
    if (score <= 2) return { label: 'Insufficiente', color: 'bg-warning', text: 'text-warning', pct: 33, segments: 2 };
    if (score <= 3) return { label: 'Sufficiente', color: 'bg-warning', text: 'text-warning', pct: 50, segments: 3 };
    if (score <= 4) return { label: 'Buona', color: 'bg-warning', text: 'text-warning', pct: 67, segments: 4 };
    if (score <= 5) return { label: 'Forte', color: 'bg-primary', text: 'text-primary', pct: 83, segments: 5 };
    return { label: 'Eccellente', color: 'bg-success', text: 'text-success', pct: 100, segments: 6 };
  };

  const isPasswordStrong = (pwd) => {
    if (isCommonPassword(pwd)) return false;
    return pwd.length >= 12 && /[A-Z]/.test(pwd) && /[a-z]/.test(pwd) && /\d/.test(pwd) && /[!@#$%^&*()\-_=+[\]{};':"\\|,.<>/?]/.test(pwd);
  };

  /** Handle unlock failure — sets error and lockout state (v4: exponential backoff) */
  const handleUnlockFailure = (result) => {
    if (result.locked && result.remaining) {
      const secs = Math.ceil(Number(result.remaining));
      setLockoutSeconds(secs);
      // Defensive: if lockout fires we should not retain the just-typed password
      setPassword('');
      setConfirm('');
      const mm = String(Math.floor(secs / 60)).padStart(2, '0');
      const ss = String(secs % 60).padStart(2, '0');
      const attemptsInfo = result.attempts && result.maxAttempts
        ? ` (${result.attempts}/${result.maxAttempts})`
        : '';
      setError(`Troppi tentativi falliti${attemptsInfo}. Riprova tra ${mm}:${ss}`);
    } else {
      // Translate backend errors to user-friendly messages with suggested actions
      const rawErr = result.error || 'Password non corretta.';
      if (rawErr.includes('non è verificabile') || rawErr.includes('tampered') || rawErr.includes('incompatibile')) {
        setError('Il database non è compatibile con questa versione. Vai in Impostazioni e usa Factory Reset per ricominciare.');
      } else if (rawErr.includes('Password troppo debole') || rawErr.includes('12 caratteri')) {
        setError('La password deve avere almeno 12 caratteri, con maiuscole, minuscole, numeri e un simbolo.');
      } else if (rawErr.includes('Password non corretta') || rawErr.includes('Password errata')) {
        setError('Password non corretta. Riprova.');
      } else if (rawErr.includes('danneggiato')) {
        setError('Il database risulta danneggiato. Prova a importare un backup dalle Impostazioni.');
      } else if (rawErr.includes('spazio su disco')) {
        setError('Spazio su disco insufficiente. Libera spazio e riprova.');
      } else if (rawErr.includes('Nessun database')) {
        setError('Nessun database trovato. Crea un nuovo vault con una password sicura.');
      } else if (rawErr.includes('anomalia')) {
        setError('Rilevata un\'anomalia di sicurezza. Contatta il supporto tecnico.');
      } else {
        setError(rawErr);
      }
    }
    setLoading(false);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (lockoutSeconds > 0) return; // bloccato dal countdown
    setError('');

    if (isNew) {
      if (isCommonPassword(password)) {
        setError('Questa password è troppo comune. Scegline una unica e non riconducibile a te.');
        return;
      }
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

      // Enrollment is a separate, explicit choice in onboarding or Settings.
      onUnlock(isNew);
    } catch (err) {
      devError(err);
      setError('Errore di sistema durante lo sblocco');
    } finally {
      setPassword('');
      setConfirm('');
      setLoading(false);
    }
  };

  // Defensive: clear any password material from memory when this screen unmounts
  useEffect(() => () => {
    setPassword('');
    setConfirm('');
    setResetPassword('');
    setRecoveryInput('');
  }, []);

  // Loading Iniziale
  if (isNew === null) return (
    <div className="flex items-center justify-center min-h-dvh bg-background">
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
    <div className="flex items-center justify-center min-h-dvh bg-background relative drag-region overflow-hidden">
      
      {/* Login / Setup Card */}
      <div className="glass-card p-10 w-full max-w-[440px] mx-4 relative z-10 no-drag animate-slide-up shadow-2xl border-border/50">

        <div className="flex flex-col items-center mb-10">
          <div className="relative mb-6">
            <img src={logoSrc} alt="LexFlow" className="w-20 h-20 object-contain relative z-10" draggable={false} />
          </div>
          
          <h1 className="text-2xl font-black text-text tracking-tight">LexFlow</h1>
          
          {isNew ? (
            <div className="text-center mt-3 space-y-2">
              <div className="px-3 py-1 bg-primary/10 border border-primary/20 rounded-full inline-block">
                <span className="text-2xs font-bold text-primary uppercase tracking-label">Configurazione Iniziale</span>
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
              className="w-full py-4 bg-primary text-black rounded-2xl flex items-center justify-center gap-3 transition-colors hover:scale-[1.02] font-bold"
            >
              <Fingerprint size={24} />
              Accedi con Biometria
            </button>
            <button 
              onClick={() => setShowPasswordField(true)} 
              className="w-full text-text-dim hover:text-text text-xs font-semibold transition-colors py-2"
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
              <label htmlFor="login-master-pwd" className="text-2xs font-bold text-text-dim uppercase tracking-label ml-1 mb-2 block">Master Password</label>
              <div className="relative">
                <KeyRound size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-text-dim group-focus-within:text-primary transition-colors" />
                <input
                  id="login-master-pwd"
                  type={showPwd ? 'text' : 'password'}
                  className="input-field pl-12 pr-12 py-4 rounded-2xl bg-input border-border hover:border-primary/30 transition-colors text-text placeholder:text-text-dim/40"
                  placeholder="Inserisci la password..."
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  autoFocus
                  autoComplete="off"
                  data-1p-ignore="true"
                  data-lpignore="true"
                  data-bwignore="true"
                  data-form-type="other"
                  spellCheck="false"
                  autoCorrect="off"
                  autoCapitalize="off"
                />
                <button type="button" className="absolute right-4 top-1/2 -translate-y-1/2 text-text-dim hover:text-white transition-colors" onClick={() => setShowPwd(!showPwd)}>
                  {showPwd ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            {isNew && password && (
              <div className="space-y-2 px-1">
                <div className="flex justify-between items-end">
                  <span className="text-2xs font-bold uppercase tracking-widest opacity-50">Sicurezza</span>
                  <span className={`text-xs font-bold ${strength.text}`}>
                    {strength.label}
                  </span>
                </div>
                <div className="flex gap-1.5 h-1.5">
                  {[1, 2, 3, 4, 5, 6].map((s) => (
                    <div 
                      key={s} 
                      className={`h-full flex-1 rounded-full transition-colors duration-500 ${s <= strength.segments ? strength.color : 'bg-surface'}`}
                    />
                  ))}
                </div>
              </div>
            )}

            {isNew && (
              <div className="relative animate-fade-in">
                <label htmlFor="login-confirm-pwd" className="text-2xs font-bold text-text-dim uppercase tracking-label ml-1 mb-2 block">Conferma Password</label>
                <div className="relative">
                  <ShieldCheck size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-text-dim" />
                  <input
                    id="login-confirm-pwd"
                    type={showPwd ? 'text' : 'password'}
                    className="input-field pl-12 py-4 rounded-2xl bg-input border-border text-text placeholder:text-text-dim/40"
                    placeholder="Ripeti la password..."
                    value={confirm}
                    onChange={e => setConfirm(e.target.value)}
                    autoComplete="off"
                    data-1p-ignore="true"
                    data-lpignore="true"
                    data-bwignore="true"
                    data-form-type="other"
                    spellCheck="false"
                    autoCorrect="off"
                    autoCapitalize="off"
                  />
                </div>
              </div>
            )}
          </div>

          {error && (
            <div className={`${lockoutSeconds > 0 ? 'bg-warning-soft border-warning-border' : 'bg-danger-soft border-danger-border'} border p-3 rounded-xl flex items-center gap-2 animate-shake`}>
              {lockoutSeconds > 0 ? (
                <Timer size={16} className="text-warning flex-shrink-0 animate-pulse" />
              ) : (
                <ShieldAlert size={16} className="text-danger flex-shrink-0" />
              )}
              <p className={`${lockoutSeconds > 0 ? 'text-warning' : 'text-danger'} text-xs-p font-semibold leading-tight`}>{error}</p>
            </div>
          )}

          <button 
            type="submit" 
            disabled={loading || lockoutSeconds > 0} 
            className="btn-primary w-full py-4 rounded-2xl justify-center font-bold text-sm tracking-widest hover:scale-[1.02] active:scale-[0.98] transition-colors disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:scale-100"
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

        <div className="mt-8 pt-6 border-t border-border/30 flex flex-col items-center gap-4">
          {!isNew && (
            <div className="flex flex-col items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  setRecoveryInput('');
                  setRecoveryError('');
                  setShowRecoveryKey(false);
                  setShowRecovery(true);
                }}
                className="text-text-dim hover:text-primary text-2xs font-bold uppercase tracking-widest transition-colors"
              >
                Usa Chiave di Recupero
              </button>
              <button
                type="button"
                onClick={() => {
                  setResetPassword('');
                  setResetConfirmText('');
                  setResetError('');
                  setShowResetPwd(false);
                  setResetCooldown(5);
                  setShowResetModal(true);
                }}
                className="text-text-dim hover:text-danger text-2xs font-bold uppercase tracking-widest transition-colors"
              >
                Factory Reset Vault
              </button>
            </div>
          )}

          <div className="flex items-center gap-4 opacity-60">
            <div className="flex items-center gap-1.5 text-3xs font-bold text-text-muted uppercase tracking-widest">
              AES-256 GCM
            </div>
            <div className="w-1 h-1 bg-text-muted rounded-full" />
            <div className="flex items-center gap-1.5 text-3xs font-bold text-text-muted uppercase tracking-widest">
              Zero-Knowledge
            </div>
          </div>
        </div>
      </div>

      {/* Reset Vault Modal -- sostituisce window.prompt (no password in chiaro nel UI) */}
      {showResetModal && (
        <div
          className="fixed inset-0 z-[200] bg-black/80 blur-overlay flex items-center justify-center p-4 animate-fade-in"
          role="dialog"
          aria-modal="true"
          aria-labelledby="reset-modal-title"
          onKeyDown={(e) => { if (e.key === 'Escape') closeResetModal(); }}
        >
          <button type="button" className="absolute inset-0 cursor-default" aria-label="Chiudi" onClick={closeResetModal} tabIndex={-1} />
          <div className="relative z-10 modal-card modal-card-sm no-drag">
            <div className="modal-header-gradient modal-header-gradient-danger">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 bg-danger-soft rounded-2xl flex items-center justify-center border border-danger-border">
                    <ShieldAlert size={22} className="text-danger" />
                  </div>
                  <div>
                    <h3 id="reset-modal-title" className="text-xl font-bold text-text">Factory Reset</h3>
                    <p className="text-xs text-text-dim mt-0.5">Tutti i dati verranno eliminati</p>
                  </div>
                </div>
                <button type="button" onClick={closeResetModal} aria-label="Chiudi" className="p-2 hover:bg-card-hover rounded-xl text-text-dim transition-colors group">
                  <X size={20} className="group-hover:rotate-90 transition-transform" />
                </button>
              </div>
            </div>
            <div className="px-8 py-6 space-y-4">
              <p className="text-text-muted text-xs leading-relaxed">
                Inserisci la password attuale e digita <code className="px-1.5 py-0.5 rounded bg-card-hover text-danger font-mono text-2xs">RESET</code> per confermare l'eliminazione completa del Vault.{' '}
                <span className="text-danger font-semibold">Questa azione è irreversibile.</span>
              </p>
              <div className="relative">
                <input
                  type={showResetPwd ? 'text' : 'password'}
                  className="input-field w-full py-3 pl-4 pr-12 rounded-xl bg-input border-border text-text placeholder:text-text-dim/40 text-sm"
                  placeholder="Password attuale..."
                  value={resetPassword}
                  onChange={e => setResetPassword(e.target.value)}
                  autoFocus
                  autoComplete="off"
                  data-1p-ignore="true"
                  data-lpignore="true"
                  data-bwignore="true"
                  data-form-type="other"
                  spellCheck="false"
                  autoCorrect="off"
                  autoCapitalize="off"
                  onKeyDown={(e) => { if (e.key === 'Enter') e.preventDefault(); }}
                />
                <button
                  type="button"
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-text-dim hover:text-text transition-colors"
                  onClick={() => setShowResetPwd(v => !v)}
                  tabIndex={-1}
                  aria-label={showResetPwd ? 'Nascondi password' : 'Mostra password'}
                >
                  {showResetPwd ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              <input
                type="text"
                className="input-field w-full py-3 px-4 rounded-xl bg-input border-border text-text placeholder:text-text-dim/40 text-sm font-mono tracking-widest"
                placeholder="Scrivi RESET per confermare"
                value={resetConfirmText}
                onChange={(e) => setResetConfirmText(e.target.value)}
                autoComplete="off"
                spellCheck="false"
                autoCorrect="off"
                autoCapitalize="characters"
                aria-label="Conferma testuale: scrivi RESET"
                onKeyDown={(e) => { if (e.key === 'Enter') e.preventDefault(); }}
              />
              {resetError && (
                <div className="bg-danger-soft border border-danger-border p-2 rounded-lg">
                  <p className="text-danger text-xs-p font-semibold">{resetError}</p>
                </div>
              )}
            </div>
            <div className="modal-footer">
              <button type="button" onClick={closeResetModal} className="btn-cancel">Annulla</button>
              <button
                type="button"
                onClick={executeReset}
                disabled={!canConfirmReset}
                aria-disabled={!canConfirmReset}
                className="px-6 py-3 rounded-2xl bg-danger-soft border border-danger-border text-danger hover:bg-danger-soft transition-colors text-xs font-bold uppercase tracking-widest disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {resetCooldown > 0 ? `Attendi ${resetCooldown}s...` : 'Elimina vault'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Recovery Key Modal */}
      {showRecovery && (
        <div
          className="fixed inset-0 z-[200] bg-black/80 blur-overlay flex items-center justify-center p-4 animate-fade-in"
          role="dialog"
          aria-modal="true"
          aria-labelledby="recovery-modal-title"
          onKeyDown={(e) => { if (e.key === 'Escape') closeRecoveryModal(); }}
        >
          <button type="button" className="absolute inset-0 cursor-default" aria-label="Chiudi" onClick={closeRecoveryModal} tabIndex={-1} />
          <div className="relative z-10 glass-card max-w-md w-full p-0 overflow-hidden animate-fade-in-up">
            <div className="modal-header">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 bg-primary-soft rounded-2xl flex items-center justify-center border border-primary/20">
                  <KeyRound size={22} className="text-primary" />
                </div>
                <div>
                  <h3 id="recovery-modal-title" className="text-xl font-bold text-text">Chiave di Recupero</h3>
                  <p className="text-xs text-text-dim mt-0.5">Inserisci la chiave per sbloccare il vault</p>
                </div>
              </div>
              <button type="button" onClick={closeRecoveryModal} aria-label="Chiudi" className="p-2 hover:bg-card-hover rounded-xl text-text-dim transition-colors">
                <X size={20} />
              </button>
            </div>
            <div className="px-8 py-6 space-y-4">
              <div className="relative">
                <input
                  type={showRecoveryKey ? 'text' : 'password'}
                  value={recoveryInput}
                  onChange={e => setRecoveryInput(e.target.value.toUpperCase())}
                  placeholder="XXXX-XXXX-XXXX-XXXX"
                  className="w-full px-4 py-3 pr-12 rounded-xl bg-input border border-border text-text text-center font-mono text-lg tracking-[4px] placeholder:text-text-dim/40 outline-none focus:border-primary"
                  autoFocus
                  autoComplete="off"
                  data-1p-ignore="true"
                  data-lpignore="true"
                  data-bwignore="true"
                  data-form-type="other"
                  spellCheck="false"
                  autoCorrect="off"
                  autoCapitalize="characters"
                  aria-label="Chiave di recupero"
                />
                <button
                  type="button"
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-text-dim hover:text-text transition-colors"
                  onClick={() => setShowRecoveryKey(v => !v)}
                  tabIndex={-1}
                  aria-label={showRecoveryKey ? 'Nascondi chiave' : 'Mostra chiave'}
                >
                  {showRecoveryKey ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              {recoveryError && (
                <p className="text-danger text-2xs font-semibold" role="alert">{recoveryError}</p>
              )}
            </div>
            <div className="modal-footer">
              <button type="button" onClick={closeRecoveryModal} className="btn-cancel">Annulla</button>
              <button
                type="button"
                onClick={async () => {
                  setRecoveryError('');
                  if (!recoveryInput || recoveryInput.length < 10) {
                    setRecoveryError('Chiave troppo corta');
                    return;
                  }
                  try {
                    const res = await api.unlockWithRecovery(recoveryInput.trim());
                    if (res?.success) {
                      closeRecoveryModal();
                      onUnlock();
                    } else {
                      setRecoveryError(res?.error || 'Chiave non valida');
                    }
                  } catch (err) {
                    devWarn('Recovery unlock error:', err);
                    setRecoveryError('Chiave non valida o errore di sistema');
                  }
                }}
                className="btn-primary px-6 py-3 text-xs font-bold uppercase tracking-widest"
              >
                Sblocca
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

LoginScreen.propTypes = {
  onUnlock: PropTypes.func,
  autoLocked: PropTypes.bool,
};