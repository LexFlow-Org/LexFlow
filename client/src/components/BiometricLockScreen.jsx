import { useState, useEffect, useRef } from 'react';
import PropTypes from 'prop-types';
import { ArrowLeft, Fingerprint, Lock } from 'lucide-react';
import toast from 'react-hot-toast';
import * as api from '../tauri-api';

/**
 * BiometricLockScreen — schermata di sblocco con biometria + fallback password.
 * Estratta da PracticeDetail per ridurre cognitive complexity (target <250 LOC).
 */
export default function BiometricLockScreen({ practice, onBack, onUnlock }) {
  const [bioAttempted, setBioAttempted] = useState(false);
  const [bioConfigured, setBioConfigured] = useState(null); // null = checking, true/false
  const [showPasswordFallback, setShowPasswordFallback] = useState(false);
  const [practicePassword, setPracticePassword] = useState('');
  const [practicePasswordError, setPracticePasswordError] = useState('');
  // FIX-26: tieni la password in un ref transitorio per zerizzarla subito dopo l'uso
  const pwdRef = useRef('');

  // Check if biometrics are configured on mount
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const available = await api.checkBio();
        if (!available) { if (!cancelled) { setBioConfigured(false); setShowPasswordFallback(true); } return; }
        const saved = await api.hasBioSaved();
        if (!cancelled) {
          setBioConfigured(saved);
          if (!saved) setShowPasswordFallback(true); // Not configured → show password directly
        }
      } catch {
        if (!cancelled) { setBioConfigured(false); setShowPasswordFallback(true); }
      }
    })();
    return () => { cancelled = true; };
  }, []);

  // Auto-trigger biometric only if configured
  useEffect(() => {
    if (bioConfigured !== true || bioAttempted) return;

    let removed = false;
    const attemptBio = async () => {
      try {
        const result = await api.bioLogin();
        if (result) onUnlock();
      } catch (err) {
        console.debug('[BiometricLockScreen] Biometric auth failed or dismissed', err);
      } finally {
        // FIX-9: marca l'attempt nel finally per coprire anche errori
        setBioAttempted(true);
      }
    };

    if (document.hasFocus()) {
      attemptBio();
      return () => {};
    }

    // FIX-6: cleanup window focus listener su unmount/dep-change
    const onFocus = () => {
      if (removed) return;
      removed = true;
      window.removeEventListener('focus', onFocus);
      attemptBio();
    };
    window.addEventListener('focus', onFocus);
    return () => {
      removed = true;
      window.removeEventListener('focus', onFocus);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- onUnlock is stable via useCallback; bioAttempted gate prevents re-runs
  }, [bioConfigured, bioAttempted]);

  const retryBiometric = async () => {
    try {
      const result = await api.bioLogin();
      if (result) { onUnlock(); return; }
      toast.error('Verifica biometrica non riuscita. Riprova.');
    } catch (err) {
      console.debug('[BiometricLockScreen] Biometric retry failed', err);
      toast.error('Verifica biometrica fallita. Usa la password.');
    }
  };

  const handlePasswordFallback = async (e) => {
    e.preventDefault();
    if (!practicePassword) return;
    setPracticePasswordError('');
    // FIX-26: copia la password in ref transitorio e verifica; zerizza subito.
    pwdRef.current = practicePassword;
    try {
      const result = await api.verifyVaultPassword(pwdRef.current);
      // Zerizza immediatamente, sia su successo che fallimento
      pwdRef.current = '';
      setPracticePassword('');
      if (result?.valid) { onUnlock(); return; }
      setPracticePasswordError('Password errata');
    } catch (err) {
      pwdRef.current = '';
      setPracticePassword('');
      console.debug('[BiometricLockScreen] Password verification failed', err);
      setPracticePasswordError('Errore verifica password');
    }
  };

  return (
    <div className="h-full flex flex-col bg-background animate-fade-in">
      <div className="flex items-center px-6 py-4 border-b border-border">
        <button onClick={onBack} className="p-2 hover:bg-card-hover rounded-full transition-colors text-text-dim hover:text-text" aria-label="Torna indietro">
          <ArrowLeft size={20} />
        </button>
        <div className="ml-4">
          <h1 className="text-xl font-bold text-text">{practice.client}</h1>
          <p className="text-xs text-text-dim mt-0.5">{practice.code ? `RG ${practice.code}` : practice.object}</p>
        </div>
      </div>
      <div className="flex-1 flex items-center justify-center">
        <div className="text-center space-y-6 max-w-xs">
          {/* Icon: fingerprint if configured, lock if not */}
          <div className="w-20 h-20 rounded-2xl bg-primary/10 flex items-center justify-center mx-auto border border-primary/20 animate-pulse">
            {bioConfigured ? <Fingerprint size={36} className="text-primary" /> : <Lock size={36} className="text-primary" />}
          </div>
          <div>
            <h2 className="text-xl font-bold text-text mb-2">Verifica Identità</h2>
            <p className="text-sm text-text-muted">
              {bioConfigured === null && 'Verifica in corso...'}
              {bioConfigured === false && 'Inserisci la Master Password per accedere.'}
              {bioConfigured === true && (bioAttempted ? 'Autenticazione non riuscita. Riprova o usa la password.' : 'Autenticazione biometrica in corso...')}
            </p>
            {bioConfigured === false && (
              <p className="text-2xs text-warning mt-2 font-semibold">Biometria non configurata — usa la password</p>
            )}
          </div>
          {/* Biometric retry + fallback (only when bio IS configured) */}
          {bioConfigured === true && bioAttempted && !showPasswordFallback && (
            <div className="space-y-3">
              <button onClick={retryBiometric} className="btn-primary px-8 py-3 text-sm w-full">
                <Fingerprint size={18} /> Riprova Biometria
              </button>
              <button
                onClick={() => setShowPasswordFallback(true)}
                className="w-full text-text-dim hover:text-text text-xs font-semibold transition-colors py-2"
              >
                Usa la Master Password
              </button>
            </div>
          )}
          {/* Password form */}
          {showPasswordFallback && (
            <form onSubmit={handlePasswordFallback} className="space-y-3 text-left">
              <label htmlFor="pd-bio-pwd" className="text-2xs font-bold text-text-dim uppercase tracking-label ml-1 block">Master Password</label>
              <input
                id="pd-bio-pwd"
                type="password"
                className="input-field w-full py-3 px-4 rounded-xl bg-surface border-border text-text placeholder:text-text-dim text-sm"
                placeholder="Inserisci la password..."
                value={practicePassword}
                onChange={e => setPracticePassword(e.target.value)}
                autoFocus
              />
              {practicePasswordError && (
                <p className="text-danger text-xs-p font-semibold" role="alert">{practicePasswordError}</p>
              )}
              <button type="submit" className="btn-primary w-full py-3 text-sm">
                <Lock size={16} /> Sblocca Fascicolo
              </button>
              {bioConfigured === true && (
                <button
                  type="button"
                  onClick={() => { setShowPasswordFallback(false); setPracticePassword(''); setPracticePasswordError(''); }}
                  className="w-full text-text-dim hover:text-text text-xs font-semibold transition-colors py-2"
                >
                  Torna alla Biometria
                </button>
              )}
            </form>
          )}
        </div>
      </div>
    </div>
  );
}

BiometricLockScreen.propTypes = {
  practice: PropTypes.object.isRequired,
  onBack: PropTypes.func.isRequired,
  onUnlock: PropTypes.func.isRequired,
};
