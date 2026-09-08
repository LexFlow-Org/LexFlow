import { useState, useEffect, useRef } from 'react';
import PropTypes from 'prop-types';
import * as api from '../tauri-api';
import { ShieldCheck, KeyRound, AlertCircle, CheckCircle2, Loader2, Eye, EyeOff } from 'lucide-react';
import '../styles/license.css';

/**
 * LicenseActivation — Gate di attivazione licenza LexFlow
 *
 * Flow:
 *  1. Controlla se la licenza è già attiva (check_license)
 *  2. Se no → mostra schermata di attivazione con input chiave LXFW
 *  3. Dopo attivazione → children (LoginScreen → App)
 *
 * Sicurezza:
 *  - Anti brute-force: lockout dopo 5 tentativi (gestito lato Rust)
 *  - La chiave viene trimata e sanitizzata prima dell'invio
 *  - Nessun dato sensibile in console.log in produzione
 */
export default function LicenseActivation({ children }) {
  const [isActivated, setIsActivated] = useState(null); // null = loading
  const [license, setLicense] = useState('');
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState(null); // { type: 'success'|'error', text, detail? }
  const [showKey, setShowKey] = useState(false);
  const [shakeInput, setShakeInput] = useState(false);
  const [lockoutSeconds, setLockoutSeconds] = useState(0); // countdown brute-force
  const [lockoutEndAt, setLockoutEndAt] = useState(null);    // ms timestamp (drives countdown)
  const [gracePeriod, setGracePeriod] = useState(null); // { inGrace: bool, days: number }
  const [needsLicenseProof, setNeedsLicenseProof] = useState(false);
  const [statusReason, setStatusReason] = useState('');
  const inputRef = useRef(null);
  const toastTimer = useRef(null);

  // ── Check iniziale ────────────────────────────────────────────────────────
  useEffect(() => {
    (async () => {
      try {
        const status = await api.checkLicense();
        setNeedsLicenseProof(status.needsLicenseProof === true);
        if (!status.activated && !status.needsLicenseProof) setStatusReason(status.reason || '');
        if (status.tampered) {
          setToast({
            type: 'error',
            text: 'Manomissione rilevata',
            detail: status.reason || 'File di licenza rimosso. Contattare il supporto.',
          });
          setIsActivated(false);
          return;
        }
        // Grace period detection
        if (status.inGracePeriod) {
          setGracePeriod({ inGrace: true, days: status.graceDays || 0 });
        }
        setIsActivated(!!status.activated);
      } catch {
        setIsActivated(false);
      }
    })();
  }, []);

  // ── Auto-dismiss toast ────────────────────────────────────────────────────
  useEffect(() => {
    if (toast) {
      clearTimeout(toastTimer.current);
      // Non auto-chiudere il toast di lockout — resta finché il countdown è attivo
      if (lockoutEndAt) return;
      toastTimer.current = setTimeout(() => setToast(null), toast.type === 'success' ? 2500 : 5000);
    }
    return () => clearTimeout(toastTimer.current);
  }, [toast, lockoutEndAt]);

  // ── Lockout countdown — timestamp-driven so we don't drift across re-renders
  useEffect(() => {
    if (!lockoutEndAt) return;

    const fmt = (s) => {
      const mm = String(Math.floor(s / 60)).padStart(2, '0');
      const ss = String(s % 60).padStart(2, '0');
      return `Troppi tentativi falliti. Riprova tra ${mm}:${ss}`;
    };

    const tick = () => {
      const remaining = Math.max(0, Math.ceil((lockoutEndAt - Date.now()) / 1000));
      setLockoutSeconds(remaining);
      if (remaining === 0) {
        setLockoutEndAt(null);
        setToast(null);
        return;
      }
      setToast(t => t ? { ...t, detail: fmt(remaining) } : t);
    };

    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [lockoutEndAt]);

  // ── Sanitizza input ───────────────────────────────────────────────────────
  function handleInputChange(e) {
    // Rimuovi spazi, newline, tabs e zero-width chars — le chiavi LXFW sono una stringa continua
    const cleaned = e.target.value.replaceAll(/[\s\u200B-\u200D\uFEFF]/g, '');
    setLicense(cleaned);
    if (toast?.type === 'error') setToast(null);
  }

  // ── Paste handler ─────────────────────────────────────────────────────────
  function handlePaste(e) {
    e.preventDefault();
    const text = (e.clipboardData || globalThis.clipboardData).getData('text');
    const cleaned = text.replaceAll(/[\s\u200B-\u200D\uFEFF]/g, '');
    setLicense(cleaned);
    if (toast?.type === 'error') setToast(null);
  }

  // ── Attivazione ───────────────────────────────────────────────────────────
  function handleActivationResponse(response, receivedAt) {
    if (response.needsRenewal) {
      setNeedsLicenseProof(false);
      setLicense('');
      setShowKey(false);
      setStatusReason('La licenza originale è verificata ma scaduta. Inserisci il codice di rinnovo.');
      return;
    }
    if (response.success) {
      // Clear license key from state IMMEDIATELY — don't keep secrets in memory
      // through the 1800ms transition timeout.
      setLicense('');
      setShowKey(false);
      const title = response.lawyerTitle || 'Avv.';
      const cleanName = (response.lawyerName || '').replace(/^(Avv\.|Avv|Avvocato|Praticante)\.?\s+/i, '').trim();
      const parts = [response.client, cleanName ? `${title} ${cleanName}` : ''].filter(Boolean);
      setToast({
        type: 'success',
        text: needsLicenseProof ? 'Licenza verificata con successo' : 'Licenza attivata con successo',
        detail: parts.length ? `Registrata a: ${parts.join(' — ')}` : undefined,
      });
      setTimeout(() => setIsActivated(true), 1800);
      return;
    }

    if (response.needsLicenseProof) setNeedsLicenseProof(true);
    if (response.activationPending) setStatusReason(response.error || 'Attivazione da completare. Riavvia LexFlow per riprovare.');

    if (response.locked) {
      const secs = Math.max(1, Math.round(response.remaining || 300));
      setLockoutEndAt(receivedAt + secs * 1000);
      const mm = String(Math.floor(secs / 60)).padStart(2, '0');
      const ss = String(secs % 60).padStart(2, '0');
      setToast({
        type: 'error',
        text: 'Account temporaneamente bloccato',
        detail: `Troppi tentativi falliti. Riprova tra ${mm}:${ss}`,
      });
      return;
    }

    const errMsg = response.error || 'Chiave non valida o scaduta.';
    const isBurned = errMsg.includes('già stata utilizzata');
    setToast({
      type: 'error',
      text: isBurned ? 'Chiave già utilizzata' : errMsg,
      detail: isBurned ? 'Questo codice risulta già utilizzato e non può avviare una nuova attivazione. Se stai aggiornando LexFlow, conserva i dati dell’app e verifica l’attivazione esistente con il supporto.' : undefined,
    });
    triggerShake();
  }

  async function handleActivate(e) {
    if (e) e.preventDefault();
    if (lockoutSeconds > 0) return;
    const key = license.trim();

    if (!key) {
      setToast({ type: 'error', text: 'Inserisci la chiave di licenza.' });
      triggerShake();
      return;
    }

    if (!key.startsWith('LXFW.') || key.split('.').length !== 3) {
      // Don't reveal exact internal schema — just say it's invalid.
      setToast({ type: 'error', text: 'Formato licenza non valido' });
      triggerShake();
      return;
    }

    setLoading(true);
    setToast(null);

    try {
      const response = await api.activateLicense(key);
      // eslint-disable-next-line react-hooks/purity -- runs only after this form submit request resolves
      handleActivationResponse(response, Date.now());
    } catch {
      setToast({ type: 'error', text: 'Errore di comunicazione con il sistema.' });
    } finally {
      setLoading(false);
    }
  }

  function triggerShake() {
    setShakeInput(true);
    setTimeout(() => setShakeInput(false), 500);
  }

  // ── Loading splash ────────────────────────────────────────────────────────
  if (isActivated === null) {
    return (
      <div className="lic-splash">
        <div className="lic-splash-logo">
          <ShieldCheck size={32} strokeWidth={1.5} />
        </div>
        <span className="lic-splash-text">Verifica licenza…</span>
      </div>
    );
  }

  // ── App sbloccata ─────────────────────────────────────────────────────────
  if (isActivated) {
    return (
      <>
        {gracePeriod?.inGrace && (
          <div className="lic-grace-banner">
            <AlertCircle size={16} />
            <span>
              <strong>Licenza in Grace Period</strong> — La licenza è scaduta ma hai ancora{' '}
              {gracePeriod.days} giorni per rinnovare. Contatta il supporto per il rinnovo.
            </span>
          </div>
        )}
        {children}
      </>
    );
  }

  // ── Schermata di attivazione ──────────────────────────────────────────────
  const hasInput = license.trim().length > 0;

  const getMaskedKey = () => {
    if (showKey) return license;
    if (license.length > 8) {
      // Show only first 8 chars + ***  — minimise disclosure.
      return license.slice(0, 8) + '***';
    }
    return license;
  };
  const maskedKey = getMaskedKey();

  return (
    <div className="lic-overlay">
      <div className="lic-card">
        {/* Header */}
        <div className="lic-header">
          <div className="lic-icon-ring">
            <KeyRound size={24} strokeWidth={1.5} />
          </div>
          <div>
            <h1 className="lic-title">{needsLicenseProof ? 'Verifica della licenza esistente' : 'Attivazione LexFlow'}</h1>
            <p className="lic-subtitle">{needsLicenseProof
              ? 'Per completare l’aggiornamento, reinserisci il codice originale su questo computer. Conferma l’attivazione già salvata: non serve una nuova licenza.'
              : 'Inserisci la chiave di licenza per sbloccare il software'}</p>
          </div>
        </div>

        {statusReason && <p className="lic-hint" role="status">{statusReason}</p>}

        {/* Form */}
        <form onSubmit={handleActivate} className="lic-form">
          <label className="lic-label" htmlFor="license-key">Chiave di licenza</label>

          <div className={`lic-input-wrap ${shakeInput ? 'lic-shake' : ''} ${hasInput ? 'has-value' : ''}`}>
            <textarea
              ref={inputRef}
              id="license-key"
              className="lic-textarea"
              value={showKey ? license : maskedKey}
              onChange={handleInputChange}
              onPaste={handlePaste}
              onFocus={() => setShowKey(true)}
              placeholder="LXFW.eyJjIjoiLi4u..."
              rows={3}
              disabled={loading}
              spellCheck={false}
              autoComplete="off"
              autoCorrect="off"
            />

            {hasInput && (
              <button
                type="button"
                className="lic-eye-btn"
                onClick={() => setShowKey(!showKey)}
                tabIndex={-1}
                aria-label={showKey ? 'Nascondi chiave' : 'Mostra chiave'}
              >
                {showKey ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            )}
          </div>

          <div className="lic-hint">
            Formato: <code>LXFW.&lt;payload&gt;.&lt;firma&gt;</code> — ricevuta al momento dell'acquisto
          </div>

          <button
            className="lic-btn-activate"
            type="submit"
            disabled={loading || !hasInput || lockoutSeconds > 0}
          >
            {loading ? (
              <>
                <Loader2 size={16} className="lic-spinner" />
                Verifica in corso…
              </>
            ) : (
              <>
                <ShieldCheck size={16} />
                {needsLicenseProof ? 'Verifica licenza esistente' : 'Attiva Licenza'}
              </>
            )}
          </button>
        </form>

        {/* Footer */}
        <div className="lic-footer">
          <span>La verifica della licenza avviene interamente in locale</span>
        </div>
      </div>

      {/* ── Toast ── */}
      {toast && (
        <div className={`lic-toast ${toast.type}`}>
          <div className="lic-toast-icon">
            {toast.type === 'success' ? <CheckCircle2 size={20} /> : <AlertCircle size={20} />}
          </div>
          <div className="lic-toast-body">
            {/* Title is asserted once, then countdown updates announce politely */}
            <span className="lic-toast-title" role="alert">{toast.text}</span>
            {toast.detail && (
              <span className="lic-toast-detail" aria-live="polite">{toast.detail}</span>
            )}
          </div>
          <button className="lic-toast-close" type="button" aria-label="Chiudi" onClick={() => setToast(null)}>&times;</button>
        </div>
      )}
    </div>
  );
}

LicenseActivation.propTypes = {
  children: PropTypes.node,
};
