import { useState, useEffect } from 'react';
import PropTypes from 'prop-types';
import { Shield, Fingerprint, ArrowRight, Check, SkipForward } from 'lucide-react';
import * as api from '../tauri-api';

export default function OnboardingWizard({ currentStep = 0, onComplete, onConfigureBio }) {
  const [step, setStep] = useState(currentStep);
  const [bioSupported, setBioSupported] = useState(null);
  useEffect(() => {
    let mounted = true;
    api.checkBio().then(value => { if (mounted) setBioSupported(!!value); })
      .catch(() => { if (mounted) setBioSupported(false); });
    return () => { mounted = false; };
  }, []);
  const probing = bioSupported === null;
  const configuring = bioSupported && step > 0;
  const Icon = configuring ? Fingerprint : Shield;
  const handleNext = () => {
    if (probing) return;
    if (configuring) onConfigureBio?.();
    else if (bioSupported) setStep(1);
    else onComplete();
  };

  return (
    <div className="fixed inset-0 z-[9999] bg-[var(--bg)] flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="onboarding-title">
      <div className="w-full max-w-md space-y-8">
        <div className="flex items-center justify-center gap-2" aria-hidden="true">
          {Array.from({ length: bioSupported ? 2 : 1 }, (_, i) => (
            <div key={i} className={`h-1.5 rounded-full ${i <= step ? 'w-8 bg-[var(--primary)]' : 'w-4 bg-[var(--border)]'}`} />
          ))}
        </div>
        <div className="text-center space-y-4">
          <div className="w-16 h-16 mx-auto rounded-2xl flex items-center justify-center bg-[var(--primary-soft)]">
            <Icon size={28} className="text-[var(--primary)]" />
          </div>
          <h2 id="onboarding-title" className="text-xl font-bold text-[var(--text)]">{configuring ? 'Configura Biometria' : 'Vault creato'}</h2>
          <p className="text-sm text-[var(--text-dim)] max-w-sm mx-auto">
            {configuring
              ? 'Lo sblocco biometrico è facoltativo. Per attivarlo, ti chiederemo di inserire nuovamente la Master Password e confermare sul dispositivo. Puoi configurarlo anche più tardi dalle Impostazioni.'
              : 'La Master Password che hai appena scelto protegge il tuo archivio cifrato. La biometria non viene attivata automaticamente.'}
          </p>
        </div>
        <div className="flex flex-col items-center gap-3">
          <button onClick={handleNext} disabled={probing || (configuring && !onConfigureBio)}
            aria-label={configuring ? 'Configura sblocco biometrico' : bioSupported ? 'Vai al passaggio successivo' : 'Completa la configurazione e avvia LexFlow'}
            className="btn-primary px-8 py-3 rounded-xl flex items-center gap-2 font-bold text-sm disabled:opacity-50">
            {probing ? 'Verifica disponibilità…' : configuring ? <><Fingerprint size={16} /> Configura</> : bioSupported ? <><ArrowRight size={16} /> Continua</> : <><Check size={16} /> Inizia</>}
          </button>
          {configuring && <button onClick={onComplete} className="flex items-center gap-1.5 text-xs text-[var(--text-dim)] hover:text-[var(--text)] transition-colors"><SkipForward size={12} /> Salta per ora</button>}
        </div>
        <p className="text-center text-xs text-[var(--text-dim)]" aria-live="polite">Passaggio {configuring ? 2 : 1} di {probing ? '…' : bioSupported ? 2 : 1}</p>
      </div>
    </div>
  );
}

OnboardingWizard.propTypes = {
  currentStep: PropTypes.number,
  onComplete: PropTypes.func.isRequired,
  onConfigureBio: PropTypes.func,
};
