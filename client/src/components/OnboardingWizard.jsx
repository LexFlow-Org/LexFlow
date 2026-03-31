import { useState, useEffect } from 'react';
import { Shield, Fingerprint, ArrowRight, Check, SkipForward } from 'lucide-react';
import * as api from '../tauri-api';

const steps = [
  {
    icon: Shield,
    title: 'Crea il tuo Vault',
    description: 'Imposta una password master sicura per proteggere tutti i tuoi dati con crittografia AES-256-GCM-SIV.',
    skippable: false,
  },
  {
    icon: Fingerprint,
    title: 'Configura Biometria',
    description: 'Abilita Touch ID, Windows Hello o impronta digitale per sbloccare il vault senza digitare la password.',
    skippable: true,
    skipLabel: 'Salta per ora',
  },
];

export default function OnboardingWizard({ currentStep = 0, onComplete, onConfigureBio }) {
  const [step, setStep] = useState(currentStep);
  const [bioLoading, setBioLoading] = useState(false);
  const [bioResult, setBioResult] = useState(null); // 'success' | 'failed' | null
  const [bioSupported, setBioSupported] = useState(null); // null=checking, true/false

  useEffect(() => {
    api.checkBio().then(setBioSupported).catch(() => setBioSupported(false));
  }, []);

  // Passi visibili: 1 se biometria non supportata, 2 se supportata
  // Durante il check iniziale (null) mostra solo lo step 0 per non bloccare la UI
  const visibleSteps = bioSupported ? steps : [steps[0]];

  const handleNext = async () => {
    // Step 1 (Biometria): gestione configurazione biometrica
    if (step === 1 && !bioResult) {
      setBioLoading(true);
      try {
        // Prima verifica se la biometria è già stata configurata (auto-enroll da LoginScreen)
        const saved = await api.hasBioSaved();
        if (saved) {
          setBioResult('success');
          setTimeout(() => onComplete(), 800);
          return;
        }
        // Prova onConfigureBio se fornito da App.jsx
        if (onConfigureBio) {
          const success = await onConfigureBio();
          setBioResult(success ? 'success' : 'failed');
          if (success) {
            setTimeout(() => onComplete(), 800);
            return;
          }
        } else {
          // Nessun modo per configurare ora — mostra messaggio informativo
          setBioResult('failed');
        }
      } catch {
        setBioResult('failed');
      } finally {
        setBioLoading(false);
      }
      return;
    }

    if (step < visibleSteps.length - 1) {
      setStep(s => s + 1);
    } else {
      onComplete();
    }
  };

  const handleSkip = () => {
    if (step < visibleSteps.length - 1) {
      setStep(s => s + 1);
    } else {
      onComplete();
    }
  };

  const currentStepData = visibleSteps[step];
  const Icon = currentStepData.icon;
  const isLastStep = step === visibleSteps.length - 1;

  return (
    <div className="fixed inset-0 z-[9999] bg-[var(--bg)] flex items-center justify-center p-4">
      <div className="w-full max-w-md space-y-8">
        {/* Progress */}
        <div className="flex items-center justify-center gap-2">
          {visibleSteps.map((_, i) => (
            <div key={i} className={`h-1.5 rounded-full transition-all duration-300 ${
              i <= step ? 'w-8 bg-[var(--primary)]' : 'w-4 bg-[var(--border)]'
            }`} />
          ))}
        </div>

        {/* Step content */}
        <div className="text-center space-y-4">
          <div className={`w-16 h-16 mx-auto rounded-2xl flex items-center justify-center ${
            bioResult === 'success' ? 'bg-green-500/10' : 'bg-[var(--primary-soft)]'
          }`}>
            {bioResult === 'success' ? (
              <Check size={28} className="text-green-500" />
            ) : (
              <Icon size={28} className="text-[var(--primary)]" />
            )}
          </div>
          <h2 className="text-xl font-bold text-[var(--text)]">
            {bioResult === 'success' ? 'Biometria Configurata!' : currentStepData.title}
          </h2>
          <p className="text-sm text-[var(--text-dim)] max-w-sm mx-auto">
            {bioResult === 'success'
              ? 'Da ora potrai sbloccare il vault con la biometria.'
              : bioResult === 'failed'
                ? 'Non è stato possibile configurare la biometria. Puoi attivarla in qualsiasi momento dalle Impostazioni.'
                : currentStepData.description}
          </p>
        </div>

        {/* Actions */}
        <div className="flex flex-col items-center gap-3">
          <button
            onClick={handleNext}
            disabled={bioLoading}
            className="btn-primary px-8 py-3 rounded-xl flex items-center gap-2 font-bold text-sm disabled:opacity-50"
          >
            {bioLoading ? (
              'Verifica in corso...'
            ) : isLastStep ? (
              <><Check size={16} /> Inizia</>
            ) : step === 1 ? (
              <><Fingerprint size={16} /> Configura</>
            ) : (
              <><ArrowRight size={16} /> Continua</>
            )}
          </button>

          {/* Skip — solo per step skippable */}
          {currentStepData.skippable && (
            <button
              onClick={handleSkip}
              className="flex items-center gap-1.5 text-xs text-[var(--text-dim)] hover:text-[var(--text)] transition-colors"
            >
              <SkipForward size={12} />
              {currentStepData.skipLabel}
            </button>
          )}
        </div>

        {/* Step counter */}
        <p className="text-center text-xs text-[var(--text-dim)]">
          Passaggio {step + 1} di {visibleSteps.length}
        </p>
      </div>
    </div>
  );
}
