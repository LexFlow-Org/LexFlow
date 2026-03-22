import { useState } from 'react';
import { Shield, Fingerprint, FileText, ArrowRight, Check } from 'lucide-react';

const steps = [
  { icon: Shield, title: 'Crea il tuo Vault', description: 'Imposta una password master sicura per proteggere tutti i tuoi dati con crittografia AES-256-GCM-SIV.' },
  { icon: Fingerprint, title: 'Configura Biometria', description: 'Abilita Touch ID, Windows Hello o impronta digitale per sbloccare il vault senza digitare la password.' },
  { icon: FileText, title: 'Crea il primo Fascicolo', description: 'Inizia aggiungendo il tuo primo fascicolo. Potrai gestire pratiche, scadenze, contatti e molto altro.' },
];

export default function OnboardingWizard({ currentStep = 0, onComplete }) {
  const [step, setStep] = useState(currentStep);

  return (
    <div className="fixed inset-0 z-[9999] bg-[var(--bg)] flex items-center justify-center p-4">
      <div className="w-full max-w-md space-y-8">
        {/* Progress */}
        <div className="flex items-center justify-center gap-2">
          {steps.map((_, i) => (
            <div key={i} className={`h-1.5 rounded-full transition-all duration-300 ${
              i <= step ? 'w-8 bg-[var(--primary)]' : 'w-4 bg-[var(--border)]'
            }`} />
          ))}
        </div>

        {/* Step content */}
        <div className="text-center space-y-4">
          {(() => {
            const Icon = steps[step].icon;
            return (
              <>
                <div className="w-16 h-16 mx-auto rounded-2xl bg-[var(--primary-soft)] flex items-center justify-center">
                  <Icon size={28} className="text-[var(--primary)]" />
                </div>
                <h2 className="text-xl font-bold text-[var(--text)]">{steps[step].title}</h2>
                <p className="text-sm text-[var(--text-dim)] max-w-sm mx-auto">{steps[step].description}</p>
              </>
            );
          })()}
        </div>

        {/* Actions */}
        <div className="flex justify-center gap-3">
          {step < steps.length - 1 ? (
            <button
              onClick={() => setStep(s => s + 1)}
              className="btn-primary px-8 py-3 rounded-xl flex items-center gap-2 font-bold text-sm"
            >
              Continua <ArrowRight size={16} />
            </button>
          ) : (
            <button
              onClick={onComplete}
              className="btn-primary px-8 py-3 rounded-xl flex items-center gap-2 font-bold text-sm"
            >
              Inizia <Check size={16} />
            </button>
          )}
        </div>

        {/* Step indicator */}
        <p className="text-center text-xs text-[var(--text-dim)]">
          Passaggio {step + 1} di {steps.length}
        </p>
      </div>
    </div>
  );
}
