import { useState, useEffect, useMemo } from 'react';
import * as api from '../tauri-api';

// Strip leading honorifics ("Avv. Mario Rossi" → "Mario Rossi") so the title
// shown in the table is whatever the user selected, not what the license token
// happens to embed.
function stripTitlePrefix(name) {
  if (!name) return '';
  return String(name)
    .trim()
    .replace(/^(Avv\.|Avv|Avvocato|Praticante)\.?\s+/i, '')
    .trim();
}

export default function LicenseSettings() {
  const [licenseInfo, setLicenseInfo] = useState(null);
  const [loadError, setLoadError] = useState(null);
  // 'pending' until checkLicense fully resolves with an activation flag.
  const [verificationStatus, setVerificationStatus] = useState('pending');

  useEffect(() => {
    let mounted = true;
    api.checkLicense()
      .then(res => {
        if (!mounted) return;
        if (res?.activated) {
          setLicenseInfo(res);
          setVerificationStatus('verified');
        } else {
          setVerificationStatus('not-activated');
        }
      })
      .catch(err => {
        if (!mounted) return;
        console.warn("Errore nel recupero licenza:", err);
        setLoadError(typeof err === 'string' ? err : (err?.message || 'Errore sconosciuto'));
        setVerificationStatus('error');
      });
    return () => { mounted = false; };
  }, []);

  // Memoize the cleaned-up display name so it isn't recomputed on every render.
  const displayName = useMemo(() => stripTitlePrefix(licenseInfo?.lawyerName), [licenseInfo?.lawyerName]);

  // Show an explicit error block when the license check rejected outright.
  if (loadError) {
    return (
      <div className="p-6 bg-danger-soft border border-danger-border rounded-xl mt-8" role="alert">
        <h3 className="text-danger font-semibold mb-2 flex items-center gap-2">Licenza — errore di lettura</h3>
        <p className="text-xs text-text-muted leading-relaxed">
          Non è stato possibile leggere lo stato della licenza. Controlla il file di licenza o riavvia l&apos;app.
        </p>
        <p className="mt-2 text-2xs text-text-dim font-mono break-all">{loadError}</p>
      </div>
    );
  }

  // Se la licenza non è attiva, il componente non occupa spazio nella UI
  if (!licenseInfo) return null;

  return (
    <div className="p-6 bg-surface border border-border rounded-xl mt-8 animate-fade-in">
      <h3 className="text-text font-semibold mb-4 flex items-center gap-2">
        Informazioni Software
      </h3>
      <div className="space-y-3 text-sm">
        <div className="flex justify-between items-center border-b border-border pb-2">
          <span className="text-text-dim">Stato Attivazione:</span>
          {licenseInfo.inGracePeriod ? (
            <span className="text-warning font-medium bg-warning-soft px-2 py-0.5 rounded">
              Grace Period ({licenseInfo.graceDays}gg)
            </span>
          ) : (
            <span className="text-success font-medium bg-success-soft px-2 py-0.5 rounded">
              Attiva
            </span>
          )}
        </div>
        {licenseInfo.lawyerName && (
        <div className="flex justify-between items-center border-b border-border pb-2">
          <span className="text-text-dim">Avvocato:</span>
          <span className="text-text font-mono">{licenseInfo.lawyerTitle || 'Avv.'} {displayName}</span>
        </div>
        )}
        {licenseInfo.studioName && (
        <div className="flex justify-between items-center border-b border-border pb-2">
          <span className="text-text-dim">Studio:</span>
          <span className="text-text font-mono">{licenseInfo.studioName}</span>
        </div>
        )}
        <div className="flex justify-between items-center border-b border-border pb-2">
          <span className="text-text-dim">Protezione:</span>
          <span className="text-text-muted">v2.4 Burned-Key (Ed25519 + AES-256-GCM)</span>
        </div>
      </div>
      {verificationStatus === 'verified' && (
        <div className="mt-4 text-2xs text-text-dim text-right italic">
          Verifica crittografica locale eseguita con successo
        </div>
      )}
    </div>
  );
}
