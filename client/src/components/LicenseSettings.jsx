import { useState, useEffect } from 'react';
import * as api from '../tauri-api';

export default function LicenseSettings() {
  const [licenseInfo, setLicenseInfo] = useState(null);

  useEffect(() => {
    api.checkLicense()
      .then(res => {
        if (res.activated) {
          setLicenseInfo(res);
        }
      })
      .catch(err => {
        console.warn("Errore nel recupero licenza:", err);
      });
  }, []);

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
          <span className="text-text font-mono">{licenseInfo.lawyerTitle || 'Avv.'} {licenseInfo.lawyerName}</span>
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
      <div className="mt-4 text-2xs text-text-dim text-right italic">
        Verifica crittografica locale eseguita con successo
      </div>
    </div>
  );
}
