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
    <div className="p-6 bg-slate-900/50 border border-white/10 rounded-xl mt-8 animate-fade-in">
      <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
        Informazioni Software
      </h3>
      <div className="space-y-3 text-sm">
        <div className="flex justify-between items-center border-b border-white/5 pb-2">
          <span className="text-slate-400">Stato Attivazione:</span>
          {licenseInfo.inGracePeriod ? (
            <span className="text-orange-400 font-medium bg-orange-400/10 px-2 py-0.5 rounded">
              Grace Period ({licenseInfo.graceDays}gg)
            </span>
          ) : (
            <span className="text-green-400 font-medium bg-green-400/10 px-2 py-0.5 rounded">
              Attiva
            </span>
          )}
        </div>
        <div className="flex justify-between items-center border-b border-white/5 pb-2">
          <span className="text-slate-400">Intestatario:</span>
          <span className="text-white font-mono">{licenseInfo.client}</span>
        </div>
        <div className="flex justify-between items-center border-b border-white/5 pb-2">
          <span className="text-slate-400">Protezione:</span>
          <span className="text-slate-300">v2.4 Burned-Key (Ed25519 + AES-256-GCM)</span>
        </div>
      </div>
      <div className="mt-4 text-[10px] text-slate-500 text-right italic">
        Verifica crittografica locale eseguita con successo
      </div>
    </div>
  );
}
