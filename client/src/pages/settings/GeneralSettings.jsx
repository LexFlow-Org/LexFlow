import { useState } from 'react';

export default function GeneralSettings({ settings, onSettingsChange }) {
  const [lawyerTitle, setLawyerTitle] = useState(settings?.lawyerTitle || 'Avv.');
  const [lawyerName, setLawyerName] = useState(settings?.lawyerName || '');
  const [studioName, setStudioName] = useState(settings?.studioName || '');

  const handleSave = (field, value) => {
    onSettingsChange({ ...settings, [field]: value });
  };

  return (
    <section className="glass-card p-6 space-y-6">
      <div className="flex items-center gap-3">
        <h2 className="text-lg font-bold text-text">Profilo Studio</h2>
      </div>
      <div className="space-y-4">
        <div>
          <label className="text-2xs font-bold text-text-dim uppercase tracking-label block mb-1">Titolo e Nome</label>
          <div className="flex gap-2">
            <select
              value={lawyerTitle}
              onChange={e => { setLawyerTitle(e.target.value); handleSave('lawyerTitle', e.target.value); }}
              className="px-3 py-2.5 rounded-xl bg-surface border border-border text-text text-sm"
              aria-label="Titolo professionale"
            >
              <option value="Avv.">Avv.</option>
              <option value="Dott.">Dott.</option>
              <option value="Prof.">Prof.</option>
            </select>
            <input
              value={lawyerName}
              onChange={e => setLawyerName(e.target.value)}
              onBlur={() => handleSave('lawyerName', lawyerName)}
              placeholder="Nome e Cognome"
              className="flex-1 px-4 py-2.5 rounded-xl bg-surface border border-border text-text text-sm placeholder:text-text-dim outline-none focus:border-primary"
            />
          </div>
        </div>
        <div>
          <label className="text-2xs font-bold text-text-dim uppercase tracking-label block mb-1">Nome Studio</label>
          <input
            value={studioName}
            onChange={e => setStudioName(e.target.value)}
            onBlur={() => handleSave('studioName', studioName)}
            placeholder="Studio Legale..."
            className="w-full px-4 py-2.5 rounded-xl bg-surface border border-border text-text text-sm placeholder:text-text-dim outline-none focus:border-primary"
          />
        </div>
      </div>
    </section>
  );
}
