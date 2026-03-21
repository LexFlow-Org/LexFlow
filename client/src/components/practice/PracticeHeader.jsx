import { ArrowLeft } from 'lucide-react';

const TYPE_LABELS = {
  civile: 'Civile', penale: 'Penale', amm: 'Amministrativo',
  trib: 'Tributario', lavoro: 'Lavoro', soc: 'Societario',
};

const STATUS_LABELS = {
  active: 'Attivo', closed: 'Chiuso', suspended: 'Sospeso',
};

export default function PracticeHeader({ practice, onBack }) {
  const typeLabel = TYPE_LABELS[practice.type] || practice.type || 'Altro';
  const statusLabel = STATUS_LABELS[practice.status] || practice.status || '';

  return (
    <div className="flex items-center gap-4 mb-6">
      <button onClick={onBack} className="p-2 rounded-xl hover:bg-[var(--bg-hover)] transition-colors" aria-label="Indietro">
        <ArrowLeft size={20} className="text-[var(--text-dim)]" />
      </button>
      <div className="flex-1 min-w-0">
        <h1 className="text-xl font-bold text-[var(--text)] truncate">{practice.client || 'Senza cliente'}</h1>
        <p className="text-xs text-[var(--text-dim)] truncate">{practice.object || ''}</p>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <span className="text-2xs font-bold uppercase tracking-label px-2.5 py-1 rounded-lg border border-[var(--border)] text-[var(--text-dim)]">
          {typeLabel}
        </span>
        <span className={`text-2xs font-bold uppercase tracking-label px-2.5 py-1 rounded-lg ${
          practice.status === 'active' ? 'text-emerald-400 border border-emerald-400/30' :
          practice.status === 'closed' ? 'text-red-400 border border-red-400/30' :
          'text-amber-400 border border-amber-400/30'
        }`}>
          {statusLabel}
        </span>
      </div>
    </div>
  );
}
