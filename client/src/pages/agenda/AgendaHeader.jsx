import { Plus, Printer } from 'lucide-react';

const VIEW_LABELS = { today: 'Oggi', week: 'Settimana', month: 'Mese' };
const CATEGORIES = ['udienza', 'scadenza', 'riunione', 'personale', 'altro'];

export default function AgendaHeader({
  view, onViewChange, categoryFilter, onCategoryChange,
  onNewEvent, dateLabel
}) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
      <div className="flex items-center gap-3">
        <h1 className="text-lg font-bold text-[var(--text)]">Agenda</h1>
        <div className="flex items-center gap-1 bg-[var(--bg)] rounded-xl p-1">
          {Object.entries(VIEW_LABELS).map(([key, label]) => (
            <button
              key={key}
              onClick={() => onViewChange(key)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                view === key ? 'bg-[var(--primary)] text-black' : 'text-[var(--text-dim)] hover:text-[var(--text)]'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        {CATEGORIES.map(cat => (
          <button
            key={cat}
            onClick={() => onCategoryChange(cat === categoryFilter ? null : cat)}
            className={`text-2xs font-bold uppercase tracking-label px-2.5 py-1 rounded-lg border transition-colors ${
              cat === categoryFilter
                ? 'border-[var(--primary)] text-[var(--primary)] bg-[var(--primary-soft)]'
                : 'border-[var(--border)] text-[var(--text-dim)] hover:border-[var(--primary)]'
            }`}
          >
            {cat}
          </button>
        ))}

        <button
          onClick={() => window.print()}
          className="p-2 rounded-lg hover:bg-[var(--bg-hover)] text-[var(--text-dim)] transition-colors"
          title="Stampa agenda"
          data-no-print
        >
          <Printer size={16} />
        </button>

        <button
          onClick={onNewEvent}
          className="btn-primary px-3 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1.5"
        >
          <Plus size={14} /> Nuovo
        </button>
      </div>
    </div>
  );
}
