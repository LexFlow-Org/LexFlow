import { useState, useEffect } from 'react';
import { Shield, Clock, Search, RefreshCw } from 'lucide-react';
import * as api from '../tauri-api';

const EVENT_COLORS = {
  'Sblocco': 'text-emerald-400',
  'Blocco': 'text-amber-400',
  'Nuovo': 'text-blue-400',
  'Modifica': 'text-purple-400',
  'Eliminazione': 'text-red-400',
  'Export': 'text-cyan-400',
  'Import': 'text-cyan-400',
  'Cambio': 'text-orange-400',
  'Reset': 'text-red-400',
  'Migrat': 'text-indigo-400',
};

function getEventColor(event) {
  for (const [key, color] of Object.entries(EVENT_COLORS)) {
    if (event.includes(key)) return color;
  }
  return 'text-[var(--text-dim)]';
}

export default function AuditLogPage() {
  const [log, setLog] = useState([]);
  const [filter, setFilter] = useState('');
  const [loading, setLoading] = useState(true);

  const loadLog = async () => {
    setLoading(true);
    try {
      const data = await api.getAuditLog();
      setLog(Array.isArray(data) ? data.reverse() : []); // newest first
    } catch (e) {
      console.warn('[AuditLog] Failed to load:', e);
      setLog([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadLog(); }, []);

  const filtered = filter
    ? log.filter(entry => {
        const text = `${entry.event || ''} ${entry.time || ''}`.toLowerCase();
        return text.includes(filter.toLowerCase());
      })
    : log;

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-4">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-3">
          <Shield size={22} className="text-[var(--primary)]" />
          <h1 className="text-lg font-bold text-[var(--text)]">Registro Attività</h1>
          <span className="text-xs text-[var(--text-dim)] bg-[var(--bg)] px-2 py-0.5 rounded-full">
            {filtered.length} eventi
          </span>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--text-dim)]" />
            <input
              value={filter}
              onChange={e => setFilter(e.target.value)}
              placeholder="Filtra..."
              className="pl-8 pr-3 py-1.5 text-xs bg-[var(--bg)] border border-[var(--border)]
                         rounded-lg text-[var(--text)] placeholder:text-[var(--text-dim)] outline-none
                         focus:border-[var(--primary)]"
            />
          </div>
          <button onClick={loadLog}
                  className="p-1.5 rounded-lg hover:bg-[var(--bg-hover)] text-[var(--text-dim)]
                             transition-colors" title="Aggiorna">
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {loading ? (
        <div className="text-center py-12 text-sm text-[var(--text-dim)]">Caricamento...</div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-12 text-sm text-[var(--text-dim)]">
          {filter ? 'Nessun evento corrisponde al filtro' : 'Nessun evento registrato'}
        </div>
      ) : (
        <div className="space-y-1">
          {filtered.map((entry, i) => {
            const event = entry.event || entry;
            const ts = entry.time || '';
            const colorClass = getEventColor(typeof event === 'string' ? event : '');
            const displayEvent = typeof event === 'string' ? event : JSON.stringify(event);
            const displayTs = ts ? new Date(ts).toLocaleString('it-IT', {
              day: '2-digit', month: '2-digit', year: 'numeric',
              hour: '2-digit', minute: '2-digit', second: '2-digit'
            }) : '';

            return (
              <div key={i}
                   className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-[var(--bg-hover)]
                              transition-colors group">
                <Clock size={12} className="text-[var(--text-dim)] shrink-0" />
                <span className="text-xs text-[var(--text-dim)] font-mono w-36 shrink-0">
                  {displayTs}
                </span>
                <span className={`text-sm flex-1 ${colorClass}`}>
                  {displayEvent}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
