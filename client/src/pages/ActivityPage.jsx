import { useState, useEffect } from 'react';
import { Activity, Clock, RefreshCw } from 'lucide-react';
import * as api from '../tauri-api';

export default function ActivityPage() {
  const [log, setLog] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await api.getAuditLog();
      setLog(Array.isArray(data) ? data.reverse() : []);
    } catch { setLog([]); }
    finally { setLoading(false); }
  };

  useEffect(() => { loadData(); }, []);

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Activity size={22} className="text-[var(--primary)]" />
          <h1 className="text-lg font-bold text-[var(--text)]">Attività Recenti</h1>
        </div>
        <button onClick={loadData} className="p-1.5 rounded-lg hover:bg-[var(--bg-hover)] text-[var(--text-dim)]">
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
        </button>
      </div>

      {loading ? (
        <div className="text-center py-12 text-sm text-[var(--text-dim)]">Caricamento...</div>
      ) : log.length === 0 ? (
        <div className="text-center py-12 text-sm text-[var(--text-dim)]">Nessuna attività registrata</div>
      ) : (
        <div className="relative">
          <div className="absolute left-4 top-0 bottom-0 w-px bg-[var(--border)]" />
          <div className="space-y-1">
            {log.map((entry, i) => {
              const event = typeof entry === 'string' ? entry : (entry.event || JSON.stringify(entry));
              const ts = entry.time || '';
              const displayTs = ts ? new Date(ts).toLocaleString('it-IT', {
                day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit'
              }) : '';
              return (
                <div key={i} className="flex items-start gap-4 pl-2 py-2 group">
                  <div className="w-5 h-5 rounded-full bg-[var(--bg-card)] border-2 border-[var(--primary)] z-10 shrink-0 mt-0.5" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-[var(--text)]">{event}</p>
                    <p className="text-2xs text-[var(--text-dim)] font-mono mt-0.5 flex items-center gap-1">
                      <Clock size={10} /> {displayTs}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
