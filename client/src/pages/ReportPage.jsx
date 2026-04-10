import { useState, useEffect, useMemo } from 'react';
import { BarChart3, TrendingUp, Clock, FileText, RefreshCw } from 'lucide-react';
import * as api from '../tauri-api';

export default function ReportPage({ practices = [] }) {
  const [timeLogs, setTimeLogs] = useState([]);
  const [activityLog, setActivityLog] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activityLoading, setActivityLoading] = useState(false);

  const loadActivity = async () => {
    setActivityLoading(true);
    try {
      const data = await api.getAuditLog();
      setActivityLog(Array.isArray(data) ? [...data].reverse() : []);
    } catch { setActivityLog([]); }
    finally { setActivityLoading(false); }
  };

  useEffect(() => {
    const load = () => {
      api.loadTimeLogs?.().then(t => {
        setTimeLogs(t || []);
        setLoading(false);
      }).catch(() => setLoading(false));
    };
    load();
    loadActivity();
    const onFocus = () => { load(); loadActivity(); };
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, []);

  const stats = useMemo(() => {
    const active = practices.filter(p => p.status === 'active').length;
    const closed = practices.filter(p => p.status === 'closed').length;
    const total = practices.length;

    // Hours this week
    const now = new Date();
    const weekStart = new Date(now);
    weekStart.setDate(now.getDate() - now.getDay());
    weekStart.setHours(0, 0, 0, 0);
    // timeLogs stores minutes, convert to hours for display
    const weekHours = (timeLogs || [])
      .filter(l => new Date(l.date || l.createdAt) >= weekStart)
      .reduce((sum, l) => sum + ((l.minutes || 0) / 60), 0);

    // Hours by day of week
    const dayHours = [0, 0, 0, 0, 0, 0, 0];
    (timeLogs || []).forEach(l => {
      const d = new Date(l.date || l.createdAt);
      if (d >= weekStart) dayHours[d.getDay()] += ((l.minutes || 0) / 60);
    });

    // Type distribution
    const typeCounts = {};
    practices.forEach(p => {
      const t = p.type || 'altro';
      typeCounts[t] = (typeCounts[t] || 0) + 1;
    });

    return { active, closed, total, weekHours, dayHours, typeCounts };
  }, [practices, timeLogs]);

  const dayLabels = ['Dom', 'Lun', 'Mar', 'Mer', 'Gio', 'Ven', 'Sab'];
  const maxDayHours = Math.max(...stats.dayHours, 1);

  if (loading) return <div className="flex-1 flex items-center justify-center text-[var(--text-dim)]">Caricamento...</div>;

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6">
      <div className="flex items-center gap-3">
        <BarChart3 size={22} className="text-[var(--primary)]" />
        <h1 className="text-lg font-bold text-[var(--text)]">Report & Analytics</h1>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Fascicoli Totali', value: stats.total, icon: FileText },
          { label: 'Attivi', value: stats.active, icon: TrendingUp },
          { label: 'Chiusi', value: stats.closed, icon: FileText },
          { label: 'Ore Settimana', value: stats.weekHours.toFixed(1), icon: Clock },
        ].map((s, i) => (
          <div key={i} className="glass-card p-4 flex items-center gap-3">
            <s.icon size={18} className="text-[var(--primary)] shrink-0" />
            <div>
              <p className="text-xl font-black text-[var(--text)] tabular-nums">{s.value}</p>
              <p className="text-3xs text-[var(--text-dim)] font-bold uppercase tracking-wider">{s.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Hours bar chart (CSS-only) */}
      <div className="glass-card p-5">
        <h3 className="text-2xs font-black uppercase tracking-label text-[var(--text-dim)] mb-4">Ore Lavorate — Questa Settimana</h3>
        <div className="flex items-end gap-2 h-32">
          {stats.dayHours.map((h, i) => (
            <div key={i} className="flex-1 flex flex-col items-center gap-1">
              <span className="text-3xs text-[var(--text-dim)] font-mono">{h > 0 ? h.toFixed(1) : ''}</span>
              <div
                className="w-full rounded-t-md bg-[var(--primary)] transition-all duration-500"
                style={{ height: `${(h / maxDayHours) * 100}%`, minHeight: h > 0 ? 4 : 0 }}
              />
              <span className="text-3xs text-[var(--text-dim)] font-medium">{dayLabels[i]}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Type distribution */}
      <div className="glass-card p-5">
        <h3 className="text-2xs font-black uppercase tracking-label text-[var(--text-dim)] mb-4">Distribuzione per Materia</h3>
        <div className="space-y-2">
          {Object.entries(stats.typeCounts).sort((a, b) => b[1] - a[1]).map(([type, count]) => (
            <div key={type} className="flex items-center gap-3">
              <span className="text-xs text-[var(--text)] w-20 capitalize">{type}</span>
              <div className="flex-1 h-3 bg-[var(--bg)] rounded-full overflow-hidden">
                <div
                  className="h-full bg-[var(--primary)] rounded-full transition-all duration-500"
                  style={{ width: `${(count / stats.total) * 100}%` }}
                />
              </div>
              <span className="text-xs text-[var(--text-dim)] font-mono w-8 text-right">{count}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Activity Log */}
      <div className="glass-card p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-2xs font-black uppercase tracking-label text-[var(--text-dim)]">Attivita' Recenti</h3>
          <button onClick={loadActivity} className="p-1.5 rounded-lg hover:bg-[var(--bg-hover)] text-[var(--text-dim)]">
            <RefreshCw size={14} className={activityLoading ? 'animate-spin' : ''} />
          </button>
        </div>
        {activityLog.length === 0 ? (
          <p className="text-center py-6 text-sm text-[var(--text-dim)]">Nessuna attivita' registrata</p>
        ) : (
          <div className="relative max-h-[300px] overflow-y-auto custom-scrollbar">
            <div className="absolute left-4 top-0 bottom-0 w-px bg-[var(--border)]" />
            <div className="space-y-1">
              {activityLog.slice(0, 30).map((entry, i) => {
                const event = typeof entry === 'string' ? entry : (entry.event || JSON.stringify(entry));
                const ts = entry.time || '';
                const displayTs = ts ? new Date(ts).toLocaleString('it-IT', {
                  day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit'
                }) : '';
                return (
                  <div key={i} className="flex items-start gap-4 pl-2 py-2">
                    <div className="w-4 h-4 rounded-full bg-[var(--bg-card)] border-2 border-[var(--primary)] z-10 shrink-0 mt-0.5" />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-[var(--text)]">{event}</p>
                      {displayTs && <p className="text-2xs text-[var(--text-dim)] font-mono mt-0.5 flex items-center gap-1"><Clock size={10} /> {displayTs}</p>}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
