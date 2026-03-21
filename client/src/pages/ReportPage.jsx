import { useState, useEffect, useMemo } from 'react';
import { BarChart3, TrendingUp, Clock, FileText } from 'lucide-react';
import * as api from '../tauri-api';

export default function ReportPage() {
  const [practices, setPractices] = useState([]);
  const [timeLogs, setTimeLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      api.loadPractices().catch(() => []),
      api.loadTimeLogs?.().catch(() => []),
    ]).then(([p, t]) => {
      setPractices(p || []);
      setTimeLogs(t || []);
      setLoading(false);
    });
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
    const weekHours = (timeLogs || [])
      .filter(l => new Date(l.date) >= weekStart)
      .reduce((sum, l) => sum + (l.hours || 0), 0);

    // Hours by day of week
    const dayHours = [0, 0, 0, 0, 0, 0, 0];
    (timeLogs || []).forEach(l => {
      const d = new Date(l.date);
      if (d >= weekStart) dayHours[d.getDay()] += (l.hours || 0);
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
    </div>
  );
}
