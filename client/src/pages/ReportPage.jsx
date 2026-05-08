import { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import { BarChart3, TrendingUp, Clock, FileText, RefreshCw, Download } from 'lucide-react';
import toast from 'react-hot-toast';
import * as api from '../tauri-api';

// Italian labels for practice types (FIX-27)
const TYPE_LABELS_IT = {
  civile: 'Civile',
  penale: 'Penale',
  amministrativo: 'Amministrativo',
  tributario: 'Tributario',
  lavoro: 'Lavoro',
  famiglia: 'Famiglia',
  societario: 'Societario',
  immobiliare: 'Immobiliare',
  altro: 'Altro',
};

const RAW_EVENT_LABELS_IT = {
  vault_unlocked: 'Vault sbloccato',
  vault_locked: 'Vault bloccato',
  practice_created: 'Fascicolo creato',
  practice_updated: 'Fascicolo aggiornato',
  practice_deleted: 'Fascicolo eliminato',
  document_added: 'Documento aggiunto',
  document_removed: 'Documento rimosso',
  backup_created: 'Backup creato',
  password_changed: 'Password cambiata',
  recovery_key_generated: 'Recovery key generata',
};

function localizeEventLabel(raw) {
  if (typeof raw !== 'string') return raw;
  return RAW_EVENT_LABELS_IT[raw] || raw;
}

const DEFAULT_VISIBLE_ACTIVITIES = 30;

export default function ReportPage({ practices = [], loading: practicesLoading }) {
  const [timeLogs, setTimeLogs] = useState([]);
  const [activityLog, setActivityLog] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activityLoading, setActivityLoading] = useState(false);
  const [showAllActivity, setShowAllActivity] = useState(false);

  // FIX-24 throttle window-focus reload (only if last load > 5s ago)
  const lastLoadRef = useRef(0);

  const loadActivity = useCallback(async () => {
    setActivityLoading(true);
    try {
      const data = await api.getAuditLog();
      setActivityLog(Array.isArray(data) ? [...data].reverse() : []);
    } catch { setActivityLog([]); }
    finally { setActivityLoading(false); }
  }, []);

  // FIX-21 defensive finally on loadTimeLogs
  const loadLogs = useCallback(() => {
    return Promise.resolve(api.loadTimeLogs?.())
      .then(t => setTimeLogs(t || []))
      .catch(e => console.error(e))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    loadLogs();
    loadActivity();
    lastLoadRef.current = Date.now();

    const onFocus = () => {
      const now = Date.now();
      // FIX-24 throttle to >5s gaps
      if (now - lastLoadRef.current < 5000) return;
      lastLoadRef.current = now;
      loadLogs();
      loadActivity();
    };
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, [loadLogs, loadActivity]);

  const stats = useMemo(() => {
    const active = practices.filter(p => p.status === 'active').length;
    const closed = practices.filter(p => p.status === 'closed').length;
    const total = practices.length;

    // FIX-19 ISO 8601 Monday-start week
    const now = new Date();
    const weekStart = new Date(now);
    const dow = (now.getDay() + 6) % 7; // Monday=0, Sunday=6
    weekStart.setDate(now.getDate() - dow);
    weekStart.setHours(0, 0, 0, 0);

    // timeLogs stores minutes; convert to hours for display
    const weekHours = (timeLogs || [])
      .filter(l => new Date(l.date || l.createdAt) >= weekStart)
      .reduce((sum, l) => sum + ((l.minutes || 0) / 60), 0);

    // Hours by day of week — index 0=Mon..6=Sun (FIX-19)
    const dayHours = [0, 0, 0, 0, 0, 0, 0];
    (timeLogs || []).forEach(l => {
      const d = new Date(l.date || l.createdAt);
      if (d >= weekStart) {
        const idx = (d.getDay() + 6) % 7;
        dayHours[idx] += ((l.minutes || 0) / 60);
      }
    });

    // Type distribution
    const typeCounts = {};
    practices.forEach(p => {
      const t = p.type || 'altro';
      typeCounts[t] = (typeCounts[t] || 0) + 1;
    });

    return { active, closed, total, weekHours, dayHours, typeCounts };
  }, [practices, timeLogs]);

  // FIX-19 day labels Monday-first
  const dayLabels = ['Lun', 'Mar', 'Mer', 'Gio', 'Ven', 'Sab', 'Dom'];
  const maxDayHours = Math.max(...stats.dayHours, 1);

  // FIX-20 distinguish "loading" vs "no practices"
  const isLoading = loading || practicesLoading;
  const isEmpty = !isLoading && practices.length === 0;

  // FIX-18 CSV export
  const handleExportCsv = async () => {
    try {
      const path = await api.exportTimeLogsCsv();
      toast.success(`CSV ore esportato: ${path}`);
      if (api.openPath) await api.openPath(path);
    } catch (e) {
      toast.error(`Errore export: ${e?.message || e}`);
    }
  };

  if (isLoading) {
    return (
      <div className="flex-1 flex items-center justify-center text-[var(--text-dim)]">
        Caricamento...
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <BarChart3 size={22} className="text-[var(--primary)]" />
          <h1 className="text-lg font-bold text-[var(--text)]">Report &amp; Analytics</h1>
        </div>
        <button
          onClick={handleExportCsv}
          className="flex items-center gap-2 px-3 py-2 text-xs font-bold uppercase tracking-wider text-[var(--text)] bg-[var(--bg-card)] border border-[var(--border)] rounded-lg hover:bg-[var(--bg-hover)] transition-colors"
          aria-label="Esporta CSV ore"
        >
          <Download size={14} /> Esporta CSV
        </button>
      </div>

      {isEmpty && (
        <div className="glass-card p-6 text-center text-sm text-[var(--text-dim)]">
          Nessun fascicolo registrato. Crea il primo fascicolo per popolare il report.
        </div>
      )}

      {/* Stats cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Fascicoli Totali', value: stats.total, icon: FileText },
          { label: 'Attivi', value: stats.active, icon: TrendingUp },
          { label: 'Chiusi', value: stats.closed, icon: FileText },
          { label: 'Ore Settimana', value: stats.weekHours.toFixed(1), icon: Clock },
        ].map((s) => (
          <div key={s.label} className="glass-card p-4 flex items-center gap-3">
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
        <h3 className="text-2xs font-black uppercase tracking-label text-[var(--text-dim)] mb-4">
          Ore Lavorate &mdash; Questa Settimana
        </h3>
        <div className="flex items-end gap-2 h-32">
          {stats.dayHours.map((h, i) => (
            <div key={dayLabels[i]} className="flex-1 flex flex-col items-center gap-1">
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
        <h3 className="text-2xs font-black uppercase tracking-label text-[var(--text-dim)] mb-4">
          Distribuzione per Materia
        </h3>
        {stats.total === 0 ? (
          <p className="text-center py-4 text-sm text-[var(--text-dim)]">
            Nessun fascicolo da mostrare
          </p>
        ) : (
          <div className="space-y-2">
            {Object.entries(stats.typeCounts).sort((a, b) => b[1] - a[1]).map(([type, count]) => {
              // FIX-25 NaN guard on bar width
              const pct = stats.total > 0 ? (count / stats.total) * 100 : 0;
              // FIX-27 full Italian labels
              const label = TYPE_LABELS_IT[type] || (type.charAt(0).toUpperCase() + type.slice(1));
              return (
                <div key={type} className="flex items-center gap-3">
                  <span className="text-xs text-[var(--text)] w-24 truncate" title={label}>{label}</span>
                  <div className="flex-1 h-3 bg-[var(--bg)] rounded-full overflow-hidden">
                    <div
                      className="h-full bg-[var(--primary)] rounded-full transition-all duration-500"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-xs text-[var(--text-dim)] font-mono w-8 text-right">{count}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Activity Log — FIX-26 fix Italian copy: "Attivita'" -> "Attività" */}
      <div className="glass-card p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-2xs font-black uppercase tracking-label text-[var(--text-dim)]">
            Attività Recenti
          </h3>
          <button
            onClick={loadActivity}
            className="p-1.5 rounded-lg hover:bg-[var(--bg-hover)] text-[var(--text-dim)]"
            aria-label="Aggiorna registro attività"
          >
            <RefreshCw size={14} className={activityLoading ? 'animate-spin' : ''} />
          </button>
        </div>
        {activityLog.length === 0 ? (
          <p className="text-center py-6 text-sm text-[var(--text-dim)]">
            Nessuna attività registrata
          </p>
        ) : (
          <div className="relative max-h-[300px] overflow-y-auto custom-scrollbar">
            <div className="absolute left-4 top-0 bottom-0 w-px bg-[var(--border)]" />
            <div className="space-y-1">
              {(showAllActivity ? activityLog : activityLog.slice(0, DEFAULT_VISIBLE_ACTIVITIES))
                .map((entry) => {
                  const rawEvent = typeof entry === 'string' ? entry : (entry.event || JSON.stringify(entry));
                  const event = localizeEventLabel(rawEvent);
                  const ts = (entry && entry.time) || '';
                  // FIX-23 composite key from time + event (fallback to JSON)
                  const compositeKey = `${ts}|${rawEvent}`;
                  const displayTs = ts ? new Date(ts).toLocaleString('it-IT', {
                    day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit',
                  }) : '';
                  return (
                    <div key={compositeKey} className="flex items-start gap-4 pl-2 py-2">
                      <div className="w-4 h-4 rounded-full bg-[var(--bg-card)] border-2 border-[var(--primary)] z-10 shrink-0 mt-0.5" />
                      <div className="flex-1 min-w-0">
                        <p className="text-xs text-[var(--text)]">{event}</p>
                        {displayTs && (
                          <p className="text-2xs text-[var(--text-dim)] font-mono mt-0.5 flex items-center gap-1">
                            <Clock size={10} /> {displayTs}
                          </p>
                        )}
                      </div>
                    </div>
                  );
                })}
            </div>
            {/* FIX-22 Mostra tutto CTA */}
            {activityLog.length > DEFAULT_VISIBLE_ACTIVITIES && (
              <div className="pt-3 text-center">
                <button
                  onClick={() => setShowAllActivity(s => !s)}
                  className="text-2xs font-bold uppercase tracking-wider text-[var(--primary)] hover:underline"
                >
                  {showAllActivity ? 'Mostra meno' : `Mostra tutto (${activityLog.length})`}
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
