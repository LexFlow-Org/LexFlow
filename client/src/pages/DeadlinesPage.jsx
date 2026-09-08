import { useState, useEffect, useMemo, useRef, memo, useLayoutEffect } from 'react';
import PropTypes from 'prop-types';
import { CalendarClock, ChevronRight, Check, Calendar, FolderOpen } from 'lucide-react';
import toast from 'react-hot-toast';
import * as api from '../tauri-api';
import { formatDateIT, mapAgendaToScheduleItems, parseLocalYMD } from '../utils/helpers';

const TYPE_LABELS = { civile: 'Civile', penale: 'Penale', amm: 'Amministrativo', lavoro: 'Lavoro', stra: 'Stragiudiziale' };

/**
 * Compute urgency level + UI metadata from a row's day-diff.
 *   diff < 0   → overdue (rosso)
 *   diff === 0 → today  (giallo)
 *   diff > 0   → future (neutro)
 */
function computeUrgency(d) {
  if (typeof d?.diff !== 'number') return { level: 'future', borderClass: 'border-l-border' };
  if (d.diff < 0) return { level: 'overdue', borderClass: 'border-l-danger' };
  if (d.diff === 0) return { level: 'today', borderClass: 'border-l-warning' };
  return { level: 'future', borderClass: 'border-l-border' };
}

const URGENCY_LABEL = { overdue: 'in ritardo', today: 'oggi', future: 'in arrivo' };

const DeadlineRow = memo(function DeadlineRow({ d, onSelectPractice, onNavigate }) {
  const [showPopover, setShowPopover] = useState(false);
  const [popoverFlipUp, setPopoverFlipUp] = useState(false);
  const popRef = useRef(null);
  const popoverContentRef = useRef(null);

  // Close popover on outside click
  useEffect(() => {
    if (!showPopover) return;
    const handler = (e) => { if (popRef.current && !popRef.current.contains(e.target)) setShowPopover(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [showPopover]);

  // FIX-21: flip popover above the row when it would overflow viewport bottom
  useLayoutEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (!showPopover) { setPopoverFlipUp(false); return; }
    const el = popoverContentRef.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    if (r.bottom > window.innerHeight - 12) setPopoverFlipUp(true);
  }, [showPopover]);

  const navigateToAgenda = () => {
    const timeParam = d.timeStart ? `&time=${d.timeStart}` : '';
    if (onNavigate) onNavigate('/agenda?date=' + d.date + timeParam);
  };

  // FIX-22: click ALWAYS navigates to agenda; popover offers an extra
  // "vai al fascicolo" branch only when a practice is linked. No more
  // ambiguity ("nothing happens until you pick from popover").
  const handleClick = () => {
    if (d.practiceId) setShowPopover(v => !v);
    else navigateToAgenda();
  };

  const urgency = computeUrgency(d);
  // FIX-20: empty/whitespace label fallback
  const safeLabel = (d.label && d.label.trim()) || 'Scadenza senza titolo';
  // FIX-17: descriptive aria-label
  const ariaLabel = `${safeLabel}, ${formatDateIT(d.date)}, ${URGENCY_LABEL[urgency.level]}`;

  return (
    <div className="relative" ref={popRef}>
      <button
        type="button"
        aria-label={ariaLabel}
        aria-haspopup={d.practiceId ? 'menu' : undefined}
        aria-expanded={d.practiceId ? showPopover : undefined}
        className={`flex items-center gap-3 p-3 rounded-xl bg-cat-scadenza border-l-4 ${urgency.borderClass} hover:bg-card transition cursor-pointer group border border-border hover:border-border text-left w-full`}
        onClick={handleClick}
      >
      <div className="w-2.5 h-2.5 rounded-full flex-shrink-0 bg-cat-scadenza" />
      <div className="flex-1 min-w-0">
        <p className="text-sm font-bold text-text truncate">{safeLabel}</p>
        <div className="flex items-center gap-2 mt-1">
          <FolderOpen size={11} className="text-text-muted flex-shrink-0" />
          {d.client && d.client !== 'Agenda' ? (
            <span className="text-xs text-text-muted">{d.client}</span>
          ) : (
            <span className="text-xs text-text-dim">Agenda</span>
          )}
          {TYPE_LABELS[d.type] && (
            <span className="text-2xs text-text-dim uppercase tracking-wider font-semibold">
              {TYPE_LABELS[d.type]}
            </span>
          )}
        </div>
      </div>
      <div className="text-xs font-mono text-text-muted bg-surface px-2.5 py-1 rounded-lg">{formatDateIT(d.date)}</div>
      <ChevronRight size={14} className="text-text-dim group-hover:text-primary transition flex-shrink-0" />
    </button>

    {/* Popover: Apri in Agenda / Vai al Fascicolo */}
    {showPopover && (
      <div
        ref={popoverContentRef}
        role="menu"
        className={`absolute right-4 z-50 flex flex-col gap-1 p-1.5 rounded-xl bg-card border border-border shadow-2xl min-w-[180px] animate-slide-up ${popoverFlipUp ? 'bottom-full mb-1' : 'top-full mt-1'}`}
      >
        <button role="menuitem" onClick={() => { setShowPopover(false); navigateToAgenda(); }} className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-bold text-white hover:bg-card transition">
          <Calendar size={14} className="text-primary" /> Apri in Agenda
        </button>
        <button role="menuitem" onClick={() => { setShowPopover(false); onSelectPractice?.(d.practiceId); }} className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-bold text-white hover:bg-card transition">
          <FolderOpen size={14} className="text-primary" /> Vai al Fascicolo
        </button>
      </div>
    )}
    </div>
  );
});

DeadlineRow.propTypes = {
  d: PropTypes.shape({
    diff: PropTypes.number,
    label: PropTypes.string,
    client: PropTypes.string,
    type: PropTypes.string,
    date: PropTypes.string,
    timeStart: PropTypes.string,
    source: PropTypes.string,
    practiceId: PropTypes.string,
    id: PropTypes.string,
  }),
  onSelectPractice: PropTypes.func,
  onNavigate: PropTypes.func,
};

function DeadlineSection({ title, items, onSelectPractice, onNavigate }) {
  if (items.length === 0) return null;
  return (
    <div className="mb-6">
      <div className="flex items-center gap-2 mb-3 pb-2 border-b border-border">
        <h3 className="text-2xs font-black uppercase tracking-label text-text">{title} ({items.length})</h3>
      </div>
      <div className="space-y-2">
        {items.map((d) => <DeadlineRow key={`${d.date}_${d.label}_${d.practiceId || d.id}`} d={d} onSelectPractice={onSelectPractice} onNavigate={onNavigate} />)}
      </div>
    </div>
  );
}

DeadlineSection.propTypes = {
  title: PropTypes.string,
  items: PropTypes.array,
  onSelectPractice: PropTypes.func,
  onNavigate: PropTypes.func,
};

export default function DeadlinesPage({ practices, onSelectPractice, settings, agendaEvents, onNavigate, onSettingsChange }) {
  const [briefingDraft, setBriefingDraft] = useState(null);
  const savedBriefing = {
    briefingMattina: settings?.briefingMattina || '08:30',
    briefingPomeriggio: settings?.briefingPomeriggio || '14:30',
    briefingSera: settings?.briefingSera || '19:30',
  };
  const briefingSource = JSON.stringify([savedBriefing, settings?.notifyEnabled !== false]);
  const briefingValues = briefingDraft?.source === briefingSource ? briefingDraft.values : savedBriefing;
  const { briefingMattina, briefingPomeriggio, briefingSera } = briefingValues;
  const briefingDirty = Object.keys(savedBriefing).some(key => briefingValues[key] !== savedBriefing[key]);

  // FIX-15: read the freshest agendaEvents at save-time. Without the ref, the
  // sync would carry the snapshot captured at component-mount in the closure,
  // missing edits the user just made before tapping "Salva".
  const agendaRef = useRef(agendaEvents);
  useEffect(() => { agendaRef.current = agendaEvents; }, [agendaEvents]);

  const handleBriefingSave = async () => {
    // FIX-18: warn on duplicate / out-of-order briefing times
    const times = [briefingMattina, briefingPomeriggio, briefingSera].filter(Boolean);
    const uniq = new Set(times);
    if (uniq.size !== times.length) {
      toast.error('Gli orari briefing devono essere distinti');
      return;
    }
    if (briefingMattina && briefingPomeriggio && briefingMattina >= briefingPomeriggio) {
      toast.error('Mattina deve precedere Pomeriggio');
      return;
    }
    if (briefingPomeriggio && briefingSera && briefingPomeriggio >= briefingSera) {
      toast.error('Pomeriggio deve precedere Sera');
      return;
    }

    try {
      const updated = { ...settings, briefingMattina, briefingPomeriggio, briefingSera };
      await api.saveSettings(updated);
      // Sync backend scheduler con formato corretto: briefingTimes (array) + items preservati
      const briefingTimes = times;
      const items = mapAgendaToScheduleItems(agendaRef.current, settings?.preavviso || 30);
      await api.syncNotificationSchedule({ briefingTimes, items });
      setBriefingDraft(null);
      // Propagate to parent so all pages see the updated briefing times
      if (onSettingsChange) onSettingsChange({ briefingMattina, briefingPomeriggio, briefingSera });
      toast.success('Orari briefing aggiornati');
    } catch {
      toast.error('Errore nel salvataggio');
    }
  };

  const onBriefingChange = (key) => (e) => {
    setBriefingDraft({ source: briefingSource, values: { ...briefingValues, [key]: e.target.value } });
  };

  // Pre-build practices map for O(1) lookup
  const practicesMap = useMemo(() => {
    const map = new Map();
    (practices || []).forEach(p => { if (p?.id) map.set(p.id, p); });
    return map;
  }, [practices]);

  // Collect all deadlines from active practices + agenda scadenze
  const { allDeadlines, pastDeadlines, todayDeadlines, weekDeadlines, futureDeadlines, next30 } = useMemo(() => {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    /**
     * Parse date string and return days-diff from today, or null if invalid.
     * FIX-14: `new Date("YYYY-MM-DD")` parses as UTC midnight, which on
     * negative-UTC users wrongly classifies a "today" deadline as "yesterday".
     * Use parseLocalYMD when the input is YMD; fall back to Date for ISO
     * timestamps.
     */
    const daysDiff = (dateStr) => {
      if (!dateStr) return null;
      let d;
      if (typeof dateStr === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
        d = parseLocalYMD(dateStr);
      } else {
        d = new Date(dateStr);
      }
      if (Number.isNaN(d.getTime())) return null;
      d.setHours(0, 0, 0, 0);
      return Math.ceil((d - today) / (1000 * 60 * 60 * 24));
    };

    const all = [];
    (practices || []).filter(p => p.status === 'active').forEach(p => {
      (p.deadlines || []).forEach(d => {
        const diff = daysDiff(d.date);
        if (diff === null) return;
        all.push({ ...d, practiceId: p.id, client: p.client, object: p.object, type: p.type, diff, source: 'practice' });
      });
    });

    (agendaEvents || []).filter(e => e.category === 'scadenza' && !e.completed && !e.autoSync).forEach(e => {
      const diff = daysDiff(e.date);
      if (diff === null) return;
      all.push({
        id: e.id,
        label: e.title,
        date: e.date,
        timeStart: e.timeStart || null,
        practiceId: e.practiceId || null,
        client: e.practiceId ? (practicesMap.get(e.practiceId)?.client || 'Agenda') : 'Agenda',
        object: e.notes || '',
        type: e.practiceId ? (practicesMap.get(e.practiceId)?.type || 'agenda') : 'agenda',
        diff,
        source: 'agenda',
      });
    });
    // Sort lexicographically — YYYY-MM-DD strings sort the same way as their
    // local-midnight Dates and avoid the UTC-parse trap of `new Date(ymd)`.
    all.sort((a, b) => (a.date || '').localeCompare(b.date || ''));

    return {
      allDeadlines: all,
      pastDeadlines: all.filter(d => d.diff < 0),
      todayDeadlines: all.filter(d => d.diff === 0),
      weekDeadlines: all.filter(d => d.diff > 0 && d.diff <= 7),
      futureDeadlines: all.filter(d => d.diff > 7),
      next30: all.filter(d => d.diff > 0 && d.diff <= 30),
    };
  }, [practices, agendaEvents, practicesMap]);

  return (
    <div className="animate-slide-up space-y-0">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-black text-text flex items-center gap-3 tracking-tight">
            <div className="w-10 h-10 rounded-xl bg-surface flex items-center justify-center">
              <CalendarClock size={20} className="text-text-muted" />
            </div>
            Scadenze
          </h1>
          <p className="text-text-dim text-xs mt-1.5 uppercase tracking-label font-bold">{allDeadlines.length} scadenz{allDeadlines.length === 1 ? 'a' : 'e'} totali</p>
        </div>
      </div>

      {/* 3 Stat Cards + Briefing Widget */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        {/* In Scadenza Oggi */}
        <div className="glass-card p-5 border border-border">
          <p className="text-2xs font-bold text-text-dim uppercase tracking-wider mb-2">In Scadenza Oggi</p>
          <p className="text-3xl font-black text-text">{todayDeadlines.length}</p>
          <p className="text-xs text-text-muted mt-1 truncate">
            {todayDeadlines.length === 0 ? 'Nessuna scadenza' : todayDeadlines.map(d => d.label).join(', ')}
          </p>
        </div>

        {/* In Ritardo */}
        <div className="glass-card p-5 border border-border">
          <p className="text-2xs font-bold text-text-dim uppercase tracking-wider mb-2">In Ritardo</p>
          <p className="text-3xl font-black text-text">{pastDeadlines.length}</p>
          <p className="text-xs text-text-muted mt-1 truncate">
            {pastDeadlines.length === 0
              ? 'Tutto in regola'
              : (() => {
                  const n = pastDeadlines.length;
                  const s = n === 1 ? 'a' : 'e';
                  return `${n} scadenz${s} superat${s}`;
                })()}
          </p>
        </div>

        {/* Prossimi 30 giorni */}
        <div className="glass-card p-5 border border-border">
          <p className="text-2xs font-bold text-text-dim uppercase tracking-wider mb-2">Prossimi 30 Giorni</p>
          <p className="text-3xl font-black text-text">{next30.length}</p>
          <p className="text-xs text-text-muted mt-1 truncate">
            {next30.length === 0 ? 'Calendario libero' : `${next30.length} in arrivo`}
          </p>
        </div>

        {/* Orari Briefing — EDITABILE */}
        <div className={`glass-card p-4 transition-opacity duration-300 ${settings?.notifyEnabled === false ? 'opacity-40' : ''}`}>
          <div className="flex items-center justify-between mb-3">
            <p className="text-2xs font-bold text-text-dim uppercase tracking-wider">Orari Briefing</p>
            {briefingDirty && settings?.notifyEnabled !== false && (
              <button onClick={handleBriefingSave} className="flex items-center gap-1 text-2xs font-bold text-primary hover:text-primary-hover transition-colors">
                <Check size={12} /> Salva
              </button>
            )}
          </div>
          <div className={`space-y-2 ${settings?.notifyEnabled === false ? 'pointer-events-none' : ''}`}>
            {[
              { label: 'Mattina', value: briefingMattina, onChange: onBriefingChange('briefingMattina') },
              { label: 'Pomeriggio', value: briefingPomeriggio, onChange: onBriefingChange('briefingPomeriggio') },
              { label: 'Sera', value: briefingSera, onChange: onBriefingChange('briefingSera') },
            ].map(({ label, value, onChange }) => (
              <div key={label} className="flex items-center justify-between bg-surface rounded-lg px-3 py-2 border border-border">
                <span className="text-xs text-text font-medium">{label}</span>
                <input type="time" disabled={settings?.notifyEnabled === false} className={`bg-surface border border-border rounded-lg px-2.5 py-1 text-xs text-text font-mono text-center focus:border-primary/50 focus:ring-1 focus:ring-primary/20 outline-none transition-colors w-24 ${settings?.notifyEnabled === false ? 'cursor-not-allowed' : ''}`} value={value} onChange={onChange} />
              </div>
            ))}
          </div>
        </div>
      </div>

      {allDeadlines.length === 0 ? (
        <div className="text-center py-16">
          <CalendarClock size={40} className="text-text-dim mx-auto mb-3" />
          <p className="text-text-muted text-sm">Nessuna scadenza impostata</p>
        </div>
      ) : (
        <div className="glass-card p-6">
          <DeadlineSection title="Scadute" items={pastDeadlines} onSelectPractice={onSelectPractice} onNavigate={onNavigate} />
          <DeadlineSection title="Oggi" items={todayDeadlines} onSelectPractice={onSelectPractice} onNavigate={onNavigate} />
          <DeadlineSection title="Prossimi 7 giorni" items={weekDeadlines} onSelectPractice={onSelectPractice} onNavigate={onNavigate} />
          <DeadlineSection title="Future" items={futureDeadlines} onSelectPractice={onSelectPractice} onNavigate={onNavigate} />
        </div>
      )}
    </div>
  );
}

DeadlinesPage.propTypes = {
  practices: PropTypes.array.isRequired,
  onSelectPractice: PropTypes.func,
  settings: PropTypes.object,
  agendaEvents: PropTypes.array,
  onNavigate: PropTypes.func,
  onSettingsChange: PropTypes.func,
};