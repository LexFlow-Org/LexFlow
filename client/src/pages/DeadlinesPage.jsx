import { useState, useEffect, useMemo } from 'react';
import PropTypes from 'prop-types';
import { CalendarClock, ChevronRight, Check, Calendar } from 'lucide-react';
import toast from 'react-hot-toast';
import * as api from '../tauri-api';
import { formatDateIT } from '../utils/helpers';

const TYPE_LABELS = { civile: 'Civile', penale: 'Penale', amm: 'Amministrativo', stra: 'Stragiudiziale', agenda: 'Agenda' };

function DeadlineRow({ d, onSelectPractice, onNavigate }) {
  const handleClick = () => {
    if (d.source === 'agenda') {
      if (onNavigate) onNavigate('/agenda');
    } else if (d.practiceId) {
      onSelectPractice(d.practiceId);
    }
  };
  return (
    <button
      type="button"
      className="flex items-center gap-3 p-3 rounded-xl bg-white/[0.03] hover:bg-white/[0.06] transition cursor-pointer group border border-white/5 hover:border-white/10 text-left w-full"
      onClick={handleClick}
    >
      <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${(() => {
        if (d.diff < 0) return 'bg-red-400';
        if (d.diff === 0 || d.diff <= 3) return 'bg-amber-400';
        return 'bg-blue-400';
      })()}`} />
      <div className="flex-1 min-w-0">
        <p className="text-xs font-bold text-white">{d.label}</p>
        <div className="flex items-center gap-2 mt-0.5">
          <span className="text-[10px] text-text-dim">{d.client}</span>
          <span className="text-[9px] text-text-dim/60 uppercase tracking-wider">
            {TYPE_LABELS[d.type]}
          </span>
        </div>
      </div>
      <div className="text-[10px] font-mono text-text-dim bg-white/5 px-2 py-0.5 rounded">{formatDateIT(d.date)}</div>
      {d.source === 'agenda' && <Calendar size={12} className="text-primary/60 flex-shrink-0" title="Da Agenda" />}
      <ChevronRight size={14} className="text-text-dim group-hover:text-primary transition flex-shrink-0" />
    </button>
  );
}

DeadlineRow.propTypes = {
  d: PropTypes.shape({
    diff: PropTypes.number,
    label: PropTypes.string,
    client: PropTypes.string,
    type: PropTypes.string,
    date: PropTypes.string,
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
      <h3 className="text-[10px] font-black text-text-dim uppercase tracking-[2px] mb-3">{title} ({items.length})</h3>
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

export default function DeadlinesPage({ practices, onSelectPractice, settings, agendaEvents, onNavigate }) {
  const [briefingMattina, setBriefingMattina] = useState(settings?.briefingMattina || '08:30');
  const [briefingPomeriggio, setBriefingPomeriggio] = useState(settings?.briefingPomeriggio || '14:30');
  const [briefingSera, setBriefingSera] = useState(settings?.briefingSera || '19:30');
  const [briefingDirty, setBriefingDirty] = useState(false);

  useEffect(() => {
    setBriefingMattina(settings?.briefingMattina || '08:30');
    setBriefingPomeriggio(settings?.briefingPomeriggio || '14:30');
    setBriefingSera(settings?.briefingSera || '19:30');
    setBriefingDirty(false);
  }, [settings]);

  const handleBriefingSave = async () => {
    try {
      const updated = { ...settings, briefingMattina, briefingPomeriggio, briefingSera };
      await api.saveSettings(updated);
      // Sync backend scheduler con formato corretto: briefingTimes (array) + items preservati
      const briefingTimes = [briefingMattina, briefingPomeriggio, briefingSera].filter(Boolean);
      const items = (agendaEvents || [])
        .filter(e => !e.completed && e.timeStart)
        .map(e => ({
          id: e.id,
          date: e.date,
          time: e.timeStart,
          title: e.title,
          remindMinutes: (() => {
            if (typeof e.remindMinutes === 'number') return e.remindMinutes;
            if (e.remindMinutes === 'custom') return 0;
            return Number.parseInt(e.remindMinutes, 10) || (settings?.preavviso || 30);
          })(),
          customRemindTime: e.customRemindTime || null,
        }));
      await api.syncNotificationSchedule({ briefingTimes, items });
      setBriefingDirty(false);
      toast.success('Orari briefing aggiornati');
    } catch {
      toast.error('Errore nel salvataggio');
    }
  };

  const onBriefingChange = (setter) => (e) => { setter(e.target.value); setBriefingDirty(true); };

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

    const all = [];
    (practices || []).filter(p => p.status === 'active').forEach(p => {
      (p.deadlines || []).forEach(d => {
        const dDate = new Date(d.date);
        if (Number.isNaN(dDate.getTime())) return;
        dDate.setHours(0, 0, 0, 0);
        const diff = Math.ceil((dDate - today) / (1000 * 60 * 60 * 24));
        all.push({ ...d, practiceId: p.id, client: p.client, object: p.object, type: p.type, diff, source: 'practice' });
      });
    });

    (agendaEvents || []).filter(e => e.category === 'scadenza' && !e.completed).forEach(e => {
      const dDate = new Date(e.date);
      if (Number.isNaN(dDate.getTime())) return;
      dDate.setHours(0, 0, 0, 0);
      const diff = Math.ceil((dDate - today) / (1000 * 60 * 60 * 24));
      all.push({
        id: e.id,
        label: e.title,
        date: e.date,
        practiceId: e.practiceId || null,
        client: e.practiceId ? (practicesMap.get(e.practiceId)?.client || 'Agenda') : 'Agenda',
        object: e.notes || '',
        type: 'agenda',
        diff,
        source: 'agenda',
      });
    });
    all.sort((a, b) => new Date(a.date) - new Date(b.date));

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
    <div className="main-content animate-slide-up">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-black text-white flex items-center gap-3 tracking-tight">
            <div className="w-10 h-10 rounded-xl bg-white/5 flex items-center justify-center">
              <CalendarClock size={20} className="text-text-muted" />
            </div>
            Scadenze
          </h1>
          <p className="text-text-dim text-xs mt-1.5 uppercase tracking-[2px] font-bold">{allDeadlines.length} scadenz{allDeadlines.length === 1 ? 'a' : 'e'} totali</p>
        </div>
      </div>

      {/* 3 Stat Cards + Briefing Widget */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        {/* In Scadenza Oggi */}
        <div className="glass-card p-5 border border-white/5">
          <p className="text-[10px] font-bold text-text-dim uppercase tracking-wider mb-2">In Scadenza Oggi</p>
          <p className="text-3xl font-black text-white">{todayDeadlines.length}</p>
          <p className="text-[10px] text-text-dim mt-1">
            {todayDeadlines.length === 0 ? 'Nessuna scadenza' : todayDeadlines.map(d => d.label).join(', ')}
          </p>
        </div>

        {/* In Ritardo */}
        <div className="glass-card p-5 border border-white/5">
          <p className="text-[10px] font-bold text-text-dim uppercase tracking-wider mb-2">In Ritardo</p>
          <p className={`text-3xl font-black ${pastDeadlines.length > 0 ? 'text-red-400' : 'text-white'}`}>{pastDeadlines.length}</p>
          <p className="text-[10px] text-text-dim mt-1">
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
        <div className="glass-card p-5 border border-white/5">
          <p className="text-[10px] font-bold text-text-dim uppercase tracking-wider mb-2">Prossimi 30 Giorni</p>
          <p className="text-3xl font-black text-white">{next30.length}</p>
          <p className="text-[10px] text-text-dim mt-1">
            {next30.length === 0 ? 'Calendario libero' : `${next30.length} in arrivo`}
          </p>
        </div>

        {/* Orari Briefing — EDITABILE */}
        <div className="glass-card p-4">
          <div className="flex items-center justify-between mb-3">
            <p className="text-[10px] font-bold text-text-dim uppercase tracking-wider">Orari Briefing</p>
            {briefingDirty && (
              <button onClick={handleBriefingSave} className="flex items-center gap-1 text-[10px] font-bold text-primary hover:text-primary-hover transition-colors">
                <Check size={12} /> Salva
              </button>
            )}
          </div>
          <div className="space-y-2">
            {[
              { label: 'Mattina', value: briefingMattina, onChange: onBriefingChange(setBriefingMattina) },
              { label: 'Pomeriggio', value: briefingPomeriggio, onChange: onBriefingChange(setBriefingPomeriggio) },
              { label: 'Sera', value: briefingSera, onChange: onBriefingChange(setBriefingSera) },
            ].map(({ label, value, onChange }) => (
              <div key={label} className="flex items-center justify-between bg-white/[0.03] rounded-lg px-3 py-2 border border-white/5">
                <span className="text-xs text-white font-medium">{label}</span>
                <input type="time" className="bg-black/30 border border-white/10 rounded-lg px-2.5 py-1 text-xs text-white font-mono text-center focus:border-primary/50 focus:ring-1 focus:ring-primary/20 outline-none transition-all w-20" value={value} onChange={onChange} />
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
};