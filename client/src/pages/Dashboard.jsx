import { useMemo, useState, useRef, useEffect } from 'react';
import PropTypes from 'prop-types';
import { Briefcase, CalendarDays, CalendarClock, Coffee, Sun, Sunrise, ChevronDown } from 'lucide-react';

const CAT_COLORS = { udienza: '#d4a940', scadenza: '#EF6B6B', riunione: '#5B8DEF', studio: '#8B7CF6', personale: '#2DD4BF' };
const CAT_COLOR = c => CAT_COLORS[c] || '#7c8099';

function RelevantEventsWidget({ relevant, periodLabel, onSelectPractice, onNavigate }) {
  const scrollRef = useRef(null);
  const [scrollInfo, setScrollInfo] = useState({ atBottom: true, hiddenCount: 0 });

  const MAX_VISIBLE_HEIGHT = 240; // max height in px before scrolling kicks in
  const needsScroll = relevant.length > 5; // threshold to enable scroll

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const update = () => {
      const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 8;
      // Count how many items are below the visible area
      const items = el.querySelectorAll('[data-event-row]');
      let hidden = 0;
      items.forEach(item => {
        const rect = item.getBoundingClientRect();
        const containerRect = el.getBoundingClientRect();
        if (rect.top >= containerRect.bottom) hidden++;
      });
      setScrollInfo({ atBottom, hiddenCount: hidden });
    };
    update();
    el.addEventListener('scroll', update, { passive: true });
    return () => el.removeEventListener('scroll', update);
  }, [relevant]);

  if (relevant.length === 0) {
    return (
      <div className="relative z-10 mt-6 bg-white/[0.06] rounded-2xl p-5 border border-white/[0.08] backdrop-blur-sm">
        <div className="flex items-center justify-center gap-3 py-3 text-text-dim opacity-60">
          <CalendarDays size={20} />
          <p className="text-sm">Nessun impegno rilevante per {periodLabel}.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="relative z-10 mt-6 bg-white/[0.06] rounded-2xl p-5 border border-white/[0.08] backdrop-blur-sm">
      <div
        ref={scrollRef}
        className="space-y-2 overflow-y-auto no-scrollbar"
        style={{ maxHeight: needsScroll ? MAX_VISIBLE_HEIGHT : 'none' }}
      >
        {relevant.map((ev, i) => (
          <div key={ev.id || i} data-event-row className="relative">
            <button
              type="button"
              onClick={() => { if (onNavigate) onNavigate('/agenda?date=' + ev.date); }}
              className={`w-full flex items-center gap-3 text-sm rounded-xl px-3 py-2 hover:bg-white/[0.07] transition-colors group text-left cursor-pointer ${ev.practiceId ? 'pr-12' : ''}`}
              title="Apri in Agenda"
            >
              <span className="text-[11px] font-mono text-text-muted bg-white/5 px-2 py-0.5 rounded w-14 text-center flex-shrink-0">
                {ev.timeStart || '--:--'}
              </span>
              <span className="w-2.5 h-2.5 rounded-full flex-shrink-0 ring-2 ring-white/10" style={{ background: CAT_COLOR(ev.category) }} />
              <span className="text-white truncate group-hover:text-primary transition-colors min-w-0 flex-1 text-left">
                {ev.title}
              </span>
              {ev.category && (
                <span className="text-[9px] font-bold uppercase tracking-wider flex-shrink-0 px-2 py-0.5 rounded-md"
                  style={{ color: CAT_COLOR(ev.category), background: CAT_COLOR(ev.category) + '1a' }}
                >{ev.category}</span>
              )}
            </button>
            {ev.practiceId && (
              <button type="button"
                onClick={(e) => { e.stopPropagation(); if (onSelectPractice) onSelectPractice(ev.practiceId); }}
                className="absolute right-2 top-1/2 -translate-y-1/2 p-2 hover:bg-primary/15 bg-primary/5 rounded-xl transition-all flex-shrink-0 group/brief border border-primary/10 hover:border-primary/30"
                title="Vai al Fascicolo"
              >
                <Briefcase size={15} className="text-primary/70 group-hover/brief:text-primary transition-colors" />
              </button>
            )}
          </div>
        ))}
      </div>

      {/* ── Indicatore "altri impegni" — fade + testo dinamico ── */}
      {needsScroll && !scrollInfo.atBottom && (
        <div className="relative mt-0">
          {/* Gradient fade */}
          <div className="absolute -top-10 left-0 right-0 h-10 bg-gradient-to-t from-white/[0.06] to-transparent pointer-events-none rounded-b-2xl" />
          {/* Text indicator */}
          <button
            onClick={() => scrollRef.current?.scrollBy({ top: 120, behavior: 'smooth' })}
            className="w-full flex items-center justify-center gap-1.5 pt-2 pb-0.5 text-[10px] font-semibold text-text-dim hover:text-primary transition-colors"
          >
            <ChevronDown size={12} className="animate-bounce" />
            <span>
              {(() => {
                if (scrollInfo.hiddenCount <= 0) return 'Scorri per vedere tutti gli impegni';
                const suffix = scrollInfo.hiddenCount === 1 ? 'o' : 'i';
                return `Altri ${scrollInfo.hiddenCount} impegn${suffix} ${periodLabel}`;
              })()}
            </span>
            <ChevronDown size={12} className="animate-bounce" />
          </button>
        </div>
      )}
    </div>
  );
}

RelevantEventsWidget.propTypes = {
  relevant: PropTypes.array.isRequired,
  periodLabel: PropTypes.string.isRequired,
  onSelectPractice: PropTypes.func,
  onNavigate: PropTypes.func,
};

Dashboard.propTypes = {
  practices: PropTypes.array,
  agendaEvents: PropTypes.array,
  onNavigate: PropTypes.func,
  onSelectPractice: PropTypes.func,
};

export default function Dashboard({ practices, agendaEvents, onNavigate, onSelectPractice }) {

  // ── Greeting contestuale con stile diverso per fascia oraria ──
  const hero = useMemo(() => {
    const h = new Date().getHours();
    if (h < 13) return {
      label: 'AGGIORNAMENTO MATTUTINO',
      greeting: 'Buongiorno',
      sub: 'Ecco gli impegni previsti per la giornata di oggi.',
      gradient: 'from-amber-800/30 via-amber-900/20 to-amber-900/15',
      iconBg: 'text-amber-400/40',
      icon: <Sunrise size={120} strokeWidth={1} />,
    };
    if (h < 18) return {
      label: 'AGGIORNAMENTO POMERIDIANO',
      greeting: 'Buon Pomeriggio',
      sub: 'Focus sulle attività rimanenti prima della chiusura dello studio.',
      gradient: 'from-rose-800/30 via-rose-900/20 to-rose-900/15',
      iconBg: 'text-rose-300/40',
      icon: <Sun size={120} strokeWidth={1} />,
    };
    return {
      label: 'AGGIORNAMENTO SERALE',
      greeting: 'Buonasera',
      sub: 'Riepilogo e preparazione per la giornata di domani.',
      gradient: 'from-sky-800/25 via-sky-900/18 to-sky-900/12',
      iconBg: 'text-sky-400/35',
      icon: <Coffee size={120} strokeWidth={1} />,
    };
  }, []);

  // ── Calcoli statistiche (più informative) ──
  const stats = useMemo(() => {
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const todayStr = today.toISOString().split('T')[0];
    let activeCount = 0;
    let deadlineCount = 0;

    (practices || []).forEach(p => {
      if (p.status === 'active') {
        activeCount++;
        (p.deadlines || []).forEach(d => {
          const dd = new Date(d.date); dd.setHours(0, 0, 0, 0);
          if (dd >= today) deadlineCount++;
        });
      }
    });

    // Also count agenda "scadenza" events as deadlines
    (agendaEvents || []).forEach(e => {
      if (e.category === 'scadenza' && !e.completed) {
        const dd = new Date(e.date); dd.setHours(0, 0, 0, 0);
        if (dd >= today) deadlineCount++;
      }
    });

    // Impegni di oggi: totali e completati
    const todayEvents = (agendaEvents || []).filter(e => e.date === todayStr && !e.autoSync);
    const todayTotal = todayEvents.length;
    const todayCompleted = todayEvents.filter(e => e.completed).length;
    const todayRemaining = todayTotal - todayCompleted;

    return { activeCount, todayTotal, todayCompleted, todayRemaining, deadlineCount };
  }, [practices, agendaEvents]);

  // ── Impegni rilevanti (oggi/domani) — TUTTI, senza troncamento ──
  const { relevant, periodLabel } = useMemo(() => {
    const now = new Date();
    const h = now.getHours();
    const todayStr = now.toISOString().split('T')[0];
    const tomorrow = new Date(now); tomorrow.setDate(now.getDate() + 1);
    const tomorrowStr = tomorrow.toISOString().split('T')[0];

    const events = agendaEvents || [];
    let filtered;
    let periodLabel;

    if (h < 13) {
      filtered = events.filter(e => e.date === todayStr && !e.completed);
      periodLabel = 'oggi';
    } else if (h < 18) {
      filtered = events.filter(e => e.date === todayStr && !e.completed && (e.timeStart || '') >= '13:00');
      periodLabel = 'questo pomeriggio';
    } else {
      filtered = events.filter(e => e.date === tomorrowStr && !e.completed);
      periodLabel = 'domani';
    }

    return {
      relevant: filtered.sort((a, b) => (a.timeStart || '').localeCompare(b.timeStart || '')),
      periodLabel,
    };
  }, [agendaEvents]);

  return (
    <div className="main-content animate-slide-up pb-8">

      {/* ═══ HERO CARD ═══ */}
      <div className={`relative rounded-3xl overflow-hidden bg-surface border border-white/[0.08] p-8 mb-8`}>
        {/* Gradient overlay */}
        <div className={`absolute inset-0 bg-gradient-to-r ${hero.gradient} pointer-events-none`} />
        {/* Icona decorativa grande */}
        <div className={`absolute right-6 top-6 ${hero.iconBg} pointer-events-none select-none`}>
          {hero.icon}
        </div>

        <div className="relative z-10">
          <p className="text-[10px] font-black uppercase tracking-[3px] text-text-muted flex items-center gap-2 mb-3">
            <Sunrise size={14} className="text-primary" />
            {hero.label}
          </p>
          <h1 className="text-3xl font-black text-white tracking-tight mb-1">{hero.greeting}</h1>
          <p className="text-sm text-text-muted max-w-md">{hero.sub}</p>
        </div>

      {/* ── Widget impegni rilevanti dentro la hero ── */}
      <RelevantEventsWidget relevant={relevant} periodLabel={periodLabel} onSelectPractice={onSelectPractice} onNavigate={onNavigate} />
      </div>

      {/* ═══ 3 STAT CARDS — informative ═══ */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <button type="button" onClick={() => onNavigate('/pratiche')} className="glass-card p-5 flex items-center gap-4 border border-white/5 hover:border-white/10 transition-colors cursor-pointer group text-left">
          <div className="w-11 h-11 rounded-xl bg-white/5 flex items-center justify-center flex-shrink-0 group-hover:bg-primary/10 transition-colors">
            <Briefcase size={20} className="text-text-muted group-hover:text-primary transition-colors" />
          </div>
          <div>
            <p className="text-2xl font-black text-white tabular-nums">{stats.activeCount}</p>
            <p className="text-[10px] text-text-muted font-bold uppercase tracking-wider">Fascicoli Attivi</p>
          </div>
        </button>

        <button type="button" onClick={() => onNavigate('/agenda')} className="glass-card p-5 flex items-center gap-4 border border-white/5 hover:border-white/10 transition-colors cursor-pointer group text-left">
          <div className="w-11 h-11 rounded-xl bg-white/5 flex items-center justify-center flex-shrink-0 group-hover:bg-primary/10 transition-colors">
            <CalendarDays size={20} className="text-text-muted group-hover:text-primary transition-colors" />
          </div>
          <div>
            <div className="flex items-baseline gap-2">
              <p className="text-2xl font-black text-white tabular-nums">{stats.todayRemaining}</p>
            </div>
            <p className="text-[10px] text-text-muted font-bold uppercase tracking-wider">
              Impegni Rimanenti Oggi
            </p>
          </div>
        </button>

        <button type="button" onClick={() => onNavigate('/scadenze')} className="glass-card p-5 flex items-center gap-4 border border-white/5 hover:border-white/10 transition-colors cursor-pointer group text-left">
          <div className="w-11 h-11 rounded-xl bg-white/5 flex items-center justify-center flex-shrink-0 group-hover:bg-primary/10 transition-colors">
            <CalendarClock size={20} className="text-text-muted group-hover:text-primary transition-colors" />
          </div>
          <div>
            <p className="text-2xl font-black text-white tabular-nums">{stats.deadlineCount}</p>
            <p className="text-[10px] text-text-muted font-bold uppercase tracking-wider">Scadenze In Arrivo</p>
          </div>
        </button>
      </div>
    </div>
  );
}