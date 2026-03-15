import { useMemo, useState, useRef, useEffect, memo } from 'react';
import PropTypes from 'prop-types';
import { FolderOpen, CalendarDays, CalendarClock, Coffee, Sun, Sunrise, ChevronDown } from 'lucide-react';
import { catDotClass, catPillClass, getHeroColor } from '../theme';

const RelevantEventsWidget = memo(function RelevantEventsWidget({ relevant, periodLabel, onSelectPractice, onNavigate }) {
  const scrollRef = useRef(null);
  const [scrollInfo, setScrollInfo] = useState({ atBottom: true, hiddenCount: 0 });

  const MAX_VISIBLE_HEIGHT = 240; // max height in px before scrolling kicks in
  const needsScroll = relevant.length > 5; // threshold to enable scroll

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    let rafId = 0;
    const update = () => {
      const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 8;
      const items = el.querySelectorAll('[data-event-row]');
      const containerBottom = el.getBoundingClientRect().bottom;
      let hidden = 0;
      items.forEach(item => {
        if (item.getBoundingClientRect().top >= containerBottom) hidden++;
      });
      setScrollInfo({ atBottom, hiddenCount: hidden });
    };
    const onScroll = () => {
      cancelAnimationFrame(rafId);
      rafId = requestAnimationFrame(update);
    };
    update();
    el.addEventListener('scroll', onScroll, { passive: true });
    return () => { el.removeEventListener('scroll', onScroll); cancelAnimationFrame(rafId); };
  }, [relevant]);

  if (relevant.length === 0) {
    return (
      <div className="relative z-10 mt-6">
        <div className={`flex items-center justify-center gap-2.5 py-4 text-white/40`}>
          <CalendarDays size={16} strokeWidth={1.5} />
          <p className="text-xs tracking-wide">Nessun impegno rilevante per {periodLabel}.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="relative z-10 mt-6 rounded-2xl p-5 bg-black/20 backdrop-blur-sm">
      <div
        ref={scrollRef}
        className="space-y-2 overflow-y-auto no-scrollbar"
        style={{ maxHeight: needsScroll ? MAX_VISIBLE_HEIGHT : 'none' }}
      >
        {relevant.map((ev, i) => (
          <div key={ev.id || i} data-event-row>
            <div
              role="button"
              tabIndex={0}
              onClick={() => { if (onNavigate) { const tp = ev.timeStart ? `&time=${ev.timeStart}` : ''; onNavigate('/agenda?date=' + ev.date + tp); } }}
              onKeyDown={(e) => { if (e.key === 'Enter') { const tp = ev.timeStart ? `&time=${ev.timeStart}` : ''; onNavigate?.('/agenda?date=' + ev.date + tp); } }}
              className="w-full flex items-center gap-3 text-sm rounded-xl px-4 py-3 transition-colors group text-left cursor-pointer hover:bg-white/[0.07]"
              title="Apri in Agenda"
            >
              {/* Pallino categoria */}
              <span className={`w-2 h-2 rounded-full flex-shrink-0 ${catDotClass(ev.category)}`} />

              {/* Orario evento */}
              {ev.timeStart && (
                <span className="text-[11px] font-mono font-bold flex-shrink-0 tabular-nums text-white/60">
                  {ev.timeStart}
                </span>
              )}

              {/* Nome impegno — in una pill */}
              <span className="truncate group-hover:text-primary transition-colors min-w-0 text-left font-semibold text-sm px-2.5 py-0.5 rounded-lg text-white bg-white/[0.08]">
                {ev.title}
              </span>

              {/* Icona fascicolo (se collegato) — subito dopo il titolo */}
              {ev.practiceId && (
                <button type="button"
                  onClick={(e) => { e.stopPropagation(); if (onSelectPractice) onSelectPractice(ev.practiceId); }}
                  className="p-1.5 hover:bg-white/15 bg-white/10 rounded-lg transition-all flex-shrink-0 group/brief border border-white/10 hover:border-white/20"
                  title="Vai al Fascicolo"
                >
                  <FolderOpen size={14} className="text-white/70 group-hover/brief:text-white transition-colors" />
                </button>
              )}

              {/* Spacer per spingere la categoria all'estrema destra */}
              <div className="flex-1 min-w-2" />

              {/* Tipo impegno — all'estrema destra */}
              {ev.category && (
                <span className={`text-[9px] font-bold uppercase tracking-wider flex-shrink-0 px-2.5 py-1 rounded-lg border ${catPillClass(ev.category)}`}
                >{ev.category}</span>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* ── Indicatore "altri impegni" — fade + testo dinamico ── */}
      {needsScroll && !scrollInfo.atBottom && (
        <div className="relative mt-0">
          {/* Gradient fade */}
          <div className="absolute -top-10 left-0 right-0 h-10 bg-gradient-to-t from-black/20 to-transparent pointer-events-none rounded-b-2xl" />
          {/* Text indicator */}
          <button
            onClick={() => scrollRef.current?.scrollBy({ top: 120, behavior: 'smooth' })}
            className="w-full flex items-center justify-center gap-1.5 pt-2 pb-0.5 text-[10px] font-semibold text-white/50 hover:text-primary transition-colors"
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
});

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

  // ── Greeting contestuale — osserva cambio tema via MutationObserver ──
  const [currentTheme, setCurrentTheme] = useState(() =>
    document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark'
  );
  useEffect(() => {
    const obs = new MutationObserver(() => {
      setCurrentTheme(document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark');
    });
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    return () => obs.disconnect();
  }, []);

  const hero = useMemo(() => {
    const h = new Date().getHours();
    const { background } = getHeroColor(currentTheme);

    if (h >= 5 && h < 13) return {
      label: 'AGGIORNAMENTO MATTUTINO',
      greeting: 'Buongiorno',
      sub: 'Ecco gli impegni previsti per la giornata di oggi.',
      background,
      icon: <Sunrise size={100} strokeWidth={1} />,
    };
    if (h >= 13 && h < 18) return {
      label: 'AGGIORNAMENTO POMERIDIANO',
      greeting: 'Buon Pomeriggio',
      sub: 'Focus sulle attività rimanenti prima della chiusura dello studio.',
      background,
      icon: <Sun size={100} strokeWidth={1} />,
    };
    return {
      label: 'AGGIORNAMENTO SERALE',
      greeting: 'Buonasera',
      sub: 'Riepilogo e preparazione per la giornata di domani.',
      background,
      icon: <Coffee size={100} strokeWidth={1} />,
    };
  }, [currentTheme]);

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
      <div className="hero-card"
        style={{ backgroundColor: hero.background }}>
        {/* Icona decorativa grande */}
        <div className="absolute right-6 top-6 pointer-events-none select-none text-white/[0.12]">
          {hero.icon}
        </div>

        <div className="relative z-10">
          <p className="text-[10px] font-black uppercase tracking-[3px] mb-3 text-white/70">
            {hero.label}
          </p>
          <h1 className="text-4xl font-black tracking-tight mb-1 text-white drop-shadow-[0_1px_2px_rgba(0,0,0,0.3)]">{hero.greeting}</h1>
          <p className="text-sm max-w-md text-white/80">{hero.sub}</p>
        </div>

      {/* ── Widget impegni rilevanti dentro la hero ── */}
      <RelevantEventsWidget relevant={relevant} periodLabel={periodLabel} onSelectPractice={onSelectPractice} onNavigate={onNavigate} />
      </div>

      {/* ═══ 3 STAT CARDS — informative ═══ */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <button type="button" onClick={() => onNavigate('/pratiche')} className="glass-card p-5 flex items-center gap-4 hover:border-border transition-colors cursor-pointer group text-left">
          <div className="w-11 h-11 rounded-xl bg-white/5 flex items-center justify-center flex-shrink-0 group-hover:bg-primary/10 transition-colors">
            <FolderOpen size={20} className="text-text-muted group-hover:text-primary transition-colors" />
          </div>
          <div>
            <p className="text-2xl font-black text-text tabular-nums">{stats.activeCount}</p>
            <p className="text-[10px] text-text-muted font-bold uppercase tracking-wider">Fascicoli Attivi</p>
          </div>
        </button>

        <button type="button" onClick={() => onNavigate('/agenda')} className="glass-card p-5 flex items-center gap-4 hover:border-border transition-colors cursor-pointer group text-left">
          <div className="w-11 h-11 rounded-xl bg-white/5 flex items-center justify-center flex-shrink-0 group-hover:bg-primary/10 transition-colors">
            <CalendarDays size={20} className="text-text-muted group-hover:text-primary transition-colors" />
          </div>
          <div>
            <div className="flex items-baseline gap-2">
              <p className="text-2xl font-black text-text tabular-nums">{stats.todayRemaining}</p>
            </div>
            <p className="text-[10px] text-text-muted font-bold uppercase tracking-wider">
              Impegni Rimanenti Oggi
            </p>
          </div>
        </button>

        <button type="button" onClick={() => onNavigate('/scadenze')} className="glass-card p-5 flex items-center gap-4 hover:border-border transition-colors cursor-pointer group text-left">
          <div className="w-11 h-11 rounded-xl bg-white/5 flex items-center justify-center flex-shrink-0 group-hover:bg-primary/10 transition-colors">
            <CalendarClock size={20} className="text-text-muted group-hover:text-primary transition-colors" />
          </div>
          <div>
            <p className="text-2xl font-black text-text tabular-nums">{stats.deadlineCount}</p>
            <p className="text-[10px] text-text-muted font-bold uppercase tracking-wider">Scadenze In Arrivo</p>
          </div>
        </button>
      </div>
    </div>
  );
}