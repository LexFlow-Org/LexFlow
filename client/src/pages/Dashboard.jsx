import { useMemo, useState, useRef, useEffect, memo } from 'react';
import PropTypes from 'prop-types';
import { FolderOpen, CalendarDays, CalendarClock, Coffee, Sun, Sunrise, ChevronDown, Clock } from 'lucide-react';
import { catDotClass, catPillClass, getHeroColor } from '../theme';
import { toDateStr, parseLocalYMD } from '../utils/helpers';

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
  }, [relevant.length]); // PERF: only re-attach when list size changes, not on every array ref change

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
    <div className="relative z-10 mt-6 rounded-2xl p-5">
      <div
        ref={scrollRef}
        className="space-y-2 overflow-y-auto no-scrollbar"
        style={{ maxHeight: needsScroll ? MAX_VISIBLE_HEIGHT : 'none' }}
      >
        {relevant.map((ev, i) => (
          <div key={ev.id || i} data-event-row>
            {/* Period separator for evening view (oggi/domani) */}
            {ev._period && (i === 0 || relevant[i - 1]?._period !== ev._period) && (
              <div className="flex items-center gap-2 mb-2 mt-1">
                <span className="text-2xs font-bold uppercase tracking-wider text-white/50">
                  {ev._period === 'oggi' ? <><Clock size={10} className="inline mr-1" />Ancora oggi</> : <><Sunrise size={10} className="inline mr-1" />Domani</>}
                </span>
                <div className="flex-1 h-px bg-white/10" />
              </div>
            )}
            <div className="w-full flex items-center justify-between text-sm rounded-xl px-4 py-3 transition-all bg-white/[0.08] border border-white/15 hover:bg-white/15 hover:border-white/25 group">
              {/* Blocco sinistro: row attivabile (NO nested buttons → role=button) */}
              <div
                role="button"
                tabIndex={0}
                onClick={() => { if (onNavigate) { const tp = ev.timeStart ? `&time=${ev.timeStart}` : ''; onNavigate('/agenda?date=' + ev.date + tp); } }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    const tp = ev.timeStart ? `&time=${ev.timeStart}` : '';
                    onNavigate?.('/agenda?date=' + ev.date + tp);
                  }
                }}
                className="flex items-center gap-2.5 min-w-0 flex-1 cursor-pointer text-left rounded-lg outline-none focus-visible:ring-2 focus-visible:ring-white/40"
                title="Apri in Agenda"
              >
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${catDotClass(ev.category)}`} />
                {ev.timeStart && (
                  <span className="text-xs font-mono font-bold flex-shrink-0 tabular-nums text-white/60">
                    {ev.timeStart}
                  </span>
                )}
                <span className="truncate font-semibold text-sm text-white">
                  {ev.title}
                </span>
              </div>
              {/* Bottone fascicolo separato — non più nested */}
              {ev.practiceId && (
                <button type="button"
                  onClick={(e) => { e.stopPropagation(); if (onSelectPractice) onSelectPractice(ev.practiceId); }}
                  className="p-1.5 rounded-lg transition-colors flex-shrink-0 hover:bg-white/15 ml-2"
                  title="Vai al Fascicolo"
                >
                  <FolderOpen size={13} className="text-white/50 hover:text-white transition-colors" />
                </button>
              )}
              {/* Pill categoria a destra */}
              {ev.category && (
                <span className={`text-3xs font-bold uppercase tracking-wider flex-shrink-0 px-2 py-0.5 rounded-md border ml-2 ${catPillClass(ev.category)}`}
                >{ev.category}</span>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* ── Indicatore "altri impegni" — fade + testo dinamico ── */}
      {needsScroll && !scrollInfo.atBottom && (
        <div className="relative mt-0">
          {/* Spacer (gradient rimosso — nessun overlay) */}
          {/* Text indicator */}
          <button
            onClick={() => scrollRef.current?.scrollBy({ top: 120, behavior: 'smooth' })}
            className="w-full flex items-center justify-center gap-1.5 pt-2 pb-0.5 text-2xs font-semibold text-white/50 hover:text-primary transition-colors"
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

  // ── Heartbeat orario: tick ogni 5 min, basta a far ricalcolare il greeting
  // se la dashboard resta aperta a cavallo delle 13:00 / 18:00 / 5:00.
  const [tick, setTick] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setTick(Date.now()), 5 * 60 * 1000);
    return () => clearInterval(id);
  }, []);

  // ── Greeting contestuale — colori identici in dark e light ──
  const hero = useMemo(() => {
    const h = new Date().getHours();
    const { background } = getHeroColor();

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
    // tick triggers re-evaluation as hour rolls over
  }, [tick]);

  // ── Calcoli statistiche (più informative) ──
  const stats = useMemo(() => {
    const today = new Date(); today.setHours(0, 0, 0, 0);
    const todayStr = toDateStr(today); // local YMD, not UTC
    let activeCount = 0;
    let deadlineCount = 0;

    (practices || []).forEach(p => {
      if (p.status === 'active') {
        activeCount++;
        (p.deadlines || []).forEach(d => {
          const dd = parseLocalYMD(d.date);
          if (Number.isNaN(dd.getTime())) return;
          if (dd >= today) deadlineCount++;
        });
      }
    });

    // Also count agenda "scadenza" events as deadlines — but EXCLUDE
    // autoSync events: those are already counted as practice deadlines
    // (they're auto-mirrored from practice.deadlines into agenda).
    (agendaEvents || []).forEach(e => {
      if (e.category === 'scadenza' && !e.completed && !e.autoSync) {
        const dd = parseLocalYMD(e.date);
        if (Number.isNaN(dd.getTime())) return;
        if (dd >= today) deadlineCount++;
      }
    });

    // Impegni di oggi: totali e completati (autoSync already excluded — keeps
    // todayRemaining and deadlineCount reading from the same source-of-truth)
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
    const todayStr = toDateStr(now); // local, not UTC
    const tomorrow = new Date(now); tomorrow.setDate(now.getDate() + 1);
    const tomorrowStr = toDateStr(tomorrow);

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
      // Sera: mostra eventi rimasti di oggi (dalle 18+) E quelli di domani
      const todayRemaining = events.filter(e => e.date === todayStr && !e.completed && (e.timeStart || '') >= '18:00');
      const tomorrowEvents = events.filter(e => e.date === tomorrowStr && !e.completed);
      // Marca gli eventi di domani per distinguerli visivamente
      filtered = [
        ...todayRemaining.map(e => ({ ...e, _period: 'oggi' })),
        ...tomorrowEvents.map(e => ({ ...e, _period: 'domani' })),
      ];
      periodLabel = 'questa sera';
    }

    // Sort: untimed events go LAST (an event "all-day" should not jump above
    // a timed 09:00 just because '' < '09:00'). Within timed events, ascending
    // by HH:mm is enough thanks to lexicographic ordering.
    return {
      relevant: filtered.sort((a, b) => {
        const at = a.timeStart || '';
        const bt = b.timeStart || '';
        if (!at && !bt) return 0;
        if (!at) return 1;
        if (!bt) return -1;
        return at.localeCompare(bt);
      }),
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
          <p className="text-2xs font-black uppercase tracking-title mb-3 text-white/70">
            {hero.label}
          </p>
          <h1 className="text-4xl font-black tracking-tight mb-1 text-white">{hero.greeting}</h1>
          <p className="text-sm max-w-md text-white/80">{hero.sub}</p>
        </div>

      {/* ── Widget impegni rilevanti dentro la hero ── */}
      <RelevantEventsWidget relevant={relevant} periodLabel={periodLabel} onSelectPractice={onSelectPractice} onNavigate={onNavigate} />
      </div>

      {/* ═══ 3 STAT CARDS — informative ═══ */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <button type="button" onClick={() => onNavigate('/pratiche')} className="glass-card p-5 flex items-center gap-4 hover:border-border transition-colors cursor-pointer group text-left">
          <div className="w-11 h-11 rounded-xl bg-surface flex items-center justify-center flex-shrink-0 group-hover:bg-primary/10 transition-colors">
            <FolderOpen size={20} className="text-text-muted group-hover:text-primary transition-colors" />
          </div>
          <div>
            <p className="text-2xl font-black text-text tabular-nums">{stats.activeCount}</p>
            <p className="text-2xs text-text-muted font-bold uppercase tracking-wider">Fascicoli Attivi</p>
          </div>
        </button>

        <button type="button" onClick={() => onNavigate('/agenda')} className="glass-card p-5 flex items-center gap-4 hover:border-border transition-colors cursor-pointer group text-left">
          <div className="w-11 h-11 rounded-xl bg-surface flex items-center justify-center flex-shrink-0 group-hover:bg-primary/10 transition-colors">
            <CalendarDays size={20} className="text-text-muted group-hover:text-primary transition-colors" />
          </div>
          <div>
            <div className="flex items-baseline gap-2">
              <p className="text-2xl font-black text-text tabular-nums">{stats.todayRemaining}</p>
            </div>
            <p className="text-2xs text-text-muted font-bold uppercase tracking-wider">
              Impegni Rimanenti Oggi
            </p>
          </div>
        </button>

        <button type="button" onClick={() => onNavigate('/scadenze')} className="glass-card p-5 flex items-center gap-4 hover:border-border transition-colors cursor-pointer group text-left">
          <div className="w-11 h-11 rounded-xl bg-surface flex items-center justify-center flex-shrink-0 group-hover:bg-primary/10 transition-colors">
            <CalendarClock size={20} className="text-text-muted group-hover:text-primary transition-colors" />
          </div>
          <div>
            <p className="text-2xl font-black text-text tabular-nums">{stats.deadlineCount}</p>
            <p className="text-2xs text-text-muted font-bold uppercase tracking-wider">Scadenze In Arrivo</p>
          </div>
        </button>
      </div>

      {/* ═══ FASCICOLI MODIFICATI DI RECENTE ═══ */}
      {practices && practices.length > 0 && (
        <div className="glass-card p-5 mt-6">
          <h3 className="text-2xs font-black uppercase tracking-label text-text-muted mb-3">Fascicoli Recenti</h3>
          <div className="space-y-2">
            {practices
              .filter(p => p.status === 'active')
              .sort((a, b) => new Date(b.updatedAt || b.createdAt || 0) - new Date(a.updatedAt || a.createdAt || 0))
              .slice(0, 5)
              .map(p => (
                <button
                  key={p.id}
                  onClick={() => onSelectPractice?.(p.id)}
                  className="w-full flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-[var(--bg-hover)] transition-colors text-left group"
                >
                  <div className={`w-2 h-2 rounded-full ${catDotClass(p.type)}`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-[var(--text)] truncate font-medium">{p.client || 'Senza cliente'}</p>
                    <p className="text-xs text-[var(--text-dim)] truncate">{p.object || ''}</p>
                  </div>
                  <span className="text-3xs text-[var(--text-dim)] font-mono shrink-0">
                    {p.updatedAt ? new Date(p.updatedAt).toLocaleDateString('it-IT', { day: '2-digit', month: '2-digit' }) : ''}
                  </span>
                </button>
              ))
            }
          </div>
        </div>
      )}
    </div>
  );
}