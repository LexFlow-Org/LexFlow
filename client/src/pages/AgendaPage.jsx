import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import PropTypes from 'prop-types';
import { 
  Plus, 
  ChevronLeft, 
  ChevronRight, 
  CalendarDays, 
  Clock, 
  X, 
  Trash2, 
  ExternalLink, 
  Calendar, 
  AlertCircle, 
  BarChart3,
  Bell,
  BellRing,
  Briefcase,
  Check
} from 'lucide-react';
import toast from 'react-hot-toast';
import * as api from '../tauri-api';
import ConfirmDialog from '../components/ConfirmDialog';
import ModalOverlay from '../components/ModalOverlay';
import { genId, toDateStr } from '../utils/helpers';

const DAYS_IT = ['Domenica','Lunedì','Martedì','Mercoledì','Giovedì','Venerdì','Sabato'];
const DAYS_SHORT = ['DOM','LUN','MAR','MER','GIO','VEN','SAB'];
const MONTHS_IT = ['Gennaio','Febbraio','Marzo','Aprile','Maggio','Giugno','Luglio','Agosto','Settembre','Ottobre','Novembre','Dicembre'];

const CAT_COLORS = {
  udienza: '#d4a940',
  studio: '#8B7CF6',
  scadenza: '#EF6B6B',
  riunione: '#5B8DEF',
  personale: '#2DD4BF',
  altro: '#7c8099',
};

const CAT_LABELS = {
  udienza: 'Udienza',
  studio: 'Studio',
  scadenza: 'Scadenza',
  riunione: 'Riunione',
  personale: 'Personale',
  altro: 'Altro',
};

const HOURS = Array.from({length: 24}, (_, i) => i); // 00:00 - 23:00

function parseDate(s) {
  if (!s || typeof s !== 'string') return new Date(Number.NaN);
  const [y, m, d] = s.split('-').map(Number);
  return new Date(y, m - 1, d);
}
function fmtTime(h, m) { return String(h).padStart(2,'0') + ':' + String(m).padStart(2,'0'); }

/** Shared resize-top mousedown handler (used by TodayView & WeekView) */
function handleResizeTop(e, { startMin, endMin, minHeight, selector, ev, onSave }) {
  e.stopPropagation();
  e.preventDefault();
  const startY = e.clientY;
  const origStart = startMin;
  const evEl = e.target.closest(selector);
  let newStart = origStart;
  const onMove = (me) => {
    const dY = me.clientY - startY;
    newStart = Math.min(origStart + Math.round(dY), endMin - 15);
    newStart = Math.max(0, Math.round(newStart / 5) * 5);
    if (evEl) {
      evEl.style.top = `${(newStart / 60) * 60}px`;
      evEl.style.height = `${Math.max(((endMin - newStart) / 60) * 60, minHeight)}px`;
    }
  };
  const onUp = () => {
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup', onUp);
    if (evEl) evEl._didDrag = true;
    if (newStart !== origStart) {
      const nh = Math.floor(newStart / 60);
      const nm = newStart % 60;
      onSave({ ...ev, timeStart: fmtTime(nh, nm) });
    }
  };
  document.addEventListener('mousemove', onMove);
  document.addEventListener('mouseup', onUp);
}

/** Shared resize-bottom mousedown handler (used by TodayView & WeekView) */
function handleResizeBottom(e, { startMin, endMin, minHeight, selector, ev, onSave }) {
  e.stopPropagation();
  e.preventDefault();
  const startY = e.clientY;
  const origEnd = endMin;
  const evEl = e.target.closest(selector);
  let newEnd = origEnd;
  const onMove = (me) => {
    const dY = me.clientY - startY;
    newEnd = Math.max(origEnd + Math.round(dY), startMin + 15);
    newEnd = Math.round(newEnd / 5) * 5;
    if (evEl) evEl.style.height = `${Math.max(((newEnd - startMin) / 60) * 60, minHeight)}px`;
  };
  const onUp = () => {
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup', onUp);
    if (evEl) evEl._didDrag = true;
    if (newEnd !== origEnd) {
      const nh = Math.floor(newEnd / 60);
      const nm = newEnd % 60;
      onSave({ ...ev, timeEnd: fmtTime(nh, nm) });
    }
  };
  document.addEventListener('mousemove', onMove);
  document.addEventListener('mouseup', onUp);
}

/** Creates a ghost clone element for drag-and-drop visual feedback */
function createDragGhost(el, ghostId) {
  // Remove any existing ghost with same ID to prevent duplicates
  const existing = document.getElementById(ghostId);
  if (existing) existing.remove();
  const ghost = el.cloneNode(true);
  ghost.id = ghostId;
  ghost.style.position = 'absolute';
  ghost.style.top = el.style.top;
  ghost.style.left = el.style.left || '2px';
  ghost.style.right = el.style.right || '2px';
  ghost.style.width = el.style.width;
  ghost.style.height = el.style.height;
  ghost.style.zIndex = '60';
  ghost.style.opacity = '0.9';
  ghost.style.border = '2px dashed rgba(212,169,64,0.6)';
  ghost.style.pointerEvents = 'none';
  ghost.style.cursor = 'copy';
  el.parentElement.appendChild(ghost);
  return ghost;
}

/** Resolves the final event data after a drag/duplicate operation */
function resolveDragResult(ev, newStartMin, duration, newDate) {
  const sh = Math.floor(newStartMin / 60);
  const sm = newStartMin % 60;
  const newEndMin = newStartMin + duration;
  const eh = Math.floor(newEndMin / 60);
  const em = newEndMin % 60;
  return { ...ev, date: newDate || ev.date, timeStart: fmtTime(sh, sm), timeEnd: fmtTime(eh, em) };
}

/** Shared drag cleanup — remove listeners, reset element styles, remove ghost */
function cleanupDragListeners(onMove, onUp, el, ghostId, longPressTimer) {
  document.removeEventListener('mousemove', onMove);
  document.removeEventListener('mouseup', onUp);
  if (longPressTimer) clearTimeout(longPressTimer);
  document.body.classList.remove('agenda-dragging');
  document.body.style.cursor = '';
  const ghost = document.getElementById(ghostId);
  if (ghost) ghost.remove();
  el.style.zIndex = '';
  el.style.opacity = '';
  el.style.transition = '';
}

/** Drag handler for TodayView events — vertical only (time change + long-press duplicate) */
function handleTodayEventDrag(e, ev, onSave) {
  if (e.target.closest('.resize-handle')) return;
  const startY = e.clientY;
  const origStart = ev.startMin;
  const duration = ev.endMin - ev.startMin;
  const btn = e.currentTarget;
  const el = btn.closest('.agenda-event') || btn;
  let moved = false;
  let newStart = origStart;
  let longPressTimer = null;
  let isDuplicate = false;

  longPressTimer = setTimeout(() => {
    isDuplicate = true;
    el.style.opacity = '0.5';
    createDragGhost(el, 'drag-ghost');
    document.body.style.cursor = 'copy';
  }, 500);

  const onMove = (me) => {
    const deltaY = me.clientY - startY;
    if (!moved && Math.abs(deltaY) < 4) return;
    if (!moved) {
      moved = true;
      document.body.classList.add('agenda-dragging');
      if (!isDuplicate && longPressTimer) { clearTimeout(longPressTimer); longPressTimer = null; }
      el.style.zIndex = 50;
      el.style.transition = 'none';
      if (!isDuplicate) { el.style.opacity = '0.8'; document.body.style.cursor = 'grabbing'; }
    }
    newStart = Math.max(0, Math.min(origStart + Math.round(deltaY), 1440 - duration));
    newStart = Math.round(newStart / 5) * 5;
    const target = isDuplicate ? document.getElementById('drag-ghost') : el;
    if (target) target.style.top = `${(newStart / 60) * 60}px`;
  };

  const onUp = () => {
    cleanupDragListeners(onMove, onUp, el, 'drag-ghost', longPressTimer);

    commitDragResult(el, ev, onSave, { moved, isDuplicate, newStartMin: newStart, origStartMin: origStart, duration, newDate: ev.date, origDate: ev.date });
  };
  document.addEventListener('mousemove', onMove);
  document.addEventListener('mouseup', onUp);
}

/** Commit a drag/duplicate operation and flag the element to prevent click-through */
function commitDragResult(el, ev, onSave, { moved, isDuplicate, newStartMin, origStartMin, duration, newDate, origDate }) {
  if (isDuplicate && (moved || newDate !== origDate)) {
    el._didDrag = true;
    el._didLongPress = true;
    onSave({ ...resolveDragResult(ev, newStartMin, duration, newDate), id: genId(), completed: false });
  } else if (isDuplicate && !moved) {
    el._didLongPress = true;
    onSave({ ...ev, id: genId(), title: ev.title + ' (copia)', completed: false });
  } else if (moved && (newStartMin !== origStartMin || newDate !== origDate)) {
    el._didDrag = true;
    onSave(resolveDragResult(ev, newStartMin, duration, newDate));
  }
}

/** Initiate drag movement — called once when threshold exceeded */
function initDragMovement(el, isDuplicate, longPressTimer) {
  if (!isDuplicate && longPressTimer) { clearTimeout(longPressTimer); }
  el.style.zIndex = 50;
  el.style.transition = 'none';
  if (!isDuplicate) { el.style.opacity = '0.8'; document.body.style.cursor = 'grabbing'; }
}

/** Drag handler for WeekView events — vertical (time) + horizontal (date) + long-press duplicate */
function handleWeekEventDrag(e, ev, onSave) {
  if (e.target.closest('.resize-handle')) return;
  const startX = e.clientX;
  const startY = e.clientY;
  const btn = e.currentTarget;
  const el = btn.closest('.agenda-event') || btn;
  const grid = el.closest('.grid');
  const [esh, esm] = ev.timeStart.split(':').map(Number);
  const [eeh, eem] = ev.timeEnd.split(':').map(Number);
  const origStartMin = esh * 60 + esm;
  const duration = eeh * 60 + eem - origStartMin;
  const origDate = ev.date;
  let moved = false;
  let newDate = origDate;
  let newStartMin = origStartMin;
  let longPressTimer = null;
  let isDuplicate = false;
  const dayCols = grid ? Array.from(grid.querySelectorAll('[data-daystr]')) : [];

  longPressTimer = setTimeout(() => {
    isDuplicate = true;
    el.style.opacity = '0.5';
    document.body.style.cursor = 'copy';
    createDragGhost(el, 'week-drag-ghost');
  }, 500);

  const onMove = (me) => {
    const dX = me.clientX - startX;
    const dY = me.clientY - startY;
    if (!moved && Math.abs(dX) < 4 && Math.abs(dY) < 4) return;
    if (!moved) {
      moved = true;
      document.body.classList.add('agenda-dragging');
      initDragMovement(el, isDuplicate, longPressTimer);
      if (!isDuplicate) longPressTimer = null;
    }
    newStartMin = Math.max(0, Math.min(origStartMin + Math.round(dY), 1440 - duration));
    newStartMin = Math.round(newStartMin / 5) * 5;
    const ghost = document.getElementById('week-drag-ghost');
    const target = (isDuplicate && ghost) ? ghost : el;
    target.style.top = `${(newStartMin / 60) * 60}px`;
    for (const col of dayCols) {
      const r = col.getBoundingClientRect();
      if (me.clientX >= r.left && me.clientX <= r.right) {
        newDate = col.dataset.daystr;
        if (isDuplicate && ghost && ghost.parentElement !== col) col.appendChild(ghost);
        break;
      }
    }
  };

  const onUp = () => {
    cleanupDragListeners(onMove, onUp, el, 'week-drag-ghost', longPressTimer);
    commitDragResult(el, ev, onSave, { moved, isDuplicate, newStartMin, origStartMin, duration, newDate, origDate });
  };
  document.addEventListener('mousemove', onMove);
  document.addEventListener('mouseup', onUp);
}

// --- Componente Empty State ---
function EmptyState({ message, sub, onAdd, date }) {
  return (
    <div className="flex flex-col items-center justify-center h-full py-10 opacity-60">
      <div className="w-24 h-24 rounded-3xl bg-white/5 flex items-center justify-center mb-6 shadow-inner border border-white/5">
        <CalendarDays size={40} className="text-white/40" />
      </div>
      <p className="text-white font-bold text-lg mb-2">{message}</p>
      <p className="text-text-dim text-sm mb-6 text-center max-w-[280px]">{sub}</p>
      {onAdd && (
        <button onClick={() => onAdd(date || toDateStr(new Date()))} className="btn-primary">
          <Plus size={16} /> Aggiungi Impegno
        </button>
      )}
    </div>
  );
}

// --- Componente Modal ---
function EventModal({ event, date, onSave, onDelete, onClose, practices }) {
  const isEdit = !!event?.id;

  // Dynamic default: next half-hour from now
  const defaultTime = (() => {
    if (event?.timeStart) return event.timeStart;
    const n = new Date();
    let m = n.getMinutes();
    let h = n.getHours();
    m = m < 30 ? 30 : 0;
    if (m === 0) h = (h + 1) % 24;
    return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}`;
  })();
  const defaultEndTime = (() => {
    if (event?.timeEnd) return event.timeEnd;
    const [h, m] = defaultTime.split(':').map(Number);
    const eh = (h + 1) % 24;
    return `${String(eh).padStart(2,'0')}:${String(m).padStart(2,'0')}`;
  })();
  const [title, setTitle] = useState(event?.title || '');
  const [evDate, setEvDate] = useState(event?.date || date || toDateStr(new Date()));
  const [timeStart, setTimeStart] = useState(defaultTime);
  const [timeEnd, setTimeEnd] = useState(defaultEndTime);
  const [category, setCategory] = useState(event?.category || 'udienza');
  const [notes, setNotes] = useState(event?.notes || '');
  const [remindMinutes, setRemindMinutes] = useState(event?.remindMinutes ?? null);
  const [customRemindTime, setCustomRemindTime] = useState(event?.customRemindTime || '');
  const [practiceId, setPracticeId] = useState(event?.practiceId || '');
  const [confirmDelete, setConfirmDelete] = useState(false);

  // Preavviso dinamico: pre-imposta "Alle" con 10 min prima dell'inizio
  useEffect(() => {
    if (remindMinutes === null || remindMinutes === undefined) {
      // Default: 10 min prima
    }
    // Aggiorna il campo "Alle" in base all'ora di inizio
    if (timeStart && (customRemindTime === '' || !event?.customRemindTime)) {
      const [h, m] = timeStart.split(':').map(Number);
      const totalMin = h * 60 + m - 10;
      if (totalMin >= 0) {
        const rh = Math.floor(totalMin / 60);
        const rm = totalMin % 60;
        setCustomRemindTime(`${String(rh).padStart(2,'0')}:${String(rm).padStart(2,'0')}`);
      }
    }
  }, [timeStart, customRemindTime, event?.customRemindTime]);

  const REMIND_OPTIONS = [
    { value: null, label: 'Standard' },
    { value: 5, label: '5 min' },
    { value: 10, label: '10 min' },
    { value: 15, label: '15 min' },
    { value: 30, label: '30 min' },
    { value: 60, label: '1 ora' },
    { value: 120, label: '2 ore' },
    { value: 1440, label: '1 giorno' },
  ];

  // Only show linkable practices (active)
  const linkablePractices = (practices || []).filter(p => p.status === 'active');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!title.trim()) return;
    onSave({
      id: event?.id || genId(),
      title: title.trim(),
      date: evDate,
      timeStart,
      timeEnd,
      category,
      notes,
      remindMinutes,
      customRemindTime: remindMinutes === 'custom' ? customRemindTime : null,
      completed: event?.completed || false,
      autoSync: event?.autoSync || false,
      practiceId: practiceId || null,
    });
  };

  return (
    <ModalOverlay onClose={onClose} label={isEdit ? 'Modifica Impegno' : 'Nuovo Impegno'} focusTrap>
      <div className="bg-[#0f1016] border border-white/10 rounded-[32px] w-full max-w-2xl shadow-3xl overflow-hidden flex flex-col max-h-[92vh]">
        
        {/* Header — stile unificato con Fascicoli */}
        <div className="px-8 py-5 border-b border-white/5 flex items-center justify-between bg-gradient-to-r from-white/5 to-transparent">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-primary/10 rounded-2xl flex items-center justify-center text-primary border border-primary/20">
              {isEdit ? <CalendarDays size={28} /> : <Plus size={28} />}
            </div>
            <div>
              <h2 className="text-xl font-bold text-white tracking-tight">{isEdit ? 'Modifica Impegno' : 'Nuovo Impegno'}</h2>
              <p className="text-text-dim text-xs uppercase tracking-widest font-medium opacity-60">Gestione Agenda</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-white/10 rounded-xl text-text-dim transition-all group">
            <X size={24} className="group-hover:rotate-90 transition-transform" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-8 overflow-y-auto custom-scrollbar flex-1 space-y-6">
          
          {/* Titolo */}
          <div className="space-y-2">
            <label htmlFor="em-title" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Titolo</label>
            <input id="em-title" className="input-field w-full bg-white/5 border-white/10 focus:border-primary/50 text-lg font-semibold" 
              placeholder="Es. Udienza Tribunale..." value={title} onChange={e => setTitle(e.target.value)} required autoFocus />
          </div>

          {/* Data + Ora — Design pulito con selettore compatto */}
          <div className="grid grid-cols-3 gap-4">
            <div className="space-y-2">
              <label htmlFor="em-date" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Data</label>
              <input id="em-date" type="date" className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm text-white font-mono focus:border-primary/50 focus:ring-1 focus:ring-primary/20 outline-none transition-all" value={evDate} onChange={e => setEvDate(e.target.value)} />
            </div>
            <div className="space-y-2">
              <label htmlFor="em-start" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Inizio</label>
              <input id="em-start" type="time" className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm text-white font-mono focus:border-primary/50 focus:ring-1 focus:ring-primary/20 outline-none transition-all" value={timeStart} onChange={e => {
                setTimeStart(e.target.value);
                const [h,m] = e.target.value.split(':').map(Number);
                setTimeEnd(fmtTime(Math.min(h+1,23), m));
              }} />
            </div>
            <div className="space-y-2">
              <label htmlFor="em-end" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Fine</label>
              <input id="em-end" type="time" className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm text-white font-mono focus:border-primary/50 focus:ring-1 focus:ring-primary/20 outline-none transition-all" value={timeEnd} onChange={e => setTimeEnd(e.target.value)} />
            </div>
          </div>

          {/* Categoria */}
          <div className="space-y-3">
            <span className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1 block">Categoria</span>
            <div className="flex flex-wrap gap-2.5">
              {Object.entries(CAT_LABELS).map(([key, label]) => (
                <button key={key} type="button"
                  onClick={() => setCategory(key)}
                  className={`px-4 py-2.5 rounded-xl text-xs font-bold transition-all duration-300 border uppercase tracking-wider ${
                    category === key
                      ? 'border-transparent text-white shadow-lg scale-105 ring-2 ring-white/5'
                      : 'bg-white/5 border-white/10 text-text-dim hover:bg-white/10 hover:border-white/20'
                  }`}
                  style={category === key ? { background: CAT_COLORS[key] } : {}}
                >{label}</button>
              ))}
            </div>
          </div>

          {/* Note */}
          <div className="space-y-2">
            <label htmlFor="em-notes" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Note</label>
            <textarea id="em-notes" className="input-field w-full bg-white/5 border-white/10 min-h-[80px] resize-none" placeholder="Note aggiuntive..." rows={2} value={notes} onChange={e => setNotes(e.target.value)} />
          </div>

          {/* Preavviso personalizzato per evento */}
          <div className="space-y-3">
            <span className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1 block">Preavviso Notifica</span>
            <div className="flex flex-wrap gap-1.5 items-center">
              {REMIND_OPTIONS.map(opt => (
                <button key={String(opt.value)} type="button"
                  onClick={() => { setRemindMinutes(opt.value); }}
                  className={`px-3 py-2 rounded-xl text-[10px] font-bold uppercase tracking-wider transition-all border ${
                    remindMinutes === opt.value
                      ? 'bg-primary text-black border-primary shadow-[0_0_10px_rgba(212,169,64,0.25)]'
                      : 'bg-white/5 text-text-dim border-white/10 hover:bg-white/10 hover:text-white'
                  }`}>
                  {opt.label}
                </button>
              ))}
              {/* Pill orario personalizzato */}
              <div className={`inline-flex items-center rounded-xl border transition-all ${
                remindMinutes === 'custom'
                  ? 'border-primary bg-primary/10 shadow-[0_0_10px_rgba(212,169,64,0.25)]'
                  : 'border-white/10 bg-white/5 hover:bg-white/10'
              }`}>
                <button type="button"
                  onClick={() => setRemindMinutes('custom')}
                  className={`px-2.5 py-2 text-[10px] font-bold uppercase tracking-wider transition-colors ${
                    remindMinutes === 'custom' ? 'text-primary' : 'text-text-dim hover:text-white'
                  }`}>
                  Alle
                </button>
                <input
                  type="time"
                  value={customRemindTime}
                  onFocus={() => setRemindMinutes('custom')}
                  onChange={e => { setCustomRemindTime(e.target.value); setRemindMinutes('custom'); }}
                  className="bg-transparent border-none outline-none text-[10px] font-mono text-white w-[52px] py-1.5 pr-2 focus:ring-0"
                />
              </div>
            </div>
            <p className="text-[9px] text-text-dim mt-1">«Standard» usa il preavviso globale. «Alle» invia la notifica all&apos;orario preciso scelto.</p>
          </div>

          {/* Collegamento a fascicolo */}
          {linkablePractices.length > 0 && (
            <div className="space-y-2">
              <label htmlFor="em-practice" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1 block">Collega a Fascicolo</label>
              <select
                id="em-practice"
                value={practiceId}
                onChange={e => setPracticeId(e.target.value)}
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-sm text-white focus:border-primary/50 focus:ring-1 focus:ring-primary/20 outline-none transition-all appearance-none"
              >
                <option value="">— Nessun fascicolo —</option>
                {linkablePractices.map(p => (
                  <option key={p.id} value={p.id}>
                    {p.client} — {p.object}
                  </option>
                ))}
              </select>
            </div>
          )}
        </form>

        {/* Footer — stile unificato con Fascicoli */}
        <div className="px-8 py-5 border-t border-white/5 bg-[#14151d] flex justify-end gap-4">
          {isEdit && !event?.autoSync && (
            <button type="button" onClick={() => setConfirmDelete(true)} className="px-5 py-3 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-all text-xs font-bold uppercase tracking-widest flex items-center gap-2">
              <Trash2 size={16}/> Elimina
            </button>
          )}
          <button 
            type="submit"
            onClick={handleSubmit} 
            className="btn-primary px-10 py-3 flex items-center gap-3 shadow-xl shadow-primary/20 active:scale-[0.98] transition-all"
          >
            <span className="font-black uppercase tracking-widest text-xs">{isEdit ? 'Salva Modifiche' : 'Crea Impegno'}</span>
          </button>
        </div>

        <ConfirmDialog
          open={confirmDelete}
          title="Elimina Impegno"
          message={`Eliminare "${event?.title || ''}"? L'azione è irreversibile.`}
          confirmLabel="Elimina"
          onConfirm={() => { setConfirmDelete(false); onDelete(event.id); }}
          onCancel={() => setConfirmDelete(false)}
        />
      </div>
    </ModalOverlay>
  );
}

function StatsCard({ events }) {
  const now = new Date();
  const todayStr = toDateStr(now);
  const weekStart = new Date(now);
  weekStart.setDate(now.getDate() - ((now.getDay() + 6) % 7));
  const weekEnd = new Date(weekStart);
  weekEnd.setDate(weekStart.getDate() + 6);
  const wsStr = toDateStr(weekStart), weStr = toDateStr(weekEnd);

  const weekEvts = events.filter(e => e.date >= wsStr && e.date <= weStr);
  const todayEvts = events.filter(e => e.date === todayStr);
  const todayDone = todayEvts.filter(e => e.completed).length;
  const todayPct = todayEvts.length > 0 ? Math.round((todayDone / todayEvts.length) * 100) : 0;

  const catCounts = {};
  weekEvts.forEach(ev => { catCounts[ev.category] = (catCounts[ev.category] || 0) + 1; });
  const sortedCats = Object.entries(catCounts).sort((a,b) => b[1] - a[1]);

  return (
    <div className="space-y-4 animate-slide-up">
      <div className="glass-card p-5 relative overflow-hidden">
        <div className="flex items-center gap-5 relative z-10">
          <div className="relative flex-shrink-0">
            <svg width={72} height={72} className="transform -rotate-90">
              <circle cx={36} cy={36} r={28} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth={6}/>
              <circle cx={36} cy={36} r={28} fill="none" stroke="var(--primary)" strokeWidth={6}
                strokeLinecap="round" strokeDasharray={2*Math.PI*28}
                strokeDashoffset={2*Math.PI*28*(1 - todayPct/100)}
                className="transition-all duration-1000 ease-out"
                style={{ filter: todayPct > 0 ? 'drop-shadow(0 0 6px var(--primary))' : 'none' }}/>
            </svg>
            <div className="absolute inset-0 flex items-center justify-center flex-col">
                 <span className="text-sm font-bold text-white">{todayPct}%</span>
            </div>
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-wider text-text-muted font-bold mb-1">Produttività Oggi</p>
            <p className="text-lg font-bold text-white">{todayDone} <span className="text-sm font-normal text-text-dim">/ {todayEvts.length} compiti</span></p>
          </div>
        </div>
      </div>

      {sortedCats.length > 0 && (
        <div className="glass-card p-4">
          <p className="text-[10px] font-bold text-text-dim uppercase tracking-wider mb-3">Questa Settimana</p>
          <div className="space-y-3">
            {sortedCats.map(([cat, count]) => {
              const pct = weekEvts.length > 0 ? (count / weekEvts.length) * 100 : 0;
              return (
                <div key={cat}>
                  <div className="flex justify-between text-[10px] mb-1">
                    <span className="text-text-muted flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full" style={{background: CAT_COLORS[cat]}}/>
                      {CAT_LABELS[cat]}
                    </span>
                    <span className="text-white font-medium">{count}</span>
                  </div>
                  <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                    <div className="h-full rounded-full transition-all duration-1000" style={{width: `${pct}%`, background: CAT_COLORS[cat]}}/>
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

// --- Componente Upcoming ---
function UpcomingPanel({ events, onEdit, onToggle }) {
  const now = new Date();
  const todayStr = toDateStr(now);
  const upcoming = useMemo(() => events.filter(e => e.date >= todayStr && !e.completed).sort((a,b) => a.date === b.date ? a.timeStart.localeCompare(b.timeStart) : a.date.localeCompare(b.date)).slice(0, 8), [events, todayStr]);
  const overdue = useMemo(() => events.filter(e => e.date < todayStr && !e.completed), [events, todayStr]);

  if (upcoming.length === 0 && overdue.length === 0) return null;

  const formatRelDay = (dateStr) => {
    if (dateStr === todayStr) return 'Oggi';
    const d = parseDate(dateStr);
    const tmr = new Date(now); tmr.setDate(now.getDate() + 1);
    if (dateStr === toDateStr(tmr)) return 'Domani';
    return `${d.getDate()} ${MONTHS_IT[d.getMonth()].slice(0,3)}`;
  };

  return (
    <div className="space-y-4 animate-slide-up" style={{animationDelay: '0.1s'}}>
      {overdue.length > 0 && (
        <div className="glass-card p-4 border border-red-500/20 bg-red-500/5">
          <div className="flex items-center gap-2 mb-3">
            <AlertCircle size={14} className="text-red-400" />
            <span className="text-xs font-bold text-red-400 uppercase tracking-wide">In Ritardo ({overdue.length})</span>
          </div>
          <div className="space-y-2">
            {overdue.slice(0, 3).map(ev => (
              <button type="button" key={ev.id} onClick={() => onEdit(ev)} className="flex items-center gap-3 p-2 rounded-lg hover:bg-red-500/10 cursor-pointer transition border border-transparent hover:border-red-500/20 text-left w-full">
                <div className="w-1.5 h-8 rounded-full flex-shrink-0" style={{ background: CAT_COLORS[ev.category] }} />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-bold text-white truncate">{ev.title}</p>
                  <p className="text-[10px] text-red-300">{formatRelDay(ev.date)}</p>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}
      <div className="glass-card p-4">
        <div className="flex items-center gap-2 mb-4 border-b border-white/5 pb-2">
          <Calendar size={14} className="text-primary" />
          <span className="text-xs font-bold text-white uppercase tracking-wide">Prossimi</span>
        </div>
        <div className="space-y-1">
          {upcoming.map(ev => (
            <button type="button" key={ev.id} onClick={() => onEdit(ev)} className="group flex items-center gap-3 p-2 rounded-lg hover:bg-white/[0.04] cursor-pointer transition border border-transparent hover:border-white/5 text-left w-full">
              <span role="switch" aria-checked={!!ev.completed} tabIndex={0} onClick={e => { e.stopPropagation(); onToggle(ev.id); }} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.stopPropagation(); e.preventDefault(); onToggle(ev.id); } }} className="w-4 h-4 rounded-full border border-text-muted/50 flex items-center justify-center flex-shrink-0 hover:border-primary hover:bg-primary/10 transition cursor-pointer">
                 <div className="w-2 h-2 rounded-full bg-primary opacity-0 group-hover:opacity-100 transition-opacity" />
              </span>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-text group-hover:text-white transition-colors truncate">{ev.title}</p>
                <div className="flex items-center gap-1.5 mt-0.5">
                    <span className="w-1.5 h-1.5 rounded-full" style={{background: CAT_COLORS[ev.category]}} />
                    <p className="text-[10px] text-text-dim">{formatRelDay(ev.date)} · {ev.timeStart}</p>
                </div>
              </div>
              {ev.autoSync && <ExternalLink size={10} className="text-text-dim flex-shrink-0 opacity-50" />}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

// --- Vista Oggi ---

/** Shared hook: filter events by active category filters and group by date */
function useFilteredByDate(events, activeFilters) {
  const filtered = activeFilters.length > 0 ? events.filter(e => activeFilters.includes(e.category)) : events;
  const eventsByDate = useMemo(() => {
    const map = new Map();
    for (const e of filtered) {
      if (!map.has(e.date)) map.set(e.date, []);
      map.get(e.date).push(e);
    }
    return map;
  }, [filtered]);
  return { filtered, eventsByDate };
}

function TodayView({ events, onToggle, onEdit, onAdd, onSave, activeFilters }) {
  const now = new Date();
  const todayStr = toDateStr(now);
  const allToday = events.filter(e => e.date === todayStr).sort((a,b) => a.timeStart.localeCompare(b.timeStart));
  const todayEvts = activeFilters.length > 0 ? allToday.filter(e => activeFilters.includes(e.category)) : allToday;
  const timelineRef = useRef(null);

  useEffect(() => {
    if (timelineRef.current) {
      const nowMin = now.getHours() * 60 + now.getMinutes();
      const scrollTo = Math.max(0, (nowMin / 60) * 60 - 150);
      timelineRef.current.scrollTop = scrollTo;
    }
  }, []);

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between gap-4 flex-shrink-0 mb-4">
        <div>
          <h2 className="text-xl font-black text-white tracking-tight">
             {DAYS_IT[now.getDay()]} <span className="text-primary">{now.getDate()}</span> {MONTHS_IT[now.getMonth()]}
          </h2>
        </div>
        <button onClick={() => onAdd(todayStr)} className="btn-primary text-xs px-4 py-2">
          <Plus size={14} strokeWidth={3}/> Nuovo
        </button>
      </div>

      <div className="glass-card flex-1 overflow-hidden relative">
         {todayEvts.length === 0 ? (
            <EmptyState 
              message={allToday.length === 0 ? "Giornata Libera" : "Nessun impegno trovato"}
              sub={allToday.length === 0 ? "Non hai impegni in programma per oggi. Goditi un po' di relax." : "Prova a modificare i filtri per vedere altri impegni."}
              onAdd={allToday.length === 0 ? onAdd : null}
              date={todayStr}
            />
         ) : (
             <div ref={timelineRef} className="overflow-y-auto h-full no-scrollbar relative p-4">
                <div className="absolute top-4 left-16 right-4 bottom-4 pointer-events-none">
                     {HOURS.map((h, i) => (
                        <div key={h} className="absolute w-full border-t border-white/[0.04]" style={{top: i * 60, height: 60}}></div>
                     ))}
                </div>
                <div className="relative" style={{height: HOURS.length * 60 + 20}}>
                  {HOURS.map((h, i) => (
                    <div key={h} className="absolute left-0 w-12 text-right text-[11px] font-medium text-text-dim pt-1.5" style={{top: i * 60}}>
                      {String(h).padStart(2,'0')}:00
                    </div>
                  ))}
                  {(() => {
                    const nowMin = now.getHours() * 60 + now.getMinutes();
                    const top = (nowMin / 60) * 60;
                    return (
                        <div className="absolute left-14 right-0 z-30 flex items-center" style={{top}}>
                           <div className="text-[9px] font-bold text-primary w-10 text-right pr-2 -ml-12">{fmtTime(now.getHours(), now.getMinutes())}</div>
                           <div className="flex-1 border-t border-primary relative">
                             <div className="absolute -left-1 -top-1 w-2 h-2 rounded-full bg-primary shadow-[0_0_8px_var(--primary)]" />
                           </div>
                        </div>
                    );
                  })()}
                  {(() => {
                    // ── Overlap layout: assign columns to overlapping events ──
                    const positioned = todayEvts.map(ev => {
                      const [sh,sm] = ev.timeStart.split(':').map(Number);
                      const [eh,em] = ev.timeEnd.split(':').map(Number);
                      return { ...ev, startMin: sh*60+sm, endMin: eh*60+em };
                    }).sort((a,b) => a.startMin - b.startMin || a.endMin - b.endMin);

                    // Greedy column assignment
                    const columns = []; // array of { endMin, col }
                    const layout = positioned.map(ev => {
                      // Find first column where event doesn't overlap
                      let col = 0;
                      for (let c = 0; c < columns.length; c++) {
                        if (columns[c] <= ev.startMin) { col = c; columns[c] = ev.endMin; break; }
                        col = c + 1;
                      }
                      if (col >= columns.length) columns.push(ev.endMin);
                      else columns[col] = Math.max(columns[col], ev.endMin);
                      return { ...ev, col };
                    });

                    // Calculate total columns for each overlap group
                    const totalCols = columns.length || 1;

                    return layout.map(ev => {
                      const top = (ev.startMin / 60) * 60;
                      const height = Math.max(((ev.endMin - ev.startMin) / 60) * 60, 32);
                      const isSpecial = ev.category === 'udienza' || ev.category === 'scadenza';
                      const colWidth = totalCols > 1 ? `calc((100% - 56px - 8px) / ${totalCols})` : undefined;
                      const colLeft = totalCols > 1 ? `calc(56px + ${ev.col} * ((100% - 56px - 8px) / ${totalCols}))` : undefined;
                      return (
                        <div key={ev.id} data-evid={ev.id}
                          className={`agenda-event absolute rounded-lg px-3 py-1.5 cursor-pointer transition-all duration-200 hover:shadow-lg hover:shadow-black/20 hover:z-20 text-left
                              ${ev.category === 'udienza' ? 'bg-[#d4a940]/20 border-l-4 border-[#d4a940]' : ''}
                              ${ev.category === 'scadenza' ? 'bg-[#EF6B6B]/20 border-l-4 border-[#EF6B6B]' : ''}
                              ${isSpecial ? '' : 'bg-white/[0.08] hover:bg-white/[0.12] border-l-4 border-white/20'}
                              ${ev.completed ? 'opacity-40 line-through' : ''}
                          `}
                          style={{
                              top, height,
                              left: colLeft || 56,
                              right: totalCols > 1 ? 'auto' : 8,
                              width: colWidth || undefined,
                              borderLeftColor: CAT_COLORS[ev.category],
                              zIndex: ev.col + 1,
                          }}
                        >
                          {/* Native button overlay for click + keyboard + drag */}
                          <button type="button" aria-label={`Modifica evento: ${ev.title}`}
                            className="absolute inset-0 z-0 cursor-pointer"
                            onMouseDown={e => handleTodayEventDrag(e, ev, onSave)}
                            onClick={e => {
                              if (e.currentTarget.parentElement._didDrag) { e.currentTarget.parentElement._didDrag = false; return; }
                              if (e.currentTarget.parentElement._didLongPress) { e.currentTarget.parentElement._didLongPress = false; return; }
                              onEdit(ev);
                            }} />
                          {/* Resize handle top */}
                          <button
                            type="button" aria-label="Ridimensiona inizio evento"
                            className="resize-handle absolute top-0 left-0 right-0 h-2 cursor-ns-resize group/resizetop z-10"
                            onMouseDown={e => handleResizeTop(e, { startMin: ev.startMin, endMin: ev.endMin, minHeight: 32, selector: '[data-evid]', ev, onSave })}
                          >
                            <div className="mx-auto w-8 h-0.5 bg-white/10 group-hover/resizetop:bg-white/30 rounded-full mt-0.5 transition" />
                          </button>
                          <div className="flex justify-between items-start h-full relative z-[1]">
                               <div className="flex items-start gap-2 min-w-0 flex-1">
                                  {/* Checkbox completamento */}
                                  <button
                                    onClick={e => { e.stopPropagation(); onToggle(ev.id); }}
                                    className={`w-4 h-4 mt-0.5 rounded border flex-shrink-0 flex items-center justify-center transition-all ${
                                      ev.completed
                                        ? 'bg-green-500 border-green-500'
                                        : 'border-white/30 hover:border-primary hover:bg-primary/10'
                                    }`}
                                  >
                                    {ev.completed && <Check size={10} className="text-white" strokeWidth={3} />}
                                  </button>
                                  <div className="min-w-0">
                                    <div className="flex items-center gap-1.5">
                                        <span className={`text-xs font-bold truncate ${ev.completed ? 'text-white/50' : 'text-white'}`}>{ev.title}</span>
                                        {ev.remindMinutes != null && <BellRing size={10} className="text-amber-400 flex-shrink-0" title={ev.remindMinutes === 'custom' ? `Notifica alle ${ev.customRemindTime || '?'}` : `Preavviso: ${ev.remindMinutes} min`} />}
                                        {ev.autoSync && <ExternalLink size={10} className="text-white/70" />}
                                        {ev.practiceId && !ev.autoSync && <Briefcase size={10} className="text-primary/70" />}
                                    </div>
                                    {height >= 45 && (
                                        <p className="text-[10px] text-white/60 mt-0.5 truncate">{ev.notes || ev.category.toUpperCase()}</p>
                                    )}
                                  </div>
                               </div>
                               <span className="text-[10px] font-mono text-white/80 bg-black/20 px-1.5 py-0.5 rounded flex-shrink-0">{ev.timeStart}</span>
                          </div>
                          {/* Drag handle per ridimensionare (bottom edge) */}
                          <button
                            type="button" aria-label="Ridimensiona fine evento"
                            className="resize-handle absolute bottom-0 left-0 right-0 h-2 cursor-ns-resize group/resize z-10"
                            onMouseDown={e => handleResizeBottom(e, { startMin: ev.startMin, endMin: ev.endMin, minHeight: 32, selector: '[data-evid]', ev, onSave })}
                          >
                            <div className="mx-auto w-8 h-0.5 bg-white/10 group-hover/resize:bg-white/30 rounded-full mt-0.5 transition" />
                          </button>
                        </div>
                      );
                    });
                  })()}
                </div>
             </div>
         )}
      </div>
    </div>
  );
}

// --- Vista Settimana ---
function WeekView({ events, onEdit, onAdd, onSave, activeFilters }) {
  const [weekOffset, setWeekOffset] = useState(0);
  const scrollRef = useRef(null);
  const now = new Date();
  const todayStr = toDateStr(now);
  const sow = new Date(now);
  sow.setDate(now.getDate() - ((now.getDay() + 6) % 7) + (weekOffset * 7));
  const days = Array.from({length: 7}, (_, i) => {
    const d = new Date(sow); d.setDate(sow.getDate() + i);
    return { date: d, str: toDateStr(d) };
  });
  const { eventsByDate } = useFilteredByDate(events, activeFilters);

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between flex-shrink-0 mb-4">
        <div className="inline-flex items-center bg-white/[0.04] rounded-xl p-1 border border-white/5 gap-1">
          <button onClick={() => setWeekOffset(w => w-1)} className="btn-ghost w-7 h-7 p-0 rounded-lg"><ChevronLeft size={14}/></button>
          <span className="text-xs font-bold w-36 text-center text-white">{days[0].date.getDate()} – {days[6].date.getDate()} {MONTHS_IT[days[6].date.getMonth()]}</span>
          <button onClick={() => setWeekOffset(w => w+1)} className="btn-ghost w-7 h-7 p-0 rounded-lg"><ChevronRight size={14}/></button>
        </div>
        <button onClick={() => onAdd(todayStr)} className="btn-primary text-xs px-4 py-2">
          <Plus size={14} strokeWidth={3}/> Nuovo
        </button>
      </div>

      <div className="glass-card flex-1 flex flex-col overflow-hidden">
        <div className="grid grid-cols-[50px_repeat(7,1fr)] border-b border-white/5 bg-black/20">
          <div/>
          {days.map(({date, str}) => {
            const isToday = str === todayStr;
            return (
              <div key={str} className={`text-center py-3 ${isToday ? 'bg-primary/5' : ''}`}>
                <div className="text-[10px] font-bold text-text-dim mb-1">{DAYS_SHORT[date.getDay()]}</div>
                <div className={`text-sm font-bold w-7 h-7 mx-auto flex items-center justify-center rounded-full ${isToday ? 'bg-primary text-black shadow-lg shadow-primary/50' : 'text-text'}`}>
                    {date.getDate()}
                </div>
              </div>
            );
          })}
        </div>
        <div ref={scrollRef} className="overflow-y-auto flex-1 no-scrollbar relative">
          <div className="grid grid-cols-[50px_repeat(7,1fr)] relative" style={{height: HOURS.length * 60}}>
            <div className="relative border-r border-white/5 bg-black/20">
              {HOURS.map(h => (
                <div key={h} className="absolute w-full text-right pr-2 text-[10px] text-text-dim font-medium" style={{top: h*60 + 5}}>
                  {String(h).padStart(2,'0')}
                </div>
              ))}
            </div>
            {days.map(({str}) => {
              const isToday = str === todayStr;
              const dayEvts = eventsByDate.get(str) || [];
              return (
                <div key={str} data-daystr={str} role="grid" tabIndex={0} aria-label={`Giorno ${str} — clicca per creare evento`}
                    className={`relative border-r border-white/5 ${isToday ? 'bg-white/[0.02]' : ''}`}
                    onKeyDown={(e) => {
                       if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onAdd(str, '09:00', '10:00'); }
                    }}
                    onClick={(e) => {
                       if (e.target.closest('.week-ev')) return;
                       const rect = e.currentTarget.getBoundingClientRect();
                       const y = e.clientY - rect.top + (scrollRef.current?.scrollTop || 0);
                       const rawMin = Math.round((y / 60) * 60);
                       const startH = Math.floor(rawMin/60); 
                       onAdd(str, fmtTime(startH, 0), fmtTime(Math.min(startH+1,23), 0));
                    }}>
                  {HOURS.map(h => (<div key={h} className="absolute w-full border-t border-white/[0.03]" style={{top: h*60, height: 60}}/>))}
                  {dayEvts.map(ev => {
                    const [sh,sm] = ev.timeStart.split(':').map(Number);
                    const [eh,em] = ev.timeEnd.split(':').map(Number);
                    const top = ((sh*60+sm)/60)*60;
                    const height = Math.max(((eh*60+em-sh*60-sm)/60)*60, 20);
                    const isUdienza = ev.category === 'udienza';
                    return (
                      <div key={ev.id} className="week-ev agenda-event absolute left-0.5 right-0.5 rounded px-1.5 py-0.5 cursor-pointer text-white overflow-hidden text-left"
                        style={{
                            top, height, fontSize: 10,
                            background: isUdienza ? CAT_COLORS.udienza : `${CAT_COLORS[ev.category]}CC`,
                            borderLeft: `2px solid ${isUdienza ? '#fff' : 'rgba(255,255,255,0.3)'}`,
                            boxShadow: isUdienza ? '0 2px 8px rgba(212,169,64,0.3)' : 'none'
                        }}>
                        {/* Native button overlay for click + keyboard + drag */}
                        <button type="button" aria-label={`Modifica evento: ${ev.title}`}
                          className="absolute inset-0 z-0 cursor-pointer"
                          onMouseDown={e => handleWeekEventDrag(e, ev, onSave)}
                          onClick={e => {
                            e.stopPropagation();
                            if (e.currentTarget.parentElement._didDrag) { e.currentTarget.parentElement._didDrag = false; return; }
                            if (e.currentTarget.parentElement._didLongPress) { e.currentTarget.parentElement._didLongPress = false; return; }
                            onEdit(ev);
                          }} />
                        {/* Resize handle top */}
                        <button type="button" aria-label="Ridimensiona inizio"
                          className="resize-handle absolute top-0 left-0 right-0 h-1.5 cursor-ns-resize z-10"
                          onMouseDown={e => {
                            const [tsh,tsm] = ev.timeStart.split(':').map(Number);
                            const [teh,tem] = ev.timeEnd.split(':').map(Number);
                            handleResizeTop(e, { startMin: tsh*60+tsm, endMin: teh*60+tem, minHeight: 20, selector: '.week-ev', ev, onSave });
                          }}
                        />
                        <div className="font-bold truncate leading-tight flex items-center gap-1 relative z-[1]">{ev.title}{ev.remindMinutes != null && <BellRing size={8} className="text-amber-400 flex-shrink-0" />}</div>
                        {height >= 30 && <div className="opacity-80 text-[9px] relative z-[1]">{ev.timeStart}</div>}
                        {/* Resize handle bottom */}
                        <button type="button" aria-label="Ridimensiona fine"
                          className="resize-handle absolute bottom-0 left-0 right-0 h-1.5 cursor-ns-resize z-10"
                          onMouseDown={e => {
                            const [rsh,rsm] = ev.timeStart.split(':').map(Number);
                            const [reh,rem_] = ev.timeEnd.split(':').map(Number);
                            handleResizeBottom(e, { startMin: rsh*60+rsm, endMin: reh*60+rem_, minHeight: 20, selector: '.week-ev', ev, onSave });
                          }}
                        />
                      </div>
                    );
                  })}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

// --- Vista Mese ---
function MonthView({ events, onEdit, onAdd, activeFilters }) {
  const [monthOffset, setMonthOffset] = useState(0);
  const now = new Date();
  const todayStr = toDateStr(now);
  const viewMonth = new Date(now.getFullYear(), now.getMonth() + monthOffset, 1);
  const year = viewMonth.getFullYear();
  const month = viewMonth.getMonth();
  const daysInMonth = new Date(year, month + 1, 0).getDate();
  const startDay = (new Date(year, month, 1).getDay() + 6) % 7; 
  const cells = [];
  const prevDays = new Date(year, month, 0).getDate();
  for (let i = startDay - 1; i >= 0; i--) { cells.push({ date: new Date(year, month - 1, prevDays - i), str: toDateStr(new Date(year, month - 1, prevDays - i)), outside: true }); }
  for (let d = 1; d <= daysInMonth; d++) { cells.push({ date: new Date(year, month, d), str: toDateStr(new Date(year, month, d)), outside: false }); }
  const remaining = 42 - cells.length;
  for (let d = 1; d <= remaining; d++) { cells.push({ date: new Date(year, month + 1, d), str: toDateStr(new Date(year, month + 1, d)), outside: true }); }
  const { eventsByDate } = useFilteredByDate(events, activeFilters);

  return (
    <div className="h-full flex flex-col">
       <div className="flex items-center justify-between flex-shrink-0 mb-4">
        <div className="inline-flex items-center bg-white/[0.04] rounded-xl p-1 border border-white/5 gap-1">
          <button onClick={() => setMonthOffset(m => m-1)} className="btn-ghost w-7 h-7 p-0 rounded-lg"><ChevronLeft size={14}/></button>
          <span className="text-xs font-bold w-36 text-center text-white">{MONTHS_IT[month]} {year}</span>
          <button onClick={() => setMonthOffset(m => m+1)} className="btn-ghost w-7 h-7 p-0 rounded-lg"><ChevronRight size={14}/></button>
        </div>
        <button onClick={() => onAdd(todayStr)} className="btn-primary text-xs px-4 py-2">
          <Plus size={14} strokeWidth={3}/> Nuovo
        </button>
      </div>
      <div className="glass-card flex-1 flex flex-col overflow-hidden p-0">
        <div className="grid grid-cols-7 border-b border-white/5 bg-black/20">
          {['LUN','MAR','MER','GIO','VEN','SAB','DOM'].map((d, i) => (
            <div key={d} className={`text-center py-2 text-[10px] font-bold ${i>=5 ? 'text-primary' : 'text-text-dim'}`}>{d}</div>
          ))}
        </div>
        <div className="grid grid-cols-7 grid-rows-6 flex-1">
          {cells.map(({ date, str, outside }) => {
            const isToday = str === todayStr;
            const dayEvts = eventsByDate.get(str) || [];
            return (
              <div key={str}
                className={`border-b border-r border-white/5 p-1 relative cursor-pointer hover:bg-white/[0.03] transition group text-left ${outside ? 'opacity-30 bg-black/20' : ''} ${isToday ? 'bg-primary/[0.05]' : ''}`}>
                <button type="button" className="absolute inset-0 z-0 cursor-pointer" aria-label={`Aggiungi evento il ${str}`}
                  onClick={() => onAdd(str)} />
                <div className={`text-[10px] font-bold mb-1 ml-1 w-5 h-5 flex items-center justify-center rounded-full relative z-[1] ${isToday ? 'bg-primary text-black' : 'text-text-muted'}`}>
                  {date.getDate()}
                </div>
                <div className="space-y-1 overflow-y-auto max-h-[80px] no-scrollbar relative z-[1]">
                  {dayEvts.slice(0, 4).map(ev => (
                    <button type="button" key={ev.id} onClick={e => {e.stopPropagation(); onEdit(ev);}}
                      className="text-[9px] px-1.5 py-0.5 rounded-sm truncate text-white border-l-[2px] transition hover:scale-105 block w-full text-left cursor-pointer"
                      style={{ background: `${CAT_COLORS[ev.category]}40`, borderLeftColor: CAT_COLORS[ev.category] }}>
                      {ev.title}
                    </button>
                  ))}
                  {dayEvts.length > 4 && <div className="text-[8px] text-center text-text-dim">+{dayEvts.length - 4} altri</div>}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// --- Popup Impostazioni Avvisi ---
function NotificationSettingsPopup({ settings, agendaEvents, onSave, onClose }) {
  const [notifyEnabled, setNotifyEnabled] = useState(settings?.notifyEnabled ?? true);
  const [preavviso, setPreavviso] = useState(settings?.preavviso ?? 30);
  const [briefingMattina, setBriefingMattina] = useState(settings?.briefingMattina ?? '08:30');
  const [briefingPomeriggio, setBriefingPomeriggio] = useState(settings?.briefingPomeriggio ?? '14:30');
  const [briefingSera, setBriefingSera] = useState(settings?.briefingSera ?? '19:30');

  const PREAVVISO_OPTIONS = [
    { value: 5, label: '5 min' },
    { value: 10, label: '10 min' },
    { value: 15, label: '15 min' },
    { value: 30, label: '30 min' },
    { value: 60, label: '1 ora' },
    { value: 120, label: '2 ore' },
    { value: 1440, label: '1 giorno' },
  ];

  const handleSave = async () => {
    const updated = {
      ...settings,
      notifyEnabled,
      preavviso,
      briefingMattina,
      briefingPomeriggio,
      briefingSera,
    };
    try {
      await api.saveSettings(updated);
      // Sync backend scheduler con formato corretto: briefingTimes (array) + items
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
            return Number.parseInt(e.remindMinutes, 10) || (preavviso || 30);
          })(),
          customRemindTime: e.customRemindTime || null,
        }));
      await api.syncNotificationSchedule({ briefingTimes, items });
      onSave(updated);
      onClose();
    } catch {
      toast.error('Errore nel salvataggio');
    }
  };

  return (
    <ModalOverlay onClose={onClose} labelledBy="notif-settings-title" zIndex={200}>
      <div className="glass-card border border-white/10 shadow-2xl p-6 animate-fade-in relative z-10" style={{ maxWidth: 400, width: '100%' }}>
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-amber-500/10 flex items-center justify-center">
              <BellRing size={18} className="text-amber-400" />
            </div>
            <h3 id="notif-settings-title" className="text-base font-bold text-white uppercase tracking-wide">Impostazioni Avvisi</h3>
          </div>
          <button onClick={onClose} className="text-text-muted hover:text-white transition"><X size={20}/></button>
        </div>

        <div className="space-y-5">
          {/* Preavviso Standard — Pill selector */}
          <div>
            <span className="text-[10px] font-bold text-text-dim uppercase tracking-wider mb-2.5 block">Preavviso Standard</span>
            <div className="flex flex-wrap gap-1.5">
              {PREAVVISO_OPTIONS.map(opt => (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => setPreavviso(opt.value)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all border ${
                    preavviso === opt.value
                      ? 'bg-primary text-black border-primary shadow-[0_0_12px_rgba(212,169,64,0.3)]'
                      : 'bg-white/[0.04] text-text-muted border-white/5 hover:bg-white/[0.08] hover:text-white'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {/* Toggle Notifiche */}
          <div className="flex items-center justify-between py-2">
            <div>
              <p className="text-sm text-white font-medium">Attiva Notifiche Desktop</p>
              <p className="text-[10px] text-text-dim">Ricevi promemoria prima degli impegni</p>
            </div>
            <button
              onClick={() => setNotifyEnabled(!notifyEnabled)}
              className={`w-11 h-6 rounded-full transition-all duration-300 relative ${
                notifyEnabled ? 'bg-primary' : 'bg-white/10'
              }`}
            >
              <div className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform duration-300 ${
                notifyEnabled ? 'translate-x-5' : 'translate-x-0'
              }`} />
            </button>
          </div>

          {/* Orari Briefing — Design pill coerente con preavviso evento */}
          <div>
            <span className="text-[10px] font-bold text-text-dim uppercase tracking-wider mb-3 block">Orari Briefing</span>
            <div className="space-y-2">
              {[
                { label: 'Mattina', value: briefingMattina, onChange: setBriefingMattina },
                { label: 'Pomeriggio', value: briefingPomeriggio, onChange: setBriefingPomeriggio },
                { label: 'Sera', value: briefingSera, onChange: setBriefingSera },
              ].map(({ label, value, onChange }) => (
                <div key={label} className="flex items-center justify-between bg-white/[0.03] rounded-xl px-4 py-3 border border-white/5">
                  <span className="text-sm text-white font-medium">{label}</span>
                  <div className="inline-flex items-center rounded-lg border border-primary/30 bg-primary/10">
                    <span className="px-2 py-1.5 text-[10px] font-semibold text-primary">Alle</span>
                    <input type="time" className="bg-transparent border-none outline-none text-sm text-white font-mono w-[72px] py-1.5 pr-2.5 focus:ring-0" value={value} onChange={e => onChange(e.target.value)} />
                  </div>
                </div>
              ))}
            </div>
          </div>

          <button onClick={handleSave} className="btn-primary w-full py-2.5 text-sm mt-2">
            Salva Impostazioni
          </button>
        </div>
      </div>
    </ModalOverlay>
  );
}

// --- Componente Principale Agenda ---
export default function AgendaPage({ agendaEvents, onSaveAgenda, practices, onSelectPractice, settings }) {
  const [view, setView] = useState('today');
  const [modalEvent, setModalEvent] = useState(null);
  const [activeFilters, setActiveFilters] = useState([]);
  const [showNotifPopup, setShowNotifPopup] = useState(false);
  const [showStats, setShowStats] = useState(false);
  const [localSettings, setLocalSettings] = useState(settings || {});
  const events = agendaEvents || [];

  // Sync localSettings when parent settings prop changes
  useEffect(() => {
    if (settings) setLocalSettings(settings);
  }, [settings]);

  const toggleFilter = useCallback((cat) => setActiveFilters(prev => 
    prev.includes(cat) ? prev.filter(c => c !== cat) : [...prev, cat]
  ), []);

  const handleSave = useCallback((ev) => {
    const updated = events.some(e => e.id === ev.id) ? events.map(e => e.id === ev.id ? ev : e) : [...events, ev];
    onSaveAgenda(updated); setModalEvent(null);
  }, [events, onSaveAgenda]);

  const handleDelete = useCallback((id) => { onSaveAgenda(events.filter(e => e.id !== id)); setModalEvent(null); }, [events, onSaveAgenda]);
  const handleToggle = useCallback((id) => onSaveAgenda(events.map(e => e.id === id ? {...e, completed: !e.completed} : e)), [events, onSaveAgenda]);
  const openAdd = useCallback((date, tS, tE) => {
    // Ora attuale arrotondata ai prossimi 30 min
    const n = new Date();
    let mm = n.getMinutes(), hh = n.getHours();
    mm = mm < 30 ? 30 : 0;
    if (mm === 0) hh = (hh + 1) % 24;
    const nowStart = `${String(hh).padStart(2,'0')}:${String(mm).padStart(2,'0')}`;
    const nowEnd = `${String((hh + 1) % 24).padStart(2,'0')}:${String(mm).padStart(2,'0')}`;
    setModalEvent({ event: { date: date || toDateStr(new Date()), timeStart: tS || nowStart, timeEnd: tE || nowEnd }, isNew: true });
  }, []);
  const openEdit = useCallback((ev) => ev.autoSync && ev.practiceId && onSelectPractice ? onSelectPractice(ev.practiceId) : setModalEvent({ event: ev, isNew: false }), [onSelectPractice]);
  
  const views = [ 
    { key: 'today', label: 'Oggi', icon: Clock }, 
    { key: 'week', label: 'Settimana', icon: CalendarDays }, 
    { key: 'month', label: 'Mese', icon: Calendar } 
  ];

  return (
    <div className="animate-slide-up h-full flex flex-col overflow-hidden">
      
      {/* ═══ HEADER — Compatto e pulito ═══ */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-5 flex-shrink-0">
        <div className="flex items-center gap-3 flex-wrap">
          {/* Titolo */}
          <h1 className="text-2xl font-black text-white tracking-tight">Agenda</h1>
          
          {/* Vista Switcher */}
          <div className="inline-flex bg-white/[0.04] rounded-xl p-1 border border-white/5">
            {views.map(({ key, label, icon: Icon }) => (
              <button key={key} onClick={() => setView(key)} 
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold transition-all duration-200 ${
                  view === key 
                    ? 'bg-primary text-black shadow-[0_0_12px_rgba(212,169,64,0.25)]' 
                    : 'text-text-dim hover:text-white hover:bg-white/[0.06]'
                }`}>
                <Icon size={13}/> <span className="hidden sm:inline">{label}</span>
              </button>
            ))}
          </div>
        </div>
        
        {/* Azioni rapide */}
        <div className="flex items-center gap-2">
          {/* Stats toggle */}
          <button 
            onClick={() => setShowStats(!showStats)} 
            className={`p-2 rounded-xl transition-all border ${
              showStats 
                ? 'bg-primary/10 border-primary/20 text-primary' 
                : 'bg-white/[0.04] border-white/5 text-text-dim hover:text-white hover:bg-white/[0.08]'
            }`}
            title="Statistiche"
          >
            <BarChart3 size={16} />
          </button>
          
          {/* Bell */}
          <button 
            onClick={() => setShowNotifPopup(true)} 
            className="p-2 rounded-xl bg-white/[0.04] border border-white/5 hover:bg-white/[0.08] transition-all text-text-dim hover:text-white relative"
            title="Impostazioni Avvisi"
          >
            <Bell size={16} />
            {localSettings?.notifyEnabled && (
              <span className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-primary" />
            )}
          </button>
        </div>
      </div>

      {/* ═══ FILTRI — inline, minimalista ═══ */}
      <div className="flex items-center gap-2 mb-4 flex-shrink-0 overflow-x-auto no-scrollbar">
        {Object.entries(CAT_LABELS).map(([key, label]) => {
          const isActive = activeFilters.includes(key);
          return (
            <button 
              key={key} 
              onClick={() => toggleFilter(key)} 
              className={`whitespace-nowrap px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider transition-all border flex-shrink-0 ${
                isActive 
                  ? 'border-transparent text-white shadow-md' 
                  : 'border-white/5 text-text-dim hover:bg-white/5 hover:text-white bg-white/[0.02]'
              }`} 
              style={isActive ? { background: CAT_COLORS[key] } : {}}
            >
              {label}
            </button>
          );
        })}
        {activeFilters.length > 0 && (
          <button 
            onClick={() => setActiveFilters([])} 
            className="px-2 py-1.5 text-text-dim hover:text-red-400 transition-colors flex-shrink-0"
            title="Pulisci filtri"
          >
            <X size={14}/>
          </button>
        )}
      </div>

      {/* ═══ CONTENUTO PRINCIPALE ═══ */}
      <div className={`flex-1 overflow-hidden grid gap-5 items-start ${showStats ? 'grid-cols-1 lg:grid-cols-[1fr_260px]' : 'grid-cols-1'}`} style={{ transition: 'grid-template-columns 0.3s' }}>
        <div className="overflow-hidden h-full">
          {view === 'today' && <TodayView events={events} onToggle={handleToggle} onEdit={openEdit} onAdd={openAdd} onSave={handleSave} activeFilters={activeFilters} />}
          {view === 'week' && <WeekView events={events} onEdit={openEdit} onAdd={openAdd} onSave={handleSave} activeFilters={activeFilters} />}
          {view === 'month' && <MonthView events={events} onEdit={openEdit} onAdd={openAdd} activeFilters={activeFilters} />}
        </div>
        
        {/* Sidebar Destra — solo quando attivata, allineata in alto con l'agenda */}
        {showStats && (
          <div className="space-y-4 overflow-y-auto no-scrollbar pr-1 animate-slide-up self-start">
            <StatsCard events={events} />
            <UpcomingPanel events={events} onEdit={openEdit} onToggle={handleToggle} />
          </div>
        )}
      </div>

      {modalEvent && <EventModal event={modalEvent.event} onSave={handleSave} onDelete={handleDelete} onClose={() => setModalEvent(null)} practices={practices} />}
      {showNotifPopup && (
        <NotificationSettingsPopup 
          key={`notif-${localSettings?.briefingMattina}-${localSettings?.briefingPomeriggio}-${localSettings?.briefingSera}`}
          settings={localSettings}
          agendaEvents={events}
          onSave={(s) => setLocalSettings(s)} 
          onClose={() => setShowNotifPopup(false)} 
        />
      )}
    </div>
  );
}

EmptyState.propTypes = {
  message: PropTypes.string,
  sub: PropTypes.string,
  onAdd: PropTypes.func,
  date: PropTypes.string,
};

EventModal.propTypes = {
  event: PropTypes.object,
  date: PropTypes.string,
  onSave: PropTypes.func.isRequired,
  onDelete: PropTypes.func,
  onClose: PropTypes.func.isRequired,
  practices: PropTypes.array,
};

StatsCard.propTypes = {
  events: PropTypes.array.isRequired,
};

UpcomingPanel.propTypes = {
  events: PropTypes.array.isRequired,
  onEdit: PropTypes.func.isRequired,
  onToggle: PropTypes.func.isRequired,
};

TodayView.propTypes = {
  events: PropTypes.array.isRequired,
  onToggle: PropTypes.func.isRequired,
  onEdit: PropTypes.func.isRequired,
  onAdd: PropTypes.func.isRequired,
  onSave: PropTypes.func.isRequired,
  activeFilters: PropTypes.array.isRequired,
};

WeekView.propTypes = {
  events: PropTypes.array.isRequired,
  onEdit: PropTypes.func.isRequired,
  onAdd: PropTypes.func.isRequired,
  onSave: PropTypes.func.isRequired,
  activeFilters: PropTypes.array.isRequired,
};

MonthView.propTypes = {
  events: PropTypes.array.isRequired,
  onEdit: PropTypes.func.isRequired,
  onAdd: PropTypes.func.isRequired,
  activeFilters: PropTypes.array.isRequired,
};

NotificationSettingsPopup.propTypes = {
  settings: PropTypes.object,
  agendaEvents: PropTypes.array,
  onSave: PropTypes.func.isRequired,
  onClose: PropTypes.func.isRequired,
};

AgendaPage.propTypes = {
  agendaEvents: PropTypes.array,
  onSaveAgenda: PropTypes.func.isRequired,
  practices: PropTypes.array,
  onSelectPractice: PropTypes.func,
  settings: PropTypes.object,
};