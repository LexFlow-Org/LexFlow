import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import PropTypes from 'prop-types';
import { Clock, Play, Square, Plus, Trash2, ChevronLeft, ChevronRight, Edit3, Check, X, DollarSign, Receipt, Download, Briefcase, FileText } from 'lucide-react';
import toast from 'react-hot-toast';
import jsPDF from 'jspdf';
import 'jspdf-autotable';
import ConfirmDialog from '../components/ConfirmDialog';
import ModalOverlay from '../components/ModalOverlay';
import PracticeCombobox from '../components/PracticeCombobox';
import * as api from '../tauri-api';
import { genId, toDateStr } from '../utils/helpers';

/* ======== Helpers ======== */

function fmtDuration(min) {
  if (!min || min <= 0) return '0m';
  const h = Math.floor(min / 60);
  const m = Math.round(min % 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

const DAYS_IT = ['Dom', 'Lun', 'Mar', 'Mer', 'Gio', 'Ven', 'Sab'];
const MONTHS_IT = ['Gennaio', 'Febbraio', 'Marzo', 'Aprile', 'Maggio', 'Giugno', 'Luglio', 'Agosto', 'Settembre', 'Ottobre', 'Novembre', 'Dicembre'];

/* ======== Billing helpers ======== */

const CPA_RATE = 0.04;
const IVA_RATE = 0.22;

function calcTotals(items) {
  const subtotal = items.reduce((s, i) => s + (i.total || 0), 0);
  const cpa = subtotal * CPA_RATE;
  const ivaBase = subtotal + cpa;
  const iva = ivaBase * IVA_RATE;
  const total = ivaBase + iva;
  return { subtotal, cpa, iva, total };
}

const STATUS_LABELS = { draft: 'Bozza', sent: 'Inviata', paid: 'Pagata' };
const STATUS_COLORS = {
  draft: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
  sent: 'bg-white/10 text-white border-white/30',
  paid: 'bg-primary/10 text-primary border-primary/30',
};

/* ======== Main Component ======== */
export default function TimeTrackingPage({ practices }) {
  const [activeTab, setActiveTab] = useState('ore');
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTimer, setActiveTimer] = useState(() => {
    try {
      const saved = localStorage.getItem('lexflow_active_timer');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed?.startedAt) return parsed;
      }
    } catch { /* ignore */ }
    return null;
  });
  const [elapsed, setElapsed] = useState(0);
  const [weekOffset, setWeekOffset] = useState(0);
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingLog, setEditingLog] = useState(null);
  const intervalRef = useRef(null);
  const [invoices, setInvoices] = useState([]);
  const [showCreateInvoice, setShowCreateInvoice] = useState(false);
  const [editingInvoice, setEditingInvoice] = useState(null);
  // Pre-launch timer form
  const [timerPracticeId, setTimerPracticeId] = useState('');
  const [timerDescription, setTimerDescription] = useState('');

  useEffect(() => {
    (async () => {
      try {
        const [logData, invData] = await Promise.all([
          api.loadTimeLogs().catch(() => []),
          api.loadInvoices().catch(() => []),
        ]);
        setLogs(logData || []);
        setInvoices(invData || []);
      } catch (e) { console.error(e); }
      setLoading(false);
    })();
  }, []);

  useEffect(() => {
    if (activeTimer) {
      localStorage.setItem('lexflow_active_timer', JSON.stringify(activeTimer));
      intervalRef.current = setInterval(() => {
        setElapsed(Math.floor((Date.now() - activeTimer.startedAt) / 1000));
      }, 1000);
    } else {
      localStorage.removeItem('lexflow_active_timer');
      clearInterval(intervalRef.current);
      setElapsed(0);
    }
    return () => clearInterval(intervalRef.current);
  }, [activeTimer]);

  const startTimer = (practiceId, description) => {
    setActiveTimer({ practiceId, description, startedAt: Date.now() });
    toast.success('Timer avviato');
  };

  const stopTimer = useCallback(() => {
    if (!activeTimer) return;
    const minutes = Math.round((Date.now() - activeTimer.startedAt) / 60000);
    if (minutes < 1) { toast('Meno di 1 minuto \u2014 non registrato'); setActiveTimer(null); return; }
    const newLog = {
      id: genId(), practiceId: activeTimer.practiceId,
      description: activeTimer.description || '', date: toDateStr(new Date()),
      minutes, createdAt: new Date().toISOString(),
    };
    const updated = [newLog, ...logs];
    setLogs(updated);
    api.saveTimeLogs(updated).catch(() => {});
    setActiveTimer(null);
    toast.success(`Registrate ${fmtDuration(minutes)}`);
  }, [activeTimer, logs]);

  const saveLog = (log) => {
    const isNew = !logs.some(l => l.id === log.id);
    const updated = isNew ? [log, ...logs] : logs.map(l => l.id === log.id ? log : l);
    setLogs(updated);
    api.saveTimeLogs(updated).catch(() => {});
    setShowAddModal(false); setEditingLog(null);
    toast.success(isNew ? 'Registrazione aggiunta' : 'Registrazione aggiornata');
  };

  const deleteLog = (id) => {
    const updated = logs.filter(l => l.id !== id);
    setLogs(updated); api.saveTimeLogs(updated).catch(() => {});
    toast.success('Registrazione eliminata');
  };

  const confirmDeleteLog = (id) => {
    setConfirmDelete({
      message: 'Eliminare questa registrazione?',
      onConfirm: () => { deleteLog(id); setConfirmDelete(null); },
    });
  };

  const saveInvoice = (inv) => {
    const isNew = !invoices.some(i => i.id === inv.id);
    const updated = isNew ? [inv, ...invoices] : invoices.map(i => i.id === inv.id ? inv : i);
    setInvoices(updated); api.saveInvoices(updated).catch(() => {});
    setShowCreateInvoice(false); setEditingInvoice(null);
    toast.success(isNew ? 'Parcella creata' : 'Parcella aggiornata');
  };

  const deleteInvoice = (id) => {
    const updated = invoices.filter(i => i.id !== id);
    setInvoices(updated); api.saveInvoices(updated).catch(() => {});
    toast.success('Parcella eliminata');
  };

  const confirmDeleteInvoice = (id) => {
    setConfirmDelete({
      message: 'Eliminare questa parcella?',
      onConfirm: () => { deleteInvoice(id); setConfirmDelete(null); },
    });
  };

  const now = new Date();
  const sow = new Date(now);
  // getDay(): 0=Sun..6=Sat → shift to Monday-based week
  const dayOfWeek = now.getDay(); // 0=Sun
  const mondayOffset = dayOfWeek === 0 ? -6 : 1 - dayOfWeek; // if Sun, go back 6; else go to last Mon
  sow.setDate(now.getDate() + mondayOffset + weekOffset * 7);
  const weekDays = Array.from({ length: 7 }, (_, i) => { const d = new Date(sow); d.setDate(sow.getDate() + i); return d; });
  const weekStart = toDateStr(weekDays[0]);
  const weekEnd = toDateStr(weekDays[6]);
  const weekLogs = logs.filter(l => l.date >= weekStart && l.date <= weekEnd);
  const totalWeekMin = weekLogs.reduce((s, l) => s + (l.minutes || 0), 0);
  const getPracticeName = useMemo(() => {
    const map = new Map(practices.map(p => [p.id, p.client || 'Senza fascicolo']));
    return (id) => map.get(id) || 'Senza fascicolo';
  }, [practices]);

  const [confirmDelete, setConfirmDelete] = useState(null);

  const generatePDF = async (inv) => {
    const doc = new jsPDF();
    const gold = [212, 169, 64];
    doc.setFillColor(...gold);
    doc.rect(0, 0, 210, 35, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(22);
    doc.setFont('helvetica', 'bold');
    doc.text('PARCELLA', 14, 22);
    doc.setFontSize(10);
    doc.text(`N. ${inv.number || '\u2014'}`, 14, 30);
    doc.text(`Data: ${inv.date || '\u2014'}`, 196, 22, { align: 'right' });
    doc.setTextColor(60, 60, 60);
    doc.setFontSize(11);
    let y = 48;
    doc.setFont('helvetica', 'bold');
    doc.text('Cliente:', 14, y);
    doc.setFont('helvetica', 'normal');
    doc.text(inv.clientName || '\u2014', 50, y);
    y += 8;
    doc.setFont('helvetica', 'bold');
    doc.text('Fascicolo:', 14, y);
    doc.setFont('helvetica', 'normal');
    doc.text(inv.practiceName || '\u2014', 50, y);
    y += 14;
    const tableBody = (inv.items || []).map(it => [
      it.description || '',
      `${it.qty || 0} ${it.unit || 'h'}`,
      `\u20AC ${(it.unitPrice || 0).toFixed(2)}`,
      `\u20AC ${(it.total || 0).toFixed(2)}`,
    ]);
    const totals = calcTotals(inv.items || []);
    doc.autoTable({
      startY: y,
      head: [['Descrizione', 'Qt\u00E0', 'Prezzo', 'Importo']],
      body: tableBody,
      theme: 'grid',
      headStyles: { fillColor: gold, textColor: [255, 255, 255], fontStyle: 'bold' },
      styles: { fontSize: 10 },
      alternateRowStyles: { fillColor: [245, 245, 245] },
    });
    const finalY = doc.lastAutoTable.finalY + 10;
    const rx = 140;
    doc.setFontSize(10);
    doc.text(`Imponibile: \u20AC ${totals.subtotal.toFixed(2)}`, rx, finalY);
    doc.text(`CPA 4%: \u20AC ${totals.cpa.toFixed(2)}`, rx, finalY + 7);
    doc.text(`IVA 22%: \u20AC ${totals.iva.toFixed(2)}`, rx, finalY + 14);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(...gold);
    doc.text(`TOTALE: \u20AC ${totals.total.toFixed(2)}`, rx, finalY + 24);
    const pdfBuffer = doc.output('arraybuffer');
    const result = await api.exportPDF(pdfBuffer, `Parcella_${inv.number || 'draft'}.pdf`);
    if (result?.success) toast.success('PDF salvato');
  };

  if (loading) {
    return (<div className="flex items-center justify-center h-full"><Clock className="animate-spin text-primary" size={32} /></div>);
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20">
            <Clock size={24} className="text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Gestione Ore</h1>
            <p className="text-xs text-text-dim">Registra ore e gestisci parcelle</p>
          </div>
        </div>
        <div className="inline-flex bg-white/[0.04] rounded-xl p-1 border border-white/5">
          <button onClick={() => setActiveTab('ore')}
            className={`flex items-center gap-2 px-5 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer ${activeTab === 'ore' ? 'bg-primary/15 text-primary shadow-sm' : 'text-text-dim hover:text-white'}`}>
            <Clock size={14} /> Ore
          </button>
          <button onClick={() => setActiveTab('parcelle')}
            className={`flex items-center gap-2 px-5 py-2 rounded-lg text-xs font-bold transition-all cursor-pointer ${activeTab === 'parcelle' ? 'bg-primary/15 text-primary shadow-sm' : 'text-text-dim hover:text-white'}`}>
            <Receipt size={14} /> Parcelle
          </button>
        </div>
      </div>

      {/* ====== TAB: ORE ====== */}
      {activeTab === 'ore' && (
        <div className="flex-1 flex flex-col overflow-hidden">
          {activeTimer ? (
            <div className="glass-card p-5 mb-4 border border-primary/20 bg-primary/5 space-y-4">
              <div className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse" />
                <span className="text-[10px] font-black text-text-dim uppercase tracking-[2px]">Timer in corso</span>
              </div>
              <div className="flex items-center gap-3">
                <Briefcase size={14} className="text-text-dim flex-shrink-0" />
                <span className="text-sm text-white font-medium truncate">{getPracticeName(activeTimer.practiceId)}</span>
              </div>
              {activeTimer.description && (
                <div className="flex items-center gap-3">
                  <FileText size={14} className="text-text-dim flex-shrink-0" />
                  <span className="text-sm text-text-muted truncate">{activeTimer.description}</span>
                </div>
              )}
              <div className="flex items-center justify-between pt-2">
                <span className="font-mono text-3xl text-primary font-bold tabular-nums">
                  {String(Math.floor(elapsed / 3600)).padStart(2, '0')}:{String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0')}:{String(elapsed % 60).padStart(2, '0')}
                </span>
                <button onClick={stopTimer} className="flex items-center gap-2 px-4 py-2.5 bg-red-500/15 hover:bg-red-500/25 text-red-400 rounded-xl transition-colors text-xs font-bold">
                  <Square size={14} fill="currentColor" /> Ferma
                </button>
              </div>
            </div>
          ) : (
            <div className="glass-card p-5 mb-4 space-y-4">
              <div className="flex items-center gap-3">
                <Play size={18} className="text-primary flex-shrink-0" />
                <span className="text-[10px] font-black text-text-dim uppercase tracking-[2px]">Avvia Timer</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <PracticeCombobox
                  value={timerPracticeId}
                  onChange={setTimerPracticeId}
                  practices={practices}
                  label="Fascicolo"
                  id="timer-practice"
                />
                <div>
                  <label htmlFor="timer-desc" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] block mb-2">Attività</label>
                  <input
                    id="timer-desc"
                    type="text"
                    value={timerDescription}
                    onChange={e => setTimerDescription(e.target.value)}
                    placeholder="Descrizione attività..."
                    className="input-field w-full py-2.5"
                  />
                </div>
              </div>
              <div className="flex justify-end">
                <button
                  onClick={() => { startTimer(timerPracticeId, timerDescription); setTimerPracticeId(''); setTimerDescription(''); }}
                  disabled={!timerPracticeId}
                  className="btn-primary text-xs px-5 py-2.5 disabled:opacity-30 disabled:cursor-not-allowed disabled:shadow-none"
                >
                  <Play size={14} /> Avvia
                </button>
              </div>
            </div>
          )}

          <div className="flex items-center justify-between mb-4">
            <div className="inline-flex items-center bg-white/[0.04] rounded-xl p-1 border border-white/5 gap-1">
              <button onClick={() => setWeekOffset(w => w - 1)} className="btn-ghost w-7 h-7 p-0 rounded-lg"><ChevronLeft size={14} /></button>
              <span className="text-xs font-bold w-48 text-center text-white">
                {weekDays[0].getDate()} {MONTHS_IT[weekDays[0].getMonth()]} – {weekDays[6].getDate()} {MONTHS_IT[weekDays[6].getMonth()]}
              </span>
              <button onClick={() => setWeekOffset(w => w + 1)} className="btn-ghost w-7 h-7 p-0 rounded-lg"><ChevronRight size={14} /></button>
            </div>
            <div className="flex items-center gap-3">
              <div className="glass-card px-4 py-2 text-center min-w-[90px]">
                <span className="text-lg font-bold text-primary tabular-nums">{fmtDuration(totalWeekMin)}</span>
                <span className="text-[10px] text-text-dim block">Totale Settimana</span>
              </div>
              <button onClick={() => setShowAddModal(true)} className="btn-primary text-xs px-4 py-2">
                <Plus size={14} /> Manuale
              </button>
            </div>
          </div>

          <div className="grid grid-cols-7 gap-2 mb-4">
            {weekDays.map(d => {
              const ds = toDateStr(d);
              const dayLogs = weekLogs.filter(l => l.date === ds);
              const dayMin = dayLogs.reduce((s, l) => s + (l.minutes || 0), 0);
              const isToday = ds === toDateStr(now);
              return (
                <div key={ds} className={`glass-card p-3 text-center transition-all ${isToday ? 'border-primary/30 bg-primary/5' : ''}`}>
                  <div className="text-[10px] text-text-dim font-bold">{DAYS_IT[d.getDay()]}</div>
                  <div className={`text-sm font-bold ${isToday ? 'text-primary' : 'text-white'}`}>{d.getDate()}</div>
                  <div className="text-[10px] text-text-dim mt-1">{fmtDuration(dayMin)}</div>
                  <div className="w-full bg-white/5 rounded-full h-1 mt-1.5">
                    <div className="bg-primary h-1 rounded-full transition-all" style={{ width: `${Math.min((dayMin / 480) * 100, 100)}%` }} />
                  </div>
                </div>
              );
            })}
          </div>

          <div className="flex-1 overflow-y-auto custom-scrollbar space-y-2">
            {weekLogs.length === 0 ? (
              <div className="text-center py-10 text-text-dim">
                <Clock size={32} className="mx-auto mb-2 opacity-50" />
                <p className="text-sm">Nessuna registrazione questa settimana</p>
              </div>
            ) : (
              weekLogs.sort((a, b) => b.date.localeCompare(a.date) || (b.createdAt || '').localeCompare(a.createdAt || '')).map(log => (
                <div key={log.id} className="glass-card p-3 flex items-center gap-4 group hover:border-primary/20 transition-all">
                  <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center flex-shrink-0">
                    <Clock size={18} className="text-primary" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-bold text-white truncate">{log.description || 'Senza descrizione'}</p>
                    <p className="text-[10px] text-text-dim">{getPracticeName(log.practiceId)} \u00B7 {new Date(log.date).toLocaleDateString('it-IT')}</p>
                  </div>
                  <span className="text-sm font-mono font-bold text-primary tabular-nums">{fmtDuration(log.minutes)}</span>
                  <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button onClick={() => setEditingLog(log)} className="p-1.5 hover:bg-white/10 rounded-lg text-text-dim"><Edit3 size={14} /></button>
                    <button onClick={() => confirmDeleteLog(log.id)} className="p-1.5 hover:bg-red-500/10 rounded-lg text-text-dim hover:text-red-400"><Trash2 size={14} /></button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* ====== TAB: PARCELLE ====== */}
      {activeTab === 'parcelle' && (
        <div className="flex-1 flex flex-col overflow-hidden">
          <div className="grid grid-cols-3 gap-4 mb-6">
            <div className="glass-card p-4 text-center">
              <span className="text-2xl font-bold text-white">{invoices.length}</span>
              <span className="text-[10px] text-text-dim block mt-1">Parcelle</span>
            </div>
            <div className="glass-card p-4 text-center">
              <span className="text-2xl font-bold text-white/70">{invoices.filter(i => i.status === 'sent').length}</span>
              <span className="text-[10px] text-text-dim block mt-1">Inviate</span>
            </div>
            <div className="glass-card p-4 text-center">
              <span className="text-2xl font-bold text-primary">
                {'\u20AC'} {invoices.filter(i => i.status === 'paid').reduce((s, i) => s + (calcTotals(i.items || []).total), 0).toFixed(0)}
              </span>
              <span className="text-[10px] text-text-dim block mt-1">Incassato</span>
            </div>
          </div>

          <div className="flex justify-end mb-4">
            <button onClick={() => setShowCreateInvoice(true)} className="btn-primary text-xs px-4 py-2">
              <Plus size={14} /> Nuova Parcella
            </button>
          </div>

          <div className="flex-1 overflow-y-auto custom-scrollbar space-y-2">
            {invoices.length === 0 ? (
              <div className="text-center py-10 text-text-dim">
                <Receipt size={32} className="mx-auto mb-2 opacity-50" />
                <p className="text-sm">Nessuna parcella creata</p>
              </div>
            ) : (
              invoices.map(inv => {
                const totals = calcTotals(inv.items || []);
                return (
                  <div key={inv.id} className="glass-card p-4 flex items-center gap-4 group hover:border-primary/20 transition-all">
                    <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center flex-shrink-0">
                      <Receipt size={18} className="text-primary" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-bold text-white truncate">{inv.clientName || 'Cliente'}</p>
                        <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full border ${STATUS_COLORS[inv.status] || STATUS_COLORS.draft}`}>
                          {STATUS_LABELS[inv.status] || 'Bozza'}
                        </span>
                      </div>
                      <p className="text-[10px] text-text-dim">{inv.practiceName || 'Fascicolo'} \u00B7 N.{inv.number || '\u2014'} \u00B7 {inv.date || ''}</p>
                    </div>
                    <span className="text-sm font-bold text-primary tabular-nums">{'\u20AC'} {totals.total.toFixed(2)}</span>
                    <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button onClick={() => generatePDF(inv)} className="p-1.5 hover:bg-white/10 rounded-lg text-text-dim" title="Scarica PDF"><Download size={14} /></button>
                      <button onClick={() => setEditingInvoice(inv)} className="p-1.5 hover:bg-white/10 rounded-lg text-text-dim"><Edit3 size={14} /></button>
                      <button onClick={() => confirmDeleteInvoice(inv.id)} className="p-1.5 hover:bg-red-500/10 rounded-lg text-text-dim hover:text-red-400"><Trash2 size={14} /></button>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* ====== MODALS ====== */}
      {(showAddModal || editingLog) && (
        <ManualLogModal practices={practices} initial={editingLog}
          onSave={saveLog} onClose={() => { setShowAddModal(false); setEditingLog(null); }} />
      )}
      {(showCreateInvoice || editingInvoice) && (
        <InvoiceModal practices={practices} timeLogs={logs} invoiceCount={invoices.length}
          editMode={!!editingInvoice} initial={editingInvoice}
          onSave={saveInvoice} onClose={() => { setShowCreateInvoice(false); setEditingInvoice(null); }} />
      )}

      <ConfirmDialog
        open={!!confirmDelete}
        title="Conferma"
        message={confirmDelete?.message}
        confirmLabel="Elimina"
        onConfirm={confirmDelete?.onConfirm}
        onCancel={() => setConfirmDelete(null)}
      />
    </div>
  );
}

TimeTrackingPage.propTypes = { practices: PropTypes.array.isRequired };

/* ======== ManualLogModal ======== */
function ManualLogModal({ practices, initial, onSave, onClose }) {
  const isEdit = !!initial?.id;
  const [practiceId, setPracticeId] = useState(initial?.practiceId || practices[0]?.id || '');
  const [description, setDescription] = useState(initial?.description || '');
  const [date, setDate] = useState(initial?.date || toDateStr(new Date()));
  const [hours, setHours] = useState(initial ? String(Math.floor((initial.minutes || 0) / 60)) : '');
  const [mins, setMins] = useState(initial ? String((initial.minutes || 0) % 60) : '');

  const handleSave = (e) => {
    e.preventDefault();
    const totalMin = (Number.parseInt(hours, 10) || 0) * 60 + (Number.parseInt(mins, 10) || 0);
    if (totalMin < 1) { toast.error('Inserisci almeno 1 minuto'); return; }
    onSave({
      id: initial?.id || genId(), practiceId, description, date, minutes: totalMin,
      createdAt: initial?.createdAt || new Date().toISOString(),
    });
  };

  return (
    <ModalOverlay onClose={onClose} labelledBy="manual-log-title">
      <div className="w-full max-w-2xl bg-[#0f1016] border border-white/10 rounded-[32px] shadow-2xl overflow-hidden">
        <div className="relative px-8 pt-8 pb-6" style={{ background: 'linear-gradient(135deg, rgba(212,169,64,0.08) 0%, rgba(212,169,64,0.02) 100%)' }}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20">
                <Clock size={22} className="text-primary" />
              </div>
              <div>
                <h2 id="manual-log-title" className="text-xl font-bold text-white">{isEdit ? 'Modifica Registrazione' : 'Registrazione Manuale'}</h2>
                <p className="text-xs text-text-dim mt-0.5">Inserisci i dettagli dell&apos;attivit&agrave;</p>
              </div>
            </div>
            <button onClick={onClose} className="p-2 hover:bg-white/10 rounded-xl text-text-dim transition-all group">
              <X size={20} className="group-hover:rotate-90 transition-transform" />
            </button>
          </div>
        </div>
        <form onSubmit={handleSave} className="px-8 py-6 space-y-5">
          <div className="grid grid-cols-2 gap-4">
            <PracticeCombobox id="manual-log-practice" label="Fascicolo" value={practiceId} onChange={setPracticeId} practices={practices} />
            <div>
              <label htmlFor="manual-log-date" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] block mb-2">Data</label>
              <input id="manual-log-date" type="date" value={date} onChange={e => setDate(e.target.value)} className="input-field w-full py-3" />
            </div>
          </div>
          <div>
            <label htmlFor="manual-log-description" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] block mb-2">Descrizione</label>
            <input id="manual-log-description" value={description} onChange={e => setDescription(e.target.value)} className="input-field w-full py-3" placeholder="Attività svolta..." />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label htmlFor="manual-log-hours" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] block mb-2">Ore</label>
              <input id="manual-log-hours" type="number" min="0" value={hours} onChange={e => setHours(e.target.value)} className="input-field w-full py-3" placeholder="0" />
            </div>
            <div>
              <label htmlFor="manual-log-mins" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] block mb-2">Minuti</label>
              <input id="manual-log-mins" type="number" min="0" max="59" value={mins} onChange={e => setMins(e.target.value)} className="input-field w-full py-3" placeholder="0" />
            </div>
          </div>
        </form>
        <div className="flex justify-end gap-3 px-8 py-5 bg-[#14151d] border-t border-white/5">
          <button onClick={onClose} className="px-6 py-3 rounded-2xl text-text-dim hover:text-white hover:bg-white/5 transition-all text-xs font-bold uppercase tracking-widest">Annulla</button>
          <button onClick={handleSave} className="btn-primary px-8 py-3 text-xs font-bold uppercase tracking-widest">
            <Check size={16} /> {isEdit ? 'Salva' : 'Registra'}
          </button>
        </div>
      </div>
    </ModalOverlay>
  );
}

ManualLogModal.propTypes = {
  practices: PropTypes.array.isRequired, initial: PropTypes.object,
  onSave: PropTypes.func.isRequired, onClose: PropTypes.func.isRequired,
};

/* ======== InvoiceModal ======== */
function InvoiceModal({ practices, timeLogs, invoiceCount, editMode, initial, onSave, onClose }) {
  const [number, setNumber] = useState(initial?.number || String(invoiceCount + 1).padStart(3, '0'));
  const [invDate, setInvDate] = useState(initial?.date || toDateStr(new Date()));
  const [practiceId, setPracticeId] = useState(initial?.practiceId || '');
  const [clientName, setClientName] = useState(initial?.clientName || '');
  const [practiceName, setPracticeName] = useState(initial?.practiceName || '');
  const [status, setStatus] = useState(initial?.status || 'draft');
  const [items, setItems] = useState(() => (initial?.items || [{ description: '', qty: 1, unit: 'h', unitPrice: 0, total: 0 }]).map((it, i) => ({ ...it, _key: it._key || `inv-${Date.now()}-${i}` })));

  useEffect(() => {
    if (practiceId) {
      const p = practices.find(pr => pr.id === practiceId);
      if (p) { setClientName(p.client || ''); setPracticeName(`${p.client} \u2014 ${p.object}`); }
    }
  }, [practiceId, practices]);

  const addItem = () => setItems([...items, { _key: `inv-${Date.now()}`, description: '', qty: 1, unit: 'h', unitPrice: 0, total: 0 }]);
  const removeItem = (idx) => setItems(items.filter((_, i) => i !== idx));
  const updateItem = (idx, field, value) => {
    const updated = items.map((it, i) => {
      if (i !== idx) return it;
      const next = { ...it, [field]: value };
      next.total = (next.qty || 0) * (next.unitPrice || 0);
      return next;
    });
    setItems(updated);
  };

  const totals = calcTotals(items);

  const handleSave = (e) => {
    e.preventDefault();
    onSave({
      id: initial?.id || genId('inv_'), number, date: invDate, practiceId,
      clientName, practiceName, status, items,
      createdAt: initial?.createdAt || new Date().toISOString(),
    });
  };

  const autoFillFromLogs = () => {
    if (!practiceId) { toast.error('Seleziona prima un fascicolo'); return; }
    const pLogs = timeLogs.filter(l => l.practiceId === practiceId);
    if (pLogs.length === 0) { toast.error('Nessuna registrazione trovata'); return; }
    const totalMin = pLogs.reduce((s, l) => s + (l.minutes || 0), 0);
    const descriptions = [...new Set(pLogs.map(l => l.description).filter(Boolean))].join(', ');
    setItems([{
      _key: `inv-${Date.now()}`,
      description: descriptions || 'Attivit\u00E0 professionale',
      qty: Number.parseFloat((totalMin / 60).toFixed(1)), unit: 'h', unitPrice: 150,
      total: Number.parseFloat((totalMin / 60).toFixed(1)) * 150,
    }]);
    toast.success('Voci compilate dalle registrazioni');
  };

  return (
    <ModalOverlay onClose={onClose} labelledBy="invoice-modal-title">
      <div className="w-full max-w-2xl bg-[#0f1016] border border-white/10 rounded-[32px] shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
        <div className="relative px-8 pt-8 pb-6 flex-shrink-0" style={{ background: 'linear-gradient(135deg, rgba(212,169,64,0.08) 0%, rgba(212,169,64,0.02) 100%)' }}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20">
                <DollarSign size={22} className="text-primary" />
              </div>
              <div>
                <h2 id="invoice-modal-title" className="text-xl font-bold text-white">{editMode ? 'Modifica Parcella' : 'Nuova Parcella'}</h2>
                <p className="text-xs text-text-dim mt-0.5">Compila i dettagli della parcella</p>
              </div>
            </div>
            <button onClick={onClose} className="p-2 hover:bg-white/10 rounded-xl text-text-dim transition-all group">
              <X size={20} className="group-hover:rotate-90 transition-transform" />
            </button>
          </div>
        </div>
        <form onSubmit={handleSave} className="px-8 py-6 space-y-5 overflow-y-auto flex-1 custom-scrollbar">
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label htmlFor="inv-number" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] block mb-2">Numero</label>
              <input id="inv-number" value={number} onChange={e => setNumber(e.target.value)} className="input-field w-full py-3" />
            </div>
            <div>
              <label htmlFor="inv-date" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] block mb-2">Data</label>
              <input id="inv-date" type="date" value={invDate} onChange={e => setInvDate(e.target.value)} className="input-field w-full py-3" />
            </div>
            <div>
              <label htmlFor="inv-status" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] block mb-2">Stato</label>
              <select id="inv-status" value={status} onChange={e => setStatus(e.target.value)} className="input-field w-full py-3">
                {Object.entries(STATUS_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <PracticeCombobox id="inv-practice" label="Fascicolo" value={practiceId} onChange={setPracticeId} practices={practices} placeholder="Cerca fascicolo..." />
            <div>
              <label htmlFor="inv-client" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] block mb-2">Cliente</label>
              <input id="inv-client" value={clientName} onChange={e => setClientName(e.target.value)} className="input-field w-full py-3" placeholder="Nome cliente..." />
            </div>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-black text-text-dim uppercase tracking-[2px]">Voci</span>
            <div className="flex gap-2">
              <button type="button" onClick={autoFillFromLogs} className="text-[10px] text-primary hover:underline font-bold">Auto-compila da ore</button>
              <button type="button" onClick={addItem} className="text-[10px] text-text-muted hover:text-white font-bold flex items-center gap-1"><Plus size={12} /> Aggiungi</button>
            </div>
          </div>
          {items.map((it, idx) => (
            <div key={it._key} className="glass-card p-3 space-y-3">
              <div className="flex items-center gap-2">
                <input value={it.description} onChange={e => updateItem(idx, 'description', e.target.value)} className="input-field flex-1 py-2 text-sm" placeholder="Descrizione voce..." />
                {items.length > 1 && (
                  <button type="button" onClick={() => removeItem(idx)} className="p-1.5 hover:bg-red-500/10 text-text-dim hover:text-red-400 rounded-lg"><Trash2 size={14} /></button>
                )}
              </div>
              <div className="grid grid-cols-4 gap-3">
                <div>
                  <label htmlFor={`inv-item-qty-${idx}`} className="text-[9px] text-text-dim block mb-1">Qt&agrave;</label>
                  <input id={`inv-item-qty-${idx}`} type="number" step="0.1" min="0" value={it.qty} onChange={e => updateItem(idx, 'qty', Number.parseFloat(e.target.value) || 0)} className="input-field w-full py-2 text-sm" />
                </div>
                <div>
                  <label htmlFor={`inv-item-unit-${idx}`} className="text-[9px] text-text-dim block mb-1">Unit&agrave;</label>
                  <select id={`inv-item-unit-${idx}`} value={it.unit} onChange={e => updateItem(idx, 'unit', e.target.value)} className="input-field w-full py-2 text-sm">
                    <option value="h">Ore</option>
                    <option value="u">Unit&agrave;</option>
                    <option value="f">Forfait</option>
                  </select>
                </div>
                <div>
                  <label htmlFor={`inv-item-price-${idx}`} className="text-[9px] text-text-dim block mb-1">Prezzo &euro;</label>
                  <input id={`inv-item-price-${idx}`} type="number" step="0.01" min="0" value={it.unitPrice} onChange={e => updateItem(idx, 'unitPrice', Number.parseFloat(e.target.value) || 0)} className="input-field w-full py-2 text-sm" />
                </div>
                <div>
                  <span className="text-[9px] text-text-dim block mb-1">Totale</span>
                  <div className="input-field w-full py-2 text-sm text-primary font-bold bg-white/[0.02]">&euro; {(it.total || 0).toFixed(2)}</div>
                </div>
              </div>
            </div>
          ))}
          <div className="glass-card p-4 space-y-2 text-sm">
            <div className="flex justify-between text-text-muted"><span>Imponibile</span><span>\u20AC {totals.subtotal.toFixed(2)}</span></div>
            <div className="flex justify-between text-text-dim"><span>CPA 4%</span><span>\u20AC {totals.cpa.toFixed(2)}</span></div>
            <div className="flex justify-between text-text-dim"><span>IVA 22%</span><span>\u20AC {totals.iva.toFixed(2)}</span></div>
            <div className="flex justify-between text-white font-bold text-base pt-2 border-t border-white/10">
              <span>Totale</span><span className="text-primary">\u20AC {totals.total.toFixed(2)}</span>
            </div>
          </div>
        </form>
        <div className="flex justify-end gap-3 px-8 py-5 bg-[#14151d] border-t border-white/5 flex-shrink-0">
          <button type="button" onClick={onClose} className="px-6 py-3 rounded-2xl text-text-dim hover:text-white hover:bg-white/5 transition-all text-xs font-bold uppercase tracking-widest">Annulla</button>
          <button onClick={handleSave} className="btn-primary px-8 py-3 text-xs font-bold uppercase tracking-widest">
            <Check size={16} /> {editMode ? 'Salva' : 'Crea Parcella'}
          </button>
        </div>
      </div>
    </ModalOverlay>
  );
}

InvoiceModal.propTypes = {
  practices: PropTypes.array.isRequired, timeLogs: PropTypes.array.isRequired,
  invoiceCount: PropTypes.number.isRequired, editMode: PropTypes.bool,
  initial: PropTypes.object, onSave: PropTypes.func.isRequired,
  onClose: PropTypes.func.isRequired,
};
