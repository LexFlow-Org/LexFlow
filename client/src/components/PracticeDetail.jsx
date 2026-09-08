import { useState, useEffect, useCallback, useRef, useMemo, useId } from 'react';
import PropTypes from 'prop-types';
import {
  ArrowLeft, Calendar, FileText,
  Clock, Plus, Trash2, Send, FolderOpen,
  FolderPlus, Lock, ChevronDown, Check,
  FilePlus, Info, ShieldCheck, Download, X, Users, BellRing, Shield
} from 'lucide-react';
import { exportPracticeTypstPDF } from '../utils/typstPdfGenerator';
import ExportWarningModal from './ExportWarningModal';
import ConfirmDialog from './ConfirmDialog';
import ModalOverlay from './ModalOverlay';
import BiometricLockScreen from './BiometricLockScreen';
import toast from 'react-hot-toast';
import * as api from '../tauri-api';
import { formatDateIT } from '../utils/helpers';

/* ---------- Helpers ---------- */
// Pallino scadenza: usa bg-cat-scadenza per coerenza con DeadlinesPage e AgendaPage.
// Urgenza espressa solo tramite ring/pulse, NON cambiando il colore base.
function getDeadlineDotColor(diff) {
  if (diff < 0) return 'bg-cat-scadenza ring-2 ring-cat-scadenza/40 animate-pulse';  // scaduta
  if (diff === 0) return 'bg-cat-scadenza ring-2 ring-cat-scadenza/30';               // oggi
  if (diff <= 3) return 'bg-cat-scadenza ring-1 ring-cat-scadenza/20';                // urgente
  return 'bg-cat-scadenza';                                                            // normale
}

function getDeadlineLabel(diff) {
  if (diff < 0) return `Scaduta da ${Math.abs(diff)}gg`;
  if (diff === 0) return 'OGGI';
  if (diff === 1) return 'Domani';
  return `tra ${diff}gg`;
}

/**
 * Combina data + orario (HH:mm) in millisecondi epoch per ordinamento stabile.
 * Se manca l'orario, usa 00:00.
 */
function deadlineSortKey(d) {
  const [hh = '00', mm = '00'] = (d.time || '00:00').split(':');
  const dt = new Date(d.date);
  dt.setHours(Number(hh) || 0, Number(mm) || 0, 0, 0);
  return dt.getTime();
}

/* ---------- Status Dropdown ---------- */
function StatusDropdown({ status, onChangeStatus }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    const handleClick = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [open]);

  const doSet = (val) => { onChangeStatus(val); setOpen(false); };

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(!open)}
        aria-haspopup="listbox"
        aria-expanded={open}
        className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold border transition-colors ${
          status === 'active'
            ? 'bg-surface text-text border-border hover:bg-card'
            : 'bg-surface text-text-muted border-border hover:bg-card'
        }`}
      >
        <span className={`text-xs font-bold ${status === 'active' ? 'text-success' : 'text-text-dim'}`}>
          {status === 'active' ? '● Attivo' : '● Archiviato'}
        </span>
        <ChevronDown size={14} className="text-text-dim" />
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-2 bg-card border border-border rounded-xl shadow-2xl z-50 py-1 min-w-[200px] animate-fade-in" role="listbox">
          <button onClick={() => doSet('active')}
            className={`w-full flex items-center gap-3 px-5 py-3.5 text-xs hover:bg-surface transition-colors text-left ${status === 'active' ? 'bg-surface' : ''}`}>
            <span className="text-success font-bold">● Attivo</span>
          </button>
          <button onClick={() => doSet('closed')}
            className={`w-full flex items-center gap-3 px-5 py-3.5 text-xs hover:bg-surface transition-colors text-left ${status === 'closed' ? 'bg-surface' : ''}`}>
            <span className="text-text-dim font-bold">● Archiviato</span>
          </button>
        </div>
      )}
    </div>
  );
}

StatusDropdown.propTypes = {
  status: PropTypes.string.isRequired,
  onChangeStatus: PropTypes.func.isRequired,
};

/* ---------- Diary Note (memo per-note: evita re-format toLocaleString su ogni render) ---------- */
function DiaryNoteRow({ note, idx, onDelete }) {
  // FIX-25: precomputa il label una volta sola per nota
  const dateLabel = useMemo(() => {
    const d = new Date(note.date);
    return `${d.toLocaleDateString('it-IT', { day: '2-digit', month: 'short', year: 'numeric' })} • ${d.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' })}`;
  }, [note.date]);

  return (
    <div className="flex gap-4 group animate-fade-in">
      <div className="flex flex-col items-center pt-1">
        <div className="w-2.5 h-2.5 rounded-full bg-primary ring-2 ring-primary/20" />
        <div className="w-px h-full bg-border my-1" />
      </div>
      <div className="flex-1 rounded-2xl bg-surface border border-border p-4 hover:bg-card hover:border-border transition-colors">
        <div className="flex justify-between items-start mb-2.5">
          <span className="text-xs-p font-semibold text-primary/90 bg-primary/10 px-2.5 py-1 rounded-lg border border-primary/15">
            {dateLabel}
          </span>
          <button onClick={() => onDelete(idx)} className="opacity-0 group-hover:opacity-100 p-1.5 rounded-lg hover:bg-danger-soft text-text-dim hover:text-danger transition-colors" aria-label="Elimina nota">
            <Trash2 size={14} />
          </button>
        </div>
        <p className="text-sm text-text leading-relaxed whitespace-pre-wrap">{note.text}</p>
      </div>
    </div>
  );
}

DiaryNoteRow.propTypes = {
  note: PropTypes.shape({ text: PropTypes.string, date: PropTypes.string }).isRequired,
  idx: PropTypes.number.isRequired,
  onDelete: PropTypes.func.isRequired,
};

/* ---------- Main Component ---------- */
export default function PracticeDetail({ practice, onBack, onUpdate, agendaEvents, onNavigate }) {
  const [activeTab, setActiveTab] = useState('diary'); // diary, docs, deadlines, info
  const [biometricVerified, setBiometricVerified] = useState(false);
  const [showExportWarning, setShowExportWarning] = useState(false);
  const [showExportPwdModal, setShowExportPwdModal] = useState(false);
  const [exportPwd, setExportPwd] = useState('');
  const [exportMode, setExportMode] = useState('standard'); // standard | compressed | secured
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [showSecureConfirm, setShowSecureConfirm] = useState(false);
  const exportMenuRef = useRef(null); // FIX-14: outside-click su menu export

  // Stati per i form
  const [newNote, setNewNote] = useState('');
  const [submittingNote, setSubmittingNote] = useState(false); // FIX-18
  const [newDeadlineLabel, setNewDeadlineLabel] = useState('');
  const [newDeadlineDate, setNewDeadlineDate] = useState('');
  const [newDeadlineTime, setNewDeadlineTime] = useState('09:00');
  const [newDeadlineRemind, setNewDeadlineRemind] = useState(null); // null = usa preavviso globale
  const [newDeadlineCustomTime, setNewDeadlineCustomTime] = useState('08:00'); // per preavviso "Alle"
  const [submittingDeadline, setSubmittingDeadline] = useState(false); // FIX-19
  const [confirmDelete, setConfirmDelete] = useState(null);

  // ARIA tabs ids (FIX-17) — un namespace stabile
  const tabsBaseId = useId();

  // --- Helpers ---
  // FIX-1 + FIX-2: nessun debouncing per CRUD (delete/insert su folders/attachments/
  // diary/deadlines/status). Il fascicolo non ha campi di testo a editing inline,
  // quindi la versione debounced era una sorgente di bug (collasso di edit rapidi)
  // più che una vera ottimizzazione. saveNow ritorna una Promise reale e non
  // catturare uno stato stale, perché parte sempre dall'oggetto `practice` corrente.
  const saveNow = useCallback(async (changes) => {
    return Promise.resolve(onUpdate(changes));
  }, [onUpdate]);

  const handleBioUnlock = useCallback(() => setBiometricVerified(true), []);

  // FIX-13: Backwards-compatible folders array memoizzato per dipendenze stabili
  const folders = useMemo(() => {
    if (Array.isArray(practice.folders) && practice.folders.length > 0) return practice.folders;
    if (practice.folderPath) return [{ path: practice.folderPath, name: practice.folderPath.split('/').pop(), addedAt: practice.createdAt || new Date().toISOString() }];
    return [];
  }, [practice.folders, practice.folderPath, practice.createdAt]);

  // FIX-12: scadenze unificate + ordinate per data+orario, memoizzate
  const allDeadlines = useMemo(() => {
    const practiceDeadlines = (practice.deadlines || []).map((d, idx) => ({
      ...d, source: 'practice', idx,
    }));
    const agendaDeadlines = (agendaEvents || [])
      .filter(e => e.category === 'scadenza' && e.practiceId === practice.id && !e.autoSync && !e.completed)
      .map(e => ({
        label: e.title, date: e.date, time: e.timeStart, source: 'agenda', id: e.id,
      }));
    // FIX-10: ordina per data + orario (epoch ms), non solo data
    return [...practiceDeadlines, ...agendaDeadlines].sort((a, b) => deadlineSortKey(a) - deadlineSortKey(b));
  }, [practice.deadlines, agendaEvents, practice.id]);

  // FIX-14: chiudi menu export al click fuori (mirror StatusDropdown)
  useEffect(() => {
    if (!showExportMenu) return;
    const onMouseDown = (e) => {
      if (exportMenuRef.current && !exportMenuRef.current.contains(e.target)) setShowExportMenu(false);
    };
    document.addEventListener('mousedown', onMouseDown);
    return () => document.removeEventListener('mousedown', onMouseDown);
  }, [showExportMenu]);

  // Se il fascicolo è protetto e non verificato, mostra schermata di blocco
  if (practice.biometricProtected && !biometricVerified) {
    return (
      <BiometricLockScreen
        practice={practice}
        onBack={onBack}
        onUnlock={handleBioUnlock}
      />
    );
  }

  // --- Handlers: Folder ---
  const linkFolder = async () => {
    const folder = await api.selectFolder();
    if (!folder) return;
    // FIX-24: dedupe folders by path
    if (folders.some(f => f.path === folder)) {
      toast('Cartella già collegata', { icon: 'ℹ️' });
      return;
    }
    const newFolder = { path: folder, name: folder.split('/').pop(), addedAt: new Date().toISOString() };
    const updatedFolders = [...folders, newFolder];
    try {
      await saveNow({ folders: updatedFolders, folderPath: updatedFolders[0]?.path || null });
      toast.success('Cartella collegata');
    } catch (err) {
      // FIX-22
      console.error('[PracticeDetail] linkFolder failed', err);
      toast.error('Impossibile collegare la cartella. Verifica i permessi.');
    }
  };

  const removeFolder = async (idx) => {
    const updatedFolders = folders.filter((_, i) => i !== idx);
    try {
      await saveNow({ folders: updatedFolders, folderPath: updatedFolders[0]?.path || null });
      toast.success('Cartella scollegata');
    } catch (err) {
      console.error('[PracticeDetail] removeFolder failed', err);
      toast.error('Impossibile rimuovere il collegamento alla cartella.');
    }
  };

  const confirmRemoveFolder = (idx) => {
    setConfirmDelete({
      message: 'Scollegare questa cartella dal fascicolo?',
      onConfirm: () => { removeFolder(idx); setConfirmDelete(null); },
    });
  };

  const openFolderAtPath = async (path) => {
    if (!path) return;
    try {
      await api.openPath(path);
    } catch {
      toast.error('Impossibile aprire la cartella. Verifica che esista ancora.');
    }
  };

  const handleExport = () => {
    if (exportMode === 'secured') {
      // Show protection confirmation card before proceeding
      setShowSecureConfirm(true);
      return;
    }
    // Open the security warning modal first — actual export runs only on confirm.
    setShowExportWarning(true);
  };

  /** Shared helper: show loading toast → run PDF export → post-process → resolve toast */
  const runPdfExport = async () => {
    // FIX-3: corretto modeLabel per usare 'secured' (non 'protected')
    const modeLabel = exportMode === 'compressed'
      ? 'Compressione'
      : exportMode === 'secured'
        ? 'Protezione'
        : 'Generazione';
    const toastId = toast.loading(`${modeLabel} PDF in corso…`, { duration: 30000 });
    try {
      const result = await exportPracticeTypstPDF(practice);
      if (!result?.success) {
        toast.dismiss(toastId);
        if (result?.cancelled) return;
        toast.error(result?.error ? 'Errore durante l\'esportazione. Riprova.' : 'Impossibile generare il PDF. Riprova.');
        return;
      }

      const savedPath = result.path || '';
      const fileName = savedPath.split(/[/\\]/).pop() || 'PDF';

      // Post-processing based on export mode
      if (exportMode === 'compressed' && savedPath) {
        try {
          const compResult = await api.compressPdf(savedPath, savedPath);
          toast.dismiss(toastId);
          // FIX-8: emetti SEMPRE un toast risultato — distingui caso "no savings"
          const saved = compResult?.details?.saved_percent ?? 0;
          if (saved > 0) {
            toast.success(`PDF compresso e salvato! (-${saved}%)`, { duration: 6000 });
          } else {
            toast.success(`PDF salvato (compressione: nessun risparmio).\n${fileName}`, { duration: 6000 });
          }
          return;
        } catch (e) {
          // FIX-4: errore esplicito invece di fall-through con success
          console.error('[Export] Compression failed:', e);
          toast.dismiss(toastId);
          toast.error('Compressione fallita — il PDF è stato salvato senza compressione.');
          return;
        }
      }

      if (exportMode === 'secured' && savedPath) {
        try {
          const secResult = await api.securePdf(savedPath, savedPath, {
            noCopy: true, noPrint: true, noModify: true, watermark: 'RISERVATO',
          });
          toast.dismiss(toastId);
          // FIX-5: copy onesta sui limiti reali della protezione qpdf
          toast.success(
            `PDF blindato e salvato!\n${secResult?.message || 'Protezione applicata (qpdf owner restrictions; rimovibili da qualunque tool che ignori il flag --extract). NON usare per documenti riservati a controparti.'}`,
            { duration: 8000 }
          );
          return;
        } catch (e) {
          // FIX-4: errore esplicito invece di fall-through con success
          console.error('[Export] Secure failed:', e);
          toast.dismiss(toastId);
          toast.error('Protezione fallita — il PDF è stato salvato senza sicurezza completa.');
          return;
        }
      }

      toast.dismiss(toastId);
      toast.success(`PDF salvato con successo!\n${fileName}`, { duration: 6000 });
    } catch (err) {
      console.error('[PracticeDetail] PDF export failed:', err);
      toast.dismiss(toastId);
      toast.error('Impossibile esportare il fascicolo. Riprova.');
    }
  };

  const handleExportConfirmed = async () => {
    setShowExportWarning(false);
    // Check if biometrics are configured — if yes, try biometric first
    try {
      const bioAvail = await api.checkBio();
      const bioSaved = bioAvail ? await api.hasBioSaved() : false;
      if (bioSaved) {
        try {
          const bioResult = await api.bioLogin();
          if (bioResult) {
            await runPdfExport();
            return;
          }
        } catch { /* bio failed/dismissed — fall through to password */ }
      }
    } catch { /* ignore bio check errors */ }
    // Fallback: open password verification modal
    setExportPwd('');
    setShowExportPwdModal(true);
  };

  const handleExportWithPassword = async (e) => {
    if (e) e.preventDefault();
    if (!exportPwd) return;
    setShowExportPwdModal(false);
    // FIX-26: copia la password in ref transitorio e zerizza subito dopo
    const pwd = exportPwd;
    setExportPwd('');
    try {
      const result = await api.verifyVaultPassword(pwd);
      if (!result?.valid) {
        toast.error('Password non corretta. Esportazione non autorizzata.');
        return;
      }
    } catch (err) {
      console.error('[PracticeDetail] Export password verification failed:', err);
      toast.error('Impossibile verificare la password. Riprova.');
      return;
    }
    await runPdfExport();
  };

  // --- Handlers: PDF Upload ---
  const handleUploadPDF = async () => {
    try {
      const result = await api.selectFile();
      if (result?.name && result?.path) {
        const attachments = [...(practice.attachments || []), { name: result.name, path: result.path, addedAt: new Date().toISOString() }];
        await saveNow({ attachments });
        toast.success('Documento aggiunto al vault');
      }
    } catch (err) {
      console.error('[PracticeDetail] File upload failed:', err);
      toast.error('Impossibile caricare il documento.');
    }
  };

  const removeAttachment = async (idx) => {
    const attachments = (practice.attachments || []).filter((_, i) => i !== idx);
    try {
      await saveNow({ attachments });
      toast.success('Documento rimosso');
    } catch (err) {
      console.error('[PracticeDetail] removeAttachment failed', err);
      toast.error('Impossibile rimuovere il documento.');
    }
  };

  const confirmRemoveAttachment = (idx) => {
    setConfirmDelete({
      message: 'Rimuovere questo documento dal vault?',
      onConfirm: () => { removeAttachment(idx); setConfirmDelete(null); },
    });
  };

  // --- Handlers: Diary ---
  const addNote = async (e) => {
    e.preventDefault();
    if (!newNote.trim() || submittingNote) return;
    setSubmittingNote(true); // FIX-18
    const note = { text: newNote, date: new Date().toISOString() };
    try {
      await saveNow({ diary: [note, ...(practice.diary || [])] });
      setNewNote('');
      toast.success('Nota aggiunta');
    } catch (err) {
      console.error('[PracticeDetail] addNote failed', err);
      toast.error('Impossibile salvare la nota. Riprova.');
    } finally {
      setSubmittingNote(false);
    }
  };

  const deleteNote = async (idx) => {
    const updatedDiary = (practice.diary || []).filter((_, i) => i !== idx);
    try {
      await saveNow({ diary: updatedDiary });
      toast.success('Nota eliminata');
    } catch (err) {
      console.error('[PracticeDetail] deleteNote failed', err);
      toast.error('Impossibile eliminare la nota.');
    }
  };

  const confirmDeleteNote = (idx) => {
    setConfirmDelete({
      message: 'Eliminare questa nota dal diario?',
      onConfirm: () => { deleteNote(idx); setConfirmDelete(null); },
    });
  };

  // --- Handlers: Deadlines ---
  const addDeadline = async (e) => {
    e.preventDefault();
    if (!newDeadlineLabel.trim() || !newDeadlineDate || submittingDeadline) return;
    setSubmittingDeadline(true); // FIX-19

    const newD = {
      date: newDeadlineDate,
      label: newDeadlineLabel.trim(),
      time: newDeadlineTime || '09:00',
    };
    // FIX-20: salva preavviso usando un campo separato `customAt` invece del sentinel 'custom'
    if (newDeadlineRemind === 'custom') {
      newD.remindMinutes = 'custom';
      newD.customRemindTime = newDeadlineCustomTime;
      newD.customAt = newDeadlineCustomTime; // alias semantico
    } else if (newDeadlineRemind !== null) {
      newD.remindMinutes = newDeadlineRemind;
    }

    const deadlines = [...(practice.deadlines || []), newD];
    deadlines.sort((a, b) => deadlineSortKey(a) - deadlineSortKey(b));

    try {
      await saveNow({ deadlines });
      setNewDeadlineLabel('');
      setNewDeadlineDate('');
      setNewDeadlineTime('09:00');
      setNewDeadlineRemind(null);
      setNewDeadlineCustomTime('08:00');
      toast.success('Scadenza aggiunta');
    } catch (err) {
      console.error('[PracticeDetail] addDeadline failed', err);
      toast.error('Impossibile salvare la scadenza. Riprova.');
    } finally {
      setSubmittingDeadline(false);
    }
  };

  const deleteDeadline = async (idx) => {
    const deadlines = (practice.deadlines || []).filter((_, i) => i !== idx);
    try {
      await saveNow({ deadlines });
      toast.success('Scadenza eliminata');
    } catch (err) {
      console.error('[PracticeDetail] deleteDeadline failed', err);
      toast.error('Impossibile eliminare la scadenza.');
    }
  };

  const confirmDeleteDeadline = (idx) => {
    setConfirmDelete({
      message: 'Eliminare questa scadenza?',
      onConfirm: () => { deleteDeadline(idx); setConfirmDelete(null); },
    });
  };

  // --- Components ---
  const TABS = [
    { id: 'diary', label: 'Diario', icon: Clock, count: (practice.diary || []).length },
    { id: 'docs', label: 'Documenti', icon: FileText, count: (practice.attachments || []).length + folders.length },
    { id: 'deadlines', label: 'Scadenze', icon: Calendar, count: (practice.deadlines || []).length + ((agendaEvents || []).filter(e => e.category === 'scadenza' && e.practiceId === practice.id && !e.autoSync && !e.completed).length) },
    { id: 'info', label: 'Info', icon: Info, count: 0 },
  ];

  return (
    <div className="h-full flex flex-col bg-background animate-fade-in">
      {/* Top Bar */}
      <div className="flex items-center justify-between px-6 py-4 bg-card sticky top-0 z-10">
        <div className="flex items-center gap-4">
          <button onClick={onBack} className="p-2 hover:bg-card-hover rounded-full transition-colors text-text-dim hover:text-text" aria-label="Torna ai fascicoli">
            <ArrowLeft size={20} />
          </button>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-xl font-bold text-text">{practice.client}</h1>
              {practice.biometricProtected && (
                <ShieldCheck size={16} className="text-text-muted" title="Protetto con biometria" />
              )}
            </div>
            <p className="text-xs text-text-dim mt-0.5">
              {practice.code ? `RG ${practice.code}` : practice.object}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <StatusDropdown
            status={practice.status}
            onChangeStatus={async (newStatus) => {
              try {
                await saveNow({ status: newStatus });
                toast.success(newStatus === 'active' ? 'Fascicolo riaperto' : 'Fascicolo archiviato');
              } catch (err) {
                console.error('[PracticeDetail] update status failed', err);
                toast.error('Impossibile aggiornare lo stato del fascicolo.');
              }
            }}
          />
        </div>
      </div>

      {/* Tabs — WAI-ARIA tabs pattern (FIX-17) */}
      <div className="px-6 py-3">
        <div className="tab-switcher" role="tablist" aria-label="Sezioni fascicolo">
          {TABS.map(({ id, label, icon: Icon, count }) => {
            const tabId = `${tabsBaseId}-tab-${id}`;
            const panelId = `${tabsBaseId}-panel-${id}`;
            const selected = activeTab === id;
            return (
              <button
                key={id}
                id={tabId}
                role="tab"
                aria-selected={selected}
                aria-controls={panelId}
                tabIndex={selected ? 0 : -1}
                onClick={() => setActiveTab(id)}
                className="tab-btn"
                data-active={selected}
              >
                <Icon size={14} />
                {label}
                {count > 0 && (
                  <span className={`text-2xs px-1.5 py-0.5 rounded-full ${
                    selected ? 'bg-primary-soft text-primary' : 'bg-surface text-text-dim'
                  }`}>
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-y-auto overflow-x-hidden p-6 no-scrollbar">

        {/* ═══ TAB: DIARIO CRONOLOGICO ═══ */}
        {activeTab === 'diary' && (
          <div
            id={`${tabsBaseId}-panel-diary`}
            role="tabpanel"
            aria-labelledby={`${tabsBaseId}-tab-diary`}
            className="max-w-3xl mx-auto h-full flex flex-col"
          >
            {/* Header Diario con Export */}
            {practice.diary && practice.diary.length > 0 && (
              <div className="flex items-center justify-between mb-5">
                <span className="text-xs font-bold text-text-dim uppercase tracking-label">
                  {practice.diary.length} {practice.diary.length === 1 ? 'annotazione' : 'annotazioni'}
                </span>
                <div className="relative" ref={exportMenuRef}>
                  <div className="flex items-center rounded-xl border border-border overflow-hidden">
                    <button
                      onClick={handleExport}
                      className="flex items-center gap-2 px-4 py-2.5 text-xs font-bold bg-card text-text-muted hover:bg-card-hover hover:text-text transition-colors"
                    >
                      <Download size={14} />
                      {exportMode === 'compressed' ? 'Compresso' : exportMode === 'secured' ? 'Protetto' : 'Esporta PDF'}
                    </button>
                    <button
                      onClick={() => setShowExportMenu(v => !v)}
                      aria-haspopup="listbox"
                      aria-expanded={showExportMenu}
                      aria-label="Modalità esportazione"
                      className="px-2 py-2.5 bg-card text-text-dim hover:bg-card-hover hover:text-text border-l border-border transition-colors"
                    >
                      <ChevronDown size={14} />
                    </button>
                  </div>
                  {showExportMenu && (
                    <div className="absolute right-0 top-full mt-1 bg-card border border-border rounded-xl shadow-lg z-50 py-1 min-w-[200px] animate-fade-in" role="listbox">
                      {[
                        { id: 'standard', label: 'Standard', desc: 'PDF senza modifiche' },
                        { id: 'compressed', label: 'Compresso', desc: 'Ottimizzato per PEC' },
                        { id: 'secured', label: 'Protetto', desc: 'No copia, no stampa, watermark' },
                      ].map(opt => (
                        <button key={opt.id}
                          onClick={() => { setExportMode(opt.id); setShowExportMenu(false); }}
                          className={`w-full text-left px-4 py-2.5 text-xs hover:bg-surface transition-colors ${exportMode === opt.id ? 'text-primary font-bold' : 'text-text-muted'}`}
                        >
                          <span className="block font-bold">{opt.label}</span>
                          <span className="block text-2xs text-text-dim mt-0.5">{opt.desc}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Secure Export Confirmation Card */}
            {showSecureConfirm && (
              <div className="glass-card p-5 border border-primary/30 animate-fade-in mb-4">
                <div className="flex items-start gap-3">
                  <Shield size={20} className="text-primary mt-0.5 shrink-0" />
                  <div className="flex-1">
                    <h4 className="text-sm font-bold text-text mb-2">Esporta PDF Protetto</h4>
                    {/* FIX-21: verra' → verrà */}
                    <p className="text-xs text-text-muted leading-relaxed mb-3">
                      Il PDF verrà esportato con le seguenti protezioni:
                    </p>
                    <ul className="text-xs text-text-dim space-y-1 mb-4">
                      <li className="flex items-center gap-2"><Check size={12} className="text-success" /> Copia/incolla testo bloccata</li>
                      <li className="flex items-center gap-2"><Check size={12} className="text-success" /> Stampa bloccata</li>
                      <li className="flex items-center gap-2"><Check size={12} className="text-success" /> Modifica bloccata</li>
                      <li className="flex items-center gap-2"><Check size={12} className="text-success" /> Watermark &ldquo;RISERVATO&rdquo; applicato</li>
                    </ul>
                    {/* FIX-5: avviso onesto sui limiti */}
                    <p className="text-2xs text-warning leading-relaxed mb-4 font-semibold">
                      Avviso: queste protezioni sono &ldquo;owner restrictions&rdquo; di qpdf — possono essere
                      rimosse da qualsiasi tool che ignori il flag <code>--extract</code>.
                      NON usare per documenti riservati a controparti.
                    </p>
                    <div className="flex gap-2">
                      <button onClick={() => setShowSecureConfirm(false)}
                        className="px-4 py-2 rounded-lg text-xs font-bold text-text-muted bg-surface border border-border hover:bg-card-hover transition-colors">
                        Annulla
                      </button>
                      <button onClick={() => { setShowSecureConfirm(false); setShowExportWarning(true); }}
                        className="btn-primary px-4 py-2 rounded-lg text-xs font-bold">
                        Conferma Protezione
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}

            <div className="flex-1 space-y-4 pb-4">
               {(!practice.diary || practice.diary.length === 0) && (
                <div className="text-center py-16 text-text-dim">
                  <Clock size={36} className="mx-auto mb-3 opacity-40" />
                  <p className="text-base font-medium text-text-muted">Il diario è vuoto. Aggiungi note o verbali.</p>
                </div>
              )}
              {practice.diary?.map((note, idx) => (
                <DiaryNoteRow
                  key={`${note.date}_${idx}`}
                  note={note}
                  idx={idx}
                  onDelete={confirmDeleteNote}
                />
              ))}
            </div>

            <form onSubmit={addNote} className="flex-shrink-0 bg-background pt-4 pb-4 border-t border-border">
              <div className="relative">
                {/* FIX-16: visually-hidden label per textarea diario */}
                <label htmlFor="pd-diary-note" className="sr-only">Nuova nota di diario</label>
                <textarea
                  id="pd-diary-note"
                  className="w-full min-h-[80px] pr-14 pl-4 py-3 resize-none rounded-2xl bg-surface border border-border text-text placeholder:text-text-dim text-sm focus:border-primary/40 focus:bg-card outline-none transition-colors"
                  placeholder="Scrivi una nota di udienza, una telefonata o un appunto..."
                  value={newNote}
                  onChange={e => setNewNote(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      addNote(e);
                    }
                  }}
                />
                <button
                  type="submit"
                  disabled={!newNote.trim() || submittingNote}
                  aria-label="Aggiungi nota"
                  className="absolute right-3 bottom-3 w-9 h-9 flex items-center justify-center bg-primary rounded-xl hover:bg-primary-hover disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                >
                  <Send size={15} className="text-black" />
                </button>
              </div>
            </form>
          </div>
        )}

        {/* ═══ TAB: DOCUMENTI ═══ */}
        {activeTab === 'docs' && (
          <div
            id={`${tabsBaseId}-panel-docs`}
            role="tabpanel"
            aria-labelledby={`${tabsBaseId}-tab-docs`}
            className="max-w-3xl mx-auto"
          >
            {/* 2 Card azione */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
              <button
                type="button"
                onClick={handleUploadPDF}
                className="glass-card p-6 flex items-center gap-4 cursor-pointer hover:bg-surface hover:border-border transition-colors border border-border group text-left w-full"
              >
                <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center flex-shrink-0 group-hover:scale-110 transition-transform">
                  <FilePlus size={24} className="text-primary" />
                </div>
                <div>
                  <p className="text-base font-bold text-text">Carica Documento</p>
                  <p className="text-2xs text-text-dim uppercase tracking-wider mt-1">Aggiungi file al vault crittografato</p>
                </div>
              </button>

              <button
                type="button"
                onClick={linkFolder}
                className="glass-card p-6 flex items-center gap-4 cursor-pointer hover:bg-surface hover:border-border transition-colors border border-border group text-left w-full"
              >
                <div className="w-12 h-12 rounded-xl bg-warning-soft flex items-center justify-center flex-shrink-0 group-hover:scale-110 transition-transform">
                  <FolderPlus size={24} className="text-warning" />
                </div>
                <div>
                  <p className="text-base font-bold text-text">Collega Cartella</p>
                  <p className="text-2xs text-text-dim uppercase tracking-wider mt-1">Associa una cartella locale al fascicolo</p>
                </div>
              </button>
            </div>

            {/* Lista allegati crittografati */}
            <div>
              <h3 className="text-2xs font-black text-text-dim uppercase tracking-label mb-4">Documenti Allegati</h3>
              {(!practice.attachments || practice.attachments.length === 0) ? (
                <div className="glass-card p-8 flex flex-col items-center justify-center text-center border-2 border-dashed border-grid-line">
                  <FileText size={28} className="text-text-dim/40 mb-3" />
                  <p className="text-sm text-text-muted">Nessun documento allegato</p>
                  <p className="text-xs text-text-dim mt-1">Carica PDF o documenti nel vault crittografato</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {/* FIX-15: rimosso overlay-button trick — ora una <button> contiene il label,
                      il delete è un sibling visualmente sovrapposto. FIX-23: chiave inclusa idx per dedupe. */}
                  {practice.attachments.map((att, idx) => (
                    <div key={`${att.path || att.name}_${idx}`} className="glass-card p-1 flex items-stretch gap-1 group hover:border-primary/30 transition-colors">
                      <button
                        type="button"
                        onClick={() => att.path && api.openPath(att.path)}
                        className="flex-1 flex items-center gap-3 p-3 text-left rounded-lg hover:bg-card transition-colors min-w-0"
                        aria-label={`Apri ${att.name}`}
                      >
                        <FileText size={16} className="text-text-muted flex-shrink-0" />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-text truncate">{att.name}</p>
                          <p className="text-2xs text-text-dim">
                            {att.addedAt ? formatDateIT(att.addedAt, '') : ''}
                          </p>
                        </div>
                      </button>
                      <button
                        type="button"
                        onClick={() => confirmRemoveAttachment(idx)}
                        className="opacity-0 group-hover:opacity-100 px-3 text-text-dim hover:text-danger transition-colors flex items-center"
                        aria-label={`Rimuovi ${att.name}`}
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* ═══ CARTELLE COLLEGATE ═══ */}
            <div className="mt-6">
              <h3 className="text-2xs font-black text-text-dim uppercase tracking-label mb-4">Cartelle Collegate</h3>
              {folders.length === 0 ? (
                <div className="glass-card p-8 flex flex-col items-center justify-center text-center border-2 border-dashed border-grid-line">
                  <FolderOpen size={28} className="text-text-dim/40 mb-3" />
                  <p className="text-sm text-text-muted">Nessuna cartella collegata</p>
                  <p className="text-xs text-text-dim mt-1">Collega cartelle locali al fascicolo</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {/* FIX-15: idem — pulsante label + sibling delete */}
                  {folders.map((fld, idx) => (
                    <div key={`${fld.path}_${idx}`} className="glass-card p-1 flex items-stretch gap-1 group hover:border-warning-border transition-colors">
                      <button
                        type="button"
                        onClick={() => openFolderAtPath(fld.path)}
                        className="flex-1 flex items-center gap-3 p-3 text-left rounded-lg hover:bg-card transition-colors min-w-0"
                        aria-label={`Apri ${fld.name}`}
                      >
                        <FolderOpen size={16} className="text-text-muted flex-shrink-0" />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-text truncate">{fld.name}</p>
                          <p className="text-2xs text-text-dim">
                            {fld.addedAt ? formatDateIT(fld.addedAt, '') : ''}
                          </p>
                        </div>
                      </button>
                      <button
                        type="button"
                        onClick={() => confirmRemoveFolder(idx)}
                        className="opacity-0 group-hover:opacity-100 px-3 text-text-dim hover:text-danger transition-colors flex items-center"
                        aria-label={`Rimuovi ${fld.name}`}
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ═══ TAB: SCADENZE ═══ */}
        {activeTab === 'deadlines' && (
          <div
            id={`${tabsBaseId}-panel-deadlines`}
            role="tabpanel"
            aria-labelledby={`${tabsBaseId}-tab-deadlines`}
            className="max-w-3xl mx-auto"
          >
            <form onSubmit={addDeadline} className="mb-6 space-y-3">
              <div className="flex gap-2">
                {/* FIX-16: visually-hidden labels per ogni input */}
                <label htmlFor="pd-deadline-label" className="sr-only">Descrizione scadenza</label>
                <input
                  id="pd-deadline-label"
                  className="input-field flex-1"
                  placeholder="Descrizione scadenza..."
                  value={newDeadlineLabel}
                  onChange={e => setNewDeadlineLabel(e.target.value)}
                />
                <label htmlFor="pd-deadline-date" className="sr-only">Data scadenza</label>
                <input
                  id="pd-deadline-date"
                  type="date"
                  className="input-field w-40"
                  value={newDeadlineDate}
                  onChange={e => setNewDeadlineDate(e.target.value)}
                />
                <label htmlFor="pd-deadline-time" className="sr-only">Orario scadenza</label>
                <input
                  id="pd-deadline-time"
                  type="time"
                  className="input-field w-28"
                  value={newDeadlineTime}
                  onChange={e => setNewDeadlineTime(e.target.value)}
                />
                <button
                  type="submit"
                  className="btn-primary px-4 flex items-center gap-1.5 text-xs font-bold"
                  disabled={!newDeadlineLabel.trim() || !newDeadlineDate || submittingDeadline}
                >
                  <Plus size={14} /> Aggiungi
                </button>
              </div>
              {/* Preavviso specifico – allineato con Agenda */}
              <div className="space-y-1.5">
                <span className="text-2xs font-black text-text-dim uppercase tracking-label ml-1 block">Preavviso Notifica</span>
                <div className="flex flex-wrap gap-1.5 items-center">
                  {[
                    { value: null, label: 'Standard' },
                    { value: 5, label: '5 min' },
                    { value: 10, label: '10 min' },
                    { value: 15, label: '15 min' },
                    { value: 30, label: '30 min' },
                    { value: 60, label: '1 ora' },
                    { value: 120, label: '2 ore' },
                    { value: 1440, label: '1 giorno' },
                  ].map(opt => (
                    <button
                      key={String(opt.value)}
                      type="button"
                      onClick={() => setNewDeadlineRemind(opt.value)}
                      className={`px-3 py-1.5 rounded-xl text-2xs font-bold uppercase tracking-wider transition-colors border ${
                        newDeadlineRemind === opt.value
                          ? 'bg-primary text-black border-primary'
                          : 'bg-surface text-text-dim border-border hover:bg-card hover:text-text'
                      }`}
                    >
                      {opt.label}
                    </button>
                  ))}
                  {/* Pill orario personalizzato "Alle" */}
                  <div className={`inline-flex items-center rounded-xl border transition-colors ${
                    newDeadlineRemind === 'custom'
                      ? 'border-primary bg-primary/10'
                      : 'border-border bg-surface hover:bg-card'
                  }`}>
                    <button type="button"
                      onClick={() => setNewDeadlineRemind('custom')}
                      className={`px-2.5 py-1.5 text-2xs font-bold uppercase tracking-wider transition-colors ${
                        newDeadlineRemind === 'custom' ? 'text-primary' : 'text-text-dim hover:text-text'
                      }`}>
                      Alle
                    </button>
                    <label htmlFor="pd-deadline-customat" className="sr-only">Orario notifica personalizzato</label>
                    <input
                      id="pd-deadline-customat"
                      type="time"
                      value={newDeadlineCustomTime}
                      onFocus={() => setNewDeadlineRemind('custom')}
                      onChange={e => { setNewDeadlineCustomTime(e.target.value); setNewDeadlineRemind('custom'); }}
                      className="bg-transparent border-none outline-none text-2xs font-mono text-white w-[52px] py-1 pr-2 focus:ring-0"
                    />
                  </div>
                </div>
                <p className="text-3xs text-text-dim mt-0.5">«Standard» usa il preavviso globale. «Alle» invia la notifica all&apos;orario preciso scelto.</p>
              </div>
            </form>

            <div className="space-y-2">
              {(() => {
                const today = new Date(); today.setHours(0, 0, 0, 0);

                if (allDeadlines.length === 0) {
                  return (
                    <div className="text-center py-10 text-text-dim">
                      <Calendar size={32} className="mx-auto mb-2 opacity-40" />
                      <p className="text-text-muted">Nessuna scadenza impostata</p>
                    </div>
                  );
                }

                return allDeadlines.map((d) => {
                  const dDate = new Date(d.date); dDate.setHours(0, 0, 0, 0);
                  const diff = Math.ceil((dDate - today) / (1000 * 60 * 60 * 24));
                  const dotColor = getDeadlineDotColor(diff);
                  const deadlineLabel = getDeadlineLabel(diff);
                  // FIX-11: chiave stabile basata su data+label+id/idx
                  const key = d.source === 'agenda'
                    ? `agenda_${d.id}`
                    : `practice_${d.date}_${d.label}_${d.idx ?? ''}`;

                  const handleDeadlineClick = () => {
                    if (onNavigate) {
                      const timeParam = d.time ? `&time=${d.time}` : '';
                      onNavigate('/agenda?date=' + d.date + timeParam);
                    }
                  };

                  // FIX-7: handler keydown per Enter/Space sui ruoli button
                  const handleKeyDown = (e) => {
                    if (!onNavigate) return;
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      handleDeadlineClick();
                    }
                  };

                  return (
                    <div
                      key={key}
                      className={`glass-card p-4 group hover:border-primary/30 transition-colors ${onNavigate ? 'cursor-pointer' : ''}`}
                      onClick={onNavigate ? handleDeadlineClick : undefined}
                      onKeyDown={onNavigate ? handleKeyDown : undefined}
                      role={onNavigate ? 'button' : undefined}
                      tabIndex={onNavigate ? 0 : undefined}
                    >
                      <div className="flex items-center gap-3">
                        <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${dotColor}`} />
                        <p className="text-sm text-text font-bold flex-1">{d.label}</p>
                        <div className="text-xs font-bold px-2.5 py-1 rounded-lg bg-card border border-border text-text-muted min-w-[70px] text-center flex-shrink-0">
                          {deadlineLabel}
                        </div>
                        {d.source === 'practice' && (
                          <button onClick={(e) => { e.stopPropagation(); confirmDeleteDeadline(d.idx); }} className="opacity-0 group-hover:opacity-100 p-1.5 text-text-dim hover:text-danger transition-colors" aria-label="Elimina scadenza">
                            <Trash2 size={14} />
                          </button>
                        )}
                      </div>
                      <div className="flex items-center gap-2 mt-2 ml-5 flex-wrap">
                        <span className="text-xs text-text-muted">{formatDateIT(d.date, '')}</span>
                        {d.time && (
                          <span className="text-xs text-text-dim font-mono">ore {d.time}</span>
                        )}
                        {d.remindMinutes != null && (
                          <span className="text-2xs font-semibold text-text-muted bg-card border border-border px-1.5 py-0.5 rounded-lg flex items-center gap-1">
                            <BellRing size={10} /> {d.remindMinutes === 'custom'
                              ? `alle ${d.customAt || d.customRemindTime || '—'}`
                              : d.remindMinutes >= 1440
                                ? `${d.remindMinutes / 1440}g`
                                : d.remindMinutes >= 60
                                  ? `${d.remindMinutes / 60}h`
                                  : `${d.remindMinutes}min`}
                          </span>
                        )}
                      </div>
                    </div>
                  );
                });
              })()}
            </div>
          </div>
        )}

        {/* ═══ TAB: INFO PRATICA ═══ */}
        {activeTab === 'info' && (
          <div
            id={`${tabsBaseId}-panel-info`}
            role="tabpanel"
            aria-labelledby={`${tabsBaseId}-tab-info`}
            className="grid grid-cols-1 lg:grid-cols-2 gap-6 max-w-4xl mx-auto"
          >
            {/* Dati Generali */}
            <div className="glass-card p-6">
              <h3 className="text-sm font-bold text-text-muted uppercase tracking-wider mb-5 border-b border-border pb-2 flex items-center gap-2"><FileText size={14} className="text-text-muted" /> Dati Generali</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-y-5 gap-x-8 text-sm">
                <div>
                  <span className="block text-2xs font-bold text-text-dim uppercase tracking-wider mb-1">Materia</span>
                  <span className="text-text font-medium capitalize">{
                    { civile: 'Civile', penale: 'Penale', lavoro: 'Lavoro', amm: 'Amministrativo', stra: 'Stragiudiziale', soc: 'Societario' }[practice.type] || practice.type
                  }</span>
                </div>
                <div>
                  <span className="block text-2xs font-bold text-text-dim uppercase tracking-wider mb-1">Autorità</span>
                  <span className="text-text font-medium">{practice.court || '—'}</span>
                </div>
                <div>
                  <span className="block text-2xs font-bold text-text-dim uppercase tracking-wider mb-1">Sede</span>
                  <span className="text-text font-medium">{practice.courtLocation || '—'}</span>
                </div>
                <div>
                  <span className="block text-2xs font-bold text-text-dim uppercase tracking-wider mb-1">Riferimento</span>
                  <span className="text-text font-medium font-mono">{practice.code ? `RG ${practice.code}` : '—'}</span>
                </div>
                <div>
                  <span className="block text-2xs font-bold text-text-dim uppercase tracking-wider mb-1">Apertura</span>
                  <span className="text-text font-medium">
                    {practice.createdAt ? new Date(practice.createdAt).toLocaleDateString('it-IT', { day: '2-digit', month: 'long', year: 'numeric' }) : '—'}
                  </span>
                </div>
              </div>
            </div>

            {/* Parti Coinvolte */}
            <div className="glass-card p-6">
              <h3 className="text-sm font-bold text-text-muted uppercase tracking-wider mb-5 border-b border-border pb-2 flex items-center gap-2">
                <Users size={14} className="text-text-muted" /> Parti Coinvolte
              </h3>
              <div className="space-y-4 text-sm">
                <div>
                  <span className="block text-2xs font-bold text-text-dim uppercase tracking-wider mb-1">Cliente / Assistito</span>
                  <span className="text-text font-medium">{practice.client || '—'}</span>
                </div>
                <div>
                  <span className="block text-2xs font-bold text-text-dim uppercase tracking-wider mb-1">Controparte</span>
                  <span className="text-text font-medium">{practice.counterparty || '—'}</span>
                </div>
              </div>
            </div>

            {/* Note Strategiche — full width */}
            <div className="glass-card p-6 lg:col-span-2">
              <h3 className="text-sm font-bold text-text-muted uppercase tracking-wider mb-5 border-b border-border pb-2 flex items-center gap-2"><Clock size={14} className="text-text-muted" /> Note Strategiche</h3>
              <p className="text-sm text-text whitespace-pre-line leading-relaxed">
                {practice.description || 'Nessun appunto registrato.'}
              </p>
            </div>
          </div>
        )}
      </div>

      {/* PDF export security warning — shown before every export */}
      <ExportWarningModal
        isOpen={showExportWarning}
        onClose={() => setShowExportWarning(false)}
        onConfirm={handleExportConfirmed}
      />

      {/* Password verification modal for PDF export — centered with blur overlay */}
      {showExportPwdModal && (
        <ModalOverlay onClose={() => setShowExportPwdModal(false)} labelledBy="export-pwd-title" zIndex={9999} focusTrap>
          <div className="modal-card modal-card-sm">
            {/* Header */}
            <div className="px-6 pt-6 pb-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center border border-primary/20">
                  <Lock size={18} className="text-primary" />
                </div>
                <div>
                  <h3 id="export-pwd-title" className="text-text font-bold text-sm">Verifica Identità</h3>
                  <p className="text-text-dim text-2xs">Inserisci la Master Password per esportare</p>
                </div>
              </div>
              <button onClick={() => setShowExportPwdModal(false)} className="p-2 hover:bg-card-hover rounded-xl text-text-dim hover:text-text transition-colors group" aria-label="Chiudi">
                <X size={18} className="group-hover:rotate-90 transition-transform" />
              </button>
            </div>
            {/* Form */}
            <form onSubmit={handleExportWithPassword} className="px-6 pb-6">
              {/* FIX-16: visually-hidden label */}
              <label htmlFor="pd-export-pwd" className="sr-only">Master Password</label>
              <input
                id="pd-export-pwd"
                type="password"
                className="w-full py-3 px-4 rounded-xl bg-surface border border-border text-text placeholder:text-text-dim text-sm focus:border-primary/40 outline-none transition-colors mb-4"
                placeholder="Master Password…"
                value={exportPwd}
                onChange={e => setExportPwd(e.target.value)}
                autoFocus
              />
              <div className="flex gap-3">
                <button type="button" onClick={() => setShowExportPwdModal(false)}
                  className="flex-1 py-2.5 rounded-xl border border-border text-text-dim text-xs font-bold uppercase tracking-widest hover:bg-surface hover:text-text transition-colors">
                  Annulla
                </button>
                <button type="submit" disabled={!exportPwd}
                  className="flex-1 py-2.5 rounded-xl btn-primary text-xs font-bold uppercase tracking-widest disabled:opacity-40">
                  Esporta PDF
                </button>
              </div>
            </form>
          </div>
        </ModalOverlay>
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

const practiceShape = PropTypes.shape({
  id: PropTypes.string,
  client: PropTypes.string,
  object: PropTypes.string,
  code: PropTypes.string,
  type: PropTypes.string,
  status: PropTypes.string,
  counterparty: PropTypes.string,
  court: PropTypes.string,
  createdAt: PropTypes.string,
  description: PropTypes.string,
  biometricProtected: PropTypes.bool,
  folderPath: PropTypes.string,
  folders: PropTypes.arrayOf(PropTypes.shape({
    path: PropTypes.string,
    name: PropTypes.string,
    addedAt: PropTypes.string,
  })),
  attachments: PropTypes.arrayOf(PropTypes.shape({
    name: PropTypes.string,
    path: PropTypes.string,
    addedAt: PropTypes.string,
  })),
  diary: PropTypes.arrayOf(PropTypes.shape({
    text: PropTypes.string,
    date: PropTypes.string,
  })),
  deadlines: PropTypes.arrayOf(PropTypes.shape({
    date: PropTypes.string,
    label: PropTypes.string,
  })),
});

PracticeDetail.propTypes = {
  practice: practiceShape.isRequired,
  onBack: PropTypes.func.isRequired,
  onUpdate: PropTypes.func.isRequired,
  agendaEvents: PropTypes.array,
  onNavigate: PropTypes.func,
};
