import { useState, useEffect, useCallback, useRef } from 'react';
import PropTypes from 'prop-types';
import { 
  ArrowLeft, Calendar, FileText, 
  Clock, Plus, Trash2, Send, FolderOpen, 
  FolderPlus, Lock, ChevronDown,
  FilePlus, Info, Fingerprint, ShieldCheck, Download, X, Users
} from 'lucide-react';
import { exportPracticeTypstPDF } from '../utils/typstPdfGenerator';
import ExportWarningModal from './ExportWarningModal';
import ConfirmDialog from './ConfirmDialog';
import ModalOverlay from './ModalOverlay';
import toast from 'react-hot-toast';
import * as api from '../tauri-api';
import { formatDateIT } from '../utils/helpers';

/* ---------- Biometric Lock Screen (extracted to reduce cognitive complexity) ---------- */
function BiometricLockScreen({ practice, onBack, onUnlock }) {
  const [bioAttempted, setBioAttempted] = useState(false);
  const [bioConfigured, setBioConfigured] = useState(null); // null = checking, true/false
  const [showPasswordFallback, setShowPasswordFallback] = useState(false);
  const [practicePassword, setPracticePassword] = useState('');
  const [practicePasswordError, setPracticePasswordError] = useState('');

  // Check if biometrics are configured on mount
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const available = await api.checkBio();
        if (!available) { if (!cancelled) { setBioConfigured(false); setShowPasswordFallback(true); } return; }
        const saved = await api.hasBioSaved();
        if (!cancelled) {
          setBioConfigured(saved);
          if (!saved) setShowPasswordFallback(true); // Not configured → show password directly
        }
      } catch {
        if (!cancelled) { setBioConfigured(false); setShowPasswordFallback(true); }
      }
    })();
    return () => { cancelled = true; };
  }, []);

  // Auto-trigger biometric only if configured
  useEffect(() => {
    if (bioConfigured !== true || bioAttempted) return;
    setBioAttempted(true);
    const attemptBio = async () => {
      try {
        const result = await api.bioLogin();
        if (result) onUnlock();
      } catch (err) {
        console.debug('[PracticeDetail] Biometric auth failed or dismissed', err);
      }
    };
    if (document.hasFocus()) {
      attemptBio();
    } else {
      const onFocus = () => {
        window.removeEventListener('focus', onFocus);
        attemptBio();
      };
      window.addEventListener('focus', onFocus);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- onUnlock is stable via useCallback; bioAttempted gate prevents re-runs
  }, [bioConfigured, bioAttempted]);

  const retryBiometric = async () => {
    try {
      const result = await api.bioLogin();
      if (result) { onUnlock(); return; }
      toast.error('Autenticazione non riuscita');
    } catch (err) {
      console.debug('[PracticeDetail] Biometric retry failed', err);
      toast.error('Autenticazione fallita');
    }
  };

  const handlePasswordFallback = async (e) => {
    e.preventDefault();
    if (!practicePassword) return;
    setPracticePasswordError('');
    try {
      const result = await api.verifyVaultPassword(practicePassword);
      if (result?.valid) { setPracticePassword(''); onUnlock(); return; }
      setPracticePasswordError('Password errata');
    } catch (err) {
      console.debug('[PracticeDetail] Password verification failed', err);
      setPracticePasswordError('Errore verifica password');
    }
  };

  return (
    <div className="h-full flex flex-col bg-background animate-fade-in">
      <div className="flex items-center px-6 py-4 border-b border-border">
        <button onClick={onBack} className="p-2 hover:bg-white/10 rounded-full transition-colors text-text-dim hover:text-text">
          <ArrowLeft size={20} />
        </button>
        <div className="ml-4">
          <h1 className="text-xl font-bold text-text">{practice.client}</h1>
          <p className="text-xs text-text-dim mt-0.5">{practice.code ? `RG ${practice.code}` : practice.object}</p>
        </div>
      </div>
      <div className="flex-1 flex items-center justify-center">
        <div className="text-center space-y-6 max-w-xs">
          {/* Icon: fingerprint if configured, lock if not */}
          <div className="w-20 h-20 rounded-2xl bg-primary/10 flex items-center justify-center mx-auto border border-primary/20 animate-pulse">
            {bioConfigured ? <Fingerprint size={36} className="text-primary" /> : <Lock size={36} className="text-primary" />}
          </div>
          <div>
            <h2 className="text-xl font-bold text-text mb-2">Verifica Identità</h2>
            <p className="text-sm text-text-muted">
              {bioConfigured === null && 'Verifica in corso...'}
              {bioConfigured === false && 'Inserisci la Master Password per accedere.'}
              {bioConfigured === true && (bioAttempted ? 'Autenticazione non riuscita. Riprova o usa la password.' : 'Autenticazione biometrica in corso...')}
            </p>
            {bioConfigured === false && (
              <p className="text-[10px] text-amber-400/70 mt-2 font-semibold">Biometria non configurata — usa la password</p>
            )}
          </div>
          {/* Biometric retry + fallback (only when bio IS configured) */}
          {bioConfigured === true && bioAttempted && !showPasswordFallback && (
            <div className="space-y-3">
              <button onClick={retryBiometric} className="btn-primary px-8 py-3 text-sm w-full">
                <Fingerprint size={18} /> Riprova Biometria
              </button>
              <button 
                onClick={() => setShowPasswordFallback(true)} 
                className="w-full text-text-dim hover:text-text text-xs font-semibold transition-colors py-2"
              >
                Usa la Master Password
              </button>
            </div>
          )}
          {/* Password form */}
          {showPasswordFallback && (
            <form onSubmit={handlePasswordFallback} className="space-y-3 text-left">
              <label htmlFor="pd-bio-pwd" className="text-[10px] font-bold text-text-dim uppercase tracking-[2px] ml-1 block">Master Password</label>
              <input
                id="pd-bio-pwd"
                type="password"
                className="input-field w-full py-3 px-4 rounded-xl bg-white/5 border-border text-text placeholder:text-text-dim text-sm"
                placeholder="Inserisci la password..."
                value={practicePassword}
                onChange={e => setPracticePassword(e.target.value)}
                autoFocus
              />
              {practicePasswordError && (
                <p className="text-red-400 text-[11px] font-semibold">{practicePasswordError}</p>
              )}
              <button type="submit" className="btn-primary w-full py-3 text-sm">
                <Lock size={16} /> Sblocca Fascicolo
              </button>
              {bioConfigured === true && (
                <button 
                  type="button"
                  onClick={() => { setShowPasswordFallback(false); setPracticePassword(''); setPracticePasswordError(''); }} 
                  className="w-full text-text-dim hover:text-text text-xs font-semibold transition-colors py-2"
                >
                  Torna alla Biometria
                </button>
              )}
            </form>
          )}
        </div>
      </div>
    </div>
  );
}

BiometricLockScreen.propTypes = {
  practice: PropTypes.object.isRequired,
  onBack: PropTypes.func.isRequired,
  onUnlock: PropTypes.func.isRequired,
};

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
        className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold border transition-all ${
          status === 'active'
            ? 'bg-white/5 text-text border-border hover:bg-white/10'
            : 'bg-white/5 text-text-muted border-border hover:bg-white/10'
        }`}
      >
        <span className={`w-2 h-2 rounded-full ${status === 'active' ? 'bg-emerald-400' : 'bg-text-dim'}`} />
        {status === 'active' ? 'Attivo' : 'Archiviato'}
        <ChevronDown size={14} className="text-text-dim" />
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-2 bg-card border border-border rounded-xl shadow-2xl z-50 py-1 min-w-[200px] animate-fade-in">
          <button onClick={() => doSet('active')}
            className={`w-full flex items-center gap-3 px-4 py-3 text-xs hover:bg-white/5 transition-colors text-left ${status === 'active' ? 'bg-white/[0.03]' : ''}`}>
            <span className="w-2 h-2 rounded-full bg-emerald-400" /><span className="text-text font-medium">Attivo</span>
          </button>
          <button onClick={() => doSet('closed')}
            className={`w-full flex items-center gap-3 px-4 py-3 text-xs hover:bg-white/5 transition-colors text-left ${status === 'closed' ? 'bg-white/[0.03]' : ''}`}>
            <span className="w-2 h-2 rounded-full bg-text-dim" /><span className="text-text font-medium">Archiviato</span>
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

/* ---------- Main Component ---------- */
export default function PracticeDetail({ practice, onBack, onUpdate, agendaEvents }) {
  const [activeTab, setActiveTab] = useState('diary'); // diary, docs, deadlines, info
  const [biometricVerified, setBiometricVerified] = useState(false);
  const [showExportWarning, setShowExportWarning] = useState(false);
  const [showExportPwdModal, setShowExportPwdModal] = useState(false);
  const [exportPwd, setExportPwd] = useState('');
  
  // Stati per i form
  const [newNote, setNewNote] = useState('');
  const [newDeadlineLabel, setNewDeadlineLabel] = useState('');
  const [newDeadlineDate, setNewDeadlineDate] = useState('');
  const [newDeadlineTime, setNewDeadlineTime] = useState('09:00');
  const [newDeadlineRemind, setNewDeadlineRemind] = useState(null); // null = usa preavviso globale
  const [newDeadlineCustomTime, setNewDeadlineCustomTime] = useState('08:00'); // per preavviso "Alle"
  const [confirmDelete, setConfirmDelete] = useState(null);

  // --- Helpers ---
  const update = (changes) => onUpdate({ ...practice, ...changes });

  const handleBioUnlock = useCallback(() => setBiometricVerified(true), []);

  // Backwards-compatible folders array (old data has folderPath as string)
  const folders = (() => {
    if (Array.isArray(practice.folders) && practice.folders.length > 0) return practice.folders;
    if (practice.folderPath) return [{ path: practice.folderPath, name: practice.folderPath.split('/').pop(), addedAt: practice.createdAt || new Date().toISOString() }];
    return [];
  })();

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
    if (folder) {
      const newFolder = { path: folder, name: folder.split('/').pop(), addedAt: new Date().toISOString() };
      const updatedFolders = [...folders, newFolder];
      try {
        await update({ folders: updatedFolders, folderPath: updatedFolders[0]?.path || null });
        toast.success('Cartella collegata');
      } catch {
        toast.error('Errore collegamento cartella');
      }
    }
  };

  const removeFolder = async (idx) => {
    const updatedFolders = folders.filter((_, i) => i !== idx);
    try {
      await update({ folders: updatedFolders, folderPath: updatedFolders[0]?.path || null });
      toast.success('Cartella scollegata');
    } catch {
      toast.error('Errore rimozione cartella');
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
      toast.error('Impossibile aprire la cartella');
    }
  };

  const handleExport = () => {
    // Open the security warning modal first — actual export runs only on confirm.
    setShowExportWarning(true);
  };

  /** Shared helper: show loading toast → run PDF export → resolve toast */
  const runPdfExport = async () => {
    const toastId = toast.loading('Generazione PDF in corso…', { duration: 30000 });
    try {
      const result = await exportPracticeTypstPDF(practice);
      toast.dismiss(toastId);
      if (result?.success) {
        const fullPath = result.path || '';
        const fileName = fullPath.split(/[/\\]/).pop() || 'PDF';
        const folder = fullPath.split(/[/\\]/).slice(0, -1).pop() || '';
        toast.success(
          `PDF salvato con successo!\n${folder}/${fileName}`,
          { duration: 6000, style: { maxWidth: '420px' } }
        );
      } else if (result?.cancelled) {
        // User closed the save dialog — silent dismiss, no error toast
      } else if (result?.error) {
        console.warn('[PracticeDetail] PDF export returned error:', result.error);
        const msg = result.error?.message || String(result.error);
        toast.error(`Errore export: ${msg}`);
      } else {
        console.warn('[PracticeDetail] PDF export returned failure:', result);
        toast.error('Errore durante la generazione del PDF');
      }
    } catch (err) {
      console.error('[PracticeDetail] PDF export failed:', err);
      toast.dismiss(toastId);
      toast.error(`Errore export: ${err?.message || 'errore sconosciuto'}`);
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
    try {
      const result = await api.verifyVaultPassword(exportPwd);
      if (!result?.valid) {
        toast.error('Password errata — esportazione negata');
        setExportPwd('');
        return;
      }
    } catch (err) {
      console.error('[PracticeDetail] Export password verification failed:', err);
      toast.error('Errore verifica password');
      setExportPwd('');
      return;
    }
    setExportPwd('');
    await runPdfExport();
  };

  // --- Handlers: PDF Upload ---
  const handleUploadPDF = async () => {
    try {
      const result = await api.selectFile();
      if (result?.name && result?.path) {
        const attachments = [...(practice.attachments || []), { name: result.name, path: result.path, addedAt: new Date().toISOString() }];
        await update({ attachments });
        toast.success('Documento aggiunto al vault');
      }
    } catch (err) {
      console.error('[PracticeDetail] File upload failed:', err);
      toast.error('Errore nel caricamento');
    }
  };

  const removeAttachment = async (idx) => {
    const attachments = (practice.attachments || []).filter((_, i) => i !== idx);
    try {
      await update({ attachments });
      toast.success('Documento rimosso');
    } catch {
      toast.error('Errore rimozione documento');
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
    if (!newNote.trim()) return;
    const note = { text: newNote, date: new Date().toISOString() };
    try {
      await update({ diary: [note, ...(practice.diary || [])] });
      setNewNote('');
      toast.success('Nota aggiunta');
    } catch {
      toast.error('Errore salvataggio nota');
    }
  };

  const deleteNote = async (idx) => {
    const updatedDiary = (practice.diary || []).filter((_, i) => i !== idx);
    try {
      await update({ diary: updatedDiary });
      toast.success('Nota eliminata');
    } catch {
      toast.error('Errore eliminazione nota');
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
    if (!newDeadlineLabel.trim() || !newDeadlineDate) return;
    
    const newD = { 
      date: newDeadlineDate, 
      label: newDeadlineLabel.trim(),
      time: newDeadlineTime || '09:00',
    };
    // Salva preavviso solo se specifico (non null/globale)
    if (newDeadlineRemind === 'custom') {
      newD.remindMinutes = 'custom';
      newD.customRemindTime = newDeadlineCustomTime;
    } else if (newDeadlineRemind !== null) {
      newD.remindMinutes = newDeadlineRemind;
    }

    const deadlines = [...(practice.deadlines || []), newD];
    deadlines.sort((a, b) => new Date(a.date) - new Date(b.date));
    
    try {
      await update({ deadlines });
      setNewDeadlineLabel('');
      setNewDeadlineDate('');
      setNewDeadlineTime('09:00');
      setNewDeadlineRemind(null);
      setNewDeadlineCustomTime('08:00');
      toast.success('Scadenza aggiunta');
    } catch {
      toast.error('Errore salvataggio scadenza');
    }
  };

  const deleteDeadline = async (idx) => {
    const deadlines = (practice.deadlines || []).filter((_, i) => i !== idx);
    try {
      await update({ deadlines });
      toast.success('Scadenza eliminata');
    } catch {
      toast.error('Errore eliminazione scadenza');
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
          <button onClick={onBack} className="p-2 hover:bg-white/10 rounded-full transition-colors text-text-dim hover:text-text">
            <ArrowLeft size={20} />
          </button>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-xl font-bold text-text">{practice.client}</h1>
              {practice.biometricProtected && (
                <ShieldCheck size={16} className="text-primary/60" title="Protetto con biometria" />
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
                await update({ status: newStatus });
                toast.success(newStatus === 'active' ? 'Fascicolo riaperto' : 'Fascicolo archiviato');
              } catch {
                toast.error('Errore cambio stato fascicolo');
              }
            }}
          />
        </div>
      </div>

      {/* Tabs — Segmented Control moderno */}
      <div className="px-6 py-3">
        <div className="tab-switcher">
          {TABS.map(({ id, label, icon: Icon, count }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className="tab-btn"
              data-active={activeTab === id}
            >
              <Icon size={14} />
              {label}
              {count > 0 && (
                <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${
                  activeTab === id ? 'bg-white/20 text-white' : 'bg-white/10 text-text-dim'
                }`}>
                  {count}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-y-auto p-6 custom-scrollbar">
        
        {/* ═══ TAB: DIARIO CRONOLOGICO ═══ */}
        {activeTab === 'diary' && (
          <div className="max-w-3xl mx-auto h-full flex flex-col">
            {/* Header Diario con Export */}
            {practice.diary && practice.diary.length > 0 && (
              <div className="flex items-center justify-between mb-5">
                <span className="text-xs font-bold text-text-dim uppercase tracking-[2px]">
                  {practice.diary.length} {practice.diary.length === 1 ? 'annotazione' : 'annotazioni'}
                </span>
                <button
                  onClick={handleExport}
                  className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-bold bg-white/[0.06] text-text-muted border border-border hover:bg-white/[0.10] hover:text-text transition-all"
                >
                  <Download size={14} />
                  Esporta PDF
                </button>
              </div>
            )}
            <div className="flex-1 space-y-4 mb-6">
               {(!practice.diary || practice.diary.length === 0) && (
                <div className="text-center py-16 text-text-dim">
                  <Clock size={36} className="mx-auto mb-3 opacity-40" />
                  <p className="text-base font-medium text-text-muted">Il diario è vuoto. Aggiungi note o verbali.</p>
                </div>
              )}
              {practice.diary?.map((note, idx) => (
                <div key={note.date + idx} className="flex gap-4 group animate-fade-in">
                  <div className="flex flex-col items-center pt-1">
                    <div className="w-2.5 h-2.5 rounded-full bg-primary ring-2 ring-primary/20" />
                    <div className="w-px h-full bg-white/10 my-1" />
                  </div>
                  <div className="flex-1 rounded-2xl bg-white/[0.04] border border-white/[0.08] p-4 hover:bg-white/[0.06] hover:border-white/[0.12] transition-all">
                    <div className="flex justify-between items-start mb-2.5">
                      <span className="text-[11px] font-semibold text-primary/90 bg-primary/10 px-2.5 py-1 rounded-lg border border-primary/15">
                        {new Date(note.date).toLocaleDateString('it-IT', { day: '2-digit', month: 'short', year: 'numeric' })} • {new Date(note.date).toLocaleTimeString('it-IT', {hour:'2-digit', minute:'2-digit'})}
                      </span>
                      <button onClick={() => confirmDeleteNote(idx)} className="opacity-0 group-hover:opacity-100 p-1.5 rounded-lg hover:bg-red-500/10 text-white/30 hover:text-red-400 transition-all">
                         <Trash2 size={14} />
                      </button>
                    </div>
                    <p className="text-sm text-text leading-relaxed whitespace-pre-wrap">{note.text}</p>
                  </div>
                </div>
              ))}
            </div>

            <form onSubmit={addNote} className="sticky bottom-0 bg-background pt-4 border-t border-border">
              <div className="relative">
                <textarea
                  className="w-full min-h-[80px] pr-14 pl-4 py-3 resize-none rounded-2xl bg-white/[0.05] border border-border text-text placeholder:text-text-dim text-sm focus:border-primary/40 focus:bg-white/[0.07] outline-none transition-all"
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
                  disabled={!newNote.trim()}
                  className="absolute right-3 bottom-3 w-9 h-9 flex items-center justify-center bg-primary rounded-xl hover:bg-primary-hover disabled:opacity-30 disabled:cursor-not-allowed transition-all"
                >
                  <Send size={15} className="text-black" />
                </button>
              </div>
            </form>
          </div>
        )}

        {/* ═══ TAB: DOCUMENTI ═══ */}
        {activeTab === 'docs' && (
          <div className="max-w-3xl mx-auto">
            {/* 2 Card azione */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
              <button 
                type="button"
                onClick={handleUploadPDF}
                className="glass-card p-6 flex items-center gap-4 cursor-pointer hover:bg-white/5 hover:border-white/15 transition-all border border-white/5 group text-left w-full"
              >
                <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center flex-shrink-0 group-hover:scale-110 transition-transform">
                  <FilePlus size={24} className="text-primary" />
                </div>
                <div>
                  <p className="text-base font-bold text-text">Carica Documento</p>
                  <p className="text-[10px] text-text-dim uppercase tracking-wider mt-1">Aggiungi file al vault crittografato</p>
                </div>
              </button>

              <button 
                type="button"
                onClick={linkFolder}
                className="glass-card p-6 flex items-center gap-4 cursor-pointer hover:bg-white/5 hover:border-white/15 transition-all border border-white/5 group text-left w-full"
              >
                <div className="w-12 h-12 rounded-xl bg-amber-500/10 flex items-center justify-center flex-shrink-0 group-hover:scale-110 transition-transform">
                  <FolderPlus size={24} className="text-amber-400" />
                </div>
                <div>
                  <p className="text-base font-bold text-text">Collega Cartella</p>
                  <p className="text-[10px] text-text-dim uppercase tracking-wider mt-1">Associa una cartella locale al fascicolo</p>
                </div>
              </button>
            </div>

            {/* Lista allegati crittografati */}
            <div>
              <h3 className="text-[10px] font-black text-text-dim uppercase tracking-[2px] mb-4">Documenti Allegati</h3>
              {(!practice.attachments || practice.attachments.length === 0) ? (
                <div className="glass-card p-8 flex flex-col items-center justify-center text-center border border-dashed border-white/10">
                  <FileText size={28} className="text-text-dim/40 mb-3" />
                  <p className="text-sm text-text-muted">Nessun documento allegato</p>
                  <p className="text-xs text-text-dim mt-1">Carica PDF o documenti nel vault crittografato</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {practice.attachments.map((att, idx) => (
                    <div key={att.path || att.name}
                      className="glass-card p-3 flex items-center gap-3 group hover:border-primary/30 transition-colors text-left w-full relative"
                    >
                      <button type="button"
                        onClick={() => att.path && api.openPath(att.path)}
                        className="absolute inset-0 z-0 cursor-pointer"
                        aria-label={`Apri ${att.name}`}
                      />
                      <FileText size={16} className="text-primary flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-text truncate">{att.name}</p>
                        <p className="text-[10px] text-text-dim">
                          {att.addedAt ? formatDateIT(att.addedAt, '') : ''}
                        </p>
                      </div>
                      <button onClick={(e) => { e.stopPropagation(); att.path && api.openPath(att.path); }} className="btn-ghost text-xs p-2 relative z-[1]">
                        <FolderOpen size={14} />
                      </button>
                      <button onClick={(e) => { e.stopPropagation(); confirmRemoveAttachment(idx); }} className="opacity-0 group-hover:opacity-100 p-2 text-text-dim hover:text-red-400 transition-all relative z-[1]">
                        <Trash2 size={14} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* ═══ CARTELLE COLLEGATE ═══ */}
            <div className="mt-6">
              <h3 className="text-[10px] font-black text-text-dim uppercase tracking-[2px] mb-4">Cartelle Collegate</h3>
              {folders.length === 0 ? (
                <div className="glass-card p-8 flex flex-col items-center justify-center text-center border border-dashed border-white/10">
                  <FolderOpen size={28} className="text-text-dim/40 mb-3" />
                  <p className="text-sm text-text-muted">Nessuna cartella collegata</p>
                  <p className="text-xs text-text-dim mt-1">Collega cartelle locali al fascicolo</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {folders.map((fld, idx) => (
                    <div key={fld.path}
                      className="glass-card p-3 flex items-center gap-3 group hover:border-amber-500/30 transition-colors text-left w-full relative"
                    >
                      <button type="button"
                        onClick={() => openFolderAtPath(fld.path)}
                        className="absolute inset-0 z-0 cursor-pointer"
                        aria-label={`Apri ${fld.name}`}
                      />
                      <FolderOpen size={16} className="text-amber-400 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-text truncate">{fld.name}</p>
                        <p className="text-[10px] text-text-dim">
                          {fld.addedAt ? formatDateIT(fld.addedAt, '') : ''}
                        </p>
                      </div>
                      <button onClick={(e) => { e.stopPropagation(); openFolderAtPath(fld.path); }} className="btn-ghost text-xs p-2 relative z-[1]" title="Apri nel Finder">
                        <FolderOpen size={14} />
                      </button>
                      <button onClick={(e) => { e.stopPropagation(); confirmRemoveFolder(idx); }} className="opacity-0 group-hover:opacity-100 p-2 text-text-dim hover:text-red-400 transition-all relative z-[1]">
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
          <div className="max-w-3xl mx-auto">
            <form onSubmit={addDeadline} className="mb-6 space-y-3">
              <div className="flex gap-2">
                <input
                  className="input-field flex-1"
                  placeholder="Descrizione scadenza..."
                  value={newDeadlineLabel}
                  onChange={e => setNewDeadlineLabel(e.target.value)}
                />
                <input
                  type="date"
                  className="input-field w-40"
                  value={newDeadlineDate}
                  onChange={e => setNewDeadlineDate(e.target.value)}
                />
                <input
                  type="time"
                  className="input-field w-28"
                  value={newDeadlineTime}
                  onChange={e => setNewDeadlineTime(e.target.value)}
                />
                <button
                  type="submit"
                  className="btn-primary px-4 flex items-center gap-1.5 text-xs font-bold"
                  disabled={!newDeadlineLabel.trim() || !newDeadlineDate}
                >
                  <Plus size={14} /> Aggiungi
                </button>
              </div>
              {/* Preavviso specifico – allineato con Agenda */}
              <div className="space-y-1.5">
                <span className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1 block">Preavviso Notifica</span>
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
                      className={`px-3 py-1.5 rounded-xl text-[10px] font-bold uppercase tracking-wider transition-all border ${
                        newDeadlineRemind === opt.value
                          ? 'bg-primary text-black border-primary shadow-[0_0_10px_rgba(212,169,64,0.25)]'
                          : 'bg-white/5 text-text-dim border-white/10 hover:bg-white/10 hover:text-text'
                      }`}
                    >
                      {opt.label}
                    </button>
                  ))}
                  {/* Pill orario personalizzato "Alle" */}
                  <div className={`inline-flex items-center rounded-xl border transition-all ${
                    newDeadlineRemind === 'custom'
                      ? 'border-primary bg-primary/10 shadow-[0_0_10px_rgba(212,169,64,0.25)]'
                      : 'border-white/10 bg-white/5 hover:bg-white/10'
                  }`}>
                    <button type="button"
                      onClick={() => setNewDeadlineRemind('custom')}
                      className={`px-2.5 py-1.5 text-[10px] font-bold uppercase tracking-wider transition-colors ${
                        newDeadlineRemind === 'custom' ? 'text-primary' : 'text-text-dim hover:text-text'
                      }`}>
                      Alle
                    </button>
                    <input
                      type="time"
                      value={newDeadlineCustomTime}
                      onFocus={() => setNewDeadlineRemind('custom')}
                      onChange={e => { setNewDeadlineCustomTime(e.target.value); setNewDeadlineRemind('custom'); }}
                      className="bg-transparent border-none outline-none text-[10px] font-mono text-white w-[52px] py-1 pr-2 focus:ring-0"
                    />
                  </div>
                </div>
                <p className="text-[9px] text-text-dim mt-0.5">«Standard» usa il preavviso globale. «Alle» invia la notifica all&apos;orario preciso scelto.</p>
              </div>
            </form>

            <div className="space-y-2">
              {(() => {
                const today = new Date(); today.setHours(0,0,0,0);
                // Combine practice deadlines + agenda scadenze linked to this practice
                const practiceDeadlines = (practice.deadlines || []).map((d, idx) => ({
                  ...d, source: 'practice', idx,
                }));
                const agendaDeadlines = (agendaEvents || [])
                  .filter(e => e.category === 'scadenza' && e.practiceId === practice.id && !e.autoSync && !e.completed)
                  .map(e => ({
                    label: e.title, date: e.date, source: 'agenda', id: e.id,
                  }));
                const allDeadlines = [...practiceDeadlines, ...agendaDeadlines]
                  .sort((a, b) => new Date(a.date) - new Date(b.date));

                if (allDeadlines.length === 0) {
                  return (
                    <div className="text-center py-10 text-text-dim">
                      <Calendar size={32} className="mx-auto mb-2 opacity-40" />
                      <p className="text-text-muted">Nessuna scadenza impostata</p>
                    </div>
                  );
                }

                return allDeadlines.map((d) => {
                  const dDate = new Date(d.date); dDate.setHours(0,0,0,0);
                  const diff = Math.ceil((dDate - today) / (1000 * 60 * 60 * 24));
                  const dotColor = getDeadlineDotColor(diff);
                  const deadlineLabel = getDeadlineLabel(diff);
                  const key = d.source === 'agenda' ? `agenda_${d.id}` : `${d.date}_${d.label}`;
                  
                  return (
                    <div key={key} className="glass-card p-3 flex items-center gap-4 group hover:border-primary/30 transition-colors">
                      <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${dotColor}`} />
                      
                      <div className="flex-1">
                         <p className="text-sm text-text font-medium">{d.label}</p>
                         <div className="flex items-center gap-2 flex-wrap">
                           <p className="text-xs text-text-dim">{formatDateIT(d.date, '')}</p>
                           {d.time && (
                             <span className="text-xs text-text-muted font-mono">ore {d.time}</span>
                           )}
                           {d.remindMinutes != null && (
                             <span className="text-[9px] font-bold text-amber-400/80 uppercase tracking-wider bg-amber-400/10 px-1.5 py-0.5 rounded">
                               🔔 {d.remindMinutes === 'custom'
                                 ? `alle ${d.customRemindTime || '—'}`
                                 : d.remindMinutes >= 1440
                                   ? `${d.remindMinutes / 1440}g`
                                   : d.remindMinutes >= 60
                                     ? `${d.remindMinutes / 60}h`
                                     : `${d.remindMinutes}min`}
                             </span>
                           )}
                           {d.source === 'agenda' && (
                             <span className="text-[9px] font-bold text-primary/60 uppercase tracking-wider bg-primary/5 px-1.5 py-0.5 rounded">Agenda</span>
                           )}
                         </div>
                      </div>

                      <div className="text-xs font-bold px-2 py-1 rounded bg-white/5 text-text-muted">
                        {deadlineLabel}
                      </div>

                      {d.source === 'practice' && (
                        <button onClick={() => confirmDeleteDeadline(d.idx)} className="opacity-0 group-hover:opacity-100 p-2 text-text-dim hover:text-red-400 transition-all">
                          <Trash2 size={16} />
                        </button>
                      )}
                    </div>
                  );
                });
              })()}
            </div>
          </div>
        )}

        {/* ═══ TAB: INFO PRATICA ═══ */}
        {activeTab === 'info' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 max-w-4xl mx-auto">
            {/* Dati Generali */}
            <div className="glass-card p-6">
              <h3 className="text-sm font-bold text-text-muted uppercase tracking-wider mb-5 border-b border-border pb-2">Dati Generali</h3>
              <div className="grid grid-cols-2 gap-y-5 gap-x-8 text-sm">
                <div>
                  <span className="block text-[10px] font-bold text-text-dim uppercase tracking-wider mb-1">Materia</span>
                  <span className="text-text font-medium capitalize">{
                    {civile:'Civile', penale:'Penale', lavoro:'Lavoro', amm:'Amministrativo', stra:'Stragiudiziale'}[practice.type] || practice.type
                  }</span>
                </div>
                <div>
                  <span className="block text-[10px] font-bold text-text-dim uppercase tracking-wider mb-1">Autorità</span>
                  <span className="text-text font-medium">{practice.court || '—'}</span>
                </div>
                <div>
                  <span className="block text-[10px] font-bold text-text-dim uppercase tracking-wider mb-1">Sede</span>
                  <span className="text-text font-medium">{practice.courtLocation || '—'}</span>
                </div>
                <div>
                  <span className="block text-[10px] font-bold text-text-dim uppercase tracking-wider mb-1">Riferimento</span>
                  <span className="text-text font-medium font-mono">{practice.code ? `RG ${practice.code}` : '—'}</span>
                </div>
                <div>
                  <span className="block text-[10px] font-bold text-text-dim uppercase tracking-wider mb-1">Apertura</span>
                  <span className="text-text font-medium">
                    {practice.createdAt ? new Date(practice.createdAt).toLocaleDateString('it-IT', { day: '2-digit', month: 'long', year: 'numeric' }) : '—'}
                  </span>
                </div>
              </div>
            </div>

            {/* Parti Coinvolte */}
            <div className="glass-card p-6">
              <h3 className="text-sm font-bold text-text-muted uppercase tracking-wider mb-5 border-b border-border pb-2 flex items-center gap-2">
                <Users size={14} className="text-primary/60" /> Parti Coinvolte
              </h3>
              <div className="space-y-4 text-sm">
                <div>
                  <span className="block text-[10px] font-bold text-text-dim uppercase tracking-wider mb-1">Cliente / Assistito</span>
                  <span className="text-text font-medium">{practice.client || '—'}</span>
                </div>
                <div>
                  <span className="block text-[10px] font-bold text-text-dim uppercase tracking-wider mb-1">Controparte</span>
                  <span className="text-text font-medium">{practice.counterparty || '—'}</span>
                </div>
              </div>
            </div>

            {/* Note Strategiche — full width */}
            <div className="glass-card p-6 lg:col-span-2">
              <h3 className="text-sm font-bold text-text-muted uppercase tracking-wider mb-5 border-b border-border pb-2">Note Strategiche</h3>
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
                  <p className="text-text-dim text-[10px]">Inserisci la Master Password per esportare</p>
                </div>
              </div>
              <button onClick={() => setShowExportPwdModal(false)} className="p-2 hover:bg-white/10 rounded-xl text-text-dim hover:text-text transition-all group">
                <X size={18} className="group-hover:rotate-90 transition-transform" />
              </button>
            </div>
            {/* Form */}
            <form onSubmit={handleExportWithPassword} className="px-6 pb-6">
              <input
                type="password"
                className="w-full py-3 px-4 rounded-xl bg-white/[0.05] border border-border text-text placeholder:text-text-dim text-sm focus:border-primary/40 outline-none transition-colors mb-4"
                placeholder="Master Password…"
                value={exportPwd}
                onChange={e => setExportPwd(e.target.value)}
                autoFocus
              />
              <div className="flex gap-3">
                <button type="button" onClick={() => setShowExportPwdModal(false)}
                  className="flex-1 py-2.5 rounded-xl border border-border text-text-dim text-xs font-bold uppercase tracking-widest hover:bg-white/5 hover:text-text transition-all">
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
};