import { useState, useEffect, useCallback, useRef } from 'react';
import PropTypes from 'prop-types';
import { 
  ArrowLeft, Calendar, FileText, 
  Clock, Plus, Trash2, Send, FolderOpen, 
  FolderPlus, Lock, ChevronDown,
  FilePlus, Info, Fingerprint, ShieldCheck, Download
} from 'lucide-react';
import { exportPracticePDF } from '../utils/pdfGenerator';
import ExportWarningModal from './ExportWarningModal';
import ConfirmDialog from './ConfirmDialog';
import toast from 'react-hot-toast';
import * as api from '../tauri-api';
import { formatDateIT } from '../utils/helpers';

/* ---------- Biometric Lock Screen (extracted to reduce cognitive complexity) ---------- */
function BiometricLockScreen({ practice, onBack, onUnlock }) {
  const [bioAttempted, setBioAttempted] = useState(false);
  const [showPasswordFallback, setShowPasswordFallback] = useState(false);
  const [practicePassword, setPracticePassword] = useState('');
  const [practicePasswordError, setPracticePasswordError] = useState('');

  useEffect(() => {
    if (!bioAttempted) {
      setBioAttempted(true);
      (async () => {
        try {
          const result = await api.bioLogin();
          if (result) onUnlock();
        } catch (err) {
          console.debug('[PracticeDetail] Biometric auth failed or dismissed', err);
        }
      })();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- onUnlock is stable via useCallback; bioAttempted gate prevents re-runs
  }, [bioAttempted]);

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
    <div className="h-full flex flex-col bg-[#0c0d14] animate-fade-in">
      <div className="flex items-center px-6 py-4 border-b border-[#22263a]">
        <button onClick={onBack} className="p-2 hover:bg-white/10 rounded-full transition-colors text-text-dim hover:text-white">
          <ArrowLeft size={20} />
        </button>
        <div className="ml-4">
          <h1 className="text-xl font-bold text-white">{practice.client}</h1>
          <p className="text-xs text-text-dim mt-0.5">{practice.code ? `RG ${practice.code}` : practice.object}</p>
        </div>
      </div>
      <div className="flex-1 flex items-center justify-center">
        <div className="text-center space-y-6 max-w-xs">
          <div className="w-20 h-20 rounded-2xl bg-primary/10 flex items-center justify-center mx-auto border border-primary/20 animate-pulse">
            <Fingerprint size={36} className="text-primary" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white mb-2">Verifica Identità</h2>
            <p className="text-sm text-text-muted">
              {bioAttempted ? 'Autenticazione non riuscita. Riprova o usa la password.' : 'Autenticazione biometrica in corso...'}
            </p>
          </div>
          {bioAttempted && !showPasswordFallback && (
            <div className="space-y-3">
              <button onClick={retryBiometric} className="btn-primary px-8 py-3 text-sm w-full">
                <Fingerprint size={18} /> Riprova Biometria
              </button>
              <button 
                onClick={() => setShowPasswordFallback(true)} 
                className="w-full text-text-dim hover:text-white text-xs font-semibold transition-colors py-2"
              >
                Usa la Master Password
              </button>
            </div>
          )}
          {showPasswordFallback && (
            <form onSubmit={handlePasswordFallback} className="space-y-3 text-left">
              <label htmlFor="pd-bio-pwd" className="text-[10px] font-bold text-text-dim uppercase tracking-[2px] ml-1 block">Master Password</label>
              <input
                id="pd-bio-pwd"
                type="password"
                className="input-field w-full py-3 px-4 rounded-xl bg-white/5 border-white/10 text-white placeholder:text-white/20 text-sm"
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
              <button 
                type="button"
                onClick={() => { setShowPasswordFallback(false); setPracticePassword(''); setPracticePasswordError(''); }} 
                className="w-full text-text-dim hover:text-white text-xs font-semibold transition-colors py-2"
              >
                Torna alla Biometria
              </button>
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
function getDeadlineDotColor(diff) {
  if (diff < 0) return 'bg-red-500';
  if (diff === 0) return 'bg-orange-500';
  if (diff > 0 && diff <= 3) return 'bg-yellow-500';
  return 'bg-blue-500';
}

function getDeadlineLabel(diff) {
  if (diff < 0) return `Scaduta da ${Math.abs(diff)}gg`;
  if (diff === 0) return 'OGGI';
  if (diff === 1) return 'Domani';
  return `tra ${diff}gg`;
}

/* ---------- File-type helpers (reduces cognitive complexity) ---------- */
const IMAGE_EXTS = new Set(['jpg','jpeg','png','gif','webp','svg','bmp','tiff']);
const DOC_EXTS   = new Set(['doc','docx','odt','rtf','txt']);
const SHEET_EXTS = new Set(['xls','xlsx','csv','ods']);

function getFileTypeInfo(name) {
  const ext = name.includes('.') ? name.split('.').pop().toLowerCase() : '';
  const isPDF   = ext === 'pdf';
  const isImage = IMAGE_EXTS.has(ext);
  const isDoc   = DOC_EXTS.has(ext);
  const isSheet = SHEET_EXTS.has(ext);
  return { ext, isPDF, isImage, isDoc, isSheet };
}

function getFileBgClass(isDir, { isPDF, isImage, isDoc, isSheet }) {
  if (isDir)   return 'bg-amber-500/10';
  if (isPDF)   return 'bg-red-500/10';
  if (isImage) return 'bg-purple-500/10';
  if (isDoc)   return 'bg-blue-500/10';
  if (isSheet) return 'bg-green-500/10';
  return 'bg-white/5';
}

function getFileIconClass({ isPDF, isImage, isDoc, isSheet }) {
  if (isPDF)   return 'text-red-400';
  if (isImage) return 'text-purple-400';
  if (isDoc)   return 'text-blue-400';
  if (isSheet) return 'text-green-400';
  return 'text-text-muted';
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
            ? 'bg-white/5 text-white border-white/10 hover:bg-white/10'
            : 'bg-white/5 text-text-dim border-white/10 hover:bg-white/10'
        }`}
      >
        <span className={`w-2 h-2 rounded-full ${status === 'active' ? 'bg-emerald-400' : 'bg-text-dim'}`} />
        {status === 'active' ? 'Attivo' : 'Archiviato'}
        <ChevronDown size={14} className="text-text-dim" />
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-2 bg-[#14151d] border border-white/10 rounded-xl shadow-2xl z-50 py-1 min-w-[200px] animate-fade-in">
          <button onClick={() => doSet('active')}
            className={`w-full flex items-center gap-3 px-4 py-3 text-xs hover:bg-white/5 transition-colors text-left ${status === 'active' ? 'bg-white/[0.03]' : ''}`}>
            <span className="w-2 h-2 rounded-full bg-emerald-400" /><span className="text-white font-medium">Attivo</span>
          </button>
          <button onClick={() => doSet('closed')}
            className={`w-full flex items-center gap-3 px-4 py-3 text-xs hover:bg-white/5 transition-colors text-left ${status === 'closed' ? 'bg-white/[0.03]' : ''}`}>
            <span className="w-2 h-2 rounded-full bg-text-dim" /><span className="text-white font-medium">Archiviato</span>
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
export default function PracticeDetail({ practice, onBack, onUpdate }) {
  const [activeTab, setActiveTab] = useState('diary'); // diary, docs, deadlines, info
  const [biometricVerified, setBiometricVerified] = useState(false);
  const [showExportWarning, setShowExportWarning] = useState(false);
  const [showExportPwdModal, setShowExportPwdModal] = useState(false);
  const [exportPwd, setExportPwd] = useState('');
  const [folderExpanded, setFolderExpanded] = useState(false);
  const [folderLoading, setFolderLoading] = useState(false);
  const [folderContents, setFolderContents] = useState([]);
  
  // Stati per i form
  const [newNote, setNewNote] = useState('');
  const [newDeadlineLabel, setNewDeadlineLabel] = useState('');
  const [newDeadlineDate, setNewDeadlineDate] = useState('');
  const [confirmDelete, setConfirmDelete] = useState(null);

  // --- Helpers ---
  const update = (changes) => onUpdate({ ...practice, ...changes });

  const handleBioUnlock = useCallback(() => setBiometricVerified(true), []);

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
      update({ folderPath: folder });
      toast.success('Cartella collegata');
    }
  };

  const openFolder = async () => {
    if (!practice.folderPath) return;
    try {
      await api.openPath(practice.folderPath);
    } catch {
      toast.error('Impossibile aprire la cartella');
    }
  };

  const toggleFolderContents = async () => {
    if (folderExpanded) { setFolderExpanded(false); return; }
    setFolderLoading(true);
    try {
      const res = await api.listFolderContents(practice.folderPath);
      setFolderContents(Array.isArray(res) ? res : []);
      setFolderExpanded(true);
    } catch (err) {
      console.error('[PracticeDetail] Folder listing failed:', err);
      toast.error('Errore lettura cartella');
    } finally {
      setFolderLoading(false);
    }
  };

  const folderButtonLabel = (() => {
    if (folderLoading) return 'Caricamento…';
    return folderExpanded ? 'Nascondi contenuto' : 'Mostra contenuto';
  })();

  const handleExport = () => {
    // Open the security warning modal first — actual export runs only on confirm.
    setShowExportWarning(true);
  };

  const handleExportConfirmed = async () => {
    setShowExportWarning(false);
    // Open password verification modal instead of prompt()
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
    const success = await exportPracticePDF(practice);
    if (success) toast.success('PDF salvato correttamente');
  };

  // --- Handlers: PDF Upload ---
  const handleUploadPDF = async () => {
    try {
      const result = await api.selectFile();
      if (result?.name && result?.path) {
        const attachments = [...(practice.attachments || []), { name: result.name, path: result.path, addedAt: new Date().toISOString() }];
        update({ attachments });
        toast.success('Documento aggiunto al vault');
      }
    } catch (err) {
      console.error('[PracticeDetail] File upload failed:', err);
      toast.error('Errore nel caricamento');
    }
  };

  const removeAttachment = (idx) => {
    const attachments = (practice.attachments || []).filter((_, i) => i !== idx);
    update({ attachments });
    toast.success('Documento rimosso');
  };

  const confirmRemoveAttachment = (idx) => {
    setConfirmDelete({
      message: 'Rimuovere questo documento dal vault?',
      onConfirm: () => { removeAttachment(idx); setConfirmDelete(null); },
    });
  };

  // --- Handlers: Diary ---
  const addNote = (e) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    const note = { text: newNote, date: new Date().toISOString() };
    update({ diary: [note, ...(practice.diary || [])] });
    setNewNote('');
    toast.success('Nota aggiunta');
  };

  const deleteNote = (idx) => {
    const updatedDiary = (practice.diary || []).filter((_, i) => i !== idx);
    update({ diary: updatedDiary });
    toast.success('Nota eliminata');
  };

  const confirmDeleteNote = (idx) => {
    setConfirmDelete({
      message: 'Eliminare questa nota dal diario?',
      onConfirm: () => { deleteNote(idx); setConfirmDelete(null); },
    });
  };

  // --- Handlers: Deadlines ---
  const addDeadline = (e) => {
    e.preventDefault();
    if (!newDeadlineLabel.trim() || !newDeadlineDate) return;
    
    const deadlines = [...(practice.deadlines || []), { 
      date: newDeadlineDate, 
      label: newDeadlineLabel.trim() 
    }];
    deadlines.sort((a, b) => new Date(a.date) - new Date(b.date));
    
    update({ deadlines });
    setNewDeadlineLabel('');
    setNewDeadlineDate('');
    toast.success('Scadenza aggiunta');
  };

  const deleteDeadline = (idx) => {
    const deadlines = (practice.deadlines || []).filter((_, i) => i !== idx);
    update({ deadlines });
    toast.success('Scadenza eliminata');
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
    { id: 'docs', label: 'Documenti', icon: FileText, count: (practice.attachments || []).length },
    { id: 'deadlines', label: 'Scadenze', icon: Calendar, count: (practice.deadlines || []).length },
    { id: 'info', label: 'Info', icon: Info, count: 0 },
  ];

  return (
    <div className="h-full flex flex-col bg-[#0c0d14] animate-fade-in">
      {/* Top Bar */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#22263a] bg-[#0c0d14]/50 backdrop-blur-md sticky top-0 z-10">
        <div className="flex items-center gap-4">
          <button onClick={onBack} className="p-2 hover:bg-white/10 rounded-full transition-colors text-text-dim hover:text-white">
            <ArrowLeft size={20} />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-white">{practice.client}</h1>
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
            onChangeStatus={(newStatus) => {
              update({ status: newStatus });
              toast.success(newStatus === 'active' ? 'Fascicolo riaperto' : 'Fascicolo archiviato');
            }}
          />
        </div>
      </div>

      {/* Tabs — Segmented Control moderno */}
      <div className="px-6 py-3 border-b border-[#22263a]">
        <div className="inline-flex bg-white/[0.04] rounded-xl p-1 border border-white/5">
          {TABS.map(({ id, label, icon: Icon, count }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-all duration-200 ${
                activeTab === id 
                  ? 'bg-primary text-black shadow-[0_0_12px_rgba(212,169,64,0.25)]' 
                  : 'text-text-dim hover:text-white hover:bg-white/[0.06]'
              }`}
            >
              <Icon size={14} />
              {label}
              {count > 0 && (
                <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${
                  activeTab === id ? 'bg-black/20 text-black' : 'bg-white/10 text-text-dim'
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
              <div className="flex items-center justify-between mb-4">
                <span className="text-[10px] font-black text-text-dim uppercase tracking-[2px]">
                  {practice.diary.length} {practice.diary.length === 1 ? 'annotazione' : 'annotazioni'}
                </span>
                <button
                  onClick={handleExport}
                  className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold bg-white/[0.04] text-text-muted border border-white/5 hover:bg-white/[0.08] hover:text-white transition-all"
                >
                  <Download size={14} />
                  Esporta PDF
                </button>
              </div>
            )}
            <div className="flex-1 space-y-6 mb-6">
               {(!practice.diary || practice.diary.length === 0) && (
                <div className="text-center py-10 text-text-dim">
                  <Clock size={32} className="mx-auto mb-2 opacity-50" />
                  <p>Il diario è vuoto. Aggiungi note o verbali.</p>
                </div>
              )}
              {practice.diary?.map((note, idx) => (
                <div key={note.date + idx} className="flex gap-4 group">
                  <div className="flex flex-col items-center">
                    <div className="w-2 h-2 rounded-full bg-primary mt-2" />
                    <div className="w-px h-full bg-[#22263a] my-1" />
                  </div>
                  <div className="flex-1 glass-card p-4 relative">
                    <div className="flex justify-between items-start mb-2">
                      <span className="text-xs font-mono text-primary bg-primary/10 px-2 py-0.5 rounded border border-primary/20">
                        {new Date(note.date).toLocaleDateString('it-IT')} • {new Date(note.date).toLocaleTimeString('it-IT', {hour:'2-digit', minute:'2-digit'})}
                      </span>
                      <button onClick={() => confirmDeleteNote(idx)} className="opacity-0 group-hover:opacity-100 text-text-dim hover:text-red-400 transition-opacity">
                         <Trash2 size={14} />
                      </button>
                    </div>
                    <p className="text-sm text-text-muted whitespace-pre-wrap">{note.text}</p>
                  </div>
                </div>
              ))}
            </div>

            <form onSubmit={addNote} className="sticky bottom-0 bg-[#0c0d14] pt-4 border-t border-[#22263a]">
              <div className="relative">
                <textarea
                  className="input-field w-full min-h-[80px] pr-12 resize-none"
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
                  className="absolute right-3 bottom-3 p-2 bg-primary text-white rounded-lg hover:bg-primary-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  <Send size={16} />
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
                  <p className="text-base font-bold text-white">Carica Documento</p>
                  <p className="text-[10px] text-text-dim uppercase tracking-wider mt-1">Aggiungi file al vault crittografato</p>
                </div>
              </button>

              {practice.folderPath ? (
                <button 
                  type="button"
                  onClick={openFolder}
                  className="glass-card p-6 flex items-center gap-4 border border-white/5 cursor-pointer hover:bg-white/5 hover:border-white/15 transition-all group text-left w-full"
                >
                  <div className="w-12 h-12 rounded-xl bg-white/5 flex items-center justify-center flex-shrink-0 group-hover:scale-110 transition-transform">
                    <FolderOpen size={24} className="text-text-muted" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-base font-bold text-white">Apri Cartella</p>
                    <p className="text-[10px] text-text-dim uppercase tracking-wider mt-1 truncate">{practice.folderPath.split('/').pop()}</p>
                  </div>
                </button>
              ) : (
                <button 
                  type="button"
                  onClick={linkFolder}
                  className="glass-card p-6 flex items-center gap-4 border border-dashed border-white/10 cursor-pointer hover:bg-white/5 hover:border-white/20 transition-all group text-left w-full"
                >
                  <div className="w-12 h-12 rounded-xl bg-white/5 flex items-center justify-center flex-shrink-0 group-hover:scale-110 transition-transform">
                    <FolderPlus size={24} className="text-text-dim group-hover:text-white transition-colors" />
                  </div>
                  <div>
                    <p className="text-base font-bold text-white">Collega Cartella</p>
                    <p className="text-[10px] text-text-dim uppercase tracking-wider mt-1">Associa una cartella locale al fascicolo</p>
                  </div>
                </button>
              )}
            </div>

            {/* Lista allegati crittografati */}
            <div>
              <h3 className="text-[10px] font-black text-text-dim uppercase tracking-[2px] mb-4">Documenti Allegati</h3>
              {(!practice.attachments || practice.attachments.length === 0) ? (
                <div className="glass-card p-8 flex flex-col items-center justify-center text-center border border-dashed border-white/10">
                  <FileText size={28} className="text-text-dim/30 mb-3" />
                  <p className="text-sm text-text-dim">Nessun documento allegato</p>
                  <p className="text-xs text-text-dim/60 mt-1">Carica PDF o documenti nel vault crittografato</p>
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
                        <p className="text-sm text-white truncate">{att.name}</p>
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

            {/* ═══ FOLDER VIEWER — Contenuto cartella collegata ═══ */}
            {practice.folderPath && (
              <div className="mt-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-[10px] font-black text-text-dim uppercase tracking-[2px]">Cartella Collegata</h3>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-text-dim truncate max-w-[200px]" title={practice.folderPath}>{practice.folderPath.split('/').pop()}</span>
                    <button 
                      onClick={toggleFolderContents} 
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-white/10 bg-white/[0.03] text-[10px] font-bold text-text-muted hover:bg-white/[0.06] hover:text-white transition-all"
                    >
                      <ChevronDown size={12} className={`transition-transform ${folderExpanded ? 'rotate-180' : ''}`} />
                      {folderButtonLabel}
                    </button>
                  </div>
                </div>

                {folderExpanded && (
                  <div className="space-y-1.5 animate-fade-in">
                    {folderContents.length === 0 ? (
                      <div className="glass-card p-6 flex flex-col items-center justify-center text-center border border-dashed border-white/10">
                        <FolderOpen size={24} className="text-text-dim/30 mb-2" />
                        <p className="text-sm text-text-dim">Cartella vuota</p>
                      </div>
                    ) : (
                      <>
                        <div className="text-[10px] text-text-dim mb-2">{folderContents.length} {folderContents.length === 1 ? 'elemento' : 'elementi'}</div>
                        {folderContents.map((it) => {
                          const fileInfo = getFileTypeInfo(it.name);
                          const bgClass = getFileBgClass(it.is_dir, fileInfo);
                          const iconClass = getFileIconClass(fileInfo);
                          return (
                            <button type="button" key={it.path} onClick={() => api.openPath(it.path)}
                              className="glass-card p-3 flex items-center gap-3 cursor-pointer hover:border-primary/30 hover:bg-white/[0.03] transition-all text-left w-full group"
                            >
                              <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 ${bgClass}`}>
                                {it.is_dir
                                  ? <FolderOpen size={18} className="text-amber-400"/>
                                  : <FileText size={18} className={iconClass}/>
                                }
                              </div>
                              <div className="flex-1 min-w-0">
                                <p className="text-sm text-white truncate group-hover:text-primary transition-colors">{it.name}</p>
                                <div className="flex items-center gap-2 mt-0.5">
                                  {fileInfo.ext && !it.is_dir && <span className="text-[9px] font-bold uppercase text-text-dim bg-white/5 px-1.5 py-0.5 rounded">{fileInfo.ext}</span>}
                                  <span className="text-[10px] text-text-dim">{it.is_dir ? 'Cartella' : 'File'}</span>
                                  {it.modified && <span className="text-[10px] text-text-dim">{formatDateIT(it.modified, '')}</span>}
                                </div>
                              </div>
                            </button>
                          );
                        })}
                      </>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* ═══ TAB: SCADENZE ═══ */}
        {activeTab === 'deadlines' && (
          <div className="max-w-3xl mx-auto">
            <form onSubmit={addDeadline} className="mb-6 flex gap-2">
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
              <button
                type="submit"
                className="btn-primary px-3"
                disabled={!newDeadlineLabel.trim() || !newDeadlineDate}
              >
                <Plus size={16} />
              </button>
            </form>

            <div className="space-y-2">
              {(!practice.deadlines || practice.deadlines.length === 0) ? (
                 <div className="text-center py-10 text-text-dim">
                  <Calendar size={32} className="mx-auto mb-2 opacity-50" />
                  <p>Nessuna scadenza impostata</p>
                </div>
              ) : (() => {
                const today = new Date(); today.setHours(0,0,0,0);
                return practice.deadlines.map((d, idx) => {
                  const dDate = new Date(d.date); dDate.setHours(0,0,0,0);
                  const diff = Math.ceil((dDate - today) / (1000 * 60 * 60 * 24));
                  const dotColor = getDeadlineDotColor(diff);
                  const deadlineLabel = getDeadlineLabel(diff);
                  
                  return (
                    <div key={d.date + d.label} className="glass-card p-3 flex items-center gap-4 group hover:border-primary/30 transition-colors">
                      <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${dotColor}`} />
                      
                      <div className="flex-1">
                         <p className="text-sm text-white font-medium">{d.label}</p>
                         <p className="text-xs text-text-dim">{formatDateIT(d.date, '')}</p>
                      </div>

                      <div className="text-xs font-bold px-2 py-1 rounded bg-white/5 text-text-muted">
                        {deadlineLabel}
                      </div>

                      <button onClick={() => confirmDeleteDeadline(idx)} className="opacity-0 group-hover:opacity-100 p-2 text-text-dim hover:text-red-400 transition-all">
                        <Trash2 size={16} />
                      </button>
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
              <h3 className="text-sm font-bold text-text-muted uppercase tracking-wider mb-5 border-b border-white/5 pb-2">Dati Generali</h3>
              <div className="grid grid-cols-2 gap-y-5 gap-x-8 text-sm">
                <div>
                  <span className="block text-[10px] font-bold text-text-dim uppercase tracking-wider mb-1">Materia</span>
                  <span className="text-white font-medium capitalize">{
                    {civile:'Civile', penale:'Penale', lavoro:'Lavoro', amm:'Amministrativo', stra:'Stragiudiziale'}[practice.type] || practice.type
                  }</span>
                </div>
                <div>
                  <span className="block text-[10px] font-bold text-text-dim uppercase tracking-wider mb-1">Controparte</span>
                  <span className="text-white font-medium">{practice.counterparty || 'N/A'}</span>
                </div>
                <div>
                  <span className="block text-[10px] font-bold text-text-dim uppercase tracking-wider mb-1">Tribunale</span>
                  <span className="text-white font-medium">{practice.court || 'N/A'}</span>
                </div>
                <div>
                  <span className="block text-[10px] font-bold text-text-dim uppercase tracking-wider mb-1">Apertura</span>
                  <span className="text-white font-medium">
                    {practice.createdAt ? new Date(practice.createdAt).toLocaleDateString('it-IT', { day: '2-digit', month: 'long', year: 'numeric' }) : 'N/A'}
                  </span>
                </div>
              </div>
            </div>

            {/* Note Strategiche */}
            <div className="glass-card p-6">
              <h3 className="text-sm font-bold text-text-muted uppercase tracking-wider mb-5 border-b border-white/5 pb-2">Note Strategiche</h3>
              <p className="text-sm text-text-muted whitespace-pre-line leading-relaxed">
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

      {/* Password verification modal for PDF export (replaces prompt()) */}
      {showExportPwdModal && (
        <dialog className="modal-backdrop" open aria-modal="true" onCancel={() => setShowExportPwdModal(false)}>
          <button type="button" className="absolute inset-0 cursor-default" aria-label="Chiudi" onClick={() => setShowExportPwdModal(false)} tabIndex={-1} />
          <div className="glass-card border border-white/10 shadow-2xl p-6 animate-fade-in relative z-10" style={{ maxWidth: 380, width: '100%' }}>
            <div className="flex items-center gap-3 mb-4">
              <div className="w-9 h-9 rounded-xl bg-primary/10 flex items-center justify-center border border-primary/20">
                <Lock size={18} className="text-primary" />
              </div>
              <div>
                <h3 className="text-white font-bold text-sm">Verifica Identità</h3>
                <p className="text-text-dim text-[10px]">Inserisci la Master Password per esportare</p>
              </div>
            </div>
            <form onSubmit={handleExportWithPassword}>
              <input
                type="password"
                className="w-full py-3 px-4 rounded-xl bg-white/5 border border-white/10 text-white placeholder:text-white/20 text-sm focus:border-primary/40 outline-none transition-colors mb-4"
                placeholder="Master Password…"
                value={exportPwd}
                onChange={e => setExportPwd(e.target.value)}
                autoFocus
              />
              <div className="flex gap-3">
                <button type="button" onClick={() => setShowExportPwdModal(false)}
                  className="flex-1 py-2.5 rounded-xl border border-white/10 text-text-muted text-xs font-bold uppercase tracking-widest hover:bg-white/5 transition-colors">
                  Annulla
                </button>
                <button type="submit" disabled={!exportPwd}
                  className="flex-1 py-2.5 rounded-xl btn-primary text-xs font-bold uppercase tracking-widest disabled:opacity-50">
                  Esporta PDF
                </button>
              </div>
            </form>
          </div>
        </dialog>
      )}

      {confirmDelete && (
        <ConfirmDialog
          message={confirmDelete.message}
          onConfirm={confirmDelete.onConfirm}
          onCancel={() => setConfirmDelete(null)}
        />
      )}
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
};