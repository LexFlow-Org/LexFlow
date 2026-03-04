import { useState, useCallback } from 'react';
import PropTypes from 'prop-types';
import { 
  X, User, Building, Scale, Hash, Save, FileText, Plus, FilePlus, AlertCircle, Trash2 
} from 'lucide-react';
import * as api from '../tauri-api';
import ModalOverlay from './ModalOverlay';

// Mappa dei colori dinamici per materia (Premium Glow Style)
const MATERIA_COLORS = {
  civile: 'bg-blue-500/10 text-blue-400 border-blue-500/50 shadow-[0_0_15px_rgba(59,130,246,0.15)]',
  penale: 'bg-red-500/10 text-red-400 border-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.15)]',
  lavoro: 'bg-orange-500/10 text-orange-400 border-orange-500/50 shadow-[0_0_15px_rgba(249,115,22,0.15)]',
  amm: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/50 shadow-[0_0_15px_rgba(16,185,129,0.15)]',
  stra: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/50 shadow-[0_0_15px_rgba(234,179,8,0.15)]',
};

export default function CreatePracticeModal({ onClose, onSave }) {
  const [formData, setFormData] = useState({
    client: '',
    object: '',
    type: 'civile',
    counterparty: '',
    court: '',
    code: '',
    description: '',
    status: 'active',
    biometricProtected: true,
    attachments: [] // Stato per i file PDF
  });

  const [errors, setErrors] = useState({});

  // Helper to update a single field, clearing its error
  const updateField = useCallback((field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    setErrors(prev => {
      if (!prev[field]) return prev;
      const next = { ...prev };
      delete next[field];
      return next;
    });
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const newErrors = {};
    if (!formData.client.trim()) newErrors.client = 'Il cliente è obbligatorio';
    if (!formData.object.trim()) newErrors.object = 'L\'oggetto è obbligatorio';

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }

    try {
      await onSave({
        ...formData,
        id: crypto.randomUUID(),
        createdAt: new Date().toISOString()
      });
      onClose();
    } catch (err) {
      console.error('[CreatePractice] Save failed:', err);
    }
  };

  const handleRemoveAttachment = useCallback((path) => {
    setFormData(prev => ({
      ...prev,
      attachments: prev.attachments.filter(f => f.path !== path)
    }));
  }, []);

  // Gestore caricamento file — usa dialog nativo Tauri
  const handleSelectFile = async () => {
    try {
      const result = await api.selectFile();
      if (result?.name && result?.path) {
        setFormData(prev => ({
          ...prev,
          attachments: [...prev.attachments, { name: result.name, path: result.path, addedAt: new Date().toISOString() }]
        }));
      }
    } catch {
      // L'utente ha annullato il dialog — no action needed
      console.debug('[CreatePractice] File dialog cancelled');
    }
  };

  return (
    <ModalOverlay onClose={onClose} labelledBy="create-practice-title" focusTrap>
      <div className="bg-[#0f1016] border border-white/10 rounded-[32px] w-full max-w-2xl shadow-3xl overflow-hidden flex flex-col max-h-[92vh]">
        
        {/* Header */}
        <div className="px-8 py-6 border-b border-white/5 flex items-center justify-between bg-gradient-to-r from-white/5 to-transparent">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-primary/10 rounded-2xl flex items-center justify-center text-primary border border-primary/20">
              <Plus size={28} />
            </div>
            <div>
              <h2 id="create-practice-title" className="text-2xl font-bold text-white tracking-tight">Nuovo Fascicolo</h2>
              <p className="text-text-dim text-xs uppercase tracking-widest font-medium opacity-60">Configurazione Pratica Digitale</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-white/10 rounded-xl text-text-dim transition-all group">
            <X size={24} className="group-hover:rotate-90 transition-transform" />
          </button>
        </div>

        {/* Form Body */}
        <div className="p-8 overflow-y-auto custom-scrollbar flex-1 space-y-8">
          
          {/* Cliente */}
          <div className="space-y-2">
            <label htmlFor="cpm-client" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1 flex items-center gap-2">
              <User size={12} /> Cliente / Assistito <span className="text-primary">*</span>
            </label>
            <div className="relative group">
              <input
                id="cpm-client"
                className={`input-field pl-5 w-full bg-white/5 border-white/10 focus:border-primary/50 transition-all ${errors.client ? 'border-red-500/50 bg-red-500/5' : ''}`}
                placeholder="Inserisci il nome del cliente o della società..."
                value={formData.client}
                onChange={e => updateField('client', e.target.value)}
              />
            </div>
            {errors.client && <p className="text-red-400 text-[10px] font-bold flex items-center gap-1 ml-1 mt-1 animate-pulse"><AlertCircle size={10}/> {errors.client}</p>}
          </div>

          {/* Materia con Pills Colorate */}
          <div className="space-y-3">
            <label htmlFor="cpm-type" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Materia del Fascicolo</label>
            <div className="flex flex-wrap gap-2.5">
              {[
                { id: 'civile', label: 'Civile' },
                { id: 'penale', label: 'Penale' },
                { id: 'lavoro', label: 'Lavoro' },
                { id: 'amm', label: 'Amministrativo' },
                { id: 'stra', label: 'Stragiudiziale' }
              ].map((m) => (
                <button
                  key={m.id}
                  type="button"
                  onClick={() => updateField('type', m.id)}
                  className={`px-5 py-2.5 rounded-xl text-xs font-bold transition-all duration-300 border uppercase tracking-wider ${
                    formData.type === m.id
                      ? `${MATERIA_COLORS[m.id]} scale-105 ring-2 ring-white/5`
                      : 'bg-white/5 border-white/10 text-text-dim hover:bg-white/10 hover:border-white/20'
                  }`}
                >
                  {m.label}
                </button>
              ))}
            </div>
          </div>

          {/* Oggetto */}
          <div className="space-y-2">
            <label htmlFor="cpm-object" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Oggetto della Pratica *</label>
            <input
              id="cpm-object"
              className={`input-field w-full bg-white/5 border-white/10 ${errors.object ? 'border-red-500/50 bg-red-500/5' : ''}`}
              placeholder="Es. Recupero crediti o Descrizione sommaria..."
              value={formData.object}
              onChange={e => updateField('object', e.target.value)}
            />
            {errors.object && <p className="text-red-400 text-[10px] font-bold flex items-center gap-1 ml-1 animate-pulse"><AlertCircle size={10}/> {errors.object}</p>}
          </div>

          {/* Grid Dati Tecnici */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
            <div className="space-y-2">
              <label htmlFor="cpm-counterparty" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Controparte</label>
              <div className="relative group">
                <Scale className="absolute left-4 top-1/2 -translate-y-1/2 text-text-dim group-focus-within:text-primary transition-colors" size={16} />
                <input
                  id="cpm-counterparty"
                  className="input-field pl-12 w-full bg-white/5 border-white/10"
                  placeholder="Parte avversa..."
                  value={formData.counterparty}
                  onChange={e => updateField('counterparty', e.target.value)}
                />
              </div>
            </div>

            <div className="space-y-2">
              <label htmlFor="cpm-court" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Autorità / Tribunale</label>
              <div className="relative group">
                <Building className="absolute left-4 top-1/2 -translate-y-1/2 text-text-dim group-focus-within:text-primary transition-colors" size={16} />
                <input
                  id="cpm-court"
                  className="input-field pl-12 w-full bg-white/5 border-white/10"
                  placeholder="Sede o Giudice..."
                  value={formData.court}
                  onChange={e => updateField('court', e.target.value)}
                />
              </div>
            </div>

            <div className="space-y-2 md:col-span-2">
              <label htmlFor="cpm-code" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Riferimento (RG / Rif. Interno)</label>
              <div className="relative group">
                <Hash className="absolute left-4 top-1/2 -translate-y-1/2 text-text-dim group-focus-within:text-primary transition-colors" size={16} />
                <input
                  id="cpm-code"
                  className="input-field pl-12 w-full font-mono text-sm bg-white/5 border-white/10 tracking-widest"
                  placeholder="Es. 4567/2026"
                  value={formData.code}
                  onChange={e => updateField('code', e.target.value)}
                />
              </div>
            </div>
          </div>

          {/* Caricamento PDF (Nuova Sezione richiesta) */}
          <div className="space-y-3 pt-2">
            <label htmlFor="cpm-docs" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1 flex items-center gap-2">
              <FileText size={12} /> Documenti Allegati (PDF)
            </label>
            <button 
              id="cpm-docs"
              type="button"
              className="border-2 border-dashed border-white/10 rounded-[24px] p-8 flex flex-col items-center justify-center gap-3 hover:border-primary/40 hover:bg-primary/5 transition-all cursor-pointer group relative w-full text-left"
              onClick={handleSelectFile}
            >
              <div className="w-14 h-14 bg-white/5 rounded-full flex items-center justify-center group-hover:scale-110 transition-transform">
                <FilePlus size={28} className="text-text-dim group-hover:text-primary" />
              </div>
              <div className="text-center">
                <p className="text-sm font-bold text-white">Carica documenti PDF</p>
                <p className="text-[10px] text-text-dim mt-1 opacity-60 italic">I file verranno cifrati nel vault</p>
              </div>
              
              {/* Visualizzazione file pronti */}
              {formData.attachments.length > 0 && (
                <div className="mt-4 flex flex-wrap gap-2 justify-center">
                  {formData.attachments.map((f) => (
                    <span key={f.path} className="px-3 py-1 bg-primary text-[9px] font-bold rounded-lg text-white uppercase tracking-tighter inline-flex items-center gap-1.5">
                      {f.name.length > 15 ? `${f.name.substring(0, 15)}…` : f.name}
                      <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); handleRemoveAttachment(f.path); }}
                        className="hover:text-red-300 transition-colors"
                        aria-label={`Rimuovi ${f.name}`}
                      >
                        <Trash2 size={10} />
                      </button>
                    </span>
                  ))}
                </div>
              )}
            </button>
          </div>

          {/* Note */}
          <div className="space-y-2">
            <label htmlFor="cpm-notes" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Note / Strategia</label>
            <textarea
              id="cpm-notes"
              className="input-field w-full min-h-[120px] py-4 px-5 resize-none bg-white/5 border-white/10 focus:bg-white/10 transition-all"
              placeholder="Annotazioni libere..."
              value={formData.description}
              onChange={e => updateField('description', e.target.value)}
            />
          </div>
        </div>

        {/* Footer */}
        <div className="px-8 py-6 border-t border-white/5 bg-[#14151d] flex justify-end gap-4">
          <button 
            onClick={onClose} 
            className="px-6 py-3 rounded-2xl text-text-dim hover:text-white hover:bg-white/5 transition-all text-xs font-bold uppercase tracking-widest"
          >
            Annulla
          </button>
          <button 
            onClick={handleSubmit} 
            className="btn-primary px-10 py-3 flex items-center gap-3 shadow-xl shadow-primary/20 hover:scale-[1.05] active:scale-[0.98] transition-all"
          >
            <Save size={18} />
            <span className="font-black uppercase tracking-widest text-xs">Salva Fascicolo</span>
          </button>
        </div>
      </div>
    </ModalOverlay>
  );
}

CreatePracticeModal.propTypes = {
  onClose: PropTypes.func,
  onSave: PropTypes.func,
};