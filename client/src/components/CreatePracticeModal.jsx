import { useState, useCallback, useRef } from 'react';
import PropTypes from 'prop-types';
import {
  X, User, Building, Scale, Hash, Save, FileText, Plus, FilePlus, AlertCircle, Trash2, MapPin
} from 'lucide-react';
import * as api from '../tauri-api';
import ModalOverlay from './ModalOverlay';

// Mappa delle classi CSS per materia (definite in index.css)
const MATERIA_CSS = {
  civile: 'materia-civile',
  penale: 'materia-penale',
  lavoro: 'materia-lavoro',
  amm: 'materia-amm',
  stra: 'materia-stra',
  soc: 'materia-soc',
};

const INITIAL_FORM = {
  client: '',
  object: '',
  type: 'civile',
  counterparty: '',
  court: '',
  courtLocation: '',
  code: '',
  description: '',
  status: 'active',
  biometricProtected: true,
  attachments: [],
};

// FIX-48: helper per determinare se ci sono modifiche non salvate
function isFormDirty(formData) {
  return formData.client.trim() !== ''
    || formData.object.trim() !== ''
    || formData.counterparty.trim() !== ''
    || formData.court.trim() !== ''
    || formData.courtLocation.trim() !== ''
    || formData.code.trim() !== ''
    || formData.description.trim() !== ''
    || formData.attachments.length > 0
    || formData.type !== INITIAL_FORM.type;
}

export default function CreatePracticeModal({ onClose, onSave }) {
  const [formData, setFormData] = useState(INITIAL_FORM);
  const [errors, setErrors] = useState({});
  const [submitting, setSubmitting] = useState(false);
  const [confirmCancel, setConfirmCancel] = useState(false);
  const formDirtyRef = useRef(false);

  // Helper to update a single field, clearing its error
  const updateField = useCallback((field, value) => {
    setFormData(prev => {
      const next = { ...prev, [field]: value };
      formDirtyRef.current = isFormDirty(next);
      return next;
    });
    setErrors(prev => {
      if (!prev[field]) return prev;
      const next = { ...prev };
      delete next[field];
      return next;
    });
  }, []);

  const handleSubmit = async (e) => {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    if (submitting) return;
    const newErrors = {};
    if (!formData.client.trim()) newErrors.client = 'Il cliente è obbligatorio';
    if (!formData.object.trim()) newErrors.object = 'L\'oggetto è obbligatorio';

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }

    try {
      setSubmitting(true);
      await onSave({
        ...formData,
        id: crypto.randomUUID(),
        createdAt: new Date().toISOString(),
      });
      onClose();
    } catch (err) {
      console.error('[CreatePractice] Save failed:', err);
    } finally {
      setSubmitting(false);
    }
  };

  // FIX-48: warning se ci sono modifiche non salvate
  const handleAttemptClose = () => {
    if (formDirtyRef.current) {
      setConfirmCancel(true);
      return;
    }
    onClose();
  };

  const handleRemoveAttachment = useCallback((path) => {
    setFormData(prev => {
      const next = { ...prev, attachments: prev.attachments.filter(f => f.path !== path) };
      formDirtyRef.current = isFormDirty(next);
      return next;
    });
  }, []);

  // Gestore caricamento file — usa dialog nativo Tauri
  const handleSelectFile = async () => {
    try {
      const result = await api.selectFile();
      if (result?.name && result?.path) {
        setFormData(prev => {
          const next = {
            ...prev,
            attachments: [...prev.attachments, { name: result.name, path: result.path, addedAt: new Date().toISOString() }],
          };
          formDirtyRef.current = isFormDirty(next);
          return next;
        });
      }
    } catch {
      // L'utente ha annullato il dialog — no action needed
      console.debug('[CreatePractice] File dialog cancelled');
    }
  };

  return (
    <ModalOverlay onClose={handleAttemptClose} labelledBy="create-practice-title" focusTrap>
      <div className="modal-card modal-card-lg flex flex-col max-h-[92vh]">

        {/* Header */}
        <div className="modal-header">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-primary/10 rounded-2xl flex items-center justify-center text-primary border border-primary/20">
              <Plus size={28} />
            </div>
            <div>
              <h2 id="create-practice-title" className="text-2xl font-bold text-text tracking-tight">Nuovo Fascicolo</h2>
              <p className="text-text-dim text-xs uppercase tracking-widest font-medium opacity-60">Configurazione Pratica Digitale</p>
            </div>
          </div>
          <button onClick={handleAttemptClose} className="p-2 hover:bg-card-hover rounded-xl text-text-dim transition-colors group" aria-label="Chiudi">
            <X size={24} className="group-hover:rotate-90 transition-transform" />
          </button>
        </div>

        {/* Form Body — FIX-44: <form> wrapping così Enter submette */}
        <form onSubmit={handleSubmit} className="flex flex-col flex-1 overflow-hidden">
          <div className="p-8 overflow-y-auto custom-scrollbar flex-1 space-y-8">

            {/* Cliente */}
            <div className="space-y-2">
              <label htmlFor="cpm-client" className="text-2xs font-black text-text-dim uppercase tracking-label ml-1 flex items-center gap-2">
                <User size={12} /> Cliente / Assistito <span className="text-primary">*</span>
              </label>
              <div className="relative group">
                <input
                  id="cpm-client"
                  /* FIX-45 + FIX-46 */
                  required
                  aria-required="true"
                  aria-invalid={!!errors.client}
                  aria-describedby={errors.client ? 'cpm-client-err' : undefined}
                  className={`input-field pl-5 w-full bg-surface border-border focus:border-primary/50 transition-colors ${errors.client ? 'border-danger-border bg-danger-soft' : ''}`}
                  placeholder="Inserisci il nome del cliente o della società..."
                  value={formData.client}
                  onChange={e => updateField('client', e.target.value)}
                />
              </div>
              {errors.client && (
                <p
                  id="cpm-client-err"
                  role="alert"
                  aria-live="polite"
                  className="text-danger text-2xs font-bold flex items-center gap-1 ml-1 mt-1"
                >
                  <AlertCircle size={10}/> {errors.client}
                </p>
              )}
            </div>

            {/* Materia con Pills Colorate */}
            <div className="space-y-3">
              <span id="cpm-type-label" className="text-2xs font-black text-text-dim uppercase tracking-label ml-1 block">Materia del Fascicolo</span>
              <div className="flex flex-wrap gap-2.5" role="radiogroup" aria-labelledby="cpm-type-label">
                {[
                  { id: 'civile', label: 'Civile' },
                  { id: 'penale', label: 'Penale' },
                  { id: 'lavoro', label: 'Lavoro' },
                  { id: 'amm', label: 'Amministrativo' },
                  { id: 'stra', label: 'Stragiudiziale' },
                  { id: 'soc', label: 'Societario' },
                ].map((m) => {
                  const selected = formData.type === m.id;
                  return (
                    <button
                      key={m.id}
                      type="button"
                      role="radio"
                      aria-checked={selected}
                      onClick={() => updateField('type', m.id)}
                      /* FIX-51: aggiunto transition-transform per animare lo scale */
                      className={`px-5 py-2.5 rounded-xl text-xs font-bold transition-colors transition-transform duration-300 border uppercase tracking-wider ${
                        selected
                          ? `${MATERIA_CSS[m.id]} scale-105 ring-2 ring-border`
                          : 'bg-surface border-border text-text-dim hover:bg-card hover:border-border'
                      }`}
                    >
                      {m.label}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Oggetto */}
            <div className="space-y-2">
              <label htmlFor="cpm-object" className="text-2xs font-black text-text-dim uppercase tracking-label ml-1">Oggetto della Pratica *</label>
              <input
                id="cpm-object"
                required
                aria-required="true"
                aria-invalid={!!errors.object}
                aria-describedby={errors.object ? 'cpm-object-err' : undefined}
                className={`input-field w-full bg-surface border-border ${errors.object ? 'border-danger-border bg-danger-soft' : ''}`}
                placeholder="Es. Recupero crediti o Descrizione sommaria..."
                value={formData.object}
                onChange={e => updateField('object', e.target.value)}
              />
              {errors.object && (
                <p
                  id="cpm-object-err"
                  role="alert"
                  aria-live="polite"
                  className="text-danger text-2xs font-bold flex items-center gap-1 ml-1"
                >
                  <AlertCircle size={10}/> {errors.object}
                </p>
              )}
            </div>

            {/* Grid Dati Tecnici */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
              <div className="space-y-2">
                <label htmlFor="cpm-counterparty" className="text-2xs font-black text-text-dim uppercase tracking-label ml-1">Controparte</label>
                <div className="relative group">
                  <Scale className="absolute left-4 top-1/2 -translate-y-1/2 text-text-dim group-focus-within:text-primary transition-colors" size={16} aria-hidden="true" />
                  <input
                    id="cpm-counterparty"
                    className="input-field pl-12 w-full bg-surface border-border"
                    placeholder="Parte avversa..."
                    value={formData.counterparty}
                    onChange={e => updateField('counterparty', e.target.value)}
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label htmlFor="cpm-court" className="text-2xs font-black text-text-dim uppercase tracking-label ml-1">Autorità</label>
                  <div className="relative group">
                    <Building className="absolute left-4 top-1/2 -translate-y-1/2 text-text-dim group-focus-within:text-primary transition-colors" size={16} aria-hidden="true" />
                    <input
                      id="cpm-court"
                      className="input-field pl-12 w-full bg-surface border-border"
                      placeholder="Tribunale, Corte, Giudice..."
                      value={formData.court}
                      onChange={e => updateField('court', e.target.value)}
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <label htmlFor="cpm-courtLocation" className="text-2xs font-black text-text-dim uppercase tracking-label ml-1">Sede</label>
                  <div className="relative group">
                    <MapPin className="absolute left-4 top-1/2 -translate-y-1/2 text-text-dim group-focus-within:text-primary transition-colors" size={16} aria-hidden="true" />
                    <input
                      id="cpm-courtLocation"
                      className="input-field pl-12 w-full bg-surface border-border"
                      placeholder="Città o sez..."
                      value={formData.courtLocation}
                      onChange={e => updateField('courtLocation', e.target.value)}
                    />
                  </div>
                </div>
              </div>

              <div className="space-y-2 md:col-span-2">
                <label htmlFor="cpm-code" className="text-2xs font-black text-text-dim uppercase tracking-label ml-1">Riferimento (RG / Rif. Interno)</label>
                <div className="relative group">
                  <Hash className="absolute left-4 top-1/2 -translate-y-1/2 text-text-dim group-focus-within:text-primary transition-colors" size={16} aria-hidden="true" />
                  <input
                    id="cpm-code"
                    className="input-field pl-12 w-full font-mono text-sm bg-surface border-border tracking-widest"
                    placeholder="Es. 4567/2026"
                    value={formData.code}
                    onChange={e => updateField('code', e.target.value)}
                  />
                </div>
              </div>
            </div>

            {/* Caricamento PDF — FIX-49 + FIX-50: separato il trigger button dalla file list */}
            <div className="space-y-3 pt-2">
              <span className="text-2xs font-black text-text-dim uppercase tracking-label ml-1 flex items-center gap-2">
                <FileText size={12} /> Documenti Allegati (PDF)
              </span>
              <button
                type="button"
                aria-label="Carica documenti PDF"
                className="border-2 border-dashed border-border rounded-[24px] p-8 flex flex-col items-center justify-center gap-3 hover:border-primary/40 hover:bg-primary/5 transition-colors cursor-pointer group w-full text-left"
                onClick={handleSelectFile}
              >
                <div className="w-14 h-14 bg-surface rounded-full flex items-center justify-center group-hover:scale-110 transition-transform">
                  <FilePlus size={28} className="text-text-dim group-hover:text-primary" />
                </div>
                <div className="text-center">
                  <p className="text-sm font-bold text-text">Carica documenti PDF</p>
                  <p className="text-2xs text-text-dim mt-1 opacity-60 italic">Il vault conserva i riferimenti ai file. I documenti originali restano nella posizione scelta.</p>
                </div>
              </button>

              {/* FIX-49: file list separata dal pulsante (no <button> dentro <button>) */}
              {formData.attachments.length > 0 && (
                <ul className="flex flex-wrap gap-2 mt-2" aria-label="File allegati">
                  {formData.attachments.map((f) => (
                    <li
                      key={f.path}
                      className="px-3 py-1 bg-primary text-3xs font-bold rounded-lg text-black uppercase tracking-tighter inline-flex items-center gap-1.5"
                    >
                      {/* FIX-52: title con nome completo per troncamenti */}
                      <span title={f.name}>
                        {f.name.length > 15 ? `${f.name.substring(0, 15)}…` : f.name}
                      </span>
                      <button
                        type="button"
                        onClick={() => handleRemoveAttachment(f.path)}
                        className="hover:text-danger transition-colors"
                        aria-label={`Rimuovi ${f.name}`}
                      >
                        <Trash2 size={10} />
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Note */}
            <div className="space-y-2">
              <label htmlFor="cpm-notes" className="text-2xs font-black text-text-dim uppercase tracking-label ml-1">Note / Strategia</label>
              <textarea
                id="cpm-notes"
                className="input-field w-full min-h-[120px] py-4 px-5 resize-none bg-surface border-border focus:bg-card transition-colors"
                placeholder="Annotazioni libere..."
                value={formData.description}
                onChange={e => updateField('description', e.target.value)}
              />
            </div>
          </div>

          {/* Footer */}
          <div className="modal-footer gap-4">
            <button type="button" onClick={handleAttemptClose} className="btn-cancel">
              Annulla
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="btn-primary px-10 py-3 flex items-center gap-3 hover:scale-[1.05] active:scale-[0.98] transition-colors transition-transform disabled:opacity-50"
            >
              <Save size={18} />
              <span className="font-black uppercase tracking-widest text-xs">Salva Fascicolo</span>
            </button>
          </div>
        </form>
      </div>

      {/* FIX-48: dialog di conferma annullamento */}
      {confirmCancel && (
        <ModalOverlay onClose={() => setConfirmCancel(false)} labelledBy="cpm-cancel-title" zIndex={10000}>
          <div className="modal-card modal-card-sm">
            <div className="px-6 pt-6 pb-3">
              <h3 id="cpm-cancel-title" className="text-text font-bold text-base">Modifiche non salvate</h3>
              <p className="text-text-dim text-sm mt-2">
                Hai inserito dati nel fascicolo. Se chiudi ora, tutte le modifiche andranno perse.
              </p>
            </div>
            <div className="px-6 pb-6 pt-2 flex gap-3">
              <button
                type="button"
                onClick={() => setConfirmCancel(false)}
                className="flex-1 py-2.5 rounded-xl border border-border text-text-dim text-xs font-bold uppercase tracking-widest hover:bg-surface hover:text-text transition-colors"
              >
                Continua a modificare
              </button>
              <button
                type="button"
                onClick={() => { setConfirmCancel(false); onClose(); }}
                className="flex-1 py-2.5 rounded-xl bg-danger text-white text-xs font-bold uppercase tracking-widest hover:bg-danger/90 transition-colors"
              >
                Scarta modifiche
              </button>
            </div>
          </div>
        </ModalOverlay>
      )}
    </ModalOverlay>
  );
}

CreatePracticeModal.propTypes = {
  onClose: PropTypes.func,
  onSave: PropTypes.func,
};
