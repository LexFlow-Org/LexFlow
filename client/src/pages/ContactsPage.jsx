import { useState, useEffect, useCallback, useMemo, useRef, memo } from 'react';
import PropTypes from 'prop-types';
import { Users, Plus, Search, User, Scale, Briefcase, Building, Gavel, UserCheck, Edit3, Trash2, X, Check, Phone, Mail, MapPin, Hash, ChevronRight, Info, Shield } from 'lucide-react';
import toast from 'react-hot-toast';
import * as api from '../tauri-api';
import ConfirmDialog from '../components/ConfirmDialog';
import ModalOverlay from '../components/ModalOverlay';
import ConflictCheckPanel from '../components/ConflictCheckPanel';
import { ROLE_LABELS } from '../utils/conflictConstants';
import { genId } from '../utils/helpers';

const CONTACT_TYPES = [
  { id: 'client', label: 'Cliente', icon: User, color: 'text-materia-civile bg-materia-civile/10 border-materia-civile/20' },
  { id: 'counterparty', label: 'Controparte', icon: Scale, color: 'text-materia-penale bg-materia-penale/10 border-materia-penale/20' },
  { id: 'opposing_counsel', label: 'Avv. Controparte', icon: UserCheck, color: 'text-materia-lavoro bg-materia-lavoro/10 border-materia-lavoro/20' },
  { id: 'judge', label: 'Giudice', icon: Gavel, color: 'text-contact-judge bg-contact-judge/10 border-contact-judge/20' },
  { id: 'consultant', label: 'Consulente', icon: Briefcase, color: 'text-contact-consultant bg-contact-consultant/10 border-contact-consultant/20' },
  { id: 'other', label: 'Altro', icon: Users, color: 'text-text-dim bg-surface border-border' },
];

const TYPE_MAP = Object.fromEntries(CONTACT_TYPES.map(t => [t.id, t]));

const ROLE_PAIRS = [
  { role: 'counterparty', field: 'counterpartyId', label: 'Controparte' },
  { role: 'opposing_counsel', field: 'opposingCounselId', label: 'Avv. Controparte' },
  { role: 'client', field: 'clientId', label: 'Cliente' },
  { role: 'judge', field: 'judgeId', label: 'Giudice' },
];

export default function ContactsPage({ practices, onSelectPractice }) {
  const [activeTab, setActiveTab] = useState('contacts');
  const [contacts, setContacts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [showCreate, setShowCreate] = useState(false);
  const [editingContact, setEditingContact] = useState(null);
  const [expandedId, setExpandedId] = useState(null);
  const [pendingDeleteId, setPendingDeleteId] = useState(null);
  const prevContactsRef = useRef([]);

  useEffect(() => {
    (async () => {
      try {
        const data = await api.loadContacts();
        setContacts(data || []);
      } catch (e) { console.error(e); toast.error('Errore caricamento contatti'); }
      setLoading(false);
    })();
  }, []);

  const saveContacts = useCallback(async (newContacts) => {
    const backup = prevContactsRef.current;
    prevContactsRef.current = newContacts;
    setContacts(newContacts);
    try {
      await api.saveContacts(newContacts);
    } catch (e) {
      console.error(e);
      toast.error('Errore salvataggio');
      setContacts(backup);
      prevContactsRef.current = backup;
      throw e; // Re-throw so callers know it failed
    }
  }, []);

  const confirmDeleteContact = async () => {
    if (!pendingDeleteId) return;
    try {
      await saveContacts(contacts.filter(c => c.id !== pendingDeleteId));
      if (expandedId === pendingDeleteId) setExpandedId(null);
      toast.success('Contatto eliminato');
    } catch { /* saveContacts already showed toast.error */ }
    setPendingDeleteId(null);
  };

  // Filter + search
  const filtered = useMemo(() => {
    let list = contacts;
    if (filterType !== 'all') list = list.filter(c => c.type === filterType);
    if (searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase();
      list = list.filter(c =>
        (c.name || '').toLowerCase().includes(q) ||
        (c.email || '').toLowerCase().includes(q) ||
        (c.pec || '').toLowerCase().includes(q) ||
        (c.phone || '').toLowerCase().includes(q) ||
        (c.fiscalCode || '').toLowerCase().includes(q) ||
        (c.vatNumber || '').toLowerCase().includes(q)
      );
    }
    return list.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
  }, [contacts, filterType, searchQuery]);

  // Find practices linked to a contact
  const getLinkedPractices = useCallback((contactId) => {
    return (practices || []).filter(p => {
      if (p.clientId === contactId || p.counterpartyId === contactId || p.opposingCounselId === contactId || p.judgeId === contactId) return true;
      if (p.roles?.some(r => r.contactId === contactId)) return true;
      return false;
    });
  }, [practices]);

  // Find related contacts via shared practices (e.g. counterparty ↔ opposing_counsel)
  const collectFromPractice = useCallback((practice, contactId, seen, related) => {
    for (const { field, label } of ROLE_PAIRS) {
      const cid = practice[field];
      if (cid && cid !== contactId && !seen.has(cid)) {
        seen.add(cid);
        const found = contacts.find(ct => ct.id === cid);
        if (found) related.push({ role: label, contact: found });
      }
    }
    for (const r of (practice.roles || [])) {
      if (r.contactId && r.contactId !== contactId && !seen.has(r.contactId)) {
        seen.add(r.contactId);
        const found = contacts.find(ct => ct.id === r.contactId);
        if (found) related.push({ role: ROLE_LABELS[r.role] || r.role, contact: found });
      }
    }
  }, [contacts]);

  const getRelatedContacts = useCallback((contact) => {
    const linked = getLinkedPractices(contact.id);
    const related = [];
    const seen = new Set();
    linked.forEach(p => collectFromPractice(p, contact.id, seen, related));
    return related;
  }, [collectFromPractice, getLinkedPractices]);

  const typeCounts = useMemo(() => {
    const counts = { all: contacts.length };
    CONTACT_TYPES.forEach(t => { counts[t.id] = contacts.filter(c => c.type === t.id).length; });
    return counts;
  }, [contacts]);

  if (loading) return <div className="flex items-center justify-center h-64"><div className="w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin" /></div>;

  return (
    <div className="max-w-5xl mx-auto space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 bg-primary/10 rounded-2xl flex items-center justify-center border border-primary/20">
            <Users size={28} className="text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-text tracking-tight">Contatti & Conflitti</h1>
            <p className="text-text-dim text-sm mt-0.5">{contacts.length} contatti registrati</p>
          </div>
        </div>
        {activeTab === 'contacts' && (
          <button onClick={() => setShowCreate(true)} className="btn-primary flex items-center gap-2 px-7 py-3.5 text-xs font-bold uppercase tracking-widest">
            <Plus size={18} strokeWidth={3} /> Nuovo Contatto
          </button>
        )}
      </div>

      {/* Tab Switcher */}
      <div className="tab-switcher">
        <button onClick={() => setActiveTab('contacts')} className="tab-btn" data-active={activeTab === 'contacts'}>
          <Users size={14} /> Anagrafica
        </button>
        <button onClick={() => setActiveTab('conflicts')} className="tab-btn" data-active={activeTab === 'conflicts'}>
          <Shield size={14} /> Conflitti
        </button>
      </div>

      {/* Tab Content — Conflicts */}
      {activeTab === 'conflicts' && (
        <ConflictCheckPanel onSelectPractice={onSelectPractice} />
      )}

      {/* Tab Content — Contacts */}
      {activeTab === 'contacts' && (
      <>

      {/* Search + Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-text-dim" size={16} />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Cerca per nome, email, CF, P.IVA..."
            className="w-full pl-11 pr-4 py-3 bg-surface border border-border rounded-xl text-text text-sm placeholder:text-text-dim/50 focus:border-primary/50 outline-none"
          />
        </div>
        {/* Type filter pills — scrollable on mobile */}
        <div className="flex gap-1.5 overflow-x-auto no-scrollbar pb-1">
          <button onClick={() => setFilterType('all')}
            className={`px-3 py-2 rounded-lg text-[10px] font-bold uppercase tracking-wider whitespace-nowrap transition-colors border ${filterType === 'all' ? 'bg-primary/10 text-primary border-primary/30' : 'bg-surface text-text-dim border-border hover:bg-card'}`}>
            Tutti ({typeCounts.all})
          </button>
          {CONTACT_TYPES.map(t => (
            <button key={t.id} onClick={() => setFilterType(t.id)}
              className={`px-3 py-2 rounded-lg text-[10px] font-bold uppercase tracking-wider whitespace-nowrap transition-colors border ${filterType === t.id ? t.color : 'bg-surface text-text-dim border-border hover:bg-card'}`}>
              {t.label} ({typeCounts[t.id] || 0})
            </button>
          ))}
        </div>
      </div>

      {/* Contact List — Inline Expand */}
      <div className="space-y-1.5">
        {filtered.length === 0 ? (
          <div className="text-center py-12 opacity-40">
            <Users size={40} className="mx-auto mb-3 text-text-dim" />
            <p className="text-text-dim text-sm">
              {searchQuery ? 'Nessun risultato' : 'Nessun contatto registrato'}
            </p>
          </div>
        ) : (
          filtered.map(c => {
            const typeInfo = TYPE_MAP[c.type] || TYPE_MAP.other;
            const TypeIcon = typeInfo.icon;
            const isExpanded = expandedId === c.id;
            const linkedPractices = getLinkedPractices(c.id);
            const linkedCount = linkedPractices.length;

            return (
              <div key={c.id}>
                {/* Row wrapper: on desktop, row + card side by side when expanded */}
                <div className={`flex flex-col ${isExpanded ? 'lg:flex-row lg:gap-3' : ''}`}>
                  {/* Contact Row */}
                  <div
                    className={`relative flex items-center gap-3 px-4 py-3 rounded-xl border group transition-colors duration-200 ${
                      isExpanded
                        ? 'bg-card border-border lg:w-[38%] lg:flex-shrink-0'
                        : 'bg-surface border-border w-full'
                    }`}
                  >
                    {/* Invisible full-row expand/collapse button */}
                    <button
                      type="button"
                      aria-expanded={isExpanded}
                      aria-label={`${isExpanded ? 'Chiudi' : 'Apri'} dettaglio ${c.name}`}
                      onClick={() => setExpandedId(isExpanded ? null : c.id)}
                      className="absolute inset-0 z-0 cursor-pointer rounded-xl hover:bg-card"
                    />
                    <div className={`relative z-[1] w-10 h-10 rounded-xl flex items-center justify-center border flex-shrink-0 ${typeInfo.color}`}>
                      <TypeIcon size={18} />
                    </div>
                    <div className="relative z-[1] flex-1 min-w-0">
                      <p className="text-text font-bold text-base truncate">{c.name}</p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-xs font-bold uppercase tracking-wider text-text-dim">{typeInfo.label}</span>
                        {linkedCount > 0 && (
                          <span className="text-[9px] text-text-muted">&bull; {linkedCount} fascicoli</span>
                        )}
                      </div>
                    </div>
                    {/* Actions — visible only on hover (or always when expanded) */}
                    <div className={`relative z-10 flex items-center gap-0.5 flex-shrink-0 transition-opacity ${isExpanded ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}`}>
                      {!isExpanded && (
                        <button
                          type="button"
                          onClick={(e) => { e.stopPropagation(); setEditingContact({ ...c }); }}
                          className="p-2 hover:bg-card-hover rounded-full transition-colors cursor-pointer"
                          title="Modifica"
                        >
                          <Edit3 size={14} className="text-text-dim hover:text-primary transition-colors" />
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); setExpandedId(isExpanded ? null : c.id); }}
                        className="p-2 hover:bg-card-hover rounded-lg transition-colors cursor-pointer"
                        title={isExpanded ? 'Chiudi dettaglio' : 'Apri dettaglio'}
                      >
                        {isExpanded ? (
                          <ChevronRight size={14} className="text-primary" />
                        ) : (
                          <Info size={14} className="text-text-dim hover:text-primary transition-colors" />
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Detail Card — desktop: side by side */}
                  {isExpanded && (
                    <div className="hidden lg:block lg:flex-1 bg-surface border border-border rounded-2xl p-5 space-y-4 animate-fade-in">
                      <ContactDetailCard
                        contact={c}
                        typeInfo={typeInfo}
                        linkedPractices={linkedPractices}
                        relatedContacts={getRelatedContacts(c)}
                        onEdit={() => setEditingContact({ ...c })}
                        onDelete={() => setPendingDeleteId(c.id)}
                        onSelectPractice={onSelectPractice}
                      />
                    </div>
                  )}
                </div>

                {/* Detail Card — mobile: below the row */}
                {isExpanded && (
                  <div className="lg:hidden bg-surface border border-border rounded-2xl p-5 mt-1.5 space-y-4 animate-fade-in">
                    <ContactDetailCard
                      contact={c}
                      typeInfo={typeInfo}
                      linkedPractices={linkedPractices}
                      relatedContacts={getRelatedContacts(c)}
                      onEdit={() => setEditingContact({ ...c })}
                      onDelete={() => setPendingDeleteId(c.id)}
                      onSelectPractice={onSelectPractice}
                    />
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Create/Edit Modal */}
      {(showCreate || editingContact) && (
        <ContactModal
          initial={editingContact}
          onSave={async (contact) => {
            try {
              if (editingContact) {
                await saveContacts(contacts.map(c => c.id === contact.id ? contact : c));
                setEditingContact(null);
                toast.success('Contatto aggiornato');
              } else {
                await saveContacts([contact, ...contacts]);
                setShowCreate(false);
                toast.success('Contatto aggiunto');
              }
            } catch { /* saveContacts already showed toast.error */ }
          }}
          onClose={() => { setShowCreate(false); setEditingContact(null); }}
        />
      )}

      {/* Conferma eliminazione contatto */}
      <ConfirmDialog
        open={!!pendingDeleteId}
        title="Elimina Contatto"
        message="Vuoi eliminare definitivamente questo contatto? L'azione non è reversibile."
        confirmLabel="Elimina"
        cancelLabel="Annulla"
        onConfirm={confirmDeleteContact}
        onCancel={() => setPendingDeleteId(null)}
      />
      </>
      )}
    </div>
  );
}

/* ──── Contact Create/Edit Modal ──── */
function ContactModal({ initial, onSave, onClose }) {
  const [form, setForm] = useState(initial || {
    id: genId(),
    type: 'client',
    name: '',
    fiscalCode: '',
    vatNumber: '',
    phone: '',
    email: '',
    pec: '',
    address: '',
    barAssociation: '',
    court: '',
    notes: '',
  });

  const updateField = useCallback((field, value) => {
    setForm(prev => ({ ...prev, [field]: value }));
  }, []);

  // Use atomic-like groups: domain segments don't include dots, preventing backtracking
  const EMAIL_RE = /^[^\s@]+@[^\s@.]+(?:\.[^\s@.]+)+$/;

  const handleSubmit = () => {
    if (!form.name.trim()) {
      toast.error('Il nome è obbligatorio');
      return;
    }
    if (form.email?.trim() && !EMAIL_RE.test(form.email.trim())) {
      toast.error('Indirizzo email non valido');
      return;
    }
    if (form.pec?.trim() && !EMAIL_RE.test(form.pec.trim())) {
      toast.error('Indirizzo PEC non valido');
      return;
    }
    onSave(form);
  };

  return (
    <ModalOverlay onClose={onClose} labelledBy="contact-modal-title" focusTrap>
      <div className="modal-card modal-card-lg flex flex-col max-h-[95vh]">
        
        {/* Header — stile unificato */}
        <div className="modal-header">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-primary/10 rounded-2xl flex items-center justify-center text-primary border border-primary/20">
              <Users size={28} />
            </div>
            <div>
              <h2 id="contact-modal-title" className="text-xl font-bold text-text tracking-tight">{initial ? 'Modifica Contatto' : 'Nuovo Contatto'}</h2>
              <p className="text-text-dim text-xs uppercase tracking-widest font-medium opacity-60">Anagrafica</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-card-hover rounded-xl text-text-dim transition-colors group">
            <X size={24} className="group-hover:rotate-90 transition-transform" />
          </button>
        </div>

        {/* Body */}
        <div className="px-8 py-5 space-y-4 overflow-y-auto custom-scrollbar flex-1">
          {/* Type pills */}
          <div className="space-y-3">
            <span className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Tipo</span>
            <div className="flex flex-wrap gap-2.5">
              {CONTACT_TYPES.map(t => (
                <button key={t.id} onClick={() => updateField('type', t.id)}
                  className={`px-4 py-2.5 rounded-xl text-xs font-bold uppercase tracking-wider transition-colors duration-300 border ${form.type === t.id ? t.color + ' scale-105 ring-2 ring-border' : 'bg-surface text-text-dim border-border hover:bg-card hover:border-border'}`}>
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          {/* Name */}
          <div className="space-y-2">
            <label htmlFor="ct-name" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Nome / Ragione Sociale *</label>
            <input id="ct-name" value={form.name} onChange={e => updateField('name', e.target.value)}
              placeholder="Nome completo o ragione sociale"
              className="input-field w-full bg-surface border-border focus:border-primary/50 text-lg font-semibold" autoFocus />
          </div>

          {/* CF + P.IVA */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label htmlFor="ct-cf" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Codice Fiscale</label>
              <input id="ct-cf" value={form.fiscalCode || ''} onChange={e => updateField('fiscalCode', e.target.value.toUpperCase())}
                placeholder="RSSMRA80A01H501Z" maxLength={16}
                className="input-field w-full bg-surface border-border font-mono focus:border-primary/50" />
            </div>
            <div className="space-y-2">
              <label htmlFor="ct-vat" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">P.IVA</label>
              <input id="ct-vat" value={form.vatNumber || ''} onChange={e => updateField('vatNumber', e.target.value)}
                placeholder="01234567890" maxLength={11}
                className="input-field w-full bg-surface border-border font-mono focus:border-primary/50" />
            </div>
          </div>

          {/* Phone + Email */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label htmlFor="ct-phone" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Telefono</label>
              <input id="ct-phone" value={form.phone || ''} onChange={e => updateField('phone', e.target.value)}
                placeholder="+39 333 1234567" type="tel"
                className="input-field w-full bg-surface border-border focus:border-primary/50" />
            </div>
            <div className="space-y-2">
              <label htmlFor="ct-email" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Email</label>
              <input id="ct-email" value={form.email || ''} onChange={e => updateField('email', e.target.value)}
                placeholder="email@esempio.it" type="email"
                className="input-field w-full bg-surface border-border focus:border-primary/50" />
            </div>
          </div>

          {/* PEC */}
          <div className="space-y-2">
            <label htmlFor="ct-pec" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">PEC</label>
            <input id="ct-pec" value={form.pec || ''} onChange={e => updateField('pec', e.target.value)}
              placeholder="nome@pec-avvocati.it" type="email"
              className="input-field w-full bg-surface border-border focus:border-primary/50" />
          </div>

          {/* Address */}
          <div className="space-y-2">
            <label htmlFor="ct-address" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Indirizzo</label>
            <input id="ct-address" value={form.address || ''} onChange={e => updateField('address', e.target.value)}
              placeholder="Via Roma 1, 00100 Roma (RM)"
              className="input-field w-full bg-surface border-border focus:border-primary/50" />
          </div>

          {/* Conditional fields based on type */}
          {(form.type === 'opposing_counsel' || form.type === 'consultant') && (
            <div className="space-y-2">
              <label htmlFor="ct-bar" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Ordine / Albo</label>
              <input id="ct-bar" value={form.barAssociation || ''} onChange={e => updateField('barAssociation', e.target.value)}
                placeholder="Ordine Avvocati di Roma"
                className="input-field w-full bg-surface border-border focus:border-primary/50" />
            </div>
          )}

          {form.type === 'judge' && (
            <div className="space-y-2">
              <label htmlFor="ct-court" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Tribunale / Sezione</label>
              <input id="ct-court" value={form.court || ''} onChange={e => updateField('court', e.target.value)}
                placeholder="Tribunale di Milano, Sez. III"
                className="input-field w-full bg-surface border-border focus:border-primary/50" />
            </div>
          )}

          {/* Notes */}
          <div className="space-y-2">
            <label htmlFor="ct-notes" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Note</label>
            <textarea id="ct-notes" value={form.notes || ''} onChange={e => updateField('notes', e.target.value)}
              placeholder="Annotazioni libere..." rows={2}
              className="input-field w-full bg-surface border-border min-h-[80px] resize-none focus:border-primary/50" />
          </div>
        </div>

        {/* Footer — stile unificato */}
        <div className="modal-footer gap-4">
          <button onClick={onClose} className="btn-cancel">Annulla</button>
          <button onClick={handleSubmit} className="btn-primary px-10 py-3 flex items-center gap-3 hover:scale-[1.05] active:scale-[0.98] transition-colors">
            <Check size={18} />
            <span className="font-black uppercase tracking-widest text-xs">{initial ? 'Aggiorna' : 'Salva Contatto'}</span>
          </button>
        </div>
      </div>
    </ModalOverlay>
  );
}

ContactsPage.propTypes = {
  practices: PropTypes.array,
  onSelectPractice: PropTypes.func,
};

/* ──── Inline Detail Card (dynamic per type) ──── */
// PERF: memoized to prevent re-rendering all detail cards when parent state changes
const ContactDetailCard = memo(function ContactDetailCard({ contact, typeInfo, linkedPractices, relatedContacts, onEdit, onDelete, onSelectPractice }) {
  const TypeIcon = typeInfo.icon;
  const c = contact;

  // Determine which fields to show based on type
  const showBarAssociation = c.type === 'opposing_counsel' || c.type === 'consultant';
  const showCourt = c.type === 'judge';
  const showFiscalCode = c.type === 'client' || c.type === 'counterparty';
  const showVat = c.type === 'client';

  const hasAnyInfo = c.phone || c.email || c.pec || c.address || (showFiscalCode && c.fiscalCode) || (showVat && c.vatNumber) || (showBarAssociation && c.barAssociation) || (showCourt && c.court);

  return (
    <>
      {/* Header — unified with modal style */}
      <div className="flex items-center justify-between pb-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div className={`w-11 h-11 rounded-2xl flex items-center justify-center border ${typeInfo.color}`}>
            <TypeIcon size={20} />
          </div>
          <div>
            <h3 className="text-lg font-bold text-text tracking-tight">{c.name}</h3>
            <span className={`text-[9px] font-black uppercase tracking-[2px] ${typeInfo.color.split(' ')[0]}`}>
              {typeInfo.label}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-1">
          <button type="button" onClick={onEdit} className="p-2.5 hover:bg-primary/10 rounded-full transition-colors group/edit cursor-pointer" title="Modifica">
            <Edit3 size={15} className="text-text-dim group-hover/edit:text-primary transition-colors" />
          </button>
          <button type="button" onClick={onDelete} className="p-2.5 hover:bg-danger-soft rounded-full transition-colors cursor-pointer" title="Elimina">
            <Trash2 size={15} className="text-danger hover:text-danger" />
          </button>
        </div>
      </div>

      {/* Contact Info — grid layout */}
      {hasAnyInfo && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 pt-2">
          {c.phone && (
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-surface border border-border">
              <Phone size={14} className="text-text-muted flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-[10px] font-bold text-text-dim uppercase tracking-widest">Telefono</p>
                <span className="text-text text-xs font-medium">{c.phone}</span>
              </div>
            </div>
          )}
          {c.email && (
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-surface border border-border">
              <Mail size={14} className="text-text-muted flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-[10px] font-bold text-text-dim uppercase tracking-widest">Email</p>
                <span className="text-text text-xs font-medium truncate block">{c.email}</span>
              </div>
            </div>
          )}
          {c.pec && (
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-surface border border-border">
              <Mail size={14} className="text-warning flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-[10px] font-bold text-text-dim uppercase tracking-widest">PEC</p>
                <span className="text-text text-xs font-medium truncate block">{c.pec}</span>
              </div>
            </div>
          )}
          {c.address && (
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-surface border border-border">
              <MapPin size={14} className="text-text-muted flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-[10px] font-bold text-text-dim uppercase tracking-widest">Indirizzo</p>
                <span className="text-text text-xs font-medium truncate block">{c.address}</span>
              </div>
            </div>
          )}
          {showFiscalCode && c.fiscalCode && (
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-surface border border-border">
              <Hash size={14} className="text-text-muted flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-[10px] font-bold text-text-dim uppercase tracking-widest">Codice Fiscale</p>
                <span className="text-text text-xs font-mono font-medium">{c.fiscalCode}</span>
              </div>
            </div>
          )}
          {showVat && c.vatNumber && (
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-surface border border-border">
              <Building size={14} className="text-text-muted flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-[10px] font-bold text-text-dim uppercase tracking-widest">P.IVA</p>
                <span className="text-text text-xs font-mono font-medium">{c.vatNumber}</span>
              </div>
            </div>
          )}
          {showBarAssociation && c.barAssociation && (
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-surface border border-border">
              <Scale size={14} className="text-text-muted flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-[10px] font-bold text-text-dim uppercase tracking-widest">Ordine / Albo</p>
                <span className="text-text text-xs font-medium">{c.barAssociation}</span>
              </div>
            </div>
          )}
          {showCourt && c.court && (
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-surface border border-border">
              <Gavel size={14} className="text-text-muted flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-[10px] font-bold text-text-dim uppercase tracking-widest">Tribunale</p>
                <span className="text-text text-xs font-medium">{c.court}</span>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Notes */}
      {c.notes && (
        <p className="text-text-dim text-xs italic border-l-2 border-primary/30 pl-3 mt-1 bg-primary/[0.03] py-2 rounded-r-lg">{c.notes}</p>
      )}

      {/* Related Contacts (cross-practice relationships) */}
      {relatedContacts.length > 0 && (
        <div className="space-y-2 pt-1">
          <h4 className="text-[9px] font-black text-text-dim uppercase tracking-[2px]">Soggetti Collegati</h4>
          <div className="space-y-1">
            {relatedContacts.map(({ role, contact: rc }) => {
              const rcType = TYPE_MAP[rc.type] || TYPE_MAP.other;
              const RcIcon = rcType.icon;
              return (
                <div key={rc.id} className="flex items-center gap-2.5 px-3 py-2 bg-surface border border-border rounded-lg">
                  <div className={`w-7 h-7 rounded-lg flex items-center justify-center border ${rcType.color}`}>
                    <RcIcon size={12} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-text text-sm font-medium truncate">{rc.name}</p>
                    <p className="text-[9px] text-text-dim">{role}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Linked Practices */}
      {linkedPractices.length > 0 && (
        <div className="space-y-2 pt-1">
          <h4 className="text-[9px] font-black text-text-dim uppercase tracking-[2px]">Fascicoli ({linkedPractices.length})</h4>
          <div className="space-y-1">
            {linkedPractices.map(p => (
              <button type="button" key={p.id} onClick={() => onSelectPractice?.(p.id)}
                className="flex items-center gap-2.5 px-3 py-2 bg-surface hover:bg-card border border-border rounded-lg transition-colors group text-left w-full">
                <Briefcase size={13} className="text-text-dim flex-shrink-0" />
                <p className="text-text text-sm truncate flex-1 group-hover:text-primary transition-colors">{p.client} — {p.object}</p>
                <span className={`text-[8px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${p.status === 'active' ? 'bg-success-soft text-success' : 'bg-surface text-text-dim'}`}>
                  {p.status === 'active' ? 'Attivo' : 'Chiuso'}
                </span>
              </button>
            ))}
          </div>
        </div>
      )}
    </>
  );
});

ContactDetailCard.propTypes = {
  contact: PropTypes.object.isRequired,
  typeInfo: PropTypes.object.isRequired,
  linkedPractices: PropTypes.array.isRequired,
  relatedContacts: PropTypes.array.isRequired,
  onEdit: PropTypes.func.isRequired,
  onDelete: PropTypes.func.isRequired,
  onSelectPractice: PropTypes.func,
};

ContactModal.propTypes = {
  initial: PropTypes.object,
  onSave: PropTypes.func.isRequired,
  onClose: PropTypes.func.isRequired,
};