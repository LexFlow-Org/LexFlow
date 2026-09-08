import { getSessionGeneration } from '../utils/sessionData';
import { useState, useEffect, useCallback, useMemo, useRef, memo } from 'react';
import PropTypes from 'prop-types';
import { Users, Plus, Search, User, Scale, Briefcase, Building, Gavel, UserCheck, Edit3, Trash2, X, Check, Phone, Mail, MapPin, Hash, ChevronRight, Info, Shield } from 'lucide-react';
import toast from 'react-hot-toast';
import * as api from '../tauri-api';
import ConfirmDialog from '../components/ConfirmDialog';
import ModalOverlay from '../components/ModalOverlay';
import ConflictCheckPanel from '../components/ConflictCheckPanel';
import { ROLE_LABELS } from '../utils/conflictConstants';
import { genId, normalizeSearchText } from '../utils/helpers';
import { useDebounce } from '../hooks/useDebounce';
import { useVirtualList } from '../hooks/useVirtualList';

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
  const [loadError, setLoadError] = useState(false);
  const sessionGeneration = useRef(getSessionGeneration());
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [showCreate, setShowCreate] = useState(false);
  const [editingContact, setEditingContact] = useState(null);
  const [expandedId, setExpandedId] = useState(null);
  const [pendingDeleteId, setPendingDeleteId] = useState(null);
  const prevContactsRef = useRef([]);
  const saveQueueRef = useRef(Promise.resolve());

  // FIX-2: debounce the search query so each keystroke doesn't re-run
  // filter+normalize on the entire list.
  const debouncedQuery = useDebounce(searchQuery, 200);

  const loadContacts = useCallback(() => api.loadContacts().then(data => {
    if (sessionGeneration.current !== getSessionGeneration()) return;
    if (!Array.isArray(data)) throw new Error('Formato contatti non valido');
    prevContactsRef.current = data;
    setContacts(data);
  }).catch(() => setLoadError(true)).finally(() => setLoading(false)), []);
  useEffect(() => { loadContacts(); }, [loadContacts]);

  const saveContacts = useCallback((update) => {
    const pending = saveQueueRef.current.then(async () => {
      if (sessionGeneration.current !== getSessionGeneration()) throw new Error('Vault bloccato');
      try {
        const newContacts = update(prevContactsRef.current);
        await api.saveContacts(newContacts);
        if (sessionGeneration.current !== getSessionGeneration()) return;
        prevContactsRef.current = newContacts;
        setContacts(newContacts);
      } catch (error) {
        toast.error('Errore salvataggio');
        throw error;
      }
    });
    saveQueueRef.current = pending.catch(() => {});
    return pending;
  }, []);

  const confirmDeleteContact = async () => {
    if (!pendingDeleteId) return;
    try {
      await saveContacts(current => current.filter(c => c.id !== pendingDeleteId));
      if (expandedId === pendingDeleteId) setExpandedId(null);
      toast.success('Contatto eliminato');
    } catch { /* saveContacts already showed toast.error */ }
    setPendingDeleteId(null);
  };

  // FIX-4: sort the master list ONCE per contacts change. Filter and sort
  // had been entangled in a single useMemo, re-sorting on every keystroke.
  const sortedContacts = useMemo(
    () => [...contacts].sort((a, b) => (a.name || '').localeCompare(b.name || '')),
    [contacts],
  );

  const searchIndex = useMemo(() => sortedContacts.map(contact => ({
    contact,
    text: [contact.name, contact.email, contact.pec, contact.phone, contact.fiscalCode, contact.vatNumber]
      .map(normalizeSearchText).join('\0'),
  })), [sortedContacts]);

  const filtered = useMemo(() => {
    const query = normalizeSearchText(debouncedQuery.trim());
    return searchIndex
      .filter(({ contact, text }) => (filterType === 'all' || contact.type === filterType) && text.includes(query))
      .map(({ contact }) => contact);
  }, [searchIndex, filterType, debouncedQuery]);

  // PERF: pre-compute contact→practices map once per practices change (avoids O(n*m) per contact)
  const contactPracticesMap = useMemo(() => {
    const map = new Map();
    const addLink = (contactId, practice) => {
      if (!contactId) return;
      if (!map.has(contactId)) map.set(contactId, []);
      map.get(contactId).push(practice);
    };
    for (const p of (practices || [])) {
      addLink(p.clientId, p);
      addLink(p.counterpartyId, p);
      addLink(p.opposingCounselId, p);
      addLink(p.judgeId, p);
      if (p.roles) for (const r of p.roles) addLink(r.contactId, p);
    }
    return map;
  }, [practices]);

  const getLinkedPractices = useCallback((contactId) => {
    return contactPracticesMap.get(contactId) || [];
  }, [contactPracticesMap]);

  // FIX-7: O(1) contact lookup. Previously every related-role lookup did a
  // contacts.find(...) — quadratic in practices*roles*contacts.
  const contactsById = useMemo(() => {
    const m = new Map();
    for (const ct of contacts) if (ct?.id) m.set(ct.id, ct);
    return m;
  }, [contacts]);

  // Find related contacts via shared practices (e.g. counterparty ↔ opposing_counsel)
  const collectFromPractice = useCallback((practice, contactId, seen, related) => {
    for (const { field, label } of ROLE_PAIRS) {
      const cid = practice[field];
      if (cid && cid !== contactId && !seen.has(cid)) {
        seen.add(cid);
        const found = contactsById.get(cid);
        if (found) related.push({ role: label, contact: found });
      }
    }
    for (const r of (practice.roles || [])) {
      if (r.contactId && r.contactId !== contactId && !seen.has(r.contactId)) {
        seen.add(r.contactId);
        const found = contactsById.get(r.contactId);
        if (found) related.push({ role: ROLE_LABELS[r.role] || r.role, contact: found });
      }
    }
  }, [contactsById]);

  const getRelatedContacts = useCallback((contact) => {
    const linked = getLinkedPractices(contact.id);
    const related = [];
    const seen = new Set();
    linked.forEach(p => collectFromPractice(p, contact.id, seen, related));
    return related;
  }, [collectFromPractice, getLinkedPractices]);

  const typeCounts = useMemo(() => {
    const counts = { all: contacts.length };
    for (const contact of contacts) counts[contact.type] = (counts[contact.type] || 0) + 1;
    return counts;
  }, [contacts]);

  // Keep rows at a fixed height; large lists show details in a separate dialog.
  const VIRTUAL_THRESHOLD = 50;
  const ITEM_HEIGHT = 80;
  const useVirtual = filtered.length > VIRTUAL_THRESHOLD;
  const {
    containerRef: vlContainerRef,
    totalHeight: vlTotalHeight,
    items: vlVisibleItems,
  } = useVirtualList({ items: filtered, itemHeight: ITEM_HEIGHT, overscan: 5 });

  if (loadError) return <div role="alert" className="p-6 space-y-4">
    <p>Impossibile leggere i contatti. Riprova prima di modificarli.</p>
    <button className="btn-primary" onClick={() => { setLoading(true); setLoadError(false); void loadContacts(); }}>Riprova</button>
  </div>;

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
            className={`px-3 py-2 rounded-lg text-2xs font-bold uppercase tracking-wider whitespace-nowrap transition-colors border ${filterType === 'all' ? 'bg-primary/10 text-primary border-primary/30' : 'bg-surface text-text-dim border-border hover:bg-card'}`}>
            Tutti ({typeCounts.all})
          </button>
          {CONTACT_TYPES.map(t => (
            <button key={t.id} onClick={() => setFilterType(t.id)}
              className={`px-3 py-2 rounded-lg text-2xs font-bold uppercase tracking-wider whitespace-nowrap transition-colors border ${filterType === t.id ? t.color : 'bg-surface text-text-dim border-border hover:bg-card'}`}>
              {t.label} ({typeCounts[t.id] || 0})
            </button>
          ))}
        </div>
      </div>

      {/* Contact List — Inline Expand */}
      <ContactList
        filtered={filtered}
        searchQuery={searchQuery}
        expandedId={expandedId}
        setExpandedId={setExpandedId}
        setEditingContact={setEditingContact}
        setPendingDeleteId={setPendingDeleteId}
        getLinkedPractices={getLinkedPractices}
        getRelatedContacts={getRelatedContacts}
        onSelectPractice={onSelectPractice}
        useVirtual={useVirtual}
        vlContainerRef={vlContainerRef}
        vlTotalHeight={vlTotalHeight}
        vlVisibleItems={vlVisibleItems}
        itemHeight={ITEM_HEIGHT}
      />

      {/* Create/Edit Modal */}
      {(showCreate || editingContact) && (
        <ContactModal
          initial={editingContact}
          onSave={async (contact) => {
            try {
              if (editingContact) {
                await saveContacts(current => current.map(c => c.id === contact.id ? contact : c));
                setEditingContact(null);
                toast.success('Contatto aggiornato');
              } else {
                await saveContacts(current => [contact, ...current]);
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

/* ──── Contact List ──── */
function ContactList({
  filtered, searchQuery, expandedId, setExpandedId, setEditingContact, setPendingDeleteId,
  getLinkedPractices, getRelatedContacts, onSelectPractice,
  useVirtual, vlContainerRef, vlTotalHeight, vlVisibleItems, itemHeight,
}) {
  if (filtered.length === 0) {
    return (
      <div className="space-y-1.5">
        <div className="text-center py-12 opacity-40">
          <Users size={40} className="mx-auto mb-3 text-text-dim" />
          <p className="text-text-dim text-sm">
            {searchQuery ? 'Nessun risultato' : 'Nessun contatto registrato'}
          </p>
        </div>
      </div>
    );
  }

  const renderRow = (c, expandable = true) => {
    const typeInfo = TYPE_MAP[c.type] || TYPE_MAP.other;
    const TypeIcon = typeInfo.icon;
    const isExpanded = expandable && expandedId === c.id;
    const linkedPractices = getLinkedPractices(c.id);
    const linkedCount = linkedPractices.length;

    return (
      <div>
        {/* Row wrapper: on desktop, row + card side by side when expanded */}
        <div className={`flex flex-col ${isExpanded ? 'lg:flex-row lg:gap-3' : ''}`}>
          {/* Contact Row — single full-row expand button (FIX-6) */}
          <button
            type="button"
            aria-expanded={expandable ? isExpanded : undefined}
            aria-haspopup={expandable ? undefined : 'dialog'}
            aria-label={`${isExpanded ? 'Chiudi' : 'Apri'} dettaglio ${c.name}`}
            onClick={() => setExpandedId(isExpanded ? null : c.id)}
            className={`relative flex items-center gap-3 px-4 py-3 rounded-xl border group transition-colors duration-200 text-left w-full cursor-pointer ${
              isExpanded
                ? 'bg-card border-border lg:w-[38%] lg:flex-shrink-0'
                : 'bg-surface border-border hover:bg-card'
            }`}
          >
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center border flex-shrink-0 ${typeInfo.color}`}>
              <TypeIcon size={18} />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-text font-bold text-base truncate">{c.name}</p>
              <div className="flex items-center gap-2 mt-0.5">
                <span className="text-xs font-bold uppercase tracking-wider text-text-dim">{typeInfo.label}</span>
                {linkedCount > 0 && (
                  <span className="text-3xs text-text-muted">&bull; {linkedCount} fascicoli</span>
                )}
              </div>
            </div>
            {/* Actions — visible on hover. Edit is a separate concern and uses
                a span with role=button to avoid nesting <button> in <button>. */}
            <span className={`flex items-center gap-0.5 flex-shrink-0 transition-opacity ${isExpanded ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}`}>
              {!isExpanded && (
                <span
                  role="button"
                  tabIndex={0}
                  aria-label={`Modifica ${c.name}`}
                  onClick={(e) => { e.stopPropagation(); setEditingContact({ ...c }); }}
                  onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.stopPropagation(); setEditingContact({ ...c }); } }}
                  className="p-2 hover:bg-card-hover rounded-full transition-colors cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
                  title="Modifica"
                >
                  <Edit3 size={14} className="text-text-dim hover:text-primary transition-colors" />
                </span>
              )}
              <span className="p-2" aria-hidden="true">
                {isExpanded ? (
                  <ChevronRight size={14} className="text-primary" />
                ) : (
                  <Info size={14} className="text-text-dim group-hover:text-primary transition-colors" />
                )}
              </span>
            </span>
          </button>

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
  };

  // Opening a detail must not replace the virtual list with every contact.
  if (useVirtual) {
    const selectedContact = filtered.find(c => c.id === expandedId);
    return (
      <>
      <div ref={vlContainerRef} className="overflow-auto custom-scrollbar" style={{ maxHeight: '70vh' }}>
        <div style={{ height: vlTotalHeight, position: 'relative' }}>
          {vlVisibleItems.map(({ index, top, item }) => (
            <div
              key={item.id || index}
              style={{ position: 'absolute', top, left: 0, right: 0, height: itemHeight, paddingBottom: 6 }}
            >
              {renderRow(item, false)}
            </div>
          ))}
        </div>
      </div>
      {selectedContact && (
        <ModalOverlay onClose={() => setExpandedId(null)} label={`Dettaglio ${selectedContact.name}`} focusTrap className="w-full max-w-2xl">
          <div className="bg-surface border border-border rounded-2xl p-5 space-y-4 max-h-[85vh] overflow-y-auto custom-scrollbar">
            <div className="flex justify-end">
              <button type="button" onClick={() => setExpandedId(null)} aria-label="Chiudi dettaglio" className="p-2 rounded-full hover:bg-card">
                <X size={20} />
              </button>
            </div>
            <ContactDetailCard
              contact={selectedContact}
              typeInfo={TYPE_MAP[selectedContact.type] || TYPE_MAP.other}
              linkedPractices={getLinkedPractices(selectedContact.id)}
              relatedContacts={getRelatedContacts(selectedContact)}
              onEdit={() => { setExpandedId(null); setEditingContact({ ...selectedContact }); }}
              onDelete={() => { setExpandedId(null); setPendingDeleteId(selectedContact.id); }}
              onSelectPractice={id => { setExpandedId(null); onSelectPractice?.(id); }}
            />
          </div>
        </ModalOverlay>
      )}
      </>
    );
  }

  return (
    <div className="space-y-1.5">
      {filtered.map(c => (
        <div key={c.id}>{renderRow(c, true)}</div>
      ))}
    </div>
  );
}

ContactList.propTypes = {
  filtered: PropTypes.array.isRequired,
  searchQuery: PropTypes.string,
  expandedId: PropTypes.string,
  setExpandedId: PropTypes.func.isRequired,
  setEditingContact: PropTypes.func.isRequired,
  setPendingDeleteId: PropTypes.func.isRequired,
  getLinkedPractices: PropTypes.func.isRequired,
  getRelatedContacts: PropTypes.func.isRequired,
  onSelectPractice: PropTypes.func,
  useVirtual: PropTypes.bool,
  vlContainerRef: PropTypes.object,
  vlTotalHeight: PropTypes.number,
  vlVisibleItems: PropTypes.array,
  itemHeight: PropTypes.number,
};

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
            <span className="text-2xs font-black text-text-dim uppercase tracking-label ml-1">Tipo</span>
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
            <label htmlFor="ct-name" className="text-2xs font-black text-text-dim uppercase tracking-label ml-1">Nome / Ragione Sociale *</label>
            <input id="ct-name" value={form.name} onChange={e => updateField('name', e.target.value)}
              placeholder="Nome completo o ragione sociale"
              className="input-field w-full bg-surface border-border focus:border-primary/50 text-lg font-semibold" autoFocus />
          </div>

          {/* CF + P.IVA */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label htmlFor="ct-cf" className="text-2xs font-black text-text-dim uppercase tracking-label ml-1">Codice Fiscale</label>
              <input id="ct-cf" value={form.fiscalCode || ''} onChange={e => updateField('fiscalCode', e.target.value.toUpperCase())}
                placeholder="RSSMRA80A01H501Z" maxLength={16}
                className="input-field w-full bg-surface border-border font-mono focus:border-primary/50" />
            </div>
            <div className="space-y-2">
              <label htmlFor="ct-vat" className="text-2xs font-black text-text-dim uppercase tracking-label ml-1">P.IVA</label>
              <input id="ct-vat" value={form.vatNumber || ''} onChange={e => updateField('vatNumber', e.target.value)}
                placeholder="01234567890" maxLength={11}
                className="input-field w-full bg-surface border-border font-mono focus:border-primary/50" />
            </div>
          </div>

          {/* Phone + Email */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label htmlFor="ct-phone" className="text-2xs font-black text-text-dim uppercase tracking-label ml-1">Telefono</label>
              <input id="ct-phone" value={form.phone || ''} onChange={e => updateField('phone', e.target.value)}
                placeholder="+39 333 1234567" type="tel"
                className="input-field w-full bg-surface border-border focus:border-primary/50" />
            </div>
            <div className="space-y-2">
              <label htmlFor="ct-email" className="text-2xs font-black text-text-dim uppercase tracking-label ml-1">Email</label>
              <input id="ct-email" value={form.email || ''} onChange={e => updateField('email', e.target.value)}
                placeholder="email@esempio.it" type="email"
                className="input-field w-full bg-surface border-border focus:border-primary/50" />
            </div>
          </div>

          {/* PEC */}
          <div className="space-y-2">
            <label htmlFor="ct-pec" className="text-2xs font-black text-text-dim uppercase tracking-label ml-1">PEC</label>
            <input id="ct-pec" value={form.pec || ''} onChange={e => updateField('pec', e.target.value)}
              placeholder="nome@pec-avvocati.it" type="email"
              className="input-field w-full bg-surface border-border focus:border-primary/50" />
          </div>

          {/* Address */}
          <div className="space-y-2">
            <label htmlFor="ct-address" className="text-2xs font-black text-text-dim uppercase tracking-label ml-1">Indirizzo</label>
            <input id="ct-address" value={form.address || ''} onChange={e => updateField('address', e.target.value)}
              placeholder="Via Roma 1, 00100 Roma (RM)"
              className="input-field w-full bg-surface border-border focus:border-primary/50" />
          </div>

          {/* Conditional fields based on type */}
          {(form.type === 'opposing_counsel' || form.type === 'consultant') && (
            <div className="space-y-2">
              <label htmlFor="ct-bar" className="text-2xs font-black text-text-dim uppercase tracking-label ml-1">Ordine / Albo</label>
              <input id="ct-bar" value={form.barAssociation || ''} onChange={e => updateField('barAssociation', e.target.value)}
                placeholder="Ordine Avvocati di Roma"
                className="input-field w-full bg-surface border-border focus:border-primary/50" />
            </div>
          )}

          {form.type === 'judge' && (
            <div className="space-y-2">
              <label htmlFor="ct-court" className="text-2xs font-black text-text-dim uppercase tracking-label ml-1">Tribunale / Sezione</label>
              <input id="ct-court" value={form.court || ''} onChange={e => updateField('court', e.target.value)}
                placeholder="Tribunale di Milano, Sez. III"
                className="input-field w-full bg-surface border-border focus:border-primary/50" />
            </div>
          )}

          {/* Notes */}
          <div className="space-y-2">
            <label htmlFor="ct-notes" className="text-2xs font-black text-text-dim uppercase tracking-label ml-1">Note</label>
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
            <span className={`text-3xs font-black uppercase tracking-label ${typeInfo.color.split(' ')[0]}`}>
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
                <p className="text-2xs font-bold text-text-dim uppercase tracking-widest">Telefono</p>
                <span className="text-text text-xs font-medium">{c.phone}</span>
              </div>
            </div>
          )}
          {c.email && (
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-surface border border-border">
              <Mail size={14} className="text-text-muted flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-2xs font-bold text-text-dim uppercase tracking-widest">Email</p>
                <span className="text-text text-xs font-medium truncate block">{c.email}</span>
              </div>
            </div>
          )}
          {c.pec && (
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-surface border border-border">
              <Mail size={14} className="text-warning flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-2xs font-bold text-text-dim uppercase tracking-widest">PEC</p>
                <span className="text-text text-xs font-medium truncate block">{c.pec}</span>
              </div>
            </div>
          )}
          {c.address && (
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-surface border border-border">
              <MapPin size={14} className="text-text-muted flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-2xs font-bold text-text-dim uppercase tracking-widest">Indirizzo</p>
                <span className="text-text text-xs font-medium truncate block">{c.address}</span>
              </div>
            </div>
          )}
          {showFiscalCode && c.fiscalCode && (
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-surface border border-border">
              <Hash size={14} className="text-text-muted flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-2xs font-bold text-text-dim uppercase tracking-widest">Codice Fiscale</p>
                <span className="text-text text-xs font-mono font-medium">{c.fiscalCode}</span>
              </div>
            </div>
          )}
          {showVat && c.vatNumber && (
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-surface border border-border">
              <Building size={14} className="text-text-muted flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-2xs font-bold text-text-dim uppercase tracking-widest">P.IVA</p>
                <span className="text-text text-xs font-mono font-medium">{c.vatNumber}</span>
              </div>
            </div>
          )}
          {showBarAssociation && c.barAssociation && (
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-surface border border-border">
              <Scale size={14} className="text-text-muted flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-2xs font-bold text-text-dim uppercase tracking-widest">Ordine / Albo</p>
                <span className="text-text text-xs font-medium">{c.barAssociation}</span>
              </div>
            </div>
          )}
          {showCourt && c.court && (
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-surface border border-border">
              <Gavel size={14} className="text-text-muted flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-2xs font-bold text-text-dim uppercase tracking-widest">Tribunale</p>
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
          <h4 className="text-3xs font-black text-text-dim uppercase tracking-label">Soggetti Collegati</h4>
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
                    <p className="text-3xs text-text-dim">{role}</p>
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
          <h4 className="text-3xs font-black text-text-dim uppercase tracking-label">Fascicoli ({linkedPractices.length})</h4>
          <div className="space-y-1">
            {linkedPractices.map(p => (
              <button type="button" key={p.id} onClick={() => onSelectPractice?.(p.id)}
                className="flex items-center gap-2.5 px-3 py-2 bg-surface hover:bg-card border border-border rounded-lg transition-colors group text-left w-full">
                <Briefcase size={13} className="text-text-dim flex-shrink-0" />
                <p className="text-text text-sm truncate flex-1 group-hover:text-primary transition-colors">{p.client} — {p.object}</p>
                <span className={`text-xxs font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${p.status === 'active' ? 'bg-success-soft text-success' : 'bg-surface text-text-dim'}`}>
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