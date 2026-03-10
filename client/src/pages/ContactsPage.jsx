import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import PropTypes from 'prop-types';
import { Users, Plus, Search, User, Scale, Briefcase, Building, Gavel, UserCheck, Edit3, Trash2, X, Check, Phone, Mail, MapPin, Hash, ChevronRight, Shield, ShieldCheck, AlertTriangle, Info } from 'lucide-react';
import toast from 'react-hot-toast';
import * as api from '../tauri-api';
import ConfirmDialog from '../components/ConfirmDialog';
import ModalOverlay from '../components/ModalOverlay';
import { genId } from '../utils/helpers';

const CONTACT_TYPES = [
  { id: 'client', label: 'Cliente', icon: User, color: 'text-blue-400 bg-blue-500/10 border-blue-500/20' },
  { id: 'counterparty', label: 'Controparte', icon: Scale, color: 'text-red-400 bg-red-500/10 border-red-500/20' },
  { id: 'opposing_counsel', label: 'Avv. Controparte', icon: UserCheck, color: 'text-orange-400 bg-orange-500/10 border-orange-500/20' },
  { id: 'judge', label: 'Giudice', icon: Gavel, color: 'text-purple-400 bg-purple-500/10 border-purple-500/20' },
  { id: 'consultant', label: 'Consulente', icon: Briefcase, color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20' },
  { id: 'other', label: 'Altro', icon: Users, color: 'text-zinc-400 bg-zinc-500/10 border-zinc-500/20' },
];

const TYPE_MAP = Object.fromEntries(CONTACT_TYPES.map(t => [t.id, t]));

/* ──── Conflict Check constants ──── */
const ROLE_LABELS = {
  client: 'Cliente',
  counterparty: 'Controparte',
  opposing_counsel: 'Avv. Controparte',
  judge: 'Giudice',
  consultant: 'Consulente',
};

const FIELD_LABELS = {
  client: 'Cliente',
  counterparty: 'Controparte',
  description: 'Descrizione',
  court: 'Tribunale',
  object: 'Oggetto',
};

const STATUS_LABELS = { active: 'Attivo', closed: 'Chiuso', archived: 'Archiviato' };
const STATUS_COLORS = {
  active: 'bg-green-500/10 text-green-400 border-green-500/30',
  closed: 'bg-zinc-500/10 text-zinc-400 border-zinc-500/30',
  archived: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
};

/* ──── Conflict Check Panel (inline) ──── */
function ConflictCheckPanel({ onSelectPractice }) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const debounceRef = useRef(null);

  useEffect(() => {
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current); };
  }, []);

  const doSearch = useCallback(async (searchQuery) => {
    const q = searchQuery.trim();
    if (q.length < 2) {
      setResults(null);
      setSearched(false);
      return;
    }
    setLoading(true);
    try {
      const res = await api.checkConflict(q);
      setResults(res);
      setSearched(true);
    } catch (e) {
      console.error('Conflict check failed:', e);
      setResults({ practiceMatches: [], contactMatches: [] });
      setSearched(true);
    }
    setLoading(false);
  }, []);

  const handleInput = (val) => {
    setQuery(val);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => doSearch(val), 400);
  };

  const practiceMatches = results?.practiceMatches || [];
  const contactMatches = results?.contactMatches || [];
  const hasConflict = practiceMatches.length > 0 || contactMatches.length > 0;
  const isClean = searched && !hasConflict;

  return (
    <div className="space-y-6">
      {/* Search Bar */}
      <div className="relative">
        <Search className="absolute left-5 top-1/2 -translate-y-1/2 text-text-dim" size={20} />
        <input
          type="text"
          value={query}
          onChange={e => handleInput(e.target.value)}
          placeholder="Nome, cognome, società, codice fiscale, P.IVA..."
          className="w-full pl-14 pr-12 py-4 bg-white/5 border border-white/10 rounded-2xl text-white text-lg placeholder:text-text-dim/50 focus:border-primary/50 focus:bg-white/[0.07] focus:ring-2 focus:ring-primary/20 transition-all outline-none"
          autoFocus
        />
        {query && (
          <button onClick={() => { setQuery(''); setResults(null); setSearched(false); }} className="absolute right-4 top-1/2 -translate-y-1/2 p-1 hover:bg-white/10 rounded-lg transition-colors">
            <X size={18} className="text-text-dim" />
          </button>
        )}
      </div>

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center py-8">
          <div className="w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
        </div>
      )}

      {/* Clean Result */}
      {isClean && !loading && (
        <div className="bg-green-500/5 border border-green-500/20 rounded-2xl p-8 text-center animate-fade-in">
          <div className="w-20 h-20 bg-green-500/10 rounded-full flex items-center justify-center mx-auto mb-4 border border-green-500/20">
            <ShieldCheck size={40} className="text-green-400" />
          </div>
          <h3 className="text-xl font-bold text-green-400">Nessun Conflitto Rilevato</h3>
          <p className="text-text-dim text-sm mt-2">
            La ricerca per "<span className="text-white font-semibold">{query}</span>" non ha trovato corrispondenze nei fascicoli o nell'anagrafica contatti.
          </p>
        </div>
      )}

      {/* Conflict Results */}
      {hasConflict && !loading && (
        <div className="space-y-6 animate-fade-in">
          {/* Warning Banner */}
          <div className="bg-red-500/5 border border-red-500/20 rounded-2xl p-5 flex items-start gap-4">
            <div className="w-12 h-12 bg-red-500/10 rounded-xl flex items-center justify-center flex-shrink-0 border border-red-500/20">
              <AlertTriangle size={24} className="text-red-400" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-red-400">Conflitto Potenziale</h3>
              <p className="text-text-dim text-sm mt-1">
                Trovate <span className="text-white font-bold">{practiceMatches.length}</span> pratiche e <span className="text-white font-bold">{contactMatches.length}</span> contatti corrispondenti a "<span className="text-white font-semibold">{query}</span>".
              </p>
            </div>
          </div>

          {/* Practice Matches */}
          {practiceMatches.length > 0 && (
            <div className="space-y-3">
              <h4 className="text-[11px] font-black text-text-dim uppercase tracking-[2px] flex items-center gap-2">
                <Briefcase size={14} /> Fascicoli Coinvolti ({practiceMatches.length})
              </h4>
              <div className="space-y-2">
                {practiceMatches.map((m, i) => {
                  const p = m.practice;
                  const status = p.status || 'active';
                  return (
                    <button
                      type="button"
                      key={p.id || i}
                      onClick={() => onSelectPractice?.(p.id)}
                      className="bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.08] rounded-xl p-4 cursor-pointer transition-all group active:scale-[0.99] text-left w-full"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-3 flex-wrap">
                            <span className="text-white font-bold text-sm truncate">{p.client || 'N/A'}</span>
                            <span className={`text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-md border ${STATUS_COLORS[status]}`}>
                              {STATUS_LABELS[status]}
                            </span>
                          </div>
                          <p className="text-text-dim text-xs mt-1 truncate">{p.object || ''}</p>
                          {p.counterparty && (
                            <p className="text-text-muted text-xs mt-0.5 flex items-center gap-1">
                              <Scale size={10} /> vs {p.counterparty}
                            </p>
                          )}
                        </div>
                        <div className="flex items-center gap-3 flex-shrink-0 ml-4">
                          <div className="flex flex-wrap gap-1 max-w-[200px] justify-end">
                            {(m.matchedFields || []).map((f) => (
                              <span key={f} className="text-[8px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 whitespace-nowrap">
                                {f.startsWith('ruolo:') ? ROLE_LABELS[f.split(':')[1]] || f.split(':')[1] : FIELD_LABELS[f] || f}
                              </span>
                            ))}
                          </div>
                          <ChevronRight size={16} className="text-text-dim group-hover:text-primary transition-colors flex-shrink-0" />
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Contact Matches */}
          {contactMatches.length > 0 && (
            <div className="space-y-3">
              <h4 className="text-[11px] font-black text-text-dim uppercase tracking-[2px] flex items-center gap-2">
                <User size={14} /> Contatti Trovati ({contactMatches.length})
              </h4>
              <div className="space-y-2">
                {contactMatches.map((cm, i) => {
                  const c = cm.contact;
                  return (
                    <div key={c.id || i} className="bg-white/[0.04] border border-white/[0.08] rounded-xl p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex-1 min-w-0">
                          <span className="text-white font-bold text-sm">{c.name}</span>
                          <div className="flex items-center gap-3 mt-1 flex-wrap">
                            {c.type && (
                              <span className="text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-md bg-primary/10 text-primary border border-primary/20">
                                {ROLE_LABELS[c.type] || c.type}
                              </span>
                            )}
                            {c.fiscalCode && <span className="text-text-muted text-[10px] font-mono">{c.fiscalCode}</span>}
                            {c.vatNumber && <span className="text-text-muted text-[10px] font-mono">P.IVA {c.vatNumber}</span>}
                          </div>
                        </div>
                        <div className="text-right flex-shrink-0 ml-4">
                          <span className="text-[10px] text-text-dim">
                            {cm.linkedPracticeIds?.length || 0} fascicoli collegati
                          </span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Empty state */}
      {!searched && !loading && (
        <div className="text-center py-16 opacity-40">
          <Shield size={48} className="mx-auto mb-4 text-text-dim" />
          <p className="text-text-dim text-sm">Digita un nome per verificare eventuali conflitti di interessi</p>
          <p className="text-text-dim text-xs mt-1">La ricerca include tutti i fascicoli (attivi, chiusi, archiviati) e i contatti</p>
        </div>
      )}
    </div>
  );
}

ConflictCheckPanel.propTypes = {
  onSelectPractice: PropTypes.func,
};

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
      } catch (e) { console.error(e); }
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
    }
  }, []);

  const confirmDeleteContact = async () => {
    if (!pendingDeleteId) return;
    await saveContacts(contacts.filter(c => c.id !== pendingDeleteId));
    if (expandedId === pendingDeleteId) setExpandedId(null);
    setPendingDeleteId(null);
    toast.success('Contatto eliminato');
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
  const getRelatedContacts = useCallback((contact) => {
    const linked = getLinkedPractices(contact.id);
    const related = [];
    const seen = new Set();
    linked.forEach(p => {
      const pairs = [
        { role: 'counterparty', field: 'counterpartyId', label: 'Controparte' },
        { role: 'opposing_counsel', field: 'opposingCounselId', label: 'Avv. Controparte' },
        { role: 'client', field: 'clientId', label: 'Cliente' },
        { role: 'judge', field: 'judgeId', label: 'Giudice' },
      ];
      pairs.forEach(({ field, label }) => {
        const cid = p[field];
        if (cid && cid !== contact.id && !seen.has(cid)) {
          seen.add(cid);
          const found = contacts.find(ct => ct.id === cid);
          if (found) related.push({ role: label, contact: found });
        }
      });
      // Also check roles array
      (p.roles || []).forEach(r => {
        if (r.contactId && r.contactId !== contact.id && !seen.has(r.contactId)) {
          seen.add(r.contactId);
          const found = contacts.find(ct => ct.id === r.contactId);
          if (found) related.push({ role: ROLE_LABELS[r.role] || r.role, contact: found });
        }
      });
    });
    return related;
  }, [contacts, getLinkedPractices]);

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
            <h1 className="text-2xl font-bold text-white tracking-tight">Contatti & Conflitti</h1>
            <p className="text-text-dim text-sm mt-0.5">{contacts.length} contatti registrati</p>
          </div>
        </div>
        {activeTab === 'contacts' && (
          <button onClick={() => setShowCreate(true)} className="btn-primary px-5 py-2.5 flex items-center gap-2 text-sm font-bold">
            <Plus size={16} /> Nuovo Contatto
          </button>
        )}
      </div>

      {/* Tab Switcher */}
      <div className="inline-flex bg-white/[0.04] rounded-xl p-1 border border-white/5">
        <button onClick={() => setActiveTab('contacts')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold uppercase tracking-wider transition-all cursor-pointer ${
            activeTab === 'contacts'
              ? 'bg-primary text-black shadow-[0_0_12px_rgba(212,169,64,0.25)]'
              : 'text-text-dim hover:text-white hover:bg-white/[0.06]'
          }`}>
          <Users size={14} /> Anagrafica
        </button>
        <button onClick={() => setActiveTab('conflicts')}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold uppercase tracking-wider transition-all cursor-pointer ${
            activeTab === 'conflicts'
              ? 'bg-primary text-black shadow-[0_0_12px_rgba(212,169,64,0.25)]'
              : 'text-text-dim hover:text-white hover:bg-white/[0.06]'
          }`}>
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
            className="w-full pl-11 pr-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white text-sm placeholder:text-text-dim/50 focus:border-primary/50 outline-none"
          />
        </div>
        {/* Type filter pills — scrollable on mobile */}
        <div className="flex gap-1.5 overflow-x-auto no-scrollbar pb-1">
          <button onClick={() => setFilterType('all')}
            className={`px-3 py-2 rounded-lg text-[10px] font-bold uppercase tracking-wider whitespace-nowrap transition-all border ${filterType === 'all' ? 'bg-primary/10 text-primary border-primary/30' : 'bg-white/5 text-text-dim border-white/10 hover:bg-white/10'}`}>
            Tutti ({typeCounts.all})
          </button>
          {CONTACT_TYPES.map(t => (
            <button key={t.id} onClick={() => setFilterType(t.id)}
              className={`px-3 py-2 rounded-lg text-[10px] font-bold uppercase tracking-wider whitespace-nowrap transition-all border ${filterType === t.id ? t.color : 'bg-white/5 text-text-dim border-white/10 hover:bg-white/10'}`}>
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
                    className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all border ${
                      isExpanded
                        ? 'bg-primary/5 border-primary/20 lg:w-[38%] lg:flex-shrink-0'
                        : 'bg-white/[0.03] hover:bg-white/[0.06] border-white/[0.06] w-full'
                    }`}
                  >
                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center border flex-shrink-0 ${typeInfo.color}`}>
                      <TypeIcon size={18} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-white font-bold text-sm truncate">{c.name}</p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-[9px] font-bold uppercase tracking-wider text-text-dim">{typeInfo.label}</span>
                        {linkedCount > 0 && (
                          <span className="text-[9px] text-text-muted">&bull; {linkedCount} fascicoli</span>
                        )}
                      </div>
                    </div>
                    {/* Actions */}
                    <div className="flex items-center gap-0.5 flex-shrink-0">
                      {!isExpanded && (
                        <button
                          type="button"
                          onClick={(e) => { e.stopPropagation(); setEditingContact({ ...c }); }}
                          className="p-2 hover:bg-white/10 rounded-lg transition-all"
                          title="Modifica"
                        >
                          <Edit3 size={14} className="text-text-dim hover:text-primary" />
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => setExpandedId(isExpanded ? null : c.id)}
                        className="p-2 hover:bg-white/10 rounded-lg transition-all"
                        title={isExpanded ? 'Chiudi dettagli' : 'Mostra dettagli'}
                      >
                        {isExpanded ? (
                          <ChevronRight size={14} className="text-primary" />
                        ) : (
                          <Info size={14} className="text-text-dim hover:text-primary" />
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Detail Card — desktop: side by side */}
                  {isExpanded && (
                    <div className="hidden lg:block lg:flex-1 bg-white/[0.03] border border-white/[0.08] rounded-2xl p-5 space-y-4 animate-fade-in">
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
                  <div className="lg:hidden bg-white/[0.03] border border-white/[0.08] rounded-2xl p-5 mt-1.5 space-y-4 animate-slide-up">
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
            if (editingContact) {
              await saveContacts(contacts.map(c => c.id === contact.id ? contact : c));
              setEditingContact(null);
              toast.success('Contatto aggiornato');
            } else {
              await saveContacts([contact, ...contacts]);
              setShowCreate(false);
              toast.success('Contatto aggiunto');
            }
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

  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  const handleSubmit = () => {
    if (!form.name.trim()) {
      toast.error('Il nome è obbligatorio');
      return;
    }
    if (form.email && form.email.trim() && !EMAIL_RE.test(form.email.trim())) {
      toast.error('Indirizzo email non valido');
      return;
    }
    if (form.pec && form.pec.trim() && !EMAIL_RE.test(form.pec.trim())) {
      toast.error('Indirizzo PEC non valido');
      return;
    }
    onSave(form);
  };

  return (
    <ModalOverlay onClose={onClose} labelledBy="contact-modal-title" focusTrap>
      <div className="bg-[#0f1016] border border-white/10 rounded-[32px] w-full max-w-2xl shadow-3xl overflow-hidden flex flex-col max-h-[92vh]">
        
        {/* Header — stile unificato */}
        <div className="px-8 py-5 border-b border-white/5 flex items-center justify-between bg-gradient-to-r from-white/5 to-transparent">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-primary/10 rounded-2xl flex items-center justify-center text-primary border border-primary/20">
              <Users size={28} />
            </div>
            <div>
              <h2 id="contact-modal-title" className="text-xl font-bold text-white tracking-tight">{initial ? 'Modifica Contatto' : 'Nuovo Contatto'}</h2>
              <p className="text-text-dim text-xs uppercase tracking-widest font-medium opacity-60">Anagrafica</p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 hover:bg-white/10 rounded-xl text-text-dim transition-all group">
            <X size={24} className="group-hover:rotate-90 transition-transform" />
          </button>
        </div>

        {/* Body */}
        <div className="p-8 space-y-6 overflow-y-auto custom-scrollbar flex-1">
          {/* Type pills */}
          <div className="space-y-3">
            <span className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Tipo</span>
            <div className="flex flex-wrap gap-2.5">
              {CONTACT_TYPES.map(t => (
                <button key={t.id} onClick={() => updateField('type', t.id)}
                  className={`px-4 py-2.5 rounded-xl text-xs font-bold uppercase tracking-wider transition-all duration-300 border ${form.type === t.id ? t.color + ' scale-105 ring-2 ring-white/5' : 'bg-white/5 text-text-dim border-white/10 hover:bg-white/10 hover:border-white/20'}`}>
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
              className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white text-sm placeholder:text-text-dim/50 focus:border-primary/50 outline-none" autoFocus />
          </div>

          {/* CF + P.IVA */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label htmlFor="ct-cf" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Codice Fiscale</label>
              <input id="ct-cf" value={form.fiscalCode || ''} onChange={e => updateField('fiscalCode', e.target.value.toUpperCase())}
                placeholder="RSSMRA80A01H501Z" maxLength={16}
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white text-sm font-mono placeholder:text-text-dim/40 focus:border-primary/50 outline-none" />
            </div>
            <div className="space-y-2">
              <label htmlFor="ct-vat" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">P.IVA</label>
              <input id="ct-vat" value={form.vatNumber || ''} onChange={e => updateField('vatNumber', e.target.value)}
                placeholder="01234567890" maxLength={11}
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white text-sm font-mono placeholder:text-text-dim/40 focus:border-primary/50 outline-none" />
            </div>
          </div>

          {/* Phone + Email */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label htmlFor="ct-phone" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Telefono</label>
              <input id="ct-phone" value={form.phone || ''} onChange={e => updateField('phone', e.target.value)}
                placeholder="+39 333 1234567" type="tel"
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white text-sm placeholder:text-text-dim/40 focus:border-primary/50 outline-none" />
            </div>
            <div className="space-y-2">
              <label htmlFor="ct-email" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Email</label>
              <input id="ct-email" value={form.email || ''} onChange={e => updateField('email', e.target.value)}
                placeholder="email@esempio.it" type="email"
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white text-sm placeholder:text-text-dim/40 focus:border-primary/50 outline-none" />
            </div>
          </div>

          {/* PEC */}
          <div className="space-y-2">
            <label htmlFor="ct-pec" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">PEC</label>
            <input id="ct-pec" value={form.pec || ''} onChange={e => updateField('pec', e.target.value)}
              placeholder="nome@pec-avvocati.it" type="email"
              className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white text-sm placeholder:text-text-dim/40 focus:border-primary/50 outline-none" />
          </div>

          {/* Address */}
          <div className="space-y-2">
            <label htmlFor="ct-address" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Indirizzo</label>
            <input id="ct-address" value={form.address || ''} onChange={e => updateField('address', e.target.value)}
              placeholder="Via Roma 1, 00100 Roma (RM)"
              className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white text-sm placeholder:text-text-dim/40 focus:border-primary/50 outline-none" />
          </div>

          {/* Conditional fields based on type */}
          {(form.type === 'opposing_counsel' || form.type === 'consultant') && (
            <div className="space-y-2">
              <label htmlFor="ct-bar" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Ordine / Albo</label>
              <input id="ct-bar" value={form.barAssociation || ''} onChange={e => updateField('barAssociation', e.target.value)}
                placeholder="Ordine Avvocati di Roma"
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white text-sm placeholder:text-text-dim/40 focus:border-primary/50 outline-none" />
            </div>
          )}

          {form.type === 'judge' && (
            <div className="space-y-2">
              <label htmlFor="ct-court" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Tribunale / Sezione</label>
              <input id="ct-court" value={form.court || ''} onChange={e => updateField('court', e.target.value)}
                placeholder="Tribunale di Milano, Sez. III"
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white text-sm placeholder:text-text-dim/40 focus:border-primary/50 outline-none" />
            </div>
          )}

          {/* Notes */}
          <div className="space-y-2">
            <label htmlFor="ct-notes" className="text-[10px] font-black text-text-dim uppercase tracking-[2px] ml-1">Note</label>
            <textarea id="ct-notes" value={form.notes || ''} onChange={e => updateField('notes', e.target.value)}
              placeholder="Annotazioni libere..." rows={2}
              className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white text-sm placeholder:text-text-dim/40 focus:border-primary/50 outline-none resize-none" />
          </div>
        </div>

        {/* Footer — stile unificato */}
        <div className="px-8 py-5 border-t border-white/5 bg-[#14151d] flex justify-end gap-4">
          <button onClick={onClose} className="px-6 py-3 rounded-2xl text-text-dim hover:text-white hover:bg-white/5 transition-all text-xs font-bold uppercase tracking-widest">Annulla</button>
          <button onClick={handleSubmit} className="btn-primary px-10 py-3 flex items-center gap-3 shadow-xl shadow-primary/20 hover:scale-[1.05] active:scale-[0.98] transition-all">
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
function ContactDetailCard({ contact, typeInfo, linkedPractices, relatedContacts, onEdit, onDelete, onSelectPractice }) {
  const TypeIcon = typeInfo.icon;
  const c = contact;

  // Determine which fields to show based on type
  const showBarAssociation = c.type === 'opposing_counsel' || c.type === 'consultant';
  const showCourt = c.type === 'judge';
  const showFiscalCode = c.type === 'client' || c.type === 'counterparty';
  const showVat = c.type === 'client';

  return (
    <>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-xl flex items-center justify-center border ${typeInfo.color}`}>
            <TypeIcon size={18} />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">{c.name}</h3>
            <span className={`text-[9px] font-bold uppercase tracking-wider ${typeInfo.color.split(' ')[0]}`}>
              {typeInfo.label}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-0.5">
          <button type="button" onClick={onEdit} className="p-2 hover:bg-white/10 rounded-lg transition-all" title="Modifica">
            <Edit3 size={14} className="text-text-dim" />
          </button>
          <button type="button" onClick={onDelete} className="p-2 hover:bg-red-500/10 rounded-lg transition-all" title="Elimina">
            <Trash2 size={14} className="text-red-400/60 hover:text-red-400" />
          </button>
        </div>
      </div>

      {/* Contact Info — only non-empty fields */}
      <div className="space-y-2">
        {c.phone && (
          <div className="flex items-center gap-3 text-sm">
            <Phone size={13} className="text-text-dim flex-shrink-0" />
            <span className="text-white text-xs">{c.phone}</span>
          </div>
        )}
        {c.email && (
          <div className="flex items-center gap-3 text-sm">
            <Mail size={13} className="text-text-dim flex-shrink-0" />
            <span className="text-white text-xs">{c.email}</span>
          </div>
        )}
        {c.pec && (
          <div className="flex items-center gap-3 text-sm">
            <Mail size={13} className="text-primary/60 flex-shrink-0" />
            <span className="text-white text-xs">PEC: {c.pec}</span>
          </div>
        )}
        {c.address && (
          <div className="flex items-center gap-3 text-sm">
            <MapPin size={13} className="text-text-dim flex-shrink-0" />
            <span className="text-white text-xs">{c.address}</span>
          </div>
        )}
        {showFiscalCode && c.fiscalCode && (
          <div className="flex items-center gap-3 text-sm">
            <Hash size={13} className="text-text-dim flex-shrink-0" />
            <span className="text-white font-mono text-xs">{c.fiscalCode}</span>
          </div>
        )}
        {showVat && c.vatNumber && (
          <div className="flex items-center gap-3 text-sm">
            <Building size={13} className="text-text-dim flex-shrink-0" />
            <span className="text-white font-mono text-xs">P.IVA {c.vatNumber}</span>
          </div>
        )}
        {showBarAssociation && c.barAssociation && (
          <div className="flex items-center gap-3 text-sm">
            <Scale size={13} className="text-text-dim flex-shrink-0" />
            <span className="text-white text-xs">{c.barAssociation}</span>
          </div>
        )}
        {showCourt && c.court && (
          <div className="flex items-center gap-3 text-sm">
            <Gavel size={13} className="text-text-dim flex-shrink-0" />
            <span className="text-white text-xs">{c.court}</span>
          </div>
        )}
        {c.notes && (
          <p className="text-text-dim text-xs italic border-l-2 border-white/10 pl-3 mt-1">{c.notes}</p>
        )}
      </div>

      {/* Related Contacts (cross-practice relationships) */}
      {relatedContacts.length > 0 && (
        <div className="space-y-2 pt-1">
          <h4 className="text-[9px] font-black text-text-dim uppercase tracking-[2px]">Soggetti Collegati</h4>
          <div className="space-y-1">
            {relatedContacts.map(({ role, contact: rc }) => {
              const rcType = TYPE_MAP[rc.type] || TYPE_MAP.other;
              const RcIcon = rcType.icon;
              return (
                <div key={rc.id} className="flex items-center gap-2.5 px-3 py-2 bg-white/[0.03] border border-white/[0.05] rounded-lg">
                  <div className={`w-7 h-7 rounded-lg flex items-center justify-center border ${rcType.color}`}>
                    <RcIcon size={12} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-white text-xs font-medium truncate">{rc.name}</p>
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
                className="flex items-center gap-2.5 px-3 py-2 bg-white/[0.03] hover:bg-white/[0.06] border border-white/[0.05] rounded-lg transition-all group text-left w-full">
                <Briefcase size={13} className="text-text-dim flex-shrink-0" />
                <p className="text-white text-xs truncate flex-1 group-hover:text-primary transition-colors">{p.client} — {p.object}</p>
                <span className={`text-[8px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${p.status === 'active' ? 'bg-green-500/10 text-green-400' : 'bg-zinc-500/10 text-zinc-400'}`}>
                  {p.status === 'active' ? 'Attivo' : 'Chiuso'}
                </span>
              </button>
            ))}
          </div>
        </div>
      )}
    </>
  );
}

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