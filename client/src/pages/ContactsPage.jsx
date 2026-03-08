import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import PropTypes from 'prop-types';
import { Users, Plus, Search, User, Scale, Briefcase, Building, Gavel, UserCheck, Edit3, Trash2, X, Check, Phone, Mail, MapPin, Hash, ChevronRight, Shield, ShieldCheck, AlertTriangle } from 'lucide-react';
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
  const [selectedContact, setSelectedContact] = useState(null);
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
    if (selectedContact?.id === pendingDeleteId) setSelectedContact(null);
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

      {/* Main Layout: List + Detail */}
      <div className="flex flex-col lg:flex-row gap-4">
        {/* Contact List */}
        <div className={`space-y-1.5 ${selectedContact ? 'lg:w-1/2' : 'w-full'} transition-all`}>
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
              const isSelected = selectedContact?.id === c.id;
              const linkedCount = getLinkedPractices(c.id).length;
              return (
                <button
                  type="button"
                  key={c.id}
                  onClick={() => setSelectedContact(c)}
                  className={`flex items-center gap-3 px-4 py-3 rounded-xl cursor-pointer transition-all group active:scale-[0.99] text-left w-full ${
                    isSelected ? 'bg-primary/10 border border-primary/30' : 'bg-white/[0.03] hover:bg-white/[0.06] border border-white/[0.06]'
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
                        <span className="text-[9px] text-text-muted">• {linkedCount} fascicoli</span>
                      )}
                    </div>
                  </div>
                  <ChevronRight size={14} className="text-text-dim group-hover:text-primary transition-colors flex-shrink-0" />
                </button>
              );
            })
          )}
        </div>

        {/* Detail Panel */}
        {selectedContact && (
          <div className="lg:w-1/2 bg-white/[0.03] border border-white/[0.08] rounded-2xl p-6 space-y-5 animate-fade-in self-start lg:sticky lg:top-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {(() => {
                  const typeInfo = TYPE_MAP[selectedContact.type] || TYPE_MAP.other;
                  const TypeIcon = typeInfo.icon;
                  return (
                    <div className={`w-12 h-12 rounded-xl flex items-center justify-center border ${typeInfo.color}`}>
                      <TypeIcon size={22} />
                    </div>
                  );
                })()}
                <div>
                  <h3 className="text-lg font-bold text-white">{selectedContact.name}</h3>
                  <span className={`text-[10px] font-bold uppercase tracking-wider ${(TYPE_MAP[selectedContact.type] || TYPE_MAP.other).color.split(' ')[0]}`}>
                    {(TYPE_MAP[selectedContact.type] || TYPE_MAP.other).label}
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-1">
                <button onClick={() => setEditingContact({ ...selectedContact })} className="p-2 hover:bg-white/10 rounded-lg transition-all">
                  <Edit3 size={16} className="text-text-dim" />
                </button>
                <button onClick={() => setPendingDeleteId(selectedContact.id)} className="p-2 hover:bg-red-500/10 rounded-lg transition-all">
                  <Trash2 size={16} className="text-red-400" />
                </button>
                <button onClick={() => setSelectedContact(null)} className="p-2 hover:bg-white/10 rounded-lg transition-all lg:hidden">
                  <X size={16} className="text-text-dim" />
                </button>
              </div>
            </div>

            {/* Contact Info */}
            <div className="space-y-3">
              {selectedContact.email && (
                <div className="flex items-center gap-3 text-sm">
                  <Mail size={14} className="text-text-dim flex-shrink-0" />
                  <span className="text-white">{selectedContact.email}</span>
                </div>
              )}
              {selectedContact.pec && (
                <div className="flex items-center gap-3 text-sm">
                  <Mail size={14} className="text-primary flex-shrink-0" />
                  <span className="text-white">PEC: {selectedContact.pec}</span>
                </div>
              )}
              {selectedContact.phone && (
                <div className="flex items-center gap-3 text-sm">
                  <Phone size={14} className="text-text-dim flex-shrink-0" />
                  <span className="text-white">{selectedContact.phone}</span>
                </div>
              )}
              {selectedContact.address && (
                <div className="flex items-center gap-3 text-sm">
                  <MapPin size={14} className="text-text-dim flex-shrink-0" />
                  <span className="text-white">{selectedContact.address}</span>
                </div>
              )}
              {selectedContact.fiscalCode && (
                <div className="flex items-center gap-3 text-sm">
                  <Hash size={14} className="text-text-dim flex-shrink-0" />
                  <span className="text-white font-mono text-xs">{selectedContact.fiscalCode}</span>
                </div>
              )}
              {selectedContact.vatNumber && (
                <div className="flex items-center gap-3 text-sm">
                  <Building size={14} className="text-text-dim flex-shrink-0" />
                  <span className="text-white font-mono text-xs">P.IVA {selectedContact.vatNumber}</span>
                </div>
              )}
              {selectedContact.barAssociation && (
                <div className="flex items-center gap-3 text-sm">
                  <Scale size={14} className="text-text-dim flex-shrink-0" />
                  <span className="text-white text-xs">{selectedContact.barAssociation}</span>
                </div>
              )}
              {selectedContact.court && (
                <div className="flex items-center gap-3 text-sm">
                  <Gavel size={14} className="text-text-dim flex-shrink-0" />
                  <span className="text-white text-xs">{selectedContact.court}</span>
                </div>
              )}
              {selectedContact.notes && (
                <p className="text-text-dim text-xs mt-2 italic border-l-2 border-white/10 pl-3">{selectedContact.notes}</p>
              )}
            </div>

            {/* Linked Practices */}
            {(() => {
              const linked = getLinkedPractices(selectedContact.id);
              if (linked.length === 0) return null;
              return (
                <div className="space-y-2 pt-2">
                  <h4 className="text-[10px] font-black text-text-dim uppercase tracking-[2px]">Fascicoli Collegati ({linked.length})</h4>
                  <div className="space-y-1.5">
                    {linked.map(p => (
                      <button type="button" key={p.id} onClick={() => onSelectPractice?.(p.id)}
                        className="flex items-center gap-3 px-3 py-2 bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.06] rounded-xl cursor-pointer transition-all group active:scale-[0.98] text-left w-full">
                        <Briefcase size={14} className="text-text-dim flex-shrink-0" />
                        <div className="flex-1 min-w-0">
                          <p className="text-white text-sm truncate group-hover:text-primary transition-colors">{p.client} — {p.object}</p>
                        </div>
                        <span className={`text-[8px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${p.status === 'active' ? 'bg-green-500/10 text-green-400' : 'bg-zinc-500/10 text-zinc-400'}`}>
                          {p.status === 'active' ? 'Attivo' : 'Chiuso'}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              );
            })()}
          </div>
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
              setSelectedContact(contact);
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

  const handleSubmit = () => {
    if (!form.name.trim()) {
      toast.error('Il nome è obbligatorio');
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

ContactModal.propTypes = {
  initial: PropTypes.object,
  onSave: PropTypes.func.isRequired,
  onClose: PropTypes.func.isRequired,
};