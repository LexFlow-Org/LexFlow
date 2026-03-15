import { useState, useCallback, useRef, useEffect } from 'react';
import PropTypes from 'prop-types';
import { Search, AlertTriangle, Shield, ShieldCheck, User, Briefcase, Scale, ChevronRight, X } from 'lucide-react';
import toast from 'react-hot-toast';
import * as api from '../tauri-api';
import { ROLE_LABELS, FIELD_LABELS, STATUS_LABELS, STATUS_COLORS } from '../utils/conflictConstants';

/**
 * Reusable conflict-check search panel with debounced input,
 * practice matches and contact matches.
 * Used both in the dedicated Conflict Check page and as an
 * inline tab inside ContactsPage.
 */
export default function ConflictCheckPanel({ onSelectPractice }) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const debounceRef = useRef(null);

  // Cleanup debounce timer on unmount
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
      toast.error('Errore verifica conflitti');
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
          className="w-full pl-14 pr-12 py-4 bg-white/5 border border-border rounded-2xl text-text text-lg placeholder:text-text-dim/50 focus:border-primary/50 focus:bg-white/[0.07] focus:ring-2 focus:ring-primary/20 transition-all outline-none"
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
            La ricerca per &ldquo;<span className="text-text font-semibold">{query}</span>&rdquo; non ha trovato corrispondenze nei fascicoli o nell&apos;anagrafica contatti.
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
                Trovate <span className="text-text font-bold">{practiceMatches.length}</span> pratiche e <span className="text-text font-bold">{contactMatches.length}</span> contatti corrispondenti a &ldquo;<span className="text-text font-semibold">{query}</span>&rdquo;.
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
                            <span className="text-text font-bold text-sm truncate">{p.client || 'N/A'}</span>
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
                          {/* Matched fields pills */}
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
                          <span className="text-text font-bold text-sm">{c.name}</span>
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
