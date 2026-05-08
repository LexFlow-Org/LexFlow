import { useState, useCallback, useRef, useEffect, useId } from 'react';
import PropTypes from 'prop-types';
import { Search, AlertTriangle, Shield, ShieldCheck, User, Briefcase, Scale, ChevronRight, X } from 'lucide-react';
import toast from 'react-hot-toast';
import * as api from '../tauri-api';
import { ROLE_LABELS, CONFLICT_FIELD_LABELS, STATUS_LABELS, STATUS_COLORS } from '../utils/conflictConstants';

// FIX-41: fallback labels/colors per status sconosciuto
const UNKNOWN_STATUS_LABEL = 'Sconosciuto';
const UNKNOWN_STATUS_COLOR = 'bg-surface text-text-dim border-border';
// FIX-42: numero massimo di "matched fields" pills mostrate prima del +N
const MAX_MATCHED_PILLS = 3;

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
  // FIX-36 + FIX-37: seq-id per scartare risposte stale
  const reqIdRef = useRef(0);
  const inputId = useId();

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
    // FIX-36: incrementa il seq-id e cattura il valore corrente
    const myId = ++reqIdRef.current;
    setLoading(true);
    try {
      const res = await api.checkConflict(q);
      // Scarta se nel frattempo è arrivata una richiesta più recente
      if (myId !== reqIdRef.current) return;
      setResults(res);
      setSearched(true);
    } catch (e) {
      if (myId !== reqIdRef.current) return;
      console.error('Conflict check failed:', e);
      toast.error('Impossibile verificare i conflitti. Riprova.');
      setResults({ practiceMatches: [], contactMatches: [] });
      setSearched(true);
    } finally {
      // FIX-37: setLoading(false) sempre, anche su errore
      if (myId === reqIdRef.current) setLoading(false);
    }
  }, []);

  const handleInput = (val) => {
    setQuery(val);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    // FIX-40: debounce ridotto a 220ms
    debounceRef.current = setTimeout(() => doSearch(val), 220);
  };

  const practiceMatches = results?.practiceMatches || [];
  const contactMatches = results?.contactMatches || [];
  const hasConflict = practiceMatches.length > 0 || contactMatches.length > 0;
  const isClean = searched && !hasConflict;

  return (
    <div className="space-y-6">
      {/* Search Bar */}
      <div className="relative">
        <Search className="absolute left-5 top-1/2 -translate-y-1/2 text-text-dim" aria-hidden="true" size={20} />
        {/* FIX-38: label visually-hidden */}
        <label htmlFor={inputId} className="sr-only">Cerca conflitti di interessi</label>
        <input
          id={inputId}
          type="text"
          aria-label="Cerca conflitti di interessi"
          value={query}
          onChange={e => handleInput(e.target.value)}
          placeholder="Nome, cognome, società, codice fiscale, P.IVA..."
          className="w-full pl-14 pr-12 py-4 bg-surface border border-border rounded-2xl text-text text-lg placeholder:text-text-dim/50 focus:border-primary/50 focus:bg-card focus:ring-2 focus:ring-primary/20 transition-colors outline-none"
          /* FIX-35: niente autoFocus su input primario di pannello (può rubare focus all'apertura della pagina) */
        />
        {query && (
          <button
            /* FIX-39: aria-label + type="button" esplicito */
            type="button"
            aria-label="Cancella ricerca"
            onClick={() => { setQuery(''); setResults(null); setSearched(false); reqIdRef.current++; }}
            className="absolute right-4 top-1/2 -translate-y-1/2 p-1 hover:bg-surface rounded-lg transition-colors"
          >
            <X size={18} className="text-text-dim" />
          </button>
        )}
      </div>

      {/* Loading */}
      {loading && (
        <div className="flex items-center justify-center py-8" role="status" aria-live="polite">
          <div className="w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
          <span className="sr-only">Verifica in corso…</span>
        </div>
      )}

      {/* Clean Result */}
      {isClean && !loading && (
        <div className="bg-success-soft border border-success-border rounded-2xl p-8 text-center animate-fade-in">
          <div className="w-20 h-20 bg-success-soft rounded-full flex items-center justify-center mx-auto mb-4 border border-success-border">
            <ShieldCheck size={40} className="text-success" />
          </div>
          <h3 className="text-xl font-bold text-success">Nessun Conflitto Rilevato</h3>
          <p className="text-text-dim text-sm mt-2">
            La ricerca per &ldquo;<span className="text-text font-semibold">{query}</span>&rdquo; non ha trovato corrispondenze nei fascicoli o nell&apos;anagrafica contatti.
          </p>
        </div>
      )}

      {/* Conflict Results */}
      {hasConflict && !loading && (
        <div className="space-y-6 animate-fade-in">
          {/* Warning Banner */}
          <div className="bg-danger-soft border border-danger-border rounded-2xl p-5 flex items-start gap-4">
            <div className="w-12 h-12 bg-danger-soft rounded-xl flex items-center justify-center flex-shrink-0 border border-danger-border">
              <AlertTriangle size={24} className="text-danger" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-danger">Conflitto Potenziale</h3>
              <p className="text-text-dim text-sm mt-1">
                Trovate <span className="text-text font-bold">{practiceMatches.length}</span> pratiche e <span className="text-text font-bold">{contactMatches.length}</span> contatti corrispondenti a &ldquo;<span className="text-text font-semibold">{query}</span>&rdquo;.
              </p>
            </div>
          </div>

          {/* Practice Matches */}
          {practiceMatches.length > 0 && (
            <div className="space-y-3">
              <h4 className="text-xs-p font-black text-text-dim uppercase tracking-label flex items-center gap-2">
                <Briefcase size={14} /> Fascicoli Coinvolti ({practiceMatches.length})
              </h4>
              <div className="space-y-2">
                {practiceMatches.map((m, i) => {
                  const p = m.practice;
                  const status = p.status || 'active';
                  // FIX-41: fallback per status sconosciuti
                  const statusLabel = STATUS_LABELS[status] || UNKNOWN_STATUS_LABEL;
                  const statusColor = STATUS_COLORS[status] || UNKNOWN_STATUS_COLOR;
                  // FIX-42: limite pills + indicatore +N
                  const matched = m.matchedFields || [];
                  const visibleMatched = matched.slice(0, MAX_MATCHED_PILLS);
                  const overflow = matched.length - visibleMatched.length;
                  return (
                    <button
                      type="button"
                      key={p.id || i}
                      onClick={() => onSelectPractice?.(p.id)}
                      className="bg-card hover:bg-card-hover border border-border rounded-xl p-4 cursor-pointer transition-colors group active:scale-[0.99] text-left w-full"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-3 flex-wrap">
                            <span className="text-text font-bold text-sm truncate">{p.client || 'N/A'}</span>
                            <span className={`text-3xs font-bold uppercase tracking-wider px-2 py-0.5 rounded-md border ${statusColor}`}>
                              {statusLabel}
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
                          {/* Matched fields pills (limited) */}
                          <div className="flex flex-wrap gap-1 max-w-[200px] justify-end">
                            {visibleMatched.map((f) => (
                              <span key={f} className="text-xxs font-bold uppercase tracking-wider px-1.5 py-0.5 rounded bg-warning-soft text-warning border border-warning-border whitespace-nowrap">
                                {f.startsWith('ruolo:') ? ROLE_LABELS[f.split(':')[1]] || f.split(':')[1] : CONFLICT_FIELD_LABELS[f] || f}
                              </span>
                            ))}
                            {overflow > 0 && (
                              <span
                                className="text-xxs font-bold uppercase tracking-wider px-1.5 py-0.5 rounded bg-surface text-text-dim border border-border whitespace-nowrap"
                                title={matched.slice(MAX_MATCHED_PILLS).join(', ')}
                              >
                                +{overflow}
                              </span>
                            )}
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
              <h4 className="text-xs-p font-black text-text-dim uppercase tracking-label flex items-center gap-2">
                <User size={14} /> Contatti Trovati ({contactMatches.length})
              </h4>
              <div className="space-y-2">
                {contactMatches.map((cm, i) => {
                  const c = cm.contact;
                  return (
                    // FIX-43: anche i contact match diventano <button> per consistenza con practice matches
                    <button
                      type="button"
                      key={c.id || i}
                      // No-op: non navighiamo (non c'è pagina contatto), ma manteniamo coerenza semantica.
                      // Rendiamo il button non-interattivo a livello visivo: nessun hover/active extra.
                      onClick={() => { /* future: navigate to contact detail */ }}
                      className="bg-card border border-border rounded-xl p-4 text-left w-full cursor-default"
                      tabIndex={-1}
                      aria-disabled="true"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex-1 min-w-0">
                          <span className="text-text font-bold text-sm">{c.name}</span>
                          <div className="flex items-center gap-3 mt-1 flex-wrap">
                            {c.type && (
                              <span className="text-3xs font-bold uppercase tracking-wider px-2 py-0.5 rounded-md bg-primary/10 text-primary border border-primary/20">
                                {ROLE_LABELS[c.type] || c.type}
                              </span>
                            )}
                            {c.fiscalCode && <span className="text-text-muted text-2xs font-mono">{c.fiscalCode}</span>}
                            {c.vatNumber && <span className="text-text-muted text-2xs font-mono">P.IVA {c.vatNumber}</span>}
                          </div>
                        </div>
                        <div className="text-right flex-shrink-0 ml-4">
                          <span className="text-2xs text-text-dim">
                            {cm.linkedPracticeIds?.length || 0} fascicoli collegati
                          </span>
                        </div>
                      </div>
                    </button>
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
