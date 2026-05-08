import { useState, useRef, useEffect, useMemo, useId } from 'react';
import PropTypes from 'prop-types';
import { Search, Briefcase, X, ChevronDown } from 'lucide-react';

/**
 * Searchable combobox for selecting a practice (fascicolo).
 * Replaces native <select> with a glass-card styled dropdown.
 * Implementa il pattern WAI-ARIA combobox (role=combobox + role=listbox + aria-activedescendant).
 */
export default function PracticeCombobox({ value, onChange, practices, placeholder = 'Cerca fascicolo...', label, id }) {
  const [query, setQueryRaw] = useState('');
  const setQuery = (q) => { setQueryRaw(q); setHighlightIdx(-1); };
  const [open, setOpen] = useState(false);
  const wrapRef = useRef(null);
  const inputRef = useRef(null);
  const listRef = useRef(null);
  const [highlightIdx, setHighlightIdx] = useState(-1);

  // FIX-28: id stabile per role=listbox + aria-activedescendant
  const fallbackId = useId();
  const listboxId = id ? `${id}-listbox` : `combobox-${fallbackId}-listbox`;
  const optionIdPrefix = id ? `${id}-opt` : `combobox-${fallbackId}-opt`;

  // FIX-31: outside-click su mousedown + touchstart (mobile)
  useEffect(() => {
    if (!open) return;
    const handler = (e) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    document.addEventListener('touchstart', handler, { passive: true });
    return () => {
      document.removeEventListener('mousedown', handler);
      document.removeEventListener('touchstart', handler);
    };
  }, [open]);

  const activePractices = useMemo(
    () => (practices || []).filter(p => p.status === 'active'),
    [practices],
  );

  const filtered = useMemo(() => {
    if (!query.trim()) return activePractices;
    const q = query.trim().toLowerCase();
    return activePractices.filter(p =>
      (p.client || '').toLowerCase().includes(q) ||
      (p.object || '').toLowerCase().includes(q),
    );
  }, [activePractices, query]);

  const selected = useMemo(
    () => activePractices.find(p => p.id === value),
    [activePractices, value],
  );

  // FIX-32: pre-highlight idx 0 ogni volta che si apre o il filtro cambia
  useEffect(() => {
    if (open && filtered.length > 0 && highlightIdx < 0) {
      setHighlightIdx(0);
    }
  }, [open, filtered, highlightIdx]);

  const handleSelect = (pId) => {
    onChange(pId);
    setQuery('');
    setOpen(false);
    setHighlightIdx(-1);
  };

  const handleClear = (e) => {
    e.stopPropagation();
    onChange('');
    setQuery('');
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Escape') { setOpen(false); inputRef.current?.blur(); setHighlightIdx(-1); return; }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setHighlightIdx(i => (i + 1) % Math.max(filtered.length, 1));
      return;
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      setHighlightIdx(i => (i - 1 + filtered.length) % Math.max(filtered.length, 1));
      return;
    }
    // FIX-30: Home/End
    if (e.key === 'Home') {
      if (filtered.length === 0) return;
      e.preventDefault();
      setHighlightIdx(0);
      return;
    }
    if (e.key === 'End') {
      if (filtered.length === 0) return;
      e.preventDefault();
      setHighlightIdx(filtered.length - 1);
      return;
    }
    // FIX-30: Tab commit highlight
    if (e.key === 'Tab' && filtered.length > 0 && highlightIdx >= 0) {
      // Solo Tab plain (non Shift+Tab) committa: lascia il flusso naturale del focus
      if (!e.shiftKey) {
        e.preventDefault();
        handleSelect(filtered[highlightIdx].id);
      }
      return;
    }
    if (e.key === 'Enter') {
      // FIX-32: rifiuta Enter quando highlightIdx < 0 (no selezione visibile)
      if (filtered.length === 0 || highlightIdx < 0) return;
      e.preventDefault();
      handleSelect(filtered[highlightIdx].id);
    }
  };

  // Scroll highlighted item into view
  useEffect(() => {
    if (highlightIdx < 0 || !listRef.current) return;
    const items = listRef.current.querySelectorAll('[data-combo-item]');
    items[highlightIdx]?.scrollIntoView({ block: 'nearest' });
  }, [highlightIdx]);

  // FIX-33: focus input subito dopo l'apertura — useLayoutEffect-style via callback ref non praticabile qui;
  // usiamo un useEffect sincrono su open, che è già più pulito del setTimeout(...,0).
  useEffect(() => {
    if (open) inputRef.current?.focus();
  }, [open]);

  const activeOptionId = highlightIdx >= 0 && filtered[highlightIdx]
    ? `${optionIdPrefix}-${filtered[highlightIdx].id}`
    : undefined;

  return (
    <div ref={wrapRef} className="relative">
      {label && (
        <label htmlFor={id} className="text-2xs font-black text-text-dim uppercase tracking-label block mb-2">
          {label}
        </label>
      )}

      {/* Trigger (closed) / Input wrapper (open) */}
      {open ? (
        <div className="flex items-center gap-2 input-field py-2.5 pr-2 transition-colors w-full border-primary ring-1 ring-primary/20">
          <Search size={14} className="text-text-dim flex-shrink-0" />
          <input
            ref={inputRef}
            id={id}
            type="text"
            role="combobox"
            aria-expanded={open}
            aria-controls={listboxId}
            aria-autocomplete="list"
            aria-activedescendant={activeOptionId}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Filtra fascicoli..."
            className="flex-1 bg-transparent outline-none text-text text-sm placeholder:text-text-dim/50"
            autoComplete="off"
          />
        </div>
      ) : (
        <div className="relative">
          <button
            type="button"
            // FIX-29: aria-expanded dinamico
            aria-expanded={open}
            aria-haspopup="listbox"
            aria-controls={listboxId}
            className={`flex items-center gap-2 input-field py-2.5 cursor-pointer transition-colors w-full text-left ${value ? 'pr-8' : 'pr-2'}`}
            onClick={() => setOpen(true)}
          >
            <Briefcase size={14} className="text-text-dim flex-shrink-0" />
            <span className={`flex-1 text-sm truncate ${selected ? 'text-text' : 'text-text-dim/50'}`}>
              {selected ? `${selected.client} — ${selected.object}` : placeholder}
            </span>
            {!value && <ChevronDown size={14} className="text-text-dim flex-shrink-0" />}
          </button>
          {value && (
            <button
              type="button"
              onClick={handleClear}
              className="absolute right-2 top-1/2 -translate-y-1/2 p-1 hover:bg-card-hover rounded-lg transition-colors flex-shrink-0 z-10"
              title="Rimuovi selezione"
              aria-label="Rimuovi selezione"
            >
              <X size={12} className="text-text-dim" />
            </button>
          )}
        </div>
      )}

      {/* Dropdown — WAI-ARIA listbox (FIX-28) */}
      {open && (
        <div
          id={listboxId}
          ref={listRef}
          role="listbox"
          aria-label="Fascicoli disponibili"
          className="absolute left-0 right-0 top-full mt-1 z-50 glass-card rounded-xl max-h-52 overflow-y-auto no-scrollbar shadow-2xl border border-border"
        >
          {filtered.length === 0 ? (
            <div className="px-4 py-3 text-xs text-text-dim text-center">Nessun fascicolo trovato</div>
          ) : (
            filtered.map((p, idx) => {
              const optId = `${optionIdPrefix}-${p.id}`;
              const isSelected = p.id === value;
              const isHighlighted = idx === highlightIdx;
              return (
                <div
                  key={p.id}
                  id={optId}
                  data-combo-item
                  role="option"
                  aria-selected={isSelected}
                  // mousedown invece di click per anticipare blur input
                  onMouseDown={(e) => { e.preventDefault(); handleSelect(p.id); }}
                  onMouseEnter={() => setHighlightIdx(idx)}
                  className={`w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-card transition-colors cursor-pointer ${isSelected ? 'bg-primary/5' : ''} ${isHighlighted ? 'bg-card' : ''}`}
                >
                  <Briefcase size={14} className="text-text-dim flex-shrink-0" />
                  <span className="text-sm text-text truncate flex-1">{p.client} — {p.object}</span>
                </div>
              );
            })
          )}
        </div>
      )}
    </div>
  );
}

PracticeCombobox.propTypes = {
  value: PropTypes.string.isRequired,
  onChange: PropTypes.func.isRequired,
  // FIX-34: shape esplicito invece di array generico
  practices: PropTypes.arrayOf(PropTypes.shape({
    id: PropTypes.string.isRequired,
    client: PropTypes.string,
    object: PropTypes.string,
    status: PropTypes.string,
  })).isRequired,
  placeholder: PropTypes.string,
  label: PropTypes.string,
  id: PropTypes.string,
};
