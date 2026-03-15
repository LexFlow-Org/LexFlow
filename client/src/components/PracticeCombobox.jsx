import { useState, useRef, useEffect, useMemo } from 'react';
import PropTypes from 'prop-types';
import { Search, Briefcase, X, ChevronDown } from 'lucide-react';

/**
 * Searchable combobox for selecting a practice (fascicolo).
 * Replaces native <select> with a glass-card styled dropdown.
 * Shows the full browsable list on open; typing filters.
 */
export default function PracticeCombobox({ value, onChange, practices, placeholder = 'Cerca fascicolo...', label, id }) {
  const [query, setQueryRaw] = useState('');
  const setQuery = (q) => { setQueryRaw(q); setHighlightIdx(-1); };
  const [open, setOpen] = useState(false);
  const wrapRef = useRef(null);
  const inputRef = useRef(null);
  const listRef = useRef(null);
  const [highlightIdx, setHighlightIdx] = useState(-1);

  // Close on outside click
  useEffect(() => {
    if (!open) return;
    const handler = (e) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
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
    if (e.key === 'Escape') { setOpen(false); inputRef.current?.blur(); setHighlightIdx(-1); }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setHighlightIdx(i => (i + 1) % Math.max(filtered.length, 1));
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      setHighlightIdx(i => (i - 1 + filtered.length) % Math.max(filtered.length, 1));
    }
    if (e.key === 'Enter' && filtered.length > 0) {
      e.preventDefault();
      const idx = Math.max(highlightIdx, 0);
      handleSelect(filtered[idx].id);
    }
  };

  // Scroll highlighted item into view
  useEffect(() => {
    if (highlightIdx < 0 || !listRef.current) return;
    const items = listRef.current.querySelectorAll('[data-combo-item]');
    items[highlightIdx]?.scrollIntoView({ block: 'nearest' });
  }, [highlightIdx]);

  return (
    <div ref={wrapRef} className="relative">
      {label && (
        <label htmlFor={id} className="text-[10px] font-black text-text-dim uppercase tracking-[2px] block mb-2">
          {label}
        </label>
      )}

      {/* Trigger (closed) / Input wrapper (open) */}
      {open ? (
        <div className="flex items-center gap-2 input-field py-2.5 pr-2 transition-all w-full border-primary ring-1 ring-primary/20">
          <Search size={14} className="text-text-dim flex-shrink-0" />
          <input
            ref={inputRef}
            id={id}
            type="text"
            aria-controls="practice-listbox"
            aria-autocomplete="list"
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
            aria-expanded={false}
            aria-haspopup="listbox"
            aria-controls="practice-listbox"
            className={`flex items-center gap-2 input-field py-2.5 cursor-pointer transition-all w-full text-left ${value ? 'pr-8' : 'pr-2'}`}
            onClick={() => { setOpen(true); setTimeout(() => inputRef.current?.focus(), 0); }}
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

      {/* Dropdown */}
      {open && (
        <div id="practice-listbox" ref={listRef} className="absolute left-0 right-0 top-full mt-1 z-50 glass-card rounded-xl max-h-52 overflow-y-auto no-scrollbar shadow-2xl border border-border">
          {filtered.length === 0 ? (
            <div className="px-4 py-3 text-xs text-text-dim text-center">Nessun fascicolo trovato</div>
          ) : (
            filtered.map((p, idx) => (
              <button
                type="button"
                key={p.id}
                data-combo-item
                onClick={() => handleSelect(p.id)}
                className={`w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-card transition-colors ${p.id === value ? 'bg-primary/5' : ''} ${idx === highlightIdx ? 'bg-card' : ''}`}
              >
                <Briefcase size={14} className="text-text-dim flex-shrink-0" />
                <span className="text-sm text-text truncate flex-1">{p.client} — {p.object}</span>
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
}

PracticeCombobox.propTypes = {
  value: PropTypes.string.isRequired,
  onChange: PropTypes.func.isRequired,
  practices: PropTypes.array.isRequired,
  placeholder: PropTypes.string,
  label: PropTypes.string,
  id: PropTypes.string,
};
