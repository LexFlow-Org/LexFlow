import { useState, useRef, useEffect, useMemo } from 'react';
import PropTypes from 'prop-types';
import { Search, Briefcase, X, ChevronDown } from 'lucide-react';

/**
 * Searchable combobox for selecting a practice (fascicolo).
 * Replaces native <select> with a glass-card styled dropdown.
 * Shows the full browsable list on open; typing filters.
 */
export default function PracticeCombobox({ value, onChange, practices, placeholder = 'Cerca fascicolo...', label, id }) {
  const [query, setQuery] = useState('');
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
      setHighlightIdx(i => (i <= 0 ? filtered.length - 1 : i - 1));
    }
    if (e.key === 'Enter' && filtered.length > 0) {
      e.preventDefault();
      const idx = highlightIdx >= 0 ? highlightIdx : 0;
      handleSelect(filtered[idx].id);
    }
  };

  // Scroll highlighted item into view
  useEffect(() => {
    if (highlightIdx < 0 || !listRef.current) return;
    const items = listRef.current.querySelectorAll('[data-combo-item]');
    items[highlightIdx]?.scrollIntoView({ block: 'nearest' });
  }, [highlightIdx]);

  // Reset highlight when filtered changes
  useEffect(() => { setHighlightIdx(-1); }, [filtered]);

  return (
    <div ref={wrapRef} className="relative">
      {label && (
        <label htmlFor={id} className="text-[10px] font-black text-text-dim uppercase tracking-[2px] block mb-2">
          {label}
        </label>
      )}

      {/* Trigger / Input */}
      <div
        role="combobox"
        tabIndex={open ? -1 : 0}
        aria-expanded={open}
        aria-haspopup="listbox"
        className={`flex items-center gap-2 input-field py-2.5 pr-2 cursor-pointer transition-all ${open ? 'border-primary ring-1 ring-primary/20' : ''}`}
        onClick={() => { if (!open) { setOpen(true); setTimeout(() => inputRef.current?.focus(), 0); } }}
        onKeyDown={(e) => { if (!open && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); setOpen(true); setTimeout(() => inputRef.current?.focus(), 0); } }}
      >
        {open ? (
          <>
            <Search size={14} className="text-text-dim flex-shrink-0" />
            <input
              ref={inputRef}
              id={id}
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Filtra fascicoli..."
              className="flex-1 bg-transparent outline-none text-white text-sm placeholder:text-text-dim/50"
              autoComplete="off"
            />
          </>
        ) : (
          <>
            <Briefcase size={14} className="text-text-dim flex-shrink-0" />
            <span className={`flex-1 text-sm truncate ${selected ? 'text-white' : 'text-text-dim/50'}`}>
              {selected ? `${selected.client} — ${selected.object}` : placeholder}
            </span>
          </>
        )}
        {value && !open && (
          <button
            type="button"
            onClick={handleClear}
            className="p-1 hover:bg-white/10 rounded-lg transition-colors flex-shrink-0"
            title="Rimuovi selezione"
          >
            <X size={12} className="text-text-dim" />
          </button>
        )}
        {!open && !value && (
          <ChevronDown size={14} className="text-text-dim flex-shrink-0" />
        )}
      </div>

      {/* Dropdown */}
      {open && (
        <div ref={listRef} className="absolute left-0 right-0 top-full mt-1 z-50 glass-card rounded-xl max-h-52 overflow-y-auto no-scrollbar shadow-2xl border border-white/10">
          {filtered.length === 0 ? (
            <div className="px-4 py-3 text-xs text-text-dim text-center">Nessun fascicolo trovato</div>
          ) : (
            filtered.map((p, idx) => (
              <button
                type="button"
                key={p.id}
                data-combo-item
                onClick={() => handleSelect(p.id)}
                className={`w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-white/[0.06] transition-colors ${p.id === value ? 'bg-primary/5' : ''} ${idx === highlightIdx ? 'bg-white/[0.08]' : ''}`}
              >
                <Briefcase size={14} className="text-text-dim flex-shrink-0" />
                <span className="text-sm text-white truncate flex-1">{p.client} — {p.object}</span>
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
