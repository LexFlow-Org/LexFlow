import { useState, useRef, useEffect, useMemo } from 'react';
import PropTypes from 'prop-types';
import { Search, Briefcase, X } from 'lucide-react';

/**
 * Searchable combobox for selecting a practice (fascicolo).
 * Replaces native <select> with a glass-card styled dropdown.
 */
export default function PracticeCombobox({ value, onChange, practices, placeholder = 'Cerca fascicolo...', label, id }) {
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);
  const wrapRef = useRef(null);
  const inputRef = useRef(null);

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
  };

  const handleClear = (e) => {
    e.stopPropagation();
    onChange('');
    setQuery('');
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Escape') { setOpen(false); inputRef.current?.blur(); }
    if (e.key === 'Enter' && filtered.length > 0) {
      e.preventDefault();
      handleSelect(filtered[0].id);
    }
  };

  return (
    <div ref={wrapRef} className="relative">
      {label && (
        <label htmlFor={id} className="text-[10px] font-black text-text-dim uppercase tracking-[2px] block mb-2">
          {label}
        </label>
      )}

      {/* Trigger / Input */}
      <div
        className={`flex items-center gap-2 input-field py-2.5 pr-2 cursor-pointer transition-all ${open ? 'border-primary ring-1 ring-primary/20' : ''}`}
        onClick={() => { setOpen(true); setTimeout(() => inputRef.current?.focus(), 0); }}
      >
        <Search size={14} className="text-text-dim flex-shrink-0" />
        {open ? (
          <input
            ref={inputRef}
            id={id}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={placeholder}
            className="flex-1 bg-transparent outline-none text-white text-sm placeholder:text-text-dim/50"
            autoComplete="off"
          />
        ) : (
          <span className={`flex-1 text-sm truncate ${selected ? 'text-white' : 'text-text-dim/50'}`}>
            {selected ? `${selected.client} — ${selected.object}` : placeholder}
          </span>
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
      </div>

      {/* Dropdown */}
      {open && (
        <div className="absolute left-0 right-0 top-full mt-1 z-50 glass-card rounded-xl max-h-52 overflow-y-auto no-scrollbar shadow-2xl border border-white/10">
          {filtered.length === 0 ? (
            <div className="px-4 py-3 text-xs text-text-dim text-center">Nessun fascicolo trovato</div>
          ) : (
            filtered.map(p => (
              <button
                type="button"
                key={p.id}
                onClick={() => handleSelect(p.id)}
                className={`w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-white/[0.06] transition-colors ${p.id === value ? 'bg-primary/5' : ''}`}
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
