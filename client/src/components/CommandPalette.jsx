import { useState, useEffect, useRef, useCallback } from 'react';
import { Search, FileText, Calendar, Users, Clock, X, ArrowRight } from 'lucide-react';
import * as api from '../tauri-api';

const TYPE_ICONS = {
  practices: FileText,
  agenda: Calendar,
  contacts: Users,
  timeLogs: Clock,
};

const TYPE_LABELS = {
  practices: 'Fascicolo',
  agenda: 'Evento',
  contacts: 'Contatto',
  timeLogs: 'Ore',
};

const TYPE_COLORS = {
  practices: 'text-blue-400',
  agenda: 'text-amber-400',
  contacts: 'text-emerald-400',
  timeLogs: 'text-purple-400',
};

export default function CommandPalette({ isOpen, onClose, onNavigate }) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef(null);
  const debounceRef = useRef(null);

  // Focus input when opened
  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setResults([]);
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  // Global shortcut ⌘K / Ctrl+K
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        if (isOpen) onClose();
        else onClose('toggle'); // parent handles toggle
      }
      if (e.key === 'Escape' && isOpen) {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Debounced search
  const doSearch = useCallback(async (q) => {
    if (!q || q.length < 2) {
      setResults([]);
      return;
    }
    setLoading(true);
    try {
      const res = await api.searchVault(q, 20);
      setResults(res || []);
      setSelectedIndex(0);
    } catch (e) {
      console.warn('[CommandPalette] search error:', e);
      setResults([]);
    } finally {
      setLoading(false);
    }
  }, []);

  const handleInputChange = (e) => {
    const val = e.target.value;
    setQuery(val);
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => doSearch(val), 150);
  };

  // Keyboard navigation
  const handleKeyDown = (e) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex(i => Math.min(i + 1, results.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex(i => Math.max(i - 1, 0));
    } else if (e.key === 'Enter' && results[selectedIndex]) {
      e.preventDefault();
      handleSelect(results[selectedIndex]);
    }
  };

  const handleSelect = (result) => {
    onClose();
    if (onNavigate) onNavigate(result);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[9999] flex items-start justify-center pt-[15vh]"
         onClick={onClose}>
      <div className="absolute inset-0 bg-black/60 blur-overlay-sm" />
      <div className="relative w-full max-w-xl mx-4 bg-[var(--bg-card)] border border-[var(--border)]
                      rounded-2xl shadow-2xl overflow-hidden"
           onClick={e => e.stopPropagation()}>

        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-[var(--border)]">
          <Search size={18} className="text-[var(--text-dim)] shrink-0" />
          <input
            ref={inputRef}
            value={query}
            onChange={handleInputChange}
            onKeyDown={handleKeyDown}
            placeholder="Cerca fascicoli, contatti, eventi..."
            className="flex-1 bg-transparent text-[var(--text)] placeholder:text-[var(--text-dim)]
                       text-sm outline-none"
            autoComplete="off"
            spellCheck={false}
          />
          <kbd className="hidden sm:inline text-2xs text-[var(--text-dim)] bg-[var(--bg)]
                         px-1.5 py-0.5 rounded border border-[var(--border)] font-mono">
            ESC
          </kbd>
        </div>

        {/* Results */}
        <div className="max-h-[50vh] overflow-y-auto">
          {loading && (
            <div className="px-4 py-8 text-center text-sm text-[var(--text-dim)]">
              Ricerca in corso...
            </div>
          )}

          {!loading && query.length >= 2 && results.length === 0 && (
            <div className="px-4 py-8 text-center text-sm text-[var(--text-dim)]">
              Nessun risultato per "{query}"
            </div>
          )}

          {!loading && results.length > 0 && (
            <ul className="py-2">
              {results.map((r, i) => {
                const Icon = TYPE_ICONS[r.field] || FileText;
                const label = TYPE_LABELS[r.field] || r.field;
                const colorClass = TYPE_COLORS[r.field] || 'text-[var(--text-dim)]';
                const isSelected = i === selectedIndex;

                return (
                  <li key={r.id + r.field}
                      className={`flex items-center gap-3 px-4 py-2.5 cursor-pointer transition-colors
                        ${isSelected ? 'bg-[var(--primary-soft)]' : 'hover:bg-[var(--bg-hover)]'}`}
                      onClick={() => handleSelect(r)}
                      onMouseEnter={() => setSelectedIndex(i)}>
                    <Icon size={16} className={`shrink-0 ${colorClass}`} />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm text-[var(--text)] truncate">
                        {r.title || r.id}
                      </div>
                      {r.tags && r.tags.length > 0 && (
                        <div className="text-xs text-[var(--text-dim)] truncate mt-0.5">
                          {r.tags.join(' · ')}
                        </div>
                      )}
                    </div>
                    <span className={`text-2xs uppercase tracking-wider ${colorClass} shrink-0`}>
                      {label}
                    </span>
                    {isSelected && <ArrowRight size={14} className="text-[var(--text-dim)] shrink-0" />}
                  </li>
                );
              })}
            </ul>
          )}

          {!loading && query.length < 2 && (
            <div className="px-4 py-6 text-center text-sm text-[var(--text-dim)]">
              <p>Digita almeno 2 caratteri per cercare</p>
              <div className="flex items-center justify-center gap-4 mt-3 text-xs">
                <span className="flex items-center gap-1">
                  <kbd className="bg-[var(--bg)] px-1.5 py-0.5 rounded border border-[var(--border)] font-mono">↑↓</kbd>
                  Naviga
                </span>
                <span className="flex items-center gap-1">
                  <kbd className="bg-[var(--bg)] px-1.5 py-0.5 rounded border border-[var(--border)] font-mono">↵</kbd>
                  Seleziona
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
