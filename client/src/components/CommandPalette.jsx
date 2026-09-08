import { useState, useEffect, useRef, useCallback } from 'react';
import PropTypes from 'prop-types';
import { Search, FileText, Calendar, Users, Clock, ArrowRight } from 'lucide-react';
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

// Design tokens (CSS variables) for type colors — no more hardcoded Tailwind palette
const TYPE_COLORS = {
  practices: 'text-[var(--info,#60a5fa)]',
  agenda: 'text-[var(--warning,#fbbf24)]',
  contacts: 'text-[var(--success,#34d399)]',
  timeLogs: 'text-[var(--accent,#a78bfa)]',
};

export default function CommandPalette({ isOpen, onClose, onNavigate }) {
  return isOpen ? <OpenCommandPalette onClose={onClose} onNavigate={onNavigate} /> : null;
}

function OpenCommandPalette({ onClose, onNavigate }) {
  const [query, setQuery] = useState('');
  const [response, setResponse] = useState({ query: '', results: [] });
  const searchQuery = query.trim();
  const hasQuery = searchQuery.length >= 2;
  const loading = hasQuery && response.query !== searchQuery;
  const results = hasQuery && !loading ? response.results : [];
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef(null);
  const dialogRef = useRef(null);
  const previousFocusRef = useRef(null);

  // Body scroll lock + focus capture/restore
  useEffect(() => {
    previousFocusRef.current = document.activeElement;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    return () => {
      document.body.style.overflow = previousOverflow;
      const prev = previousFocusRef.current;
      if (prev && typeof prev.focus === 'function' && document.contains(prev)) {
        try { prev.focus(); } catch { /* ignore */ }
      }
    };
  }, []);

  useEffect(() => {
    const id = setTimeout(() => inputRef.current?.focus(), 50);
    return () => clearTimeout(id);
  }, []);

  // App owns Cmd/Ctrl+K; registering it twice cancels the parent toggle.
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  // Responses are tagged with their query: old results cannot be selected
  // while a new search is pending. Unmounting closes and clears the session.
  useEffect(() => {
    if (!hasQuery) return;
    let cancelled = false;
    const timeout = setTimeout(async () => {
      try {
        const res = await api.searchVault(searchQuery, 20);
        if (!cancelled) setResponse({ query: searchQuery, results: res || [] });
      } catch {
        if (!cancelled) setResponse({ query: searchQuery, results: [] });
      }
    }, 150);
    return () => { cancelled = true; clearTimeout(timeout); };
  }, [searchQuery, hasQuery]);

  const handleInputChange = (e) => {
    setQuery(e.target.value);
    setSelectedIndex(0);
  };

  const handleSelect = useCallback((result) => {
    onClose();
    if (onNavigate) onNavigate(result);
  }, [onClose, onNavigate]);

  // Keyboard navigation in input + Tab focus trap inside dialog
  const handleInputKeyDown = (e) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((i) => Math.min(i + 1, Math.max(0, results.length - 1)));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === 'Enter' && results[selectedIndex]) {
      e.preventDefault();
      handleSelect(results[selectedIndex]);
    }
  };

  // Trap Tab inside the dialog
  const handleDialogKeyDown = (e) => {
    if (e.key !== 'Tab') return;
    const root = dialogRef.current;
    if (!root) return;
    const focusable = Array.from(
      root.querySelectorAll(
        'button:not([disabled]), [href], input:not([disabled]), [tabindex]:not([tabindex="-1"])'
      )
    ).filter((n) => n.offsetParent !== null);
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  };

  const highlightedId = results.length > 0 ? `cmd-option-${selectedIndex}` : undefined;

  return (
    <div
      className="fixed inset-0 z-[9999] flex items-start justify-center pt-[15vh]"
      onClick={onClose}
    >
      <div className="absolute inset-0 bg-black/60 blur-overlay-sm" />
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="cmd-palette-title"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleDialogKeyDown}
        className="relative w-full max-w-xl mx-4 bg-[var(--bg-card)] border border-[var(--border)]
                      rounded-2xl shadow-2xl overflow-hidden"
      >
        <h2 id="cmd-palette-title" className="sr-only">Palette comandi</h2>

        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-[var(--border)]">
          <Search size={18} className="text-[var(--text-dim)] shrink-0" aria-hidden="true" />
          <input
            ref={inputRef}
            value={query}
            onChange={handleInputChange}
            onKeyDown={handleInputKeyDown}
            placeholder="Cerca fascicoli, contatti, eventi..."
            className="flex-1 bg-transparent text-[var(--text)] placeholder:text-[var(--text-dim)]
                       text-sm outline-none"
            autoComplete="off"
            spellCheck={false}
            role="combobox"
            aria-label="Cerca comandi"
            aria-expanded={results.length > 0}
            aria-controls="cmd-listbox"
            aria-autocomplete="list"
            aria-activedescendant={highlightedId}
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

          {!loading && hasQuery && results.length === 0 && (
            <div className="px-4 py-8 text-center text-sm text-[var(--text-dim)]">
              Nessun risultato per &quot;{query}&quot;
            </div>
          )}

          {!loading && results.length > 0 && (
            <ul id="cmd-listbox" role="listbox" className="py-2">
              {results.map((r, i) => {
                const Icon = TYPE_ICONS[r.field] || FileText;
                const label = TYPE_LABELS[r.field] || r.field;
                const colorClass = TYPE_COLORS[r.field] || 'text-[var(--text-dim)]';
                const isSelected = i === selectedIndex;
                const optionId = `cmd-option-${i}`;

                return (
                  <li
                    key={`${r.field}-${r.id}`}
                    id={optionId}
                    role="option"
                    aria-selected={isSelected}
                    className={`flex items-center gap-3 px-4 py-2.5 cursor-pointer transition-colors
                        ${isSelected ? 'bg-[var(--primary-soft)]' : 'hover:bg-[var(--bg-hover)]'}`}
                    onClick={() => handleSelect(r)}
                    onMouseEnter={() => setSelectedIndex(i)}
                  >
                    <Icon size={16} className={`shrink-0 ${colorClass}`} aria-hidden="true" />
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
                    {isSelected && <ArrowRight size={14} className="text-[var(--text-dim)] shrink-0" aria-hidden="true" />}
                  </li>
                );
              })}
            </ul>
          )}

          {!loading && !hasQuery && (
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

CommandPalette.propTypes = {
  isOpen: PropTypes.bool,
  onClose: PropTypes.func.isRequired,
  onNavigate: PropTypes.func,
};
