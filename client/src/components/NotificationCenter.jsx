import { useState, useEffect, useRef } from 'react';
import { Bell, X, Clock, AlertTriangle, CheckCircle2, Trash2 } from 'lucide-react';
import * as api from '../tauri-api';

const STORAGE_KEY = 'lexflow_notifications';
const MAX_NOTIFICATIONS = 50;

const loadNotifications = () => {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
};

const saveNotifications = (list) => {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
  } catch {
    /* storage quota or unavailable — silent */
  }
};

export default function NotificationCenter() {
  const [isOpen, setIsOpen] = useState(false);
  const [notifications, setNotifications] = useState(loadNotifications);
  const panelRef = useRef(null);
  const previousFocusRef = useRef(null);

  const unreadCount = notifications.filter((n) => !n.read).length;

  // Persist on every change
  useEffect(() => {
    saveNotifications(notifications);
  }, [notifications]);

  // Listen for notification events from Tauri backend (with cancellation flag)
  useEffect(() => {
    let cancelled = false;
    let unlisten;

    const setupListener = async () => {
      try {
        const { listen } = await import('@tauri-apps/api/event');
        if (cancelled) return;
        unlisten = await listen('show-notification', (event) => {
          const notif = {
            id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
            title: event.payload?.title || 'Notifica',
            body: event.payload?.body || '',
            time: new Date().toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' }),
            type: event.payload?.type || 'info',
            read: false,
          };
          setNotifications((prev) => [notif, ...prev].slice(0, MAX_NOTIFICATIONS));
        });
        if (cancelled && unlisten) {
          unlisten();
          unlisten = undefined;
        }
      } catch {
        /* not in Tauri context */
      }
    };

    setupListener();
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, []);

  // Wipe notifications on vault lock (privacy)
  useEffect(() => {
    if (typeof api.onVaultLocked !== 'function') return undefined;
    const off = api.onVaultLocked(() => {
      try {
        localStorage.removeItem(STORAGE_KEY);
      } catch {
        /* ignore */
      }
      setNotifications([]);
    });
    return () => {
      if (typeof off === 'function') off();
    };
  }, []);

  // Close on click outside
  useEffect(() => {
    if (!isOpen) return undefined;
    const handleClick = (e) => {
      if (panelRef.current && !panelRef.current.contains(e.target)) setIsOpen(false);
    };
    const handleKey = (e) => {
      if (e.key === 'Escape') setIsOpen(false);
    };
    document.addEventListener('mousedown', handleClick);
    document.addEventListener('keydown', handleKey);
    return () => {
      document.removeEventListener('mousedown', handleClick);
      document.removeEventListener('keydown', handleKey);
    };
  }, [isOpen]);

  // Focus management on panel open / close
  useEffect(() => {
    if (isOpen) {
      previousFocusRef.current = document.activeElement;
      const firstFocusable = panelRef.current?.querySelector(
        'button:not([disabled])'
      );
      // Focus first interactive element inside panel after mount
      setTimeout(() => firstFocusable?.focus?.(), 0);
    } else if (previousFocusRef.current) {
      const prev = previousFocusRef.current;
      if (typeof prev.focus === 'function' && document.contains(prev)) {
        try {
          prev.focus();
        } catch {
          /* ignore */
        }
      }
    }
  }, [isOpen]);

  const markAllRead = () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  };

  const clearAll = () => {
    setNotifications([]);
  };

  const togglePanel = () => {
    setIsOpen((prev) => {
      const next = !prev;
      if (next) markAllRead();
      return next;
    });
  };

  const typeIcon = (type) => {
    switch (type) {
      case 'warning': return <AlertTriangle size={14} className="text-[var(--warning)]" aria-hidden="true" />;
      case 'success': return <CheckCircle2 size={14} className="text-[var(--success)]" aria-hidden="true" />;
      default: return <Clock size={14} className="text-[var(--text-dim)]" aria-hidden="true" />;
    }
  };

  return (
    <div className="relative" ref={panelRef}>
      {/* Bell button */}
      <button
        onClick={togglePanel}
        className="relative w-10 h-10 flex items-center justify-center rounded-full text-[var(--text-dim)] hover:text-[var(--primary)] hover:bg-[var(--primary-soft)] transition-colors"
        aria-label={`Notifiche${unreadCount > 0 ? ` (${unreadCount} non lette)` : ''}`}
        aria-expanded={isOpen}
        aria-haspopup="dialog"
      >
        <Bell size={18} aria-hidden="true" />
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 w-4 h-4 bg-[var(--danger)] text-white text-[9px] font-bold rounded-full flex items-center justify-center">
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>

      {/* Panel */}
      {isOpen && (
        <div
          role="dialog"
          aria-modal="false"
          aria-labelledby="notif-center-title"
          className="absolute left-0 bottom-12 w-80 max-h-96 bg-[var(--bg-card)] border border-[var(--border)] rounded-xl shadow-2xl overflow-hidden z-50"
        >
          <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border)]">
            <h3 id="notif-center-title" className="text-sm font-bold text-[var(--text)]">Notifiche</h3>
            <div className="flex items-center gap-1">
              {notifications.length > 0 && (
                <button
                  onClick={clearAll}
                  className="text-[var(--text-dim)] hover:text-[var(--danger)] p-1 rounded transition-colors"
                  aria-label="Elimina tutte le notifiche"
                  title="Elimina tutte"
                >
                  <Trash2 size={14} aria-hidden="true" />
                </button>
              )}
              <button
                onClick={() => setIsOpen(false)}
                className="text-[var(--text-dim)] hover:text-[var(--text)] p-1 rounded transition-colors"
                aria-label="Chiudi pannello notifiche"
              >
                <X size={14} aria-hidden="true" />
              </button>
            </div>
          </div>

          <div className="overflow-y-auto max-h-72">
            {notifications.length === 0 ? (
              <div className="px-4 py-8 text-center text-xs text-[var(--text-dim)]">
                Nessuna notifica
              </div>
            ) : (
              notifications.map((n) => (
                <div
                  key={n.id}
                  className={`flex items-start gap-3 px-4 py-3 border-b border-[var(--border)] last:border-0 ${!n.read ? 'bg-[var(--primary-soft)]' : ''}`}
                >
                  <div className="mt-0.5 shrink-0">{typeIcon(n.type)}</div>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium text-[var(--text)] truncate">{n.title}</p>
                    {n.body && <p className="text-2xs text-[var(--text-dim)] truncate mt-0.5">{n.body}</p>}
                  </div>
                  <span className="text-2xs text-[var(--text-dim)] font-mono shrink-0">{n.time}</span>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
