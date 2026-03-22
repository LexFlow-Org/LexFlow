import { useState, useEffect, useRef } from 'react';
import { Bell, X, Clock, AlertTriangle, CheckCircle2 } from 'lucide-react';

export default function NotificationCenter() {
  const [isOpen, setIsOpen] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const panelRef = useRef(null);

  // Listen for notification events from Tauri backend
  useEffect(() => {
    let unlisten;
    const setupListener = async () => {
      try {
        const { listen } = await import('@tauri-apps/api/event');
        unlisten = await listen('show-notification', (event) => {
          const notif = {
            id: Date.now(),
            title: event.payload?.title || 'Notifica',
            body: event.payload?.body || '',
            time: new Date().toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' }),
            type: event.payload?.type || 'info',
            read: false,
          };
          setNotifications(prev => [notif, ...prev].slice(0, 50));
          setUnreadCount(prev => prev + 1);
        });
      } catch { /* not in Tauri context */ }
    };
    setupListener();
    return () => { if (unlisten) unlisten(); };
  }, []);

  // Close on click outside
  useEffect(() => {
    if (!isOpen) return;
    const handleClick = (e) => {
      if (panelRef.current && !panelRef.current.contains(e.target)) setIsOpen(false);
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [isOpen]);

  const markAllRead = () => {
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
    setUnreadCount(0);
  };

  const typeIcon = (type) => {
    switch (type) {
      case 'warning': return <AlertTriangle size={14} className="text-amber-400" />;
      case 'success': return <CheckCircle2 size={14} className="text-emerald-400" />;
      default: return <Clock size={14} className="text-[var(--text-dim)]" />;
    }
  };

  return (
    <div className="relative" ref={panelRef}>
      {/* Bell button */}
      <button
        onClick={() => { setIsOpen(!isOpen); if (!isOpen) markAllRead(); }}
        className="relative p-2 rounded-lg hover:bg-[var(--bg-hover)] text-[var(--text-dim)] transition-colors"
        aria-label={`Notifiche${unreadCount > 0 ? ` (${unreadCount} non lette)` : ''}`}
      >
        <Bell size={18} />
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 w-4 h-4 bg-red-500 text-white text-[9px] font-bold rounded-full flex items-center justify-center">
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </button>

      {/* Panel */}
      {isOpen && (
        <div className="absolute left-0 bottom-12 w-80 max-h-96 bg-[var(--bg-card)] border border-[var(--border)] rounded-xl shadow-2xl overflow-hidden z-50">
          <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border)]">
            <h3 className="text-sm font-bold text-[var(--text)]">Notifiche</h3>
            <button onClick={() => setIsOpen(false)} className="text-[var(--text-dim)] hover:text-[var(--text)]">
              <X size={14} />
            </button>
          </div>

          <div className="overflow-y-auto max-h-72">
            {notifications.length === 0 ? (
              <div className="px-4 py-8 text-center text-xs text-[var(--text-dim)]">
                Nessuna notifica
              </div>
            ) : (
              notifications.map(n => (
                <div key={n.id} className={`flex items-start gap-3 px-4 py-3 border-b border-[var(--border)] last:border-0 ${!n.read ? 'bg-[var(--primary-soft)]' : ''}`}>
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
