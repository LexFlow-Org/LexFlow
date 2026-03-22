import { useLocation, Link } from 'react-router-dom';
import { ChevronRight, Home } from 'lucide-react';

const ROUTE_LABELS = {
  '/': 'Dashboard',
  '/pratiche': 'Fascicoli',
  '/scadenze': 'Scadenze',
  '/agenda': 'Agenda',
  '/contatti': 'Contatti',
  '/ore': 'Gestione Ore',
  '/settings': 'Impostazioni',
  '/sicurezza': 'Sicurezza',
  '/audit': 'Registro Attività',
};

export default function Breadcrumb({ practiceTitle }) {
  const location = useLocation();
  const path = location.pathname;

  // Don't show on dashboard
  if (path === '/' || path === '') return null;

  const segments = [];

  // Always start with home
  segments.push({ path: '/', label: 'Home', icon: Home });

  // Main section
  const mainPath = '/' + path.split('/').filter(Boolean)[0];
  if (ROUTE_LABELS[mainPath]) {
    segments.push({ path: mainPath, label: ROUTE_LABELS[mainPath] });
  }

  // Practice detail
  if (path.startsWith('/practices/') && practiceTitle) {
    segments.push({ label: practiceTitle });
  }

  if (segments.length <= 1) return null;

  return (
    <nav aria-label="Breadcrumb" className="flex items-center gap-2 px-6 py-3 text-sm text-[var(--text-dim)] border-b border-[var(--border)]">
      {segments.map((seg, i) => {
        const isLast = i === segments.length - 1;
        const Icon = seg.icon;
        return (
          <span key={i} className="flex items-center gap-1.5">
            {i > 0 && <ChevronRight size={12} className="text-[var(--text-dim)]/50" />}
            {isLast ? (
              <span className="text-[var(--text)] font-medium truncate max-w-[200px]">
                {Icon && <Icon size={12} className="inline mr-1" />}
                {seg.label}
              </span>
            ) : (
              <Link to={seg.path} className="hover:text-[var(--primary)] transition-colors truncate max-w-[150px]">
                {Icon && <Icon size={12} className="inline mr-1" />}
                {seg.label}
              </Link>
            )}
          </span>
        );
      })}
    </nav>
  );
}
