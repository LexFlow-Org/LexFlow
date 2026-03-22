import { useLocation, Link } from 'react-router-dom';
import { ChevronRight, LayoutDashboard } from 'lucide-react';

const ROUTE_LABELS = {
  '/': 'Dashboard',
  '/pratiche': 'Fascicoli',
  '/scadenze': 'Scadenze',
  '/agenda': 'Agenda',
  '/contatti': 'Contatti',
  '/ore': 'Gestione Ore',
  '/settings': 'Impostazioni',
  '/report': 'Report',
  '/attivita': 'Attività',
};

export default function Breadcrumb({ practiceTitle }) {
  const location = useLocation();
  const path = location.pathname;

  // Don't show on dashboard
  if (path === '/' || path === '') return null;

  const segments = [];

  // Always start with Dashboard (not "Home" — we don't have a Home page)
  segments.push({ path: '/', label: 'Dashboard', icon: LayoutDashboard });

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
    <nav aria-label="Breadcrumb" className="flex items-center gap-2 px-6 py-3 text-sm text-[var(--text-dim)] border-b border-[var(--border)] mb-0">
      {segments.map((seg, i) => {
        const isLast = i === segments.length - 1;
        const Icon = seg.icon;
        return (
          <span key={i} className="flex items-center gap-1.5">
            {i > 0 && <ChevronRight size={14} className="text-[var(--text-dim)] opacity-40" />}
            {isLast ? (
              <span className="flex items-center gap-1.5 text-[var(--text)] font-medium truncate max-w-[200px]">
                {Icon && <Icon size={14} className="shrink-0" />}
                {seg.label}
              </span>
            ) : (
              <Link to={seg.path} className="flex items-center gap-1.5 hover:text-[var(--primary)] transition-colors truncate max-w-[150px]">
                {Icon && <Icon size={14} className="shrink-0" />}
                {seg.label}
              </Link>
            )}
          </span>
        );
      })}
    </nav>
  );
}
