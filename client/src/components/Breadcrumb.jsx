import PropTypes from 'prop-types';
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
  '/sicurezza': 'Sicurezza',
  '/report': 'Report',
  '/strumenti': 'Strumenti PDF',
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

  // Lista fascicoli con uno selezionato (selezione gestita lato App.jsx)
  if (path === '/pratiche' && practiceTitle) {
    segments.push({ label: practiceTitle });
  }

  if (segments.length <= 1) return null;

  return (
    <nav aria-label="Breadcrumb" className="flex items-center gap-2 px-6 py-3 text-sm text-[var(--text-dim)] border-b border-[var(--border)]/20 mb-4">
      {segments.map((seg, i) => {
        const isLast = i === segments.length - 1;
        const Icon = seg.icon;
        return (
          <span key={seg.path || `seg-${i}`} className="flex items-center gap-1.5">
            {i > 0 && <ChevronRight size={14} className="text-[var(--text-dim)] opacity-40" aria-hidden="true" />}
            {isLast ? (
              <span
                aria-current="page"
                title={seg.label}
                className="flex items-center gap-1.5 text-[var(--text)] font-medium truncate max-w-[200px]"
              >
                {Icon && <Icon size={14} className="shrink-0" aria-hidden="true" />}
                {seg.label}
              </span>
            ) : (
              <Link
                to={seg.path}
                title={seg.label}
                className="flex items-center gap-1.5 hover:text-[var(--primary)] transition-colors truncate max-w-[150px]"
              >
                {Icon && <Icon size={14} className="shrink-0" aria-hidden="true" />}
                {seg.label}
              </Link>
            )}
          </span>
        );
      })}
    </nav>
  );
}

Breadcrumb.propTypes = {
  practiceTitle: PropTypes.string,
};
