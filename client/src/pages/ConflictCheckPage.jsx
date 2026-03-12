import PropTypes from 'prop-types';
import { Shield } from 'lucide-react';
import ConflictCheckPanel from '../components/ConflictCheckPanel';

/**
 * Dedicated full-page view for the conflict-of-interest check.
 * Delegates all search logic + result rendering to the shared
 * <ConflictCheckPanel /> component (also used inside ContactsPage).
 */
export default function ConflictCheckPage({ onSelectPractice }) {
  return (
    <div className="max-w-4xl mx-auto space-y-8 pb-12">
      {/* Header */}
      <div className="flex items-center gap-4">
        <div className="w-14 h-14 bg-amber-500/10 rounded-2xl flex items-center justify-center border border-amber-500/20">
          <Shield size={28} className="text-amber-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Conflitto di Interessi</h1>
          <p className="text-text-dim text-sm mt-0.5">Verifica deontologica — Cerca un nome per controllare conflitti</p>
        </div>
      </div>

      <ConflictCheckPanel onSelectPractice={onSelectPractice} />
    </div>
  );
}

ConflictCheckPage.propTypes = {
  onSelectPractice: PropTypes.func,
};