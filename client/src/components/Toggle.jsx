import PropTypes from 'prop-types';

export default function Toggle({ checked, onChange, label, description, ariaLabelledBy }) {
  // Click sul label (non sul bottone) → toggla
  const handleLabelClick = (e) => {
    if (e.target.closest('button')) return; // il bottone gestisce da solo
    onChange(!checked);
  };

  return (
    <label
      className="flex items-center justify-between gap-4 cursor-pointer group"
      onClick={handleLabelClick}
    >
      <div className="flex-1 min-w-0">
        {label && <span className="text-sm text-[var(--text)] font-medium">{label}</span>}
        {description && <p className="text-xs text-[var(--text-dim)] mt-0.5">{description}</p>}
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={ariaLabelledBy ? undefined : (label || undefined)}
        aria-labelledby={ariaLabelledBy || undefined}
        onClick={(e) => { e.stopPropagation(); onChange(!checked); }}
        className={`relative inline-flex items-center min-h-11 min-w-11 shrink-0 rounded-full justify-center focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--primary)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg)] transition-colors`}
      >
        {/* visual switch track */}
        <span
          className={`relative inline-block h-6 w-11 rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out ${
            checked ? 'bg-[var(--primary)]' : 'bg-[var(--border)]'
          }`}
        >
          <span
            className={`pointer-events-none absolute top-1/2 -translate-y-1/2 inline-block h-5 w-5 rounded-full bg-white shadow-lg ring-0 transition-transform duration-200 ease-in-out ${
              checked ? 'translate-x-5' : 'translate-x-0.5'
            }`}
          />
        </span>
      </button>
    </label>
  );
}

Toggle.propTypes = {
  checked: PropTypes.bool.isRequired,
  onChange: PropTypes.func.isRequired,
  label: PropTypes.string,
  description: PropTypes.string,
  ariaLabelledBy: PropTypes.string,
};
