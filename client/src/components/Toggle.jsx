import PropTypes from 'prop-types';
import { useId } from 'react';

export default function Toggle({ checked, onChange, label, description, ariaLabelledBy }) {
  const id = useId();

  return (
    <div className="flex items-center justify-between gap-4 shrink-0 group">
      {(label || description) && (
        <label htmlFor={id} className="flex-1 min-w-0 cursor-pointer">
          {label && <span className="text-sm text-[var(--text)] font-medium">{label}</span>}
          {description && <p id={`${id}-description`} className="text-xs text-[var(--text-dim)] mt-0.5">{description}</p>}
        </label>
      )}
      <button
        id={id}
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={ariaLabelledBy ? undefined : (label || undefined)}
        aria-labelledby={ariaLabelledBy || undefined}
        aria-describedby={description ? `${id}-description` : undefined}
        onClick={() => onChange(!checked)}
        className="toggle-control"
      >
        {/* visual switch track */}
        <span className="toggle-track" aria-hidden="true">
          <span className="toggle-thumb" />
        </span>
      </button>
    </div>
  );
}

Toggle.propTypes = {
  checked: PropTypes.bool.isRequired,
  onChange: PropTypes.func.isRequired,
  label: PropTypes.string,
  description: PropTypes.string,
  ariaLabelledBy: PropTypes.string,
};
