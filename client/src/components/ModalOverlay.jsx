import { useEffect, useRef } from 'react';
import PropTypes from 'prop-types';

/**
 * Shared modal overlay.
 * Renders:
 *  - Full-screen backdrop with blur
 *  - Invisible dismiss button
 *  - A <dialog open> or <div> wrapper with ESC handling + auto-focus
 *
 * Props:
 *  - onClose      — called on ESC / backdrop click
 *  - children     — dialog content
 *  - className    — extra classes on the inner dialog container
 *  - labelledBy   — aria-labelledby for the dialog
 *  - label        — aria-label (alternative to labelledBy)
 *  - zIndex       — z-index level: 50 (default) or 200
 *  - focusTrap    — if true, trap Tab within dialog (default false)
 */
export default function ModalOverlay({
  onClose,
  children,
  className = '',
  labelledBy,
  label,
  zIndex = 50,
  focusTrap = false,
  role,
}) {
  const dialogRef = useRef(null);

  useEffect(() => {
    const el = dialogRef.current;
    if (el) el.focus();

    const handleKey = (e) => {
      if (e.key === 'Escape') onClose();
      if (focusTrap && e.key === 'Tab' && el) {
        const focusable = el.querySelectorAll(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
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
      }
    };

    document.addEventListener('keydown', handleKey);
    return () => document.removeEventListener('keydown', handleKey);
  }, [onClose, focusTrap]);

  const Z_MAP = { 50: 'z-50', 200: 'z-[200]', 9999: 'z-[9999]' };
  const zCls = Z_MAP[zIndex] || 'z-50';

  return (
    <div className={`fixed inset-0 ${zCls} flex items-center justify-center bg-black/80 backdrop-blur-xl p-4`}>
      <button
        type="button"
        className="absolute inset-0 cursor-default"
        aria-label="Chiudi"
        onClick={onClose}
        tabIndex={-1}
      />
      <dialog
        open
        ref={dialogRef}
        tabIndex={-1}
        role={role}
        aria-modal="true"
        aria-labelledby={labelledBy}
        aria-label={labelledBy ? undefined : label}
        className={`relative z-10 m-0 p-0 border-none bg-transparent ${className}`}
      >
        {children}
      </dialog>
    </div>
  );
}

ModalOverlay.propTypes = {
  onClose: PropTypes.func.isRequired,
  children: PropTypes.node.isRequired,
  className: PropTypes.string,
  labelledBy: PropTypes.string,
  label: PropTypes.string,
  zIndex: PropTypes.number,
  focusTrap: PropTypes.bool,
  role: PropTypes.string,
};
