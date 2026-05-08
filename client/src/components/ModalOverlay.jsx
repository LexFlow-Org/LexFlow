import { useEffect, useRef } from 'react';
import PropTypes from 'prop-types';

/**
 * Shared modal overlay.
 * Renders:
 *  - Full-screen backdrop with blur
 *  - Invisible dismiss button
 *  - A <dialog open> or <div> wrapper with ESC handling + auto-focus
 *  - Body scroll lock while open
 *  - Focus restore on close
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
  const previousActiveElement = useRef(null);
  const sentinelRef = useRef(null);

  // Body scroll lock + focus capture/restore
  useEffect(() => {
    // Capture previously focused element so we can restore it on close
    previousActiveElement.current = document.activeElement;

    // Body scroll lock
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    return () => {
      document.body.style.overflow = previousOverflow;
      const prev = previousActiveElement.current;
      // Restore focus only if the element is still in the DOM and focusable
      if (prev && typeof prev.focus === 'function' && document.contains(prev)) {
        try {
          prev.focus();
        } catch {
          /* element no longer focusable — ignore */
        }
      }
    };
  }, []);

  useEffect(() => {
    const el = dialogRef.current;
    if (el) el.focus();

    const getFocusable = () => {
      if (!el) return [];
      const nodes = el.querySelectorAll(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      );
      // Filter visible elements only
      return Array.from(nodes).filter(
        (n) => !n.hasAttribute('disabled') && n.offsetParent !== null
      );
    };

    const handleKey = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
        return;
      }
      if (focusTrap && e.key === 'Tab' && el) {
        const focusable = getFocusable();
        if (focusable.length === 0) {
          // No focusable children → wrap to sentinel (the dialog itself)
          e.preventDefault();
          (sentinelRef.current || el).focus();
          return;
        }
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        const active = document.activeElement;
        if (e.shiftKey && (active === first || active === el)) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && active === last) {
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
    <div className={`fixed inset-0 ${zCls} flex items-center justify-center bg-black/85 blur-overlay p-4`}>
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
        className={`relative z-10 m-0 p-0 border-none bg-transparent outline-none ${className}`}
      >
        {/* Sentinel — used when modal contains no focusable children, so Tab still
            stays trapped inside the dialog. */}
        <span
          ref={sentinelRef}
          tabIndex={-1}
          aria-hidden="true"
          style={{ position: 'absolute', width: 0, height: 0, overflow: 'hidden' }}
        />
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
