import { useState, useEffect } from 'react';

// ── Hook breakpoint mobile ──────────────────────────────────────────────────
// FIX-IM: matchMedia invece di `resize` listener — fires solo quando il
// viewport ATTRAVERSA il breakpoint, non a ogni pixel di drag della finestra.
// Meno re-render, stesso comportamento.
export function useIsMobile(breakpoint = 1024) {
  const [isMobile, setIsMobile] = useState(() => {
    if (typeof globalThis.window === 'undefined' || typeof window.matchMedia !== 'function') {
      return false;
    }
    return window.matchMedia(`(max-width: ${breakpoint}px)`).matches;
  });

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
    const mql = window.matchMedia(`(max-width: ${breakpoint}px)`);
    // Sync once in case breakpoint changed
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setIsMobile(mql.matches);
    const onChange = (e) => setIsMobile(e.matches);
    // Safari < 14 used the deprecated `addListener`; modern browsers expose
    // `addEventListener('change', ...)`. We only support modern.
    mql.addEventListener('change', onChange);
    return () => mql.removeEventListener('change', onChange);
  }, [breakpoint]);

  return isMobile;
}
