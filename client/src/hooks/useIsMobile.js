import { useState, useEffect } from 'react';

// ── Hook breakpoint mobile ──────────────────────────────────────────────────
export function useIsMobile(breakpoint = 1024) {
  const [isMobile, setIsMobile] = useState(
    globalThis.window === undefined ? false : globalThis.window.innerWidth < breakpoint
  );
  useEffect(() => {
    const handler = () => setIsMobile(window.innerWidth < breakpoint);
    window.addEventListener('resize', handler);
    return () => window.removeEventListener('resize', handler);
  }, [breakpoint]);
  return isMobile;
}
