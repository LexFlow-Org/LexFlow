import { useRef, useCallback, useEffect, useState } from 'react';

/**
 * Debounces a *value*: returns the most recent `value` that has been stable
 * for at least `delay` ms.
 *
 * Use for: search inputs, filter fields, anything that triggers an expensive
 * `useMemo` derivation downstream.
 *
 *   const debouncedQuery = useDebounce(query, 200);
 *   const filtered = useMemo(() => list.filter(match), [list, debouncedQuery]);
 */
export function useDebounce(value, delay = 200) {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);

  return debounced;
}

/**
 * Returns a debounced version of the callback.
 * The callback is invoked after `delay` ms of inactivity.
 * Call flush() to force immediate execution (e.g. on unmount/lock).
 */
export function useDebouncedCallback(callback, delay = 500) {
  const timeoutRef = useRef(null);
  const callbackRef = useRef(callback);
  const pendingArgsRef = useRef(null);

  // Always use latest callback
  useEffect(() => { callbackRef.current = callback; }, [callback]);

  const flush = useCallback(() => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
    if (pendingArgsRef.current !== null) {
      callbackRef.current(...pendingArgsRef.current);
      pendingArgsRef.current = null;
    }
  }, []);

  const debounced = useCallback((...args) => {
    pendingArgsRef.current = args;
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    timeoutRef.current = setTimeout(() => {
      timeoutRef.current = null;
      if (pendingArgsRef.current !== null) {
        callbackRef.current(...pendingArgsRef.current);
        pendingArgsRef.current = null;
      }
    }, delay);
  }, [delay]);

  // Flush on unmount to prevent data loss
  useEffect(() => () => flush(), [flush]);

  return { debounced, flush };
}
