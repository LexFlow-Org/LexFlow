import { useRef, useCallback, useEffect } from 'react';

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
