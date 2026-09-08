import { useEffect, useState } from 'react';

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
