/* eslint-disable react-refresh/only-export-components */
import { createContext, useContext, useMemo } from 'react';

/**
 * AppContext holds the core data state that many components need.
 * Eliminates prop drilling through 3-4 levels of components.
 *
 * Usage: const { practices, agendaEvents, settings } = useAppData();
 *
 * NOTE: il provider memoiza il `value` derivandolo dalle proprietà passate,
 * così i consumer NON si re-renderano se le reference dei callback cambiano
 * tra render del parent ma il loro contenuto è stabile.
 */
const AppContext = createContext(null);

export function AppProvider({ value, children }) {
  const memoValue = useMemo(
    () => value,
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      value?.practices,
      value?.agendaEvents,
      value?.settings,
      value?.savePractices,
      value?.saveAgenda,
    ]
  );
  return <AppContext.Provider value={memoValue}>{children}</AppContext.Provider>;
}

export function useAppData() {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useAppData must be used within AppProvider');
  return ctx;
}
