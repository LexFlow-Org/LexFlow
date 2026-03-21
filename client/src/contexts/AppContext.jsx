import { createContext, useContext } from 'react';

/**
 * AppContext holds the core data state that many components need.
 * Eliminates prop drilling through 3-4 levels of components.
 *
 * Usage: const { practices, agendaEvents, settings } = useAppData();
 */
const AppContext = createContext(null);

export function AppProvider({ value, children }) {
  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

export function useAppData() {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useAppData must be used within AppProvider');
  return ctx;
}
