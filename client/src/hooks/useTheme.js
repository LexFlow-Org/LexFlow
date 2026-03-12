import { useState, useEffect, useCallback } from 'react';
import * as api from '../tauri-api';

/**
 * useTheme — gestisce il toggle tra tema 'dark' e 'light'.
 * Persiste la scelta nel settings del vault tramite api.saveSettings().
 * Applica data-theme="light" su <html> per il tema chiaro.
 */
export function useTheme(settings, onSaveSettings) {
  const [theme, setTheme] = useState(() => {
    // Leggi dal localStorage come fallback rapido per evitare flash
    return localStorage.getItem('lexflow-theme') || 'dark';
  });

  // Sync con settings quando arrivano dal backend
  useEffect(() => {
    if (settings?.theme && settings.theme !== theme) {
      setTheme(settings.theme);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings?.theme]);

  // Applica il tema al DOM
  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'light') {
      root.setAttribute('data-theme', 'light');
    } else {
      root.removeAttribute('data-theme');
    }
    localStorage.setItem('lexflow-theme', theme);
  }, [theme]);

  const toggleTheme = useCallback(async () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    localStorage.setItem('lexflow-theme', next);
    // Persisti nel vault settings
    if (onSaveSettings) {
      try {
        const updated = { ...settings, theme: next };
        await onSaveSettings(updated);
      } catch (e) {
        console.warn('[useTheme] save failed:', e);
      }
    }
  }, [theme, settings, onSaveSettings]);

  return { theme, toggleTheme };
}
