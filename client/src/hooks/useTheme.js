import { useState, useEffect, useCallback } from 'react';
import * as api from '../tauri-api';

/**
 * useTheme — gestisce il toggle tra tema 'dark' e 'light'.
 * Persiste la scelta nel settings del vault tramite api.saveSettings().
 * Applica data-theme="light" su <html> per il tema chiaro.
 */
export function useTheme(settings, onSaveSettings) {
  const [theme, setTheme] = useState(() => {
    // Leggi dal localStorage — deve combaciare con lo script inline in index.html
    return localStorage.getItem('lexflow-theme') || 'dark';
  });

  // Flag: true dopo il primo sync col backend — prima del sync non sovrascriviamo
  const [synced, setSynced] = useState(false);

  // Sync con settings quando arrivano dal backend (solo la prima volta)
  useEffect(() => {
    if (synced) return; // già sincronizzato — non sovrascrivere scelte utente
    if (settings?.theme) {
      setSynced(true);
      if (settings.theme !== theme) {
        setTheme(settings.theme);
        localStorage.setItem('lexflow-theme', settings.theme);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings?.theme]);

  // Applica il tema al DOM
  useEffect(() => {
    const root = document.documentElement;
    // Remove theme-ready first for instant switch
    root.classList.remove('theme-ready');
    if (theme === 'light') {
      root.setAttribute('data-theme', 'light');
    } else {
      root.removeAttribute('data-theme');
    }
    localStorage.setItem('lexflow-theme', theme);
    // Re-enable transitions after instant switch
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        root.classList.add('theme-ready');
      });
    });
  }, [theme]);

  const toggleTheme = useCallback(async () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    // Remove theme-ready to disable transitions during switch
    document.documentElement.classList.remove('theme-ready');
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
