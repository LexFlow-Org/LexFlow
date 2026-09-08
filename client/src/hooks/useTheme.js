import { useState, useEffect, useCallback } from 'react';

/** Backend preference until the user chooses a theme in this session. */
export function useTheme(settings, onSaveSettings) {
  const [initialTheme] = useState(() => {
    try { return localStorage.getItem('lexflow-theme') === 'light' ? 'light' : 'dark'; }
    catch { return 'dark'; }
  });
  const [localTheme, setLocalTheme] = useState(null);
  const savedTheme = settings?.theme === 'light' || settings?.theme === 'dark' ? settings.theme : null;
  const theme = localTheme ?? savedTheme ?? initialTheme;

  useEffect(() => {
    const root = document.documentElement;
    root.classList.remove('theme-ready');
    if (theme === 'light') root.setAttribute('data-theme', 'light');
    else root.removeAttribute('data-theme');
    try { localStorage.setItem('lexflow-theme', theme); } catch { /* storage unavailable */ }
    let secondFrame;
    const firstFrame = requestAnimationFrame(() => {
      secondFrame = requestAnimationFrame(() => root.classList.add('theme-ready'));
    });
    return () => {
      cancelAnimationFrame(firstFrame);
      if (secondFrame !== undefined) cancelAnimationFrame(secondFrame);
    };
  }, [theme]);

  const toggleTheme = useCallback(async () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    document.documentElement.classList.remove('theme-ready');
    setLocalTheme(next);
    if (onSaveSettings) {
      try { await onSaveSettings({ ...settings, theme: next }); }
      catch {
        // Keep the local preference usable when the settings file cannot be saved.
        if (!import.meta.env.PROD) console.warn('[useTheme] Impossibile salvare il tema');
      }
    }
  }, [theme, settings, onSaveSettings]);

  return { theme, toggleTheme };
}
