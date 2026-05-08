import { useState, useEffect, useCallback } from 'react';

/**
 * useTheme — gestisce il toggle tra tema 'dark' e 'light'.
 * Persiste la scelta nel settings del vault tramite api.saveSettings().
 * Applica data-theme="light" su <html> per il tema chiaro.
 *
 * FIX-TH5: Dipendenza da `index.html` — uno `<script>` inline in
 *   `client/index.html` legge `localStorage['lexflow-theme']` PRIMA del
 *   bundle React e applica `data-theme` sul `<html>` per evitare il flash
 *   del tema sbagliato (FOUC). Se sposti la chiave di localStorage qui,
 *   aggiorna anche quello script.
 */
export function useTheme(settings, onSaveSettings) {
  const [theme, setTheme] = useState(() => {
    // Leggi dal localStorage — deve combaciare con lo script inline in index.html
    return localStorage.getItem('lexflow-theme') || 'dark';
  });

  // Flag: true dopo il primo sync col backend — prima del sync non sovrascriviamo
  const [synced, setSynced] = useState(false);

  // FIX-TH1: One-shot sync col backend.
  //   Il sync è VOLUTAMENTE one-way e una sola volta: la prima volta che
  //   `settings.theme` arriva non-null lo accettiamo come fonte di verità.
  //   Successivi cambi di `settings.theme` (es. da un altro device) non
  //   sovrascrivono la scelta locale dell'utente, perché in questa app il
  //   tema si toggla manualmente e il vault non è ancora multi-device.
  //   Se in futuro abilitiamo sync multi-device, rimuovere il flag `synced`.
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
  // FIX-TH4: la classe `theme-ready` è gestita in `client/src/index.css` —
  //   abilita le transizioni dei colori SOLO dopo il primo paint, così lo
  //   switch iniziale è istantaneo e non sembra un fade-in lento. Se rimuovi
  //   `.theme-ready` dal CSS, qui non succede nulla di rotto, solo perdi
  //   l'ottimizzazione della transizione.
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
      } catch (err) {
        // FIX-TH3: il save può fallire (vault locked, IO error, etc).
        // Non blocchiamo l'UX: il tema rimane comunque applicato in memoria
        // e in localStorage, e il prossimo toggle proverà a ri-persistere.
        if (!import.meta.env.PROD) {
          console.warn('[useTheme] save failed:', err);
        }
      }
    }
  }, [theme, settings, onSaveSettings]);

  return { theme, toggleTheme };
}
