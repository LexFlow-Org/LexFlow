import { useState, useEffect, useCallback, useMemo, useRef, lazy, Suspense } from 'react';
import toast, { Toaster } from 'react-hot-toast';
import { Routes, Route, useNavigate, useLocation, Navigate } from 'react-router-dom';
import { Lock, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react';
import { isPermissionGranted, requestPermission } from '@tauri-apps/plugin-notification';
import * as api from './tauri-api';
import { mapAgendaToScheduleItems } from './utils/helpers';
import { SEMANTIC } from './theme';
import { clearSessionData } from './utils/sessionData';

// Componenti (caricati subito — servono al layout)
import LoginScreen from './components/LoginScreen';
import LicenseActivation from './components/LicenseActivation';
import Sidebar, { HamburgerButton } from './components/Sidebar';
import { useIsMobile } from './hooks/useIsMobile';
import { useTheme } from './hooks/useTheme';
import WindowControls from './components/WindowControls';
const PracticeDetail = lazy(() => import('./components/PracticeDetail'));
const CreatePracticeModal = lazy(() => import('./components/CreatePracticeModal'));
import TccLocationBanner from './components/TccLocationBanner';
import CommandPalette from './components/CommandPalette';
import Breadcrumb from './components/Breadcrumb';
const OnboardingWizard = lazy(() => import('./components/OnboardingWizard'));
import { AppProvider } from './contexts/AppContext';

// Pagine — lazy loading: caricate solo quando l'utente ci naviga
const Dashboard = lazy(() => import('./pages/Dashboard'));
const PracticesList = lazy(() => import('./pages/PracticesList'));
const DeadlinesPage = lazy(() => import('./pages/DeadlinesPage'));
const AgendaPage = lazy(() => import('./pages/AgendaPage'));
const SettingsPage = lazy(() => import('./pages/SettingsPage'));
const BioConfigurationModal = lazy(() => import('./pages/SettingsPage').then(module => ({ default: module.BioResetConfirmModal })));
const TimeTrackingPage = lazy(() => import('./pages/TimeTrackingPage'));
const ContactsPage = lazy(() => import('./pages/ContactsPage'));
const ReportPage = lazy(() => import('./pages/ReportPage'));
// ActivityPage merged into ReportPage
const DocumentToolsPage = lazy(() => import('./pages/DocumentToolsPage'));

export default function App() {
  const navigate = useNavigate();
  const location = useLocation();
  const contentRef = useRef(null);
  const sessionRef = useRef(0);
  const unlockedRef = useRef(false);
  const saveQueueRef = useRef(Promise.resolve());
  const practicesRef = useRef([]);
  const settingsRef = useRef({});
  const [loadingData, setLoadingData] = useState(false);
  const [dataError, setDataError] = useState('');

  // --- STATI GLOBALI DI SICUREZZA ---
  // License gating is handled by the LicenseActivation component
  const [isLocked, setIsLocked] = useState(() => {
    try {
      const params = new URLSearchParams(globalThis.location.search);
      const e2eFlag = params.get('e2e');
      // SECURITY: in Tauri release builds the webview origin is `tauri://localhost`,
      // which would match the old "isLocalhost" check.  We restrict the E2E bypass
      // to ONLY test mode (Vite test/dev), preventing any chance of a packaged
      // build accepting `?e2e=1` on the URL bar.
      if (e2eFlag === '1' && import.meta.env.MODE === 'test') return false;
    } catch { console.debug('[App] E2E param check skipped'); }
    return true;
  });
  const [autoLocked, setAutoLocked] = useState(false); // true = lock automatico (no bio auto-trigger)
  const [blurred, setBlurred] = useState(false);
  const [privacyEnabled, setPrivacyEnabled] = useState(true);
  const [version, setVersion] = useState('');

  // --- COMMAND PALETTE (⌘K) ---
  const [cmdPaletteOpen, setCmdPaletteOpen] = useState(false);

  // --- STATO SIDEBAR MOBILE ---
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const isMobile = useIsMobile(1024); // false su desktop → non monta il burger
  
  // --- STATI DEI DATI & NOTIFICHE ---
  const [practices, setPractices] = useState([]);
  const [agendaEvents, setAgendaEvents] = useState([]);
  const agendaRef = useRef([]);
  const [settings, setSettings] = useState({});
  const [selectedId, setSelectedId] = useState(null);

  // Scroll reset on route change (NOT on every selectedId tick: dentro
  // /pratiche il dettaglio gestisce il proprio scroll; resettare anche su
  // selectedId rompeva il "torna in cima" all'apertura di un fascicolo).
  useEffect(() => { contentRef.current?.scrollTo(0, 0); }, [location.pathname]);

  const [showCreate, setShowCreate] = useState(false);
  const [showOnboarding, setShowOnboarding] = useState(false);
  const [showBioConfiguration, setShowBioConfiguration] = useState(false);

  // --- TEMA CHIARO/SCURO ---
  const saveSettingsForTheme = useCallback(async (updated) => {
    setSettings(updated);
    settingsRef.current = updated;
    if (api.saveSettings) await api.saveSettings(updated);
  }, []);
  const { theme, toggleTheme } = useTheme(settings, saveSettingsForTheme);

  // --- 1. INIZIALIZZAZIONE ---
  useEffect(() => {
    // Carichiamo informazioni non-legate alla licenza (version, settings)

  api.getAppVersion?.().then(v => setVersion(v || '')).catch(() => {});

  // Detect platform and set CSS class for platform-specific optimizations
  // (e.g. disable backdrop-filter on Windows/Android where WebView renders it in software)
  api.getPlatform?.().then(platform => {
    if (platform === 'macos') {
      document.body.classList.add('is-macos');
      api.warmSwift?.().catch(() => {});
    } else if (platform === 'android' || platform === 'ios') {
      document.body.classList.add('is-mobile');
      document.body.classList.add(`is-${platform}`);
    } else {
      document.body.classList.add('is-windows');
    }
  }).catch(() => {});

  // Carichiamo le impostazioni (incluso il tempo di notifica)
  api.getSettings?.().then(s => {
      if (s) {
        setSettings(s);
        settingsRef.current = s;
        // Default to true (secure posture) when the key is missing
        setPrivacyEnabled(typeof s.privacyBlurEnabled === 'boolean' ? s.privacyBlurEnabled : true);
        // Apply screenshot protection — default to true on first launch
        const screenshotProt = typeof s.screenshotProtection === 'boolean' ? s.screenshotProtection : true;
        api.setContentProtection?.(screenshotProt).catch(() => {});
        if (s.autolockMinutes !== undefined) {
          const minutes = Number.isInteger(s.autolockMinutes) && s.autolockMinutes >= 1 && s.autolockMinutes <= 1440 ? s.autolockMinutes : 5;
          api.setAutolockMinutes?.(minutes).catch(() => {});
        }
      }
    }).catch(() => {});
  }, []);

  // --- 1b. ACTIVITY TRACKER (Anti-Inattività) ---
  useEffect(() => {
    if (isLocked) return;

    const pingBackend = () => api.pingActivity?.().catch(() => {});
    
    // Solo eventi intenzionali — mousemove e scroll generano troppi eventi
    // e thrashano il main thread (specialmente su Android). mousedown/keydown/touchstart
    // /pointerdown sono sufficienti per rilevare attività utente reale.
    // pointerdown copre stylus / penna / dispositivi misti (Pointer Events spec).
    const events = ['mousedown', 'keydown', 'touchstart', 'pointerdown'];
    let lastPing = 0;
    const throttledPing = () => {
      const now = Date.now();
      if (now - lastPing > 30000) { // Ping every 30s max
        lastPing = now;
        pingBackend();
      }
    };

    events.forEach(e => document.addEventListener(e, throttledPing, { passive: true }));
    pingBackend(); // Ping immediately on unlock

    return () => {
      events.forEach(e => document.removeEventListener(e, throttledPing));
    };
  }, [isLocked]);

  // --- 2. LOGICA NOTIFICHE DI SISTEMA ---
  // Le notifiche sono gestite ESCLUSIVAMENTE dal backend Rust (start_notification_scheduler).
  // Il backend legge il file notif-schedule cifrato ogni 60s, controlla la finestra temporale
  // (epoch-based, catchup dopo sleep/wake) e emette "show-notification" al frontend.
  // NON serve un secondo poller qui nel React — causerebbe notifiche doppie/triple
  // perché send_notification() nativo + show-notification event + backend scheduler
  // scatterebbero tutti per lo stesso evento.
  //
  // Il sync avviene tramite saveAgenda() → syncNotificationSchedule() che scrive
  // gli items + briefingTimes nel file cifrato letto dal backend.

  // --- 3. GESTIONE SICUREZZA (BLUR & LOCK) ---
  const handleLockLocal = useCallback((isAuto = false) => {
    sessionRef.current += 1;
    unlockedRef.current = false;
    practicesRef.current = [];
    agendaRef.current = [];
    clearSessionData();
    void api.clearSecureClipboard();
    toast.remove();
    setShowCreate(false);
    setShowOnboarding(false);
    setShowBioConfiguration(false);
    setCmdPaletteOpen(false);
    setSidebarOpen(false);
    setLoadingData(false);
    setDataError('');
    setBlurred(false);
    setPractices([]); 
    setAgendaEvents([]);
    setSelectedId(null);
    setAutoLocked(isAuto); // memorizza se è autolock
    setIsLocked(true);
    navigate('/');
  }, [navigate]);

  useEffect(() => {
    const removeBlurListener = api.onBlur?.((val) => {
      if (privacyEnabled) setBlurred(val);
    });

    // Clear data immediately; focus-driven authentication belongs to LoginScreen.
    const handleAutoLock = () => handleLockLocal(true);

    const removeLockListener = api.onLock?.(handleAutoLock);        // autolock backend
    const removeVaultLockedListener = api.onVaultLocked?.(handleAutoLock); // autolock backend

    return () => {
      if (typeof removeBlurListener === 'function') removeBlurListener();
      if (typeof removeLockListener === 'function') removeLockListener();
      if (typeof removeVaultLockedListener === 'function') removeVaultLockedListener();
    };
  }, [privacyEnabled, handleLockLocal]);

  const handleManualLock = useCallback(async () => {
    handleLockLocal(true);
    try { await api.lockVault(); }
    catch { toast.error('Blocco del vault non confermato. Riprova a bloccarlo o chiudi l’app.'); }
  }, [handleLockLocal]);

  // --- KEYBOARD SHORTCUTS (cross-platform: ⌘ on Mac, Ctrl on Windows/Linux) ---
  useEffect(() => {
    if (isLocked) return;
    const handleShortcut = (e) => {
      const mod = e.metaKey || e.ctrlKey;
      if (!mod) return;
      // Non intercettare se l'utente sta digitando in un input/textarea/contenteditable.
      // Eccezione: ⌘K resta sempre attivo (apre command palette anche durante editing).
      const target = e.target;
      const isTyping = target && typeof target.matches === 'function' &&
        target.matches('input, textarea, select, [contenteditable], [contenteditable="true"]');
      switch (e.key) {
        case 'k': // ⌘K — Command Palette (search) — resta attiva anche durante editing
          e.preventDefault();
          setCmdPaletteOpen(prev => !prev);
          break;
        case 'n': // ⌘N — Nuovo fascicolo
          if (isTyping) return;
          if (!e.shiftKey) {
            e.preventDefault();
            setShowCreate(true);
          }
          break;
        case 'l': // ⌘L — Blocca vault
          if (isTyping) return;
          e.preventDefault();
          handleManualLock();
          break;
        default:
          break;
      }
    };
    window.addEventListener('keydown', handleShortcut);
    return () => window.removeEventListener('keydown', handleShortcut);
  }, [isLocked, handleManualLock]);

  // --- 4. LOGICA DATI & SINCRONIZZAZIONE ---
  const syncDeadlinesToAgenda = useCallback((newPractices, currentAgenda) => {
    const manualEvents = currentAgenda.filter(e => !e.autoSync);
    // Mappa degli eventi auto-sincronizzati esistenti per preservare le modifiche utente
    // (es. orario personalizzato, note aggiuntive, completamento)
    const existingSyncedMap = new Map();
    currentAgenda.filter(e => e.autoSync).forEach(e => existingSyncedMap.set(e.id, e));
    
    const syncedEvents = [];
    
    newPractices.filter(p => p.status === 'active').forEach(p => {
      (p.deadlines || []).forEach(d => {
        const syncId = `deadline_${p.id}_${d.date}_${(d.label || '').replaceAll(/\s/g, '_')}`;
        const existing = existingSyncedMap.get(syncId);
        const deadlineTime = d.time || '09:00';
        // Calcola timeEnd = timeStart + 1h
        const [hh, mm] = deadlineTime.split(':').map(Number);
        const endH = String(Math.min(hh + 1, 23)).padStart(2, '0');
        const timeEnd = `${endH}:${String(mm).padStart(2, '0')}`;
        syncedEvents.push({
          // Valori default per nuovi eventi
          id: syncId,
          title: d.label,
          date: d.date,
          timeStart: deadlineTime,
          timeEnd,
          category: 'scadenza',
          notes: `Fascicolo: ${p.client} — ${p.object}`,
          completed: false,
          autoSync: true,
          practiceId: p.id,
          // Preavviso specifico dalla scadenza del fascicolo
          ...(d.remindMinutes != null ? { remindMinutes: d.remindMinutes } : {}),
          ...(d.customRemindTime ? { customRemindTime: d.customRemindTime } : {}),
          // Sovrascrivi con eventuali modifiche utente (orario, note, completamento)
          ...(existing ? {
            timeStart: existing.timeStart,
            timeEnd: existing.timeEnd,
            notes: existing.notes,
            completed: existing.completed,
            // Preserva remindMinutes se l'utente l'ha cambiato dall'agenda
            ...(existing.remindMinutes != null ? { remindMinutes: existing.remindMinutes } : {}),
            ...(existing.customRemindTime ? { customRemindTime: existing.customRemindTime } : {}),
          } : {}),
        });
      });
    });
    return [...manualEvents, ...syncedEvents];
  }, []);

  // Centralizza il sync dello schedule verso il backend Rust scheduler
  const syncScheduleToBackend = useCallback(async (events, settingsOverride) => {
    if (!api.syncNotificationSchedule) return;
    const s = settingsOverride || settingsRef.current;
    // Tutti gli impegni agenda (incluse scadenze auto-sincronizzate dai fascicoli)
    // diventano schedule items con orario reale + preavviso globale/individuale.
    // Non serve un blocco separato per le scadenze: syncDeadlinesToAgenda le ha già
    // inserite negli events con timeStart/category/remindMinutes corretti.
    const items = mapAgendaToScheduleItems(events, s?.preavviso ?? 30);
    const briefingTimes = [
      s?.briefingMattina || '08:30',
      s?.briefingPomeriggio || '14:30',
      s?.briefingSera || '19:30',
    ];
    console.debug('[App] syncScheduleToBackend:', items.length, 'items,', briefingTimes.length, 'briefings, preavviso:', s?.preavviso ?? 30);
    await api.syncNotificationSchedule({ briefingTimes, items })
      .catch(e => console.warn('[App] syncScheduleToBackend failed:', e));
  }, []);

  const loadAllData = useCallback(async (session) => {
    setLoadingData(true);
    setDataError('');
    try {
      // A failed read must never be treated as an empty, writable collection.
      const [rawPracs, agenda, currentSettings] = await Promise.all([
        api.loadPractices(), api.loadAgenda(), api.getSettings(),
      ]);
      if (session !== sessionRef.current || !unlockedRef.current) return false;
      if (!Array.isArray(rawPracs) || !Array.isArray(agenda)) {
        throw new Error('Formato archivio non valido');
      }
      const pracs = rawPracs.map(p => ({ ...p, biometricProtected: p.biometricProtected !== false }));
      const synced = syncDeadlinesToAgenda(pracs, agenda);
      practicesRef.current = pracs;
      agendaRef.current = synced;
      settingsRef.current = currentSettings || {};
      setPractices(pracs);
      setAgendaEvents(synced);
      setSettings(currentSettings || {});
      // Loading is read-only for case/agenda records. Derived deadlines are saved
      // with the next explicit change; a read failure cannot overwrite the vault.
      await syncScheduleToBackend(synced, currentSettings || {});
      return session === sessionRef.current && unlockedRef.current;
    } catch {
      if (session === sessionRef.current && unlockedRef.current) {
        setDataError('Impossibile leggere l’archivio. Nessun dato è stato sostituito. Riprova prima di modificarlo.');
      }
      return false;
    } finally {
      if (session === sessionRef.current) setLoadingData(false);
    }
  }, [syncDeadlinesToAgenda, syncScheduleToBackend]);

  const handleUnlock = useCallback(async (vaultIsNew = false) => {
    const session = ++sessionRef.current;
    unlockedRef.current = true;
    setBlurred(false);
    setAutoLocked(false);
    setIsLocked(false);
    if (!await loadAllData(session)) return;
    try {
      const granted = await isPermissionGranted();
      if (session !== sessionRef.current || !unlockedRef.current) return;
      if (!granted) await requestPermission();
    } catch { /* notification permission is optional */ }
    if (vaultIsNew && session === sessionRef.current && unlockedRef.current) {
      setShowOnboarding(true);
    }
  }, [loadAllData]);

  // E2E bypass: when testing, make it easy to skip the login gate.
  // SECURITY: only honored in Vite test mode — Tauri release builds use
  // `tauri://localhost` as origin and we explicitly exclude that path.
  useEffect(() => {
    try {
      const params = new URLSearchParams(globalThis.location.search);
      const e2eFlag = params.get('e2e');
      if (e2eFlag === '1' && import.meta.env.MODE === 'test') {
        // Give the app a tick to finish initial mounts
        setTimeout(() => { handleUnlock(); }, 50);
      }
    } catch { console.debug('[App] E2E bypass check skipped'); }
  }, [handleUnlock]);

  const enqueueSave = useCallback((work) => {
    const session = sessionRef.current;
    const isCurrent = () => unlockedRef.current && session === sessionRef.current;
    const pending = saveQueueRef.current.then(async () => {
      if (!isCurrent()) throw new Error('Sessione del vault terminata');
      return work(isCurrent);
    });
    saveQueueRef.current = pending.catch(() => {});
    return pending;
  }, []);

  const savePractices = useCallback((update) => enqueueSave(async (isCurrent) => {
    const newList = typeof update === 'function' ? update(practicesRef.current) : update;
    try {
      await api.savePractices(newList);
    } catch (error) {
      if (isCurrent()) toast.error('Impossibile salvare i fascicoli. Riprova.');
      throw error;
    }
    if (!isCurrent()) throw new Error('Sessione del vault terminata');
    practicesRef.current = newList;
    setPractices(newList);
    const synced = syncDeadlinesToAgenda(newList, agendaRef.current);
    try {
      await api.saveAgenda(synced);
      if (!isCurrent()) return;
      setAgendaEvents(synced);
      agendaRef.current = synced;
      await syncScheduleToBackend(synced);
    } catch {
      // The case is saved; do not encourage creating a duplicate on retry.
      if (isCurrent()) toast.error('Fascicolo salvato, ma agenda non sincronizzata. Ricarica l’archivio.');
    }
  }), [enqueueSave, syncDeadlinesToAgenda, syncScheduleToBackend]);

  const saveAgenda = useCallback(async (update) => {
    try {
      return await enqueueSave(async (isCurrent) => {
        const newEvents = typeof update === 'function' ? update(agendaRef.current) : update;
        await api.saveAgenda(newEvents);
        if (!isCurrent()) return false;
        setAgendaEvents(newEvents);
        agendaRef.current = newEvents;
        await syncScheduleToBackend(newEvents);
        return true;
      });
    } catch {
      if (unlockedRef.current) toast.error('Impossibile salvare l’agenda. Riprova.');
      return false;
    }
  }, [enqueueSave, syncScheduleToBackend]);

  // Callback for child pages (Agenda, Scadenze) to propagate settings changes
  // back to App.jsx so all pages see the updated values immediately.
  const handleSettingsChange = useCallback((updatedSettings) => {
    settingsRef.current = { ...settingsRef.current, ...updatedSettings };
    setSettings(settingsRef.current);
    if (typeof updatedSettings.privacyBlurEnabled === 'boolean') setPrivacyEnabled(updatedSettings.privacyBlurEnabled);
  }, []);

  const handleSelectPractice = (id) => {
    setSelectedId(id);
    navigate('/pratiche');
  };

  // --- 5. RENDER ---

  // License gating wraps EVERYTHING — including login screen.
  // This ensures an unlicensed install cannot even reach the vault login.

  const selectedPractice = practices.find(p => p.id === selectedId);

  // Memoizza il valore del context per evitare re-render dei consumer
  // quando cambiano solo reference di funzioni stabili.
  const ctxValue = useMemo(
    () => ({ practices, agendaEvents, settings, savePractices, saveAgenda }),
    [practices, agendaEvents, settings, savePractices, saveAgenda]
  );

  // Gate 2: Vault — richiede password (o biometria)
  if (isLocked) {
    return (
      <LicenseActivation>
        <div className="h-dvh w-screen overflow-hidden bg-background">
          <WindowControls />
          <Toaster />
          <LoginScreen onUnlock={handleUnlock} autoLocked={autoLocked} />
        </div>
      </LicenseActivation>
    );
  }

  if (loadingData || dataError) {
    return <LicenseActivation>
      <div className="min-h-dvh bg-background text-text flex items-center justify-center p-6">
        <WindowControls />
        <div role={dataError ? 'alert' : 'status'} className="max-w-lg space-y-4 text-center">
          {loadingData ? <><Loader2 className="animate-spin mx-auto" /><p>Caricamento archivio…</p></> : <>
            <p>{dataError}</p>
            <button className="btn-primary" onClick={() => loadAllData(sessionRef.current)}>Riprova caricamento</button>
          </>}
          <button className="btn-secondary ml-3" onClick={handleManualLock}>Blocca vault</button>
        </div>
      </div>
    </LicenseActivation>;
  }

  return (
    <LicenseActivation>
      {/* main.jsx fornisce già un ErrorBoundary di radice — niente nesting qui */}
      <AppProvider value={ctxValue}>
      {/* Skip link — primo elemento focusabile della pagina (WCAG 2.4.1 Bypass Blocks) */}
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[100000] focus:bg-primary focus:text-primary-ink focus:px-3 focus:py-2 focus:rounded focus:font-semibold focus:shadow-lg"
      >
        Salta al contenuto principale
      </a>
      <div className="flex h-dvh bg-background text-text-primary overflow-hidden border border-border/30 rounded-lg shadow-lg relative">

        {/* Privacy Shield — alertdialog modale (semantica corretta) */}
        {privacyEnabled && blurred && (
          <div
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="privacy-shield-title"
            aria-describedby="privacy-shield-desc"
            className="fixed inset-0 z-[9999] bg-background/95 blur-overlay flex items-center justify-center animate-fade-in"
          >
            <div className="text-center">
              <div className="w-24 h-24 bg-primary/10 rounded-full flex items-center justify-center mx-auto mb-6 animate-pulse border border-primary/20">
                <Lock size={40} className="text-primary" aria-hidden="true" />
              </div>
              <h2 id="privacy-shield-title" className="text-2xl font-bold text-white tracking-tight">LexFlow Protetto</h2>
              <p id="privacy-shield-desc" className="text-text-muted text-sm mt-2">Contenuto nascosto per privacy.</p>
              <button
                type="button"
                onClick={handleManualLock}
                className="btn-primary mt-6"
                autoFocus
              >
                Blocca il Vault
              </button>
            </div>
          </div>
        )}

        {/* Sidebar desktop (≥1024px) + Liquid Curtain mobile (<1024px) */}
        <Sidebar 
          version={version} 
          onLock={handleManualLock}
          isOpen={sidebarOpen}
          onToggle={setSidebarOpen}
          theme={theme}
          onToggleTheme={toggleTheme}
        />

        {/* Hamburger button — solo su mobile/Android (<1024px) */}
        {isMobile && <HamburgerButton onClick={() => setSidebarOpen(true)} />}

        <CommandPalette
          isOpen={cmdPaletteOpen}
          onClose={(action) => {
            if (action === 'toggle') setCmdPaletteOpen(prev => !prev);
            else setCmdPaletteOpen(false);
          }}
          onNavigate={(result) => {
            if (result.field === 'practices') {
              setSelectedId(result.id?.replace('practices_', ''));
              navigate('/pratiche');
            }
            else if (result.field === 'agenda') navigate('/agenda');
            else if (result.field === 'contacts') navigate('/contatti');
            else if (result.field === 'timeLogs') navigate('/ore');
          }}
        />
        <main id="main" tabIndex={-1} className="flex-1 min-w-0 h-dvh overflow-hidden relative flex flex-col bg-background pt-[env(titlebar-area-height,0px)] focus:outline-none">
          <WindowControls />
          <TccLocationBanner />
          <Toaster
            position="top-right"
            containerClassName="!top-16 !right-6 !z-[99999] !max-w-[calc(100vw-3rem)]"
            gutter={10}
            toastOptions={{
              className: 'lexflow-toast',
              success: {
                duration: 3000,
                className: 'lexflow-toast lexflow-toast-success',
                iconTheme: { primary: SEMANTIC.success, secondary: 'transparent' },
                icon: <CheckCircle2 size={18} className="toast-icon-success" />,
              },
              error: {
                duration: 5000,
                className: 'lexflow-toast lexflow-toast-error',
                iconTheme: { primary: SEMANTIC.danger, secondary: 'transparent' },
                icon: <AlertCircle size={18} className="toast-icon-danger" />,
              },
              loading: {
                duration: 15000,
                className: 'lexflow-toast lexflow-toast-loading',
                icon: <Loader2 size={18} className="animate-spin toast-icon-primary" />,
              }
            }}
          />

          <div ref={contentRef} className={`flex-1 ${selectedId && location.pathname === '/pratiche' ? 'overflow-hidden' : 'overflow-auto p-4 pt-3 sm:p-8 sm:pt-4'}`}>
            {!(selectedId && location.pathname === '/pratiche') && <Breadcrumb />}
            <Suspense fallback={<div className="flex items-center justify-center h-full"><Loader2 size={24} className="animate-spin text-primary" /></div>}>
            <Routes>
              <Route path="/" element={
                <Dashboard
                  practices={practices}
                  agendaEvents={agendaEvents}
                  onNavigate={navigate}
                  onSelectPractice={handleSelectPractice}
                />
              } />
              
              <Route path="/pratiche" element={
                selectedId && selectedPractice ? (
                  <PracticeDetail
                    key={selectedPractice.id}
                    practice={selectedPractice}
                    onBack={() => setSelectedId(null)}
                    onUpdate={(changes) => savePractices(current => current.map(p => p.id === selectedPractice.id ? { ...p, ...changes } : p))}
                    agendaEvents={agendaEvents}
                    onNavigate={navigate}
                  />
                ) : (
                  <PracticesList
                    practices={practices}
                    onSelect={handleSelectPractice}
                    onNewPractice={() => setShowCreate(true)}
                  />
                )
              } />
              
              <Route path="/scadenze" element={
                <DeadlinesPage practices={practices} onSelectPractice={handleSelectPractice} settings={settings} agendaEvents={agendaEvents} onNavigate={navigate} onSettingsChange={handleSettingsChange} />
              } />
              
              <Route path="/agenda" element={
                <AgendaPage
                  agendaEvents={agendaEvents}
                  onSaveAgenda={saveAgenda}
                  practices={practices}
                  onSelectPractice={handleSelectPractice}
                  settings={settings}
                  onSettingsChange={handleSettingsChange}
                />
              } />
              
              <Route path="/settings" element={<SettingsPage onLock={handleManualLock} onSettingsChange={handleSettingsChange} />} />
              <Route path="/sicurezza" element={<SettingsPage onLock={handleManualLock} onSettingsChange={handleSettingsChange} />} />
              
              {/* Redirect vecchia pagina Conflitti → Contatti & Conflitti */}
              <Route path="/conflitti" element={<Navigate to="/contatti" replace />} />
              
              <Route path="/ore" element={
                <TimeTrackingPage practices={practices} />
              } />
              
              
              <Route path="/contatti" element={
                <ContactsPage practices={practices} onSelectPractice={handleSelectPractice} />
              } />
              <Route path="/report" element={<ReportPage practices={practices} />} />
              <Route path="/strumenti" element={<DocumentToolsPage />} />
            </Routes>
            </Suspense>
          </div>
        </main>

        <Suspense fallback={null}>
        {showCreate && (
          <CreatePracticeModal
            onClose={() => setShowCreate(false)}
            onSave={(p) => savePractices(current => [p, ...current])}
          />
        )}
        {showOnboarding && (
          <OnboardingWizard
            onComplete={() => setShowOnboarding(false)}
            onConfigureBio={() => { setShowOnboarding(false); setShowBioConfiguration(true); }}
          />
        )}
        {showBioConfiguration && <BioConfigurationModal bioStatus="available" onClose={() => setShowBioConfiguration(false)} />}
        </Suspense>
      </div>
    </AppProvider>
    </LicenseActivation>
  );
}