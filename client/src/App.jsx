import { useState, useEffect, useCallback, useRef, lazy, Suspense } from 'react';
import toast, { Toaster } from 'react-hot-toast';
import { Routes, Route, useNavigate, Navigate } from 'react-router-dom';
import { Lock, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react';
import { isPermissionGranted, requestPermission } from '@tauri-apps/plugin-notification';
import * as api from './tauri-api';
import { mapAgendaToScheduleItems } from './utils/helpers';
import { SEMANTIC } from './theme';

// Componenti (caricati subito — servono al layout)
import LoginScreen from './components/LoginScreen';
import LicenseActivation from './components/LicenseActivation';
import Sidebar, { HamburgerButton } from './components/Sidebar';
import { useIsMobile } from './hooks/useIsMobile';
import { useTheme } from './hooks/useTheme';
import WindowControls from './components/WindowControls';
import PracticeDetail from './components/PracticeDetail';
import CreatePracticeModal from './components/CreatePracticeModal';
import ErrorBoundary from './ErrorBoundary';
import TccLocationBanner from './components/TccLocationBanner';

// Pagine — lazy loading: caricate solo quando l'utente ci naviga
import Dashboard from './pages/Dashboard';
const PracticesList = lazy(() => import('./pages/PracticesList'));
const DeadlinesPage = lazy(() => import('./pages/DeadlinesPage'));
const AgendaPage = lazy(() => import('./pages/AgendaPage'));
const SettingsPage = lazy(() => import('./pages/SettingsPage'));
const TimeTrackingPage = lazy(() => import('./pages/TimeTrackingPage'));
const ContactsPage = lazy(() => import('./pages/ContactsPage'));

export default function App() {
  const navigate = useNavigate();
  
  // --- STATI GLOBALI DI SICUREZZA ---
  // License gating is handled by the LicenseActivation component
  const [isLocked, setIsLocked] = useState(() => {
    try {
      const params = new URLSearchParams(globalThis.location.search);
      const e2eFlag = params.get('e2e');
      const isLocalhost = ['localhost', '127.0.0.1'].includes(globalThis.location.hostname);
      // If ?e2e=1 on localhost (or NODE env is test), start unlocked so tests can hit LicenseActivation.
      if (e2eFlag === '1' && (isLocalhost || import.meta.env.MODE === 'test')) return false;
    } catch { console.debug('[App] E2E param check skipped'); }
    return true;
  });
  const [autoLocked, setAutoLocked] = useState(false); // true = lock automatico (no bio auto-trigger)
  const [blurred, setBlurred] = useState(false);
  const [privacyEnabled, setPrivacyEnabled] = useState(true);
  const [version, setVersion] = useState('');

  // --- STATO SIDEBAR MOBILE ---
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const isMobile = useIsMobile(1024); // false su desktop → non monta il burger
  
  // --- STATI DEI DATI & NOTIFICHE ---
  const [practices, setPractices] = useState([]);
  const [agendaEvents, setAgendaEvents] = useState([]);
  const agendaRef = useRef([]);
  const [settings, setSettings] = useState({});
  const [selectedId, setSelectedId] = useState(null);

  const [showCreate, setShowCreate] = useState(false);

  // --- TEMA CHIARO/SCURO ---
  const saveSettingsForTheme = useCallback(async (updated) => {
    setSettings(updated);
    if (api.saveSettings) await api.saveSettings(updated);
  }, []);
  const { theme, toggleTheme } = useTheme(settings, saveSettingsForTheme);

  // --- 1. INIZIALIZZAZIONE ---
  useEffect(() => {
    // Carichiamo informazioni non-legate alla licenza (version, settings)

  api.getAppVersion?.().then(v => setVersion(v || '')).catch(() => {});
  
  // Warm Swift on macOS to reduce first biometric prompt latency
  api.isMac?.().then(isMac => {
    if (isMac) {
      try { api.warmSwift?.(); } catch { /* ignore */ }
    }
  }).catch(() => {});

  // Carichiamo le impostazioni (incluso il tempo di notifica)
  api.getSettings?.().then(s => {
      if (s) {
        setSettings(s);
        // Default to true (secure posture) when the key is missing
        setPrivacyEnabled(typeof s.privacyBlurEnabled === 'boolean' ? s.privacyBlurEnabled : true);
        // Apply screenshot protection — default to true on first launch
        const screenshotProt = typeof s.screenshotProtection === 'boolean' ? s.screenshotProtection : true;
        api.setContentProtection?.(screenshotProt);
        if (s.autolockMinutes !== undefined) {
          api.setAutolockMinutes?.(s.autolockMinutes);
        }
      }
    }).catch(() => {});
  }, []);

  // --- 1b. ACTIVITY TRACKER (Anti-Inattività) ---
  useEffect(() => {
    if (isLocked) return;

    const pingBackend = () => api.pingActivity?.();
    
    // Solo eventi intenzionali — mousemove e scroll generano troppi eventi
    // e thrashano il main thread (specialmente su Android). mousedown/keydown/touchstart
    // sono sufficienti per rilevare attività utente reale.
    const events = ['mousedown', 'keydown', 'touchstart'];
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

    const removeLockListener = api.onLock?.(() => handleLockLocal(true));        // autolock backend
    const removeVaultLockedListener = api.onVaultLocked?.(() => handleLockLocal(true)); // autolock backend

    return () => {
      if (typeof removeBlurListener === 'function') removeBlurListener();
      if (typeof removeLockListener === 'function') removeLockListener();
      if (typeof removeVaultLockedListener === 'function') removeVaultLockedListener();
    };
  }, [privacyEnabled, handleLockLocal]);

  const handleManualLock = async () => {
    if (api.lockVault) await api.lockVault();
    handleLockLocal(false); // lock manuale: bio auto-trigger abilitato
  };

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
        const syncId = `deadline_${p.id}_${d.date}_${d.label.replaceAll(/\s/g, '_')}`;
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
    const s = settingsOverride || settings;
    // Tutti gli impegni agenda (incluse scadenze auto-sincronizzate dai fascicoli)
    // diventano schedule items con orario reale + preavviso globale/individuale.
    // Non serve un blocco separato per le scadenze: syncDeadlinesToAgenda le ha già
    // inserite negli events con timeStart/category/remindMinutes corretti.
    const items = mapAgendaToScheduleItems(events, s?.preavviso || 30);
    const briefingTimes = [
      s?.briefingMattina || '08:30',
      s?.briefingPomeriggio || '14:30',
      s?.briefingSera || '19:30',
    ];
    console.debug('[App] syncScheduleToBackend:', items.length, 'items,', briefingTimes.length, 'briefings, preavviso:', s?.preavviso || 30);
    await api.syncNotificationSchedule({ briefingTimes, items })
      .catch(e => console.warn('[App] syncScheduleToBackend failed:', e));
  }, [settings]);

  const loadAllData = useCallback(async () => {
    try {
      const pracs = (await api.loadPractices().catch(() => []) || []).map(p => ({
        ...p,
        biometricProtected: p.biometricProtected !== false, // default true per tutti
      }));
      const agenda = await api.loadAgenda().catch(() => []) || [];
      const currentSettings = await api.getSettings().catch(() => ({}));
      
      setPractices(pracs);
      setSettings(currentSettings);
      const synced = syncDeadlinesToAgenda(pracs, agenda);
      setAgendaEvents(synced);
      agendaRef.current = synced;
      
      await api.saveAgenda(synced).catch(e => console.warn('[App] saveAgenda sync failed:', e));

      // Sync schedule al backend (riusa syncScheduleToBackend con settings override)
      await syncScheduleToBackend(synced, currentSettings);
    } catch (e) { 
      console.error("Errore caricamento dati:", e); 
    }
  }, [syncDeadlinesToAgenda, syncScheduleToBackend]);

  const handleUnlock = useCallback(async () => {
    setBlurred(false);
    setAutoLocked(false);
    setIsLocked(false);
    await loadAllData();

    // Request notification permission on first unlock (macOS requires explicit grant)
    try {
      const granted = await isPermissionGranted();
      if (!granted) {
        await requestPermission();
      }
    } catch { console.debug('[App] Notification permission non-critical'); }
  }, [loadAllData]);

  // E2E bypass: when testing, make it easy to skip the login gate.
  // This is guarded so it only activates on localhost or in test builds.
  useEffect(() => {
    try {
      const params = new URLSearchParams(globalThis.location.search);
      const e2eFlag = params.get('e2e');
      const isLocalhost = ['localhost', '127.0.0.1'].includes(globalThis.location.hostname);
      if (e2eFlag === '1' && (isLocalhost || import.meta.env.MODE === 'test')) {
        // Give the app a tick to finish initial mounts
        setTimeout(() => { handleUnlock(); }, 50);
      }
    } catch { console.debug('[App] E2E bypass check skipped'); }
  }, [handleUnlock]);

  const savePractices = async (newList) => {
    setPractices(newList);
    if (api.savePractices) {
      try {
        await api.savePractices(newList);
        const synced = syncDeadlinesToAgenda(newList, agendaRef.current);
        setAgendaEvents(synced);
        agendaRef.current = synced;
        await api.saveAgenda(synced);
        // Sync schedule col backend (include scadenze fascicoli aggiornate)
        await syncScheduleToBackend(synced);
      } catch (e) {
        console.error('[App] savePractices pipeline error:', e);
        toast.error('Errore salvataggio fascicoli');
      }
    }
  };

  const saveAgenda = async (newEvents) => {
    setAgendaEvents(newEvents);
    agendaRef.current = newEvents;
    try {
      if (api.saveAgenda) await api.saveAgenda(newEvents);
      // Sync notification schedule with updated items for backend scheduler
      await syncScheduleToBackend(newEvents);
    } catch (e) {
      console.error('[App] saveAgenda error:', e);
      toast.error('Errore salvataggio agenda');
    }
  };

  // Callback for child pages (Agenda, Scadenze) to propagate settings changes
  // back to App.jsx so all pages see the updated values immediately.
  const handleSettingsChange = useCallback((updatedSettings) => {
    setSettings(prev => ({ ...prev, ...updatedSettings }));
  }, []);

  const handleSelectPractice = (id) => {
    setSelectedId(id);
    navigate('/pratiche');
  };

  // --- 5. RENDER ---

  // License gating wraps EVERYTHING — including login screen.
  // This ensures an unlicensed install cannot even reach the vault login.

  const selectedPractice = practices.find(p => p.id === selectedId);

  // Gate 2: Vault — richiede password (o biometria)
  if (isLocked) {
    return (
      <LicenseActivation>
        <div className="h-screen w-screen overflow-hidden bg-background">
          <WindowControls />
          <LoginScreen onUnlock={handleUnlock} autoLocked={autoLocked} />
        </div>
      </LicenseActivation>
    );
  }

  return (
    <LicenseActivation>
      <ErrorBoundary>
      <div className="flex h-screen bg-background text-text-primary overflow-hidden border border-white/5 rounded-lg shadow-2xl relative">
        
        {/* Privacy Shield */}
        {privacyEnabled && blurred && (
          <button 
            type="button"
            className="fixed inset-0 z-[9999] bg-background/80 backdrop-blur-3xl flex items-center justify-center transition-opacity duration-300 cursor-pointer animate-fade-in border-none outline-none w-full"
            onClick={handleManualLock}
          >
            <div className="text-center">
              <div className="w-24 h-24 bg-primary/10 rounded-full flex items-center justify-center mx-auto mb-6 animate-pulse border border-primary/20">
                <Lock size={40} className="text-primary" />
              </div>
              <h2 className="text-2xl font-bold text-white tracking-tight">LexFlow Protetto</h2>
              <p className="text-text-muted text-sm mt-2">Contenuto nascosto per privacy.<br/>Clicca per bloccare il Vault.</p>
            </div>
          </button>
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

        <main className="flex-1 h-screen overflow-hidden relative flex flex-col bg-background pt-[env(titlebar-area-height,0px)]">
          <WindowControls />
          <TccLocationBanner />
          <Toaster
            position="bottom-right"
            containerClassName="!bottom-6 !right-6 !z-[99999]"
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

          <div className="flex-1 overflow-auto p-4 pt-3 sm:p-8 sm:pt-4">
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
                    practice={selectedPractice}
                    onBack={() => setSelectedId(null)}
                    onUpdate={async (up) => {
                      const newList = practices.map(p => p.id === up.id ? up : p);
                      await savePractices(newList);
                    }}
                    agendaEvents={agendaEvents}
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
              
              <Route path="/settings" element={<SettingsPage onLock={handleManualLock} />} />
              <Route path="/sicurezza" element={<SettingsPage onLock={handleManualLock} />} />
              
              {/* Redirect vecchia pagina Conflitti → Contatti & Conflitti */}
              <Route path="/conflitti" element={<Navigate to="/contatti" replace />} />
              
              <Route path="/ore" element={
                <TimeTrackingPage practices={practices} />
              } />
              
              
              <Route path="/contatti" element={
                <ContactsPage practices={practices} onSelectPractice={handleSelectPractice} />
              } />
            </Routes>
            </Suspense>
          </div>
        </main>

        {showCreate && (
          <CreatePracticeModal
            onClose={() => setShowCreate(false)}
            onSave={(p) => savePractices([p, ...practices])}
          />
        )}
      </div>
    </ErrorBoundary>
    </LicenseActivation>
  );
}