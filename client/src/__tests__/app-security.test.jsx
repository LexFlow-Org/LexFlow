// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import { clearSessionData, getSessionGeneration, readSessionData, writeSessionData } from '../utils/sessionData';

const observed = vi.hoisted(() => ({ current: null, lock: null }));
vi.mock('../tauri-api', () => ({
  checkBio: vi.fn(async () => true), hasBioSaved: vi.fn(async () => false),
  getAppVersion: vi.fn(async () => 'test'), getPlatform: vi.fn(async () => 'windows'),
  getSettings: vi.fn(async () => ({})), saveSettings: vi.fn(async () => {}),
  setContentProtection: vi.fn(async () => {}), setAutolockMinutes: vi.fn(async () => {}),
  loadPractices: vi.fn(async () => []), loadAgenda: vi.fn(async () => []),
  savePractices: vi.fn(async () => {}), saveAgenda: vi.fn(async () => {}),
  syncNotificationSchedule: vi.fn(async () => {}), pingActivity: vi.fn(async () => {}),
  clearSecureClipboard: vi.fn(async () => {}),
  lockVault: vi.fn(async () => {}), searchVault: vi.fn(async () => []),
  onBlur: vi.fn(() => () => {}), onVaultLocked: vi.fn(() => () => {}),
  onLock: vi.fn(cb => { observed.lock = cb; return () => {}; }),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn(), remove: vi.fn() }), Toaster: () => null }));
vi.mock('@tauri-apps/plugin-notification', () => ({ isPermissionGranted: vi.fn(async () => true), requestPermission: vi.fn() }));
vi.mock('../components/LicenseActivation', () => ({ default: ({ children }) => children }));
vi.mock('../components/LoginScreen', () => ({ default: ({ onUnlock }) => <><button onClick={() => onUnlock()}>Test unlock</button><button onClick={() => onUnlock(true)}>Test create vault</button></> }));
vi.mock('../components/Sidebar', () => ({ default: ({ onLock }) => <button onClick={onLock}>Test lock</button>, HamburgerButton: () => null }));
vi.mock('../components/WindowControls', () => ({ default: () => null }));
vi.mock('../components/TccLocationBanner', () => ({ default: () => null }));
vi.mock('../components/Breadcrumb', () => ({ default: () => null }));
vi.mock('../hooks/useTheme', () => ({ useTheme: () => ({ theme: 'dark', toggleTheme: () => {} }) }));
vi.mock('../hooks/useIsMobile', () => ({ useIsMobile: () => false }));
vi.mock('../pages/Dashboard', async () => {
  const { useAppData } = await import('../contexts/AppContext');
  return { default: function TestDashboard() {
    observed.current = useAppData();
    return <div data-testid="dashboard">{observed.current.practices.map(p => p.client).join(',')}</div>;
  } };
});
import * as api from '../tauri-api';
import App from '../App';

const deferred = () => {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
};
const mount = () => render(<MemoryRouter><App /></MemoryRouter>);
const unlock = async () => {
  fireEvent.click(screen.getByText('Test unlock'));
  await screen.findByTestId('dashboard');
};
beforeEach(() => {
  vi.clearAllMocks();
  api.loadPractices.mockResolvedValue([]);
  api.loadAgenda.mockResolvedValue([]);
  api.savePractices.mockResolvedValue(undefined);
  api.saveAgenda.mockResolvedValue(undefined);
  clearSessionData();
  observed.current = null;
});
afterEach(cleanup);

describe('vault loading and locking', () => {
  it('blocks editing after a failed read and never overwrites agenda', async () => {
    api.loadPractices.mockRejectedValueOnce(new Error('synthetic disk failure'));
    mount();
    fireEvent.click(screen.getByText('Test unlock'));
    await screen.findByText(/Impossibile leggere l’archivio/);
    expect(screen.queryByTestId('dashboard')).toBeNull();
    expect(api.saveAgenda).not.toHaveBeenCalled();
    expect(api.syncNotificationSchedule).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText('Riprova caricamento'));
    await screen.findByTestId('dashboard');
    expect(api.saveAgenda).not.toHaveBeenCalled();
  });

  it('ignores unlocked reads that complete after a lock', async () => {
    const pending = deferred();
    api.loadPractices.mockReturnValueOnce(pending.promise);
    mount();
    fireEvent.click(screen.getByText('Test unlock'));
    writeSessionData('recoveryKey', 'synthetic secret', getSessionGeneration());
    act(() => observed.lock());
    await act(async () => pending.resolve([{ id: 'a', client: 'Late confidential name' }]));
    expect(screen.getByText('Test unlock')).toBeDefined();
    expect(screen.queryByText('Late confidential name')).toBeNull();
    expect(readSessionData('recoveryKey', '')).toBe('');
    expect(api.syncNotificationSchedule).not.toHaveBeenCalled();
  });

  it('does not report a failed case write as success or update derived agenda', async () => {
    mount();
    await unlock();
    api.savePractices.mockRejectedValueOnce(new Error('disk full'));
    await act(async () => {
      await expect(observed.current.savePractices([{ id: 'a', client: 'Unsaved' }])).rejects.toThrow('disk full');
    });
    expect(observed.current.practices).toEqual([]);
    expect(api.saveAgenda).not.toHaveBeenCalled();
  });

  it('serializes agenda mutations against the latest saved state', async () => {
    mount();
    await unlock();
    const pending = deferred();
    api.saveAgenda.mockReturnValueOnce(pending.promise);
    let first, second;
    act(() => {
      first = observed.current.saveAgenda(current => [...current, { id: 'a' }]);
      second = observed.current.saveAgenda(current => [...current, { id: 'b' }]);
    });
    await waitFor(() => expect(api.saveAgenda).toHaveBeenCalledTimes(1));
    await act(async () => { pending.resolve(); await Promise.all([first, second]); });
    expect(api.saveAgenda.mock.calls[1][0]).toEqual([{ id: 'a' }, { id: 'b' }]);
    expect(observed.current.agendaEvents).toEqual([{ id: 'a' }, { id: 'b' }]);
  });

  it('opens and closes search with one Ctrl+K toggle per keystroke', async () => {
    mount();
    await unlock();
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    expect(screen.getByRole('dialog', { name: 'Palette comandi' })).toBeDefined();
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    expect(screen.queryByRole('dialog')).toBeNull();
  });
});

it('onboarding opens the real biometric password modal only after Configura', async () => {
  mount();
  fireEvent.click(screen.getByText('Test create vault'));
  const next = await screen.findByRole('button', { name: 'Vai al passaggio successivo' });
  fireEvent.click(next);
  expect(screen.queryByLabelText('Master Password per la biometria')).toBeNull();
  fireEvent.click(await screen.findByRole('button', { name: 'Configura sblocco biometrico' }));
  expect(await screen.findByLabelText('Master Password per la biometria')).toBeDefined();
  expect(screen.queryByRole('dialog', { name: 'Vault creato' })).toBeNull();
  act(() => observed.lock());
  expect(screen.queryByLabelText('Master Password per la biometria')).toBeNull();
});
