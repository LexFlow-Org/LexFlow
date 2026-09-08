// @vitest-environment jsdom
import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useSessionState } from '../hooks/useSessionState';
import { clearSessionData, getSessionGeneration, readSessionData, writeSessionData } from '../utils/sessionData';

const createStorage = () => {
  const items = new Map();
  return { getItem: key => items.get(key) ?? null, setItem: (key, value) => items.set(key, String(value)), removeItem: key => items.delete(key), clear: () => items.clear(), get length() { return items.size; } };
};
beforeEach(() => {
  vi.stubGlobal('localStorage', createStorage());
  vi.stubGlobal('sessionStorage', createStorage());
  clearSessionData();
});
afterEach(cleanup);

describe('unlocked UI session', () => {
  it('preserves navigation state only in memory and clears it on lock', () => {
    const { result, unmount } = renderHook(() => useSessionState('recoveryKey', ''));
    act(() => result.current[1]('synthetic recovery secret'));
    expect(readSessionData('recoveryKey', '')).toBe('synthetic recovery secret');
    expect(sessionStorage.getItem('lexflow_pending_recovery')).toBeNull();
    expect(localStorage.length).toBe(0);
    unmount();
    const remounted = renderHook(() => useSessionState('recoveryKey', ''));
    expect(remounted.result.current[0]).toBe('synthetic recovery secret');
    act(() => clearSessionData());
    act(() => remounted.result.current[1]('late secret from locked session'));
    expect(readSessionData('recoveryKey', '')).toBe('');
  });

  it('removes historical plaintext without removing unrelated preferences', () => {
    for (const key of ['lexflow_notifications', 'lexflow_pdf_history']) localStorage.setItem(key, 'sensitive');
    for (const key of ['lexflow_pending_recovery', 'lexflow_active_timer']) sessionStorage.setItem(key, 'sensitive');
    localStorage.setItem('lexflow-theme', 'light');
    const previous = getSessionGeneration();
    clearSessionData();
    writeSessionData('activeTimer', { description: 'late work' }, previous);
    expect(readSessionData('activeTimer', null)).toBeNull();
    expect(localStorage.getItem('lexflow_notifications')).toBeNull();
    expect(localStorage.getItem('lexflow_pdf_history')).toBeNull();
    expect(sessionStorage.length).toBe(0);
    expect(localStorage.getItem('lexflow-theme')).toBe('light');
    localStorage.clear();
  });
});
