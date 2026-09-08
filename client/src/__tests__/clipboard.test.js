// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(async () => () => {}) }));
vi.mock('@tauri-apps/plugin-notification', () => ({ isPermissionGranted: vi.fn(async () => true) }));
import { clearSecureClipboard, secureCopy } from '../tauri-api';
let clipboard;
let blocked;
beforeEach(() => {
  vi.useFakeTimers();
  clipboard = ''; blocked = false;
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
    writeText: vi.fn(async text => { clipboard = text; }),
    readText: vi.fn(async () => { if (blocked) throw new Error('background'); return clipboard; }),
  } });
});
afterEach(async () => { blocked = false; await clearSecureClipboard(); vi.useRealTimers(); });
it('retries expiry after denied background access', async () => {
  await secureCopy('synthetic recovery secret');
  blocked = true;
  window.dispatchEvent(new Event('blur'));
  await vi.advanceTimersByTimeAsync(30000);
  expect(clipboard).toBe('synthetic recovery secret');
  blocked = false;
  window.dispatchEvent(new Event('focus'));
  await vi.advanceTimersByTimeAsync(0);
  expect(clipboard).toBe('');
});
it('preserves clipboard text copied later by the user', async () => {
  await secureCopy('synthetic recovery secret');
  clipboard = 'unrelated user text';
  await vi.advanceTimersByTimeAsync(30000);
  expect(clipboard).toBe('unrelated user text');
});
