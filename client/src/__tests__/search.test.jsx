// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import CommandPalette from '../components/CommandPalette';
import * as api from '../tauri-api';
vi.mock('../tauri-api', () => ({ searchVault: vi.fn() }));
beforeEach(() => { vi.useFakeTimers(); vi.clearAllMocks(); });
afterEach(() => { cleanup(); vi.useRealTimers(); });

it('discards stale search responses and results after closing', async () => {
  let resolveOld;
  api.searchVault.mockReturnValueOnce(new Promise(resolve => { resolveOld = resolve; }));
  api.searchVault.mockResolvedValueOnce([{ id: 'new', field: 'practices', title: 'Newest result' }]);
  const view = render(<CommandPalette isOpen onClose={() => {}} />);
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'old' } });
  await act(async () => vi.advanceTimersByTimeAsync(150));
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'new' } });
  await act(async () => vi.advanceTimersByTimeAsync(150));
  expect(screen.getByText('Newest result')).toBeDefined();
  await act(async () => resolveOld([{ id: 'old', field: 'practices', title: 'Old secret' }]));
  expect(screen.queryByText('Old secret')).toBeNull();
  expect(screen.getByText('Newest result')).toBeDefined();
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'never sent' } });
  view.rerender(<CommandPalette isOpen={false} onClose={() => {}} />);
  await act(async () => vi.advanceTimersByTimeAsync(150));
  expect(api.searchVault).toHaveBeenCalledTimes(2);
});

it('cannot select the previous query while the replacement search is pending', async () => {
  api.searchVault.mockResolvedValueOnce([{ id: 'old', field: 'practices', title: 'Previous result' }]);
  api.searchVault.mockReturnValueOnce(new Promise(() => {}));
  const onNavigate = vi.fn();
  render(<CommandPalette isOpen onClose={() => {}} onNavigate={onNavigate} />);
  const input = screen.getByRole('combobox');
  fireEvent.change(input, { target: { value: 'previous' } });
  await act(async () => vi.advanceTimersByTimeAsync(150));
  expect(screen.getByText('Previous result')).toBeDefined();
  fireEvent.change(input, { target: { value: 'replacement' } });
  fireEvent.keyDown(input, { key: 'Enter' });
  expect(onNavigate).not.toHaveBeenCalled();
  expect(screen.queryByText('Previous result')).toBeNull();
});

it('reopens with a clean query and no results from the closed palette', async () => {
  api.searchVault.mockResolvedValueOnce([{ id: 'old', field: 'practices', title: 'Previous result' }]);
  const view = render(<CommandPalette isOpen onClose={() => {}} />);
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'previous' } });
  await act(async () => vi.advanceTimersByTimeAsync(150));
  view.rerender(<CommandPalette isOpen={false} onClose={() => {}} />);
  view.rerender(<CommandPalette isOpen onClose={() => {}} />);
  expect(screen.getByRole('combobox').value).toBe('');
  expect(screen.queryByText('Previous result')).toBeNull();
});
