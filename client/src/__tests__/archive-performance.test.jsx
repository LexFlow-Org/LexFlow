// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import PracticesList from '../pages/PracticesList';
import { useTheme } from '../hooks/useTheme';
beforeEach(() => {
  const storage = new Map();
  vi.stubGlobal('localStorage', { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value) });
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.unstubAllGlobals(); });

it('renders at most 50 initial rows but searches across the complete archive', async () => {
  vi.useFakeTimers();
  const practices = Array.from({ length: 125 }, (_, index) => ({
    id: `demo-${index}`, client: index === 124 ? 'Niccolò Ultimo' : `Cliente ${index}`,
    status: 'active', type: 'civile',
  }));
  const onSelect = vi.fn();
  render(<PracticesList practices={practices} onSelect={onSelect} />);
  expect(screen.getAllByRole('button').filter(b => b.textContent.includes('Materia'))).toHaveLength(50);
  expect(screen.getByText('50 di 125 fascicoli')).toBeDefined();
  fireEvent.click(screen.getByRole('button', { name: 'Mostra altri 50' }));
  expect(screen.getByText('100 di 125 fascicoli')).toBeDefined();
  fireEvent.change(screen.getByLabelText('Cerca fascicoli'), { target: { value: 'niccolo ultimo' } });
  await act(async () => vi.advanceTimersByTimeAsync(200));
  fireEvent.click(screen.getByRole('button', { name: /Niccolò Ultimo/ }));
  expect(onSelect).toHaveBeenCalledWith('demo-124');
  fireEvent.change(screen.getByLabelText('Cerca fascicoli'), { target: { value: '' } });
  await act(async () => vi.advanceTimersByTimeAsync(200));
  expect(screen.getByText('50 di 125 fascicoli')).toBeDefined();
});

function ThemeControl({ settings, onSave }) {
  const { theme, toggleTheme } = useTheme(settings, onSave);
  return <button onClick={toggleTheme}>{theme}</button>;
}
it('uses loaded theme settings while preserving a subsequent local toggle', async () => {
  const save = vi.fn().mockResolvedValue(undefined);
  const view = render(<ThemeControl settings={{}} onSave={save} />);
  expect(screen.getByRole('button').textContent).toBe('dark');
  view.rerender(<ThemeControl settings={{ theme: 'light' }} onSave={save} />);
  expect(screen.getByRole('button').textContent).toBe('light');
  fireEvent.click(screen.getByRole('button'));
  expect(save).toHaveBeenCalledWith({ theme: 'dark' });
  view.rerender(<ThemeControl settings={{ theme: 'light' }} onSave={save} />);
  expect(screen.getByRole('button').textContent).toBe('dark');
});
