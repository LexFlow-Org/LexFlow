// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import ContactsPage from '../pages/ContactsPage';
import * as api from '../tauri-api';

vi.mock('../tauri-api', () => ({ loadContacts: vi.fn(), saveContacts: vi.fn() }));
// jsdom has no layout. Bound the visible range here; the browser benchmark also
// exercises the real virtualizer with 1,000–50,000 contacts and actual geometry.
vi.mock('../hooks/useVirtualList', () => ({ useVirtualList: ({ items, itemHeight }) => ({
  containerRef: { current: null }, totalHeight: items.length * itemHeight,
  items: items.slice(0, 12).map((item, index) => ({ item, index, top: index * itemHeight })),
}) }));
afterEach(() => { cleanup(); vi.clearAllMocks(); });

it('keeps 10,000 contacts virtualized while details open, with accessible close and practice navigation', async () => {
  api.loadContacts.mockResolvedValue(Array.from({ length: 10000 }, (_, i) => ({
    id: `contact-${i}`, name: `Contatto ${String(i).padStart(5, '0')}`, type: 'client', email: `synthetic${i}@example.invalid`,
  })));
  const onSelectPractice = vi.fn();
  render(<ContactsPage practices={[{ id: 'practice-1', clientId: 'contact-0', client: 'Cliente sintetico', object: 'Fascicolo di prova' }]} onSelectPractice={onSelectPractice} />);
  const trigger = await screen.findByRole('button', { name: 'Apri dettaglio Contatto 00000' });
  trigger.focus();
  fireEvent.click(trigger);
  const dialog = screen.getByRole('dialog', { name: 'Dettaglio Contatto 00000' });
  expect(within(dialog).getByText('synthetic0@example.invalid')).toBeDefined();
  expect(screen.getAllByRole('button', { name: /^Apri dettaglio/ })).toHaveLength(12);
  expect(document.activeElement).toBe(dialog);
  fireEvent.keyDown(dialog, { key: 'Escape' });
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(document.activeElement).toBe(trigger);
  fireEvent.click(trigger);
  fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: /Fascicolo di prova/ }));
  expect(onSelectPractice).toHaveBeenCalledWith('practice-1');
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(screen.getAllByRole('button', { name: /^Apri dettaglio/ })).toHaveLength(12);
});

it('retains inline expansion for small contact lists', async () => {
  api.loadContacts.mockResolvedValue([{ id: 'only', name: 'Solo contatto', type: 'client', phone: '0000000' }]);
  render(<ContactsPage practices={[]} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Apri dettaglio Solo contatto' }));
  expect(screen.getByRole('button', { name: 'Chiudi dettaglio Solo contatto' }).getAttribute('aria-expanded')).toBe('true');
  expect(screen.queryByRole('dialog')).toBeNull();
});
