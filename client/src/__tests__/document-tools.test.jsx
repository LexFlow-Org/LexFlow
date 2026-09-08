// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
vi.mock('../tauri-api', () => ({ secureCopy: vi.fn(), selectFile: vi.fn(), pdfInfo: vi.fn(), selectSavePath: vi.fn(), securePdf: vi.fn() }));
import * as api from '../tauri-api';
import DocumentToolsPage from '../pages/DocumentToolsPage';
afterEach(() => { cleanup(); vi.useRealTimers(); vi.clearAllMocks(); });
it('keeps unsafe redaction unavailable and describes PDF restriction limits', () => {
  render(<DocumentToolsPage />);
  expect(screen.getByRole('button', { name: /Censura PDF/ }).disabled).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: /Proteggi PDF/ }));
  expect(screen.getByText(/Si apre senza password; altri programmi possono ignorare le restrizioni/)).toBeDefined();
});

it('expires the owner-password reveal 60 seconds after each click', async () => {
  vi.useFakeTimers();
  api.selectFile.mockResolvedValue('/synthetic/input.pdf');
  api.pdfInfo.mockResolvedValue({ pages: 1, file_size_label: '1 KB' });
  api.selectSavePath.mockResolvedValue('/synthetic/output.pdf');
  api.securePdf.mockResolvedValue({ success: true, message: 'Done', details: { owner_password: 'synthetic-owner-secret' } });
  render(<DocumentToolsPage />);
  fireEvent.click(screen.getByRole('button', { name: /Proteggi PDF/ }));
  await act(async () => fireEvent.click(screen.getByRole('button', { name: /Sfoglia/ })));
  await act(async () => fireEvent.click(screen.getByRole('button', { name: 'Esegui' })));
  await act(async () => vi.advanceTimersByTimeAsync(61000));
  fireEvent.click(screen.getByRole('button', { name: 'Mostra/nascondi owner password' }));
  expect(screen.getByText('synthetic-owner-secret')).toBeDefined();
  await act(async () => vi.advanceTimersByTimeAsync(60000));
  expect(screen.queryByText('synthetic-owner-secret')).toBeNull();
});
