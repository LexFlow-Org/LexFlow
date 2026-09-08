// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { clearSessionData, getSessionGeneration, writeSessionData } from '../utils/sessionData';
vi.mock('../tauri-api', () => ({ loadTimeLogs: vi.fn(), loadInvoices: vi.fn(), saveTimeLogs: vi.fn(), saveInvoices: vi.fn(), exportPDF: vi.fn() }));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }) }));
import * as api from '../tauri-api';
import TimeTrackingPage from '../pages/TimeTrackingPage';
beforeEach(() => {
  vi.clearAllMocks(); clearSessionData();
  api.loadTimeLogs.mockResolvedValue([]); api.loadInvoices.mockResolvedValue([]);
});
afterEach(cleanup);
it('blocks billing edits after failed decryption instead of overwriting with an empty list', async () => {
  api.loadInvoices.mockRejectedValueOnce(new Error('synthetic read failure'));
  render(<TimeTrackingPage practices={[]} />);
  await screen.findByText(/Impossibile leggere ore e parcelle/);
  expect(screen.queryByRole('button', { name: /Avvia/ })).toBeNull();
  expect(api.saveTimeLogs).not.toHaveBeenCalled();
  expect(api.saveInvoices).not.toHaveBeenCalled();
});
it('retains a running timer when its save fails', async () => {
  writeSessionData('activeTimer', { practiceId: 'demo', description: 'Synthetic work', startedAt: Date.now() - 90000 }, getSessionGeneration());
  api.saveTimeLogs.mockRejectedValueOnce(new Error('synthetic disk full'));
  render(<TimeTrackingPage practices={[{ id: 'demo', client: 'Demo' }]} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Ferma timer' }));
  await waitFor(() => expect(api.saveTimeLogs).toHaveBeenCalledTimes(1));
  expect(screen.getByRole('timer')).toBeDefined();
  expect(screen.getByText('Synthetic work')).toBeDefined();
});
it('exports an invoice using the explicit AutoTable ESM API', async () => {
  api.loadInvoices.mockResolvedValueOnce([{ id:'invoice-demo',number:'DEMO',date:'2026-09-06',clientName:'Synthetic client',items:[{description:'Work',qty:1,unit:'h',unitPrice:100,total:100}],status:'draft' }]);
  api.exportPDF.mockResolvedValueOnce({ success: true });
  render(<TimeTrackingPage practices={[]} />);
  fireEvent.click(await screen.findByRole('tab', { name: /Parcelle/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Scarica PDF parcella DEMO' }));
  await waitFor(() => expect(api.exportPDF).toHaveBeenCalledTimes(1));
  const buffer = api.exportPDF.mock.calls[0][0];
  expect(new TextDecoder().decode(new Uint8Array(buffer).slice(0, 5))).toBe('%PDF-');
});

it('rebases queued manual entries and repeated submit behind a pending timer save', async () => {
  let finishTimerSave;
  writeSessionData('activeTimer', { practiceId: 'demo', description: 'Timer work', startedAt: Date.now() - 90000 }, getSessionGeneration());
  api.saveTimeLogs.mockImplementationOnce(() => new Promise(resolve => { finishTimerSave = resolve; }));
  api.saveTimeLogs.mockResolvedValueOnce(undefined);
  render(<TimeTrackingPage practices={[{ id: 'demo', client: 'Demo', status: 'active' }]} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Ferma timer' }));
  await waitFor(() => expect(api.saveTimeLogs).toHaveBeenCalledTimes(1));
  fireEvent.click(screen.getByRole('button', { name: /Manuale/ }));
  fireEvent.change(screen.getByLabelText('Descrizione'), { target: { value: 'Manual work' } });
  fireEvent.change(screen.getByLabelText('Minuti'), { target: { value: '10' } });
  fireEvent.click(screen.getByRole('button', { name: 'Registra' }));
  fireEvent.click(screen.getByRole('button', { name: 'Registra' }));
  expect(api.saveTimeLogs).toHaveBeenCalledTimes(1);
  await act(async () => finishTimerSave());
  await waitFor(() => expect(api.saveTimeLogs).toHaveBeenCalledTimes(3));
  expect(api.saveTimeLogs.mock.calls[1][0].map(log => log.description)).toEqual(['Manual work', 'Timer work']);
  expect(api.saveTimeLogs.mock.calls[2][0].map(log => log.description)).toEqual(['Manual work', 'Timer work']);
});
