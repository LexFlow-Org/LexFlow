// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { ExportBackupModal } from '../pages/SettingsPage';
import * as api from '../tauri-api';
vi.mock('../tauri-api', () => ({ exportVault: vi.fn() }));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { loading: vi.fn(), success: vi.fn(), error: vi.fn(), dismiss: vi.fn() }) }));
beforeEach(() => { vi.clearAllMocks(); api.exportVault.mockResolvedValue({ success: true }); });
afterEach(cleanup);
const fillBackup = () => {
  fireEvent.change(screen.getByLabelText('Password del backup'), { target: { value: 'Backup-Diversa12!' } });
  fireEvent.change(screen.getByLabelText('Conferma password del backup'), { target: { value: 'Backup-Diversa12!' } });
};
it('requires the current master password and passes distinct backup and master credentials', async () => {
  const close = vi.fn();
  render(<ExportBackupModal onClose={close} />);
  fillBackup();
  fireEvent.click(screen.getByRole('button', { name: 'Esporta' }));
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'Inserisci la Master Password attuale per autorizzare il backup.');
  expect(api.exportVault).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('Master Password attuale'), { target: { value: 'Master-Sintetica12!' } });
  fireEvent.click(screen.getByRole('button', { name: 'Esporta' }));
  await waitFor(() => expect(close).toHaveBeenCalledTimes(1));
  expect(api.exportVault).toHaveBeenCalledWith('Backup-Diversa12!', 'Master-Sintetica12!');
  expect(screen.getByLabelText('Master Password attuale').value).toBe('');
  expect(screen.getByLabelText('Password del backup').value).toBe('');
});
it('keeps the dialog open and displays the backend authentication error', async () => {
  api.exportVault.mockRejectedValue(new Error('Master Password attuale non valida.'));
  const close = vi.fn();
  render(<ExportBackupModal onClose={close} />);
  fillBackup();
  fireEvent.change(screen.getByLabelText('Master Password attuale'), { target: { value: 'Errata' } });
  fireEvent.click(screen.getByRole('button', { name: 'Esporta' }));
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'Master Password attuale non valida.');
  expect(close).not.toHaveBeenCalled();
});
