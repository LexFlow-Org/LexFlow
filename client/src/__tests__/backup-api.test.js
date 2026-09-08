import { createHash } from 'node:crypto';
import { expect, it, vi } from 'vitest';
vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn(async () => ({ success: true })) }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn() }));
vi.mock('@tauri-apps/plugin-notification', () => ({ isPermissionGranted: vi.fn() }));
import { invoke } from '@tauri-apps/api/core';
import { exportVault } from '../tauri-api';
it('hashes backup and current master passwords separately into their own IPC fields', async () => {
  const backup = 'Backup-Sintetico12!', master = 'Master-Sintetico34!';
  const hash = value => createHash('sha256').update(value).digest('hex');
  await exportVault(backup, master);
  expect(invoke).toHaveBeenCalledWith('export_vault', { pwd: hash(backup), currentPassword: hash(master) });
});
