// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import LoginScreen from '../components/LoginScreen';
import OnboardingWizard from '../components/OnboardingWizard';
import { BioResetConfirmModal } from '../pages/SettingsPage';
import * as api from '../tauri-api';
import { clearSessionData } from '../utils/sessionData';

vi.mock('../tauri-api', () => ({
  checkBio: vi.fn(), hasBioSaved: vi.fn(), saveBio: vi.fn(), clearBio: vi.fn(), bioLogin: vi.fn(),
  vaultExists: vi.fn(), unlockVault: vi.fn(), getPlatform: vi.fn(), verifyVaultPassword: vi.fn(),
}));
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }) }));
beforeEach(() => {
  vi.clearAllMocks();
  api.checkBio.mockResolvedValue(true);
  api.hasBioSaved.mockResolvedValue(false);
  api.vaultExists.mockResolvedValue(true);
  api.unlockVault.mockResolvedValue({ success: true });
  api.getPlatform.mockResolvedValue('macos');
  api.verifyVaultPassword.mockResolvedValue({ valid: true });
  api.saveBio.mockResolvedValue(undefined);
});
afterEach(cleanup);

it('manual unlock never enrolls biometrics, including after skip or deactivation', async () => {
  const onUnlock = vi.fn();
  render(<LoginScreen onUnlock={onUnlock} />);
  const password = await screen.findByLabelText('Master Password');
  fireEvent.change(password, { target: { value: 'Synthetic!Password12' } });
  fireEvent.submit(password.closest('form'));
  await waitFor(() => expect(onUnlock).toHaveBeenCalledWith(false));
  expect(api.saveBio).not.toHaveBeenCalled();
  expect(password.value).toBe('');
});

it('onboarding skip performs no biometric enrollment', async () => {
  const complete = vi.fn(), configure = vi.fn();
  render(<OnboardingWizard currentStep={1} onComplete={complete} onConfigureBio={configure} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Salta per ora' }));
  expect(complete).toHaveBeenCalledTimes(1);
  expect(configure).not.toHaveBeenCalled();
  expect(api.saveBio).not.toHaveBeenCalled();
});

it('Configura requests the password modal without reporting success or saving credentials', async () => {
  const configure = vi.fn();
  render(<OnboardingWizard currentStep={1} onComplete={vi.fn()} onConfigureBio={configure} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Configura sblocco biometrico' }));
  expect(configure).toHaveBeenCalledTimes(1);
  expect(api.saveBio).not.toHaveBeenCalled();
  expect(screen.queryByText('Biometria Configurata!')).toBeNull();
});

it('unsupported devices finish onboarding with password only', async () => {
  api.checkBio.mockResolvedValue(false);
  const complete = vi.fn();
  render(<OnboardingWizard currentStep={1} onComplete={complete} onConfigureBio={vi.fn()} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Completa la configurazione e avvia LexFlow' }));
  await waitFor(() => expect(complete).toHaveBeenCalledTimes(1));
  expect(screen.queryByText('Configura Biometria')).toBeNull();
});

it('explicit enrollment verifies the fresh password, clears the field and names Touch ID', async () => {
  const close = vi.fn();
  render(<BioResetConfirmModal onClose={close} bioStatus="available" />);
  await screen.findByText(/Touch ID/);
  const input = screen.getByLabelText('Master Password per la biometria');
  fireEvent.change(input, { target: { value: 'Synthetic!Password12' } });
  fireEvent.click(screen.getByRole('button', { name: 'Configura Biometria' }));
  await waitFor(() => expect(api.saveBio).toHaveBeenCalledWith('Synthetic!Password12'));
  expect(api.verifyVaultPassword).toHaveBeenCalledWith('Synthetic!Password12');
  expect(input.value).toBe('');
  expect(close).toHaveBeenCalledTimes(1);
});

it('Windows password login ignores a legacy biometric enrollment and never requests Hello', async () => {
  api.getPlatform.mockResolvedValue('windows');
  api.checkBio.mockResolvedValue(false);
  api.hasBioSaved.mockResolvedValue(true);
  const onUnlock = vi.fn();
  render(<LoginScreen onUnlock={onUnlock} />);
  const password = await screen.findByLabelText('Master Password');
  await waitFor(() => expect(api.checkBio).toHaveBeenCalled());
  fireEvent.change(password, { target: { value: 'Synthetic!Password12' } });
  fireEvent.submit(password.closest('form'));
  await waitFor(() => expect(onUnlock).toHaveBeenCalledWith(false));
  expect(api.bioLogin).not.toHaveBeenCalled();
  expect(api.saveBio).not.toHaveBeenCalled();
});

it('Windows cannot enroll through a stale configuration modal', async () => {
  api.getPlatform.mockResolvedValue('windows');
  const close = vi.fn();
  render(<BioResetConfirmModal onClose={close} bioStatus="available" />);
  const password = screen.getByLabelText('Master Password per la biometria');
  fireEvent.change(password, { target: { value: 'Synthetic!Password12' } });
  fireEvent.click(screen.getByRole('button', { name: 'Configura Biometria' }));
  await screen.findByRole('alert');
  expect(api.verifyVaultPassword).not.toHaveBeenCalled();
  expect(api.saveBio).not.toHaveBeenCalled();
  expect(close).not.toHaveBeenCalled();
  expect(password.value).toBe('');
});

it('invalid passwords and a closed or locked session never enroll', async () => {
  api.verifyVaultPassword.mockResolvedValueOnce({ valid: false });
  const view = render(<BioResetConfirmModal onClose={vi.fn()} bioStatus="available" />);
  let input = screen.getByLabelText('Master Password per la biometria');
  fireEvent.change(input, { target: { value: 'WrongPassword12!' } });
  fireEvent.click(screen.getByRole('button', { name: 'Configura Biometria' }));
  await screen.findByRole('alert');
  expect(api.saveBio).not.toHaveBeenCalled();
  expect(input.value).toBe('');
  let resolve;
  api.verifyVaultPassword.mockReturnValueOnce(new Promise(done => { resolve = done; }));
  fireEvent.change(input, { target: { value: 'Synthetic!Password12' } });
  fireEvent.click(screen.getByRole('button', { name: 'Configura Biometria' }));
  await waitFor(() => expect(api.verifyVaultPassword).toHaveBeenCalledTimes(2));
  clearSessionData();
  view.unmount();
  await act(async () => resolve({ valid: true }));
  expect(api.saveBio).not.toHaveBeenCalled();
});
