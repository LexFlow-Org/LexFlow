// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';
import LicenseActivation from '../components/LicenseActivation';
import * as api from '../tauri-api';

vi.mock('../tauri-api', () => ({ checkLicense: vi.fn(), activateLicense: vi.fn() }));

beforeEach(() => vi.clearAllMocks());
afterEach(() => cleanup());

function renderGate() {
  return render(<LicenseActivation><div>Archivio autorizzato</div></LicenseActivation>);
}

describe('existing license proof after update', () => {
  it('keeps the vault gated and explains reuse only as proof of the saved activation', async () => {
    api.checkLicense.mockResolvedValue({ activated: false, needsLicenseProof: true });
    api.activateLicense.mockResolvedValue({ success: false, error: 'Il codice non corrisponde alla licenza salvata.' });
    renderGate();
    await screen.findByRole('heading', { name: 'Verifica della licenza esistente' });
    expect(screen.getByText(/non serve una nuova licenza/)).toBeInTheDocument();
    expect(screen.queryByText('Archivio autorizzato')).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Chiave di licenza'), { target: { value: 'LXFW.synthetic.signature' } });
    fireEvent.click(screen.getByRole('button', { name: 'Verifica licenza esistente' }));
    await screen.findByText('Il codice non corrisponde alla licenza salvata.');
    expect(api.activateLicense).toHaveBeenCalledExactlyOnceWith('LXFW.synthetic.signature');
    expect(screen.queryByText('Archivio autorizzato')).not.toBeInTheDocument();
  });

  it('accepts a backend-confirmed proof and clears the entered code', async () => {
    api.checkLicense.mockResolvedValue({ activated: false, needsLicenseProof: true });
    api.activateLicense.mockResolvedValue({ success: true, proofRestored: true });
    renderGate();
    const input = await screen.findByLabelText('Chiave di licenza');
    fireEvent.change(input, { target: { value: 'LXFW.synthetic.signature' } });
    fireEvent.click(screen.getByRole('button', { name: 'Verifica licenza esistente' }));
    await screen.findByText('Licenza verificata con successo');
    expect(input).toHaveValue('');
    await waitFor(() => expect(screen.getByText('Archivio autorizzato')).toBeInTheDocument(), { timeout: 2500 });
  });

  it('does not unlock the app when an expired license proof still requires renewal', async () => {
    api.checkLicense.mockResolvedValue({ activated: false, needsLicenseProof: true });
    api.activateLicense.mockResolvedValue({ success: false, proofRestored: true, needsRenewal: true });
    renderGate();
    const input = await screen.findByLabelText('Chiave di licenza');
    fireEvent.change(input, { target: { value: 'LXFW.synthetic.signature' } });
    fireEvent.click(screen.getByRole('button', { name: 'Verifica licenza esistente' }));
    await screen.findByText(/Inserisci il codice di rinnovo/);
    expect(screen.queryByText('Archivio autorizzato')).not.toBeInTheDocument();
    expect(input).toHaveValue('');
    expect(screen.getByRole('button', { name: 'Attiva Licenza' })).toBeDisabled();
  });

  it('shows a pending activation error without hiding the reason', async () => {
    api.checkLicense.mockResolvedValue({ activated: false, activationPending: true, reason: 'Completamento interrotto: riavvia LexFlow.' });
    renderGate();
    expect(await screen.findByRole('status')).toHaveTextContent('Completamento interrotto: riavvia LexFlow.');
    expect(screen.queryByText('Archivio autorizzato')).not.toBeInTheDocument();
  });

  it('opens an already verified activation without asking for the code again', async () => {
    api.checkLicense.mockResolvedValue({ activated: true });
    renderGate();
    await screen.findByText('Archivio autorizzato');
    expect(api.activateLicense).not.toHaveBeenCalled();
    expect(screen.queryByLabelText('Chiave di licenza')).not.toBeInTheDocument();
  });
});
