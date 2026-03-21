import { describe, it, expect } from 'vitest';

// Smoke tests — verify components can be imported without crashing.
// These catch broken imports, missing dependencies, and syntax errors.

describe('Component imports (smoke test)', () => {
  it('Dashboard imports without error', async () => {
    const mod = await import('../pages/Dashboard');
    expect(mod.default).toBeDefined();
  });

  it('PracticesList imports without error', async () => {
    const mod = await import('../pages/PracticesList');
    expect(mod.default).toBeDefined();
  });

  it('AgendaPage imports without error', async () => {
    const mod = await import('../pages/AgendaPage');
    expect(mod.default).toBeDefined();
  });

  it('SettingsPage imports without error', async () => {
    const mod = await import('../pages/SettingsPage');
    expect(mod.default).toBeDefined();
  });

  it('ContactsPage imports without error', async () => {
    const mod = await import('../pages/ContactsPage');
    expect(mod.default).toBeDefined();
  });

  it('TimeTrackingPage imports without error', async () => {
    const mod = await import('../pages/TimeTrackingPage');
    expect(mod.default).toBeDefined();
  });

  it('ReportPage imports without error', async () => {
    const mod = await import('../pages/ReportPage');
    expect(mod.default).toBeDefined();
  });

  it('ActivityPage imports without error', async () => {
    const mod = await import('../pages/ActivityPage');
    expect(mod.default).toBeDefined();
  });

  it('AuditLogPage imports without error', async () => {
    const mod = await import('../pages/AuditLogPage');
    expect(mod.default).toBeDefined();
  });

  it('CommandPalette imports without error', async () => {
    const mod = await import('../components/CommandPalette');
    expect(mod.default).toBeDefined();
  });

  it('NotificationCenter imports without error', async () => {
    const mod = await import('../components/NotificationCenter');
    expect(mod.default).toBeDefined();
  });

  it('Toggle imports without error', async () => {
    const mod = await import('../components/Toggle');
    expect(mod.default).toBeDefined();
  });

  it('Breadcrumb imports without error', async () => {
    const mod = await import('../components/Breadcrumb');
    expect(mod.default).toBeDefined();
  });

  it('OnboardingWizard imports without error', async () => {
    const mod = await import('../components/OnboardingWizard');
    expect(mod.default).toBeDefined();
  });
});

describe('Hooks (smoke test)', () => {
  it('useDebouncedCallback imports without error', async () => {
    const mod = await import('../hooks/useDebounce');
    expect(mod.useDebouncedCallback).toBeDefined();
  });

  it('useVirtualList imports without error', async () => {
    const mod = await import('../hooks/useVirtualList');
    expect(mod.useVirtualList).toBeDefined();
  });

  it('useIsMobile imports without error', async () => {
    const mod = await import('../hooks/useIsMobile');
    expect(mod.useIsMobile).toBeDefined();
  });
});

describe('API bridge (smoke test)', () => {
  it('tauri-api exports all expected functions', async () => {
    const api = await import('../tauri-api');
    const expected = [
      'unlockVault', 'lockVault', 'loadPractices', 'savePractices',
      'loadAgenda', 'saveAgenda', 'searchVault', 'getAuditLog',
      'changePassword', 'generateRecoveryKey', 'getVaultHealth',
      'exportTimeLogsCsv', 'exportInvoicesCsv', 'triggerBackup',
      'loadRecordHistory',
    ];
    for (const fn of expected) {
      expect(api[fn], `Missing API function: ${fn}`).toBeDefined();
    }
  });
});
