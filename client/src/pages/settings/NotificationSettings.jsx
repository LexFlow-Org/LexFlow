import { Bell, BellOff } from 'lucide-react';
import Toggle from '../../components/Toggle';

export default function NotificationSettings({ settings, onSettingsChange }) {
  const notificationsEnabled = settings?.notificationsEnabled !== false;

  const handleToggle = (val) => {
    onSettingsChange({ ...settings, notificationsEnabled: val });
  };

  return (
    <section className="glass-card p-6 space-y-6">
      <div className="flex items-center gap-3">
        {notificationsEnabled ? <Bell size={20} className="text-primary" /> : <BellOff size={20} className="text-text-dim" />}
        <h2 className="text-lg font-bold text-text">Notifiche di Sistema</h2>
      </div>
      <Toggle
        checked={notificationsEnabled}
        onChange={handleToggle}
        label="Notifiche abilitate"
        description="Ricevi notifiche per scadenze, udienze e briefing giornalieri"
      />
    </section>
  );
}
