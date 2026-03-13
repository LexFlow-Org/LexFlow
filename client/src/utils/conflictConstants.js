/* ──── Label / colour maps for conflict-check & contacts ──── */

export const ROLE_LABELS = {
  client: 'Cliente',
  counterparty: 'Controparte',
  opposing_counsel: 'Avv. Controparte',
  judge: 'Giudice',
  consultant: 'Consulente',
};

export const FIELD_LABELS = {
  client: 'Cliente',
  counterparty: 'Controparte',
  description: 'Descrizione',
  court: 'Tribunale',
  object: 'Oggetto',
};

export const STATUS_LABELS = { active: 'Attivo', closed: 'Chiuso', archived: 'Archiviato' };
export const STATUS_COLORS = {
  active: 'bg-green-500/10 text-green-400 border-green-500/30',
  closed: 'bg-zinc-500/10 text-zinc-400 border-zinc-500/30',
  archived: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
};
