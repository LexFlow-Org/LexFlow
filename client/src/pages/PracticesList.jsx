import { useState, useMemo } from 'react';
import PropTypes from 'prop-types';
import { 
  Search, 
  Plus, 
  ChevronRight, 
  Briefcase, 
  Archive,
  CheckCircle2,
  Filter,
  Fingerprint
} from 'lucide-react';

// Mappa dei colori e stili per ogni materia
const SUBJECT_STYLES = {
  civile: { color: 'text-materia-civile', bg: 'bg-materia-civile/10', border: 'border-materia-civile/20', label: 'Civile', stripe: 'bg-materia-civile', dot: 'bg-materia-civile' },
  penale: { color: 'text-materia-penale', bg: 'bg-materia-penale/10', border: 'border-materia-penale/20', label: 'Penale', stripe: 'bg-materia-penale', dot: 'bg-materia-penale' },
  lavoro: { color: 'text-materia-lavoro', bg: 'bg-materia-lavoro/10', border: 'border-materia-lavoro/20', label: 'Lavoro', stripe: 'bg-materia-lavoro', dot: 'bg-materia-lavoro' },
  amm: { color: 'text-materia-amm', bg: 'bg-materia-amm/10', border: 'border-materia-amm/20', label: 'Amministrativo', stripe: 'bg-materia-amm', dot: 'bg-materia-amm' },
  stra: { color: 'text-materia-stra', bg: 'bg-materia-stra/10', border: 'border-materia-stra/20', label: 'Stragiudiziale', stripe: 'bg-materia-stra', dot: 'bg-materia-stra' },
  default: { color: 'text-text-dim', bg: 'bg-surface', border: 'border-border', label: 'Altro', stripe: 'bg-text-dim', dot: 'bg-text-dim' }
};

export default function PracticesList({ practices = [], onSelect, onNewPractice }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [filterType, setFilterType] = useState('all');

  const safePractices = useMemo(() => Array.isArray(practices) ? practices : [], [practices]);

  const types = [
    { id: 'all', label: 'Tutte le materie' },
    { id: 'civile', label: 'Civile' },
    { id: 'penale', label: 'Penale' },
    { id: 'lavoro', label: 'Lavoro' },
    { id: 'amm', label: 'Amministrativo' },
    { id: 'stra', label: 'Stragiudiziale' },
  ];

  const stats = useMemo(() => ({
    total: safePractices.length,
    active: safePractices.filter(p => p?.status === 'active').length,
    closed: safePractices.filter(p => p?.status === 'closed').length,
  }), [safePractices]);

  const filteredPractices = useMemo(() => {
    return safePractices.filter(p => {
      if (!p) return false;
      const matchesSearch = 
        (p.client?.toLowerCase() || '').includes(searchTerm.toLowerCase()) ||
        (p.object?.toLowerCase() || '').includes(searchTerm.toLowerCase()) ||
        (p.code?.toLowerCase() || '').includes(searchTerm.toLowerCase());
      
      const matchesStatus = filterStatus === 'all' || p.status === filterStatus;
      const matchesType = filterType === 'all' || p.type === filterType;
      
      return matchesSearch && matchesStatus && matchesType;
    });
  }, [safePractices, searchTerm, filterStatus, filterType]);

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header & Main Action */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-6">
        <div className="space-y-1">
          <h1 className="text-4xl font-black text-text tracking-tight">Fascicoli</h1>
          <p className="text-text-dim text-sm uppercase tracking-[2px] font-medium opacity-60">Gestione Archivio Digitale</p>
        </div>
        <button 
          onClick={() => typeof onNewPractice === 'function' && onNewPractice()} 
          className="btn-primary flex items-center gap-2 px-7 py-3.5 shadow-2xl shadow-primary/20 hover:scale-[1.02] active:scale-[0.98] transition-all"
        >
          <Plus size={18} strokeWidth={3} />
          <span className="font-bold uppercase tracking-widest text-xs">Nuovo Fascicolo</span>
        </button>
      </div>

      {/* Stats Bar - ORA CLICCABILI PER FILTRARE */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Totali */}
        <button type="button"
          onClick={() => setFilterStatus('all')}
          className={`glass-card p-5 flex items-center gap-4 border cursor-pointer transition-all duration-300 text-left ${
            filterStatus === 'all' 
              ? 'border-primary/40 bg-primary/5 shadow-neon' 
              : 'border-border hover:bg-surface opacity-70 hover:opacity-100'
          }`}
        >
          <div className="w-11 h-11 rounded-xl bg-surface flex items-center justify-center text-text-muted">
            <Briefcase size={20} />
          </div>
          <div>
            <div className="text-2xl font-black text-text leading-none mb-1">{stats.total}</div>
            <div className="text-xs text-text-dim uppercase tracking-[2px] font-bold">Totali</div>
          </div>
        </button>

        {/* Attivi */}
        <button type="button"
          onClick={() => setFilterStatus('active')}
          className={`glass-card p-5 flex items-center gap-4 border cursor-pointer transition-all duration-300 text-left ${
            filterStatus === 'active'
              ? 'border-primary/40 bg-primary/5 shadow-neon'
              : 'border-border hover:bg-surface opacity-70 hover:opacity-100'
          }`}
        >
          <div className="w-11 h-11 rounded-xl bg-surface flex items-center justify-center text-text-muted">
            <CheckCircle2 size={20} />
          </div>
          <div>
            <div className="text-2xl font-black text-text leading-none mb-1">{stats.active}</div>
            <div className="text-xs text-text-dim uppercase tracking-[2px] font-bold">Attivi</div>
          </div>
        </button>

        {/* Chiusi */}
        <button type="button"
          onClick={() => setFilterStatus('closed')}
          className={`glass-card p-5 flex items-center gap-4 border cursor-pointer transition-all duration-300 text-left ${
            filterStatus === 'closed'
              ? 'border-primary/40 bg-primary/5 shadow-neon'
              : 'border-border hover:bg-surface opacity-70 hover:opacity-100'
          }`}
        >
          <div className="w-11 h-11 rounded-xl bg-surface flex items-center justify-center text-text-muted">
            <Archive size={20} />
          </div>
          <div>
            <div className="text-2xl font-black text-text leading-none mb-1">{stats.closed}</div>
            <div className="text-xs text-text-dim uppercase tracking-[2px] font-bold">Chiusi</div>
          </div>
        </button>
      </div>

      {/* Toolbar dei Filtri */}
      <div className="bg-surface p-2 rounded-[24px] border border-border flex flex-col lg:flex-row items-center gap-2">
        <div className="relative flex-1 group w-full">
          <Search className="absolute left-5 top-1/2 -translate-y-1/2 text-text-dim group-focus-within:text-primary transition-colors" size={20} />
          <input 
            type="text" 
            placeholder="Cerca per cliente, oggetto, RG..."
            className="w-full pl-14 pr-6 py-4 bg-transparent border-none focus:ring-0 text-sm text-text placeholder:text-text-dim/20"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        
        <div className="flex items-center gap-2 w-full lg:w-auto p-2 lg:p-0 border-t lg:border-t-0 lg:border-l border-border">
          <div className="flex items-center gap-4 px-4 h-10">
            <Filter size={14} className="text-text-dim opacity-50" />
            
            <select 
              className="bg-transparent border-none text-xs font-black uppercase tracking-[2px] text-text opacity-60 focus:ring-0 cursor-pointer hover:text-primary hover:opacity-100 transition-all p-0"
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
            >
              <option value="all" className="bg-card text-text">Stato: Tutti</option>
              <option value="active" className="bg-card text-text">Solo Attivi</option>
              <option value="closed" className="bg-card text-text">Solo Chiusi</option>
            </select>

            <div className="w-[1px] h-4 bg-border" />

            <select 
              className="bg-transparent border-none text-xs font-black uppercase tracking-[2px] text-text opacity-60 focus:ring-0 cursor-pointer hover:text-primary hover:opacity-100 transition-all p-0"
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
            >
              {types.map(t => (
                <option key={t.id} value={t.id} className="bg-card text-text">{t.label}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Lista Fascicoli */}
      <div className="space-y-4">
        {filteredPractices.length > 0 ? (
          filteredPractices.map((p, index) => {
            const style = SUBJECT_STYLES[p.type] || SUBJECT_STYLES.default;
            return (
              <button type="button"
                key={p?.id || `practice-${index}`}
                onClick={() => typeof onSelect === 'function' && onSelect(p.id)}
                className="glass-card p-6 flex items-center justify-between group hover:bg-surface hover:border-border transition-all cursor-pointer border border-border relative overflow-hidden text-left w-full"
              >
                <div className={`absolute left-0 top-0 bottom-0 w-1.5 ${style.stripe}`} />

                <div className="flex items-center gap-6 flex-1 min-w-0">
                  <div className={`w-14 h-14 rounded-2xl flex-shrink-0 flex items-center justify-center transition-all group-hover:scale-110 ${style.bg} ${style.color}`}>
                    <Briefcase size={26} />
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 flex-1 min-w-0">
                    <div className="space-y-1 overflow-hidden">
                      <div className="text-[9px] font-black text-text-dim uppercase tracking-widest opacity-50">Cliente</div>
                      <div className="text-lg tracking-tight font-bold text-text truncate">{p?.client || 'N/D'}</div>
                    </div>
                    
                    <div className="space-y-1 overflow-hidden">
                      <div className="text-[9px] font-black text-text-dim uppercase tracking-widest opacity-50">Materia</div>
                      <div className="flex items-center gap-2">
                        <div className={`w-2.5 h-2.5 rounded-full ${style.dot}`} />
                        <div className={`text-xs font-bold uppercase tracking-wider ${style.color}`}>{style.label}</div>
                      </div>
                    </div>

                    <div className="space-y-1 overflow-hidden">
                      <div className="text-[9px] font-black text-text-dim uppercase tracking-widest opacity-50">Riferimento</div>
                      <div className="text-xs font-mono text-text-muted tracking-widest bg-surface px-2 py-0.5 rounded-lg">{p?.code || '---'}</div>
                    </div>

                    <div className="hidden lg:flex flex-col justify-center items-end pr-4">
                      <div className={`text-[9px] px-3 py-1 rounded-full font-black uppercase tracking-widest border ${p?.status === 'active' ? 'bg-surface text-text border-border' : 'bg-surface text-text-dim border-border'}`}>
                        <span className="flex items-center gap-1.5">
                          <span className={`w-1.5 h-1.5 rounded-full ${p?.status === 'active' ? 'bg-success' : 'bg-text-dim'}`} />
                          {p?.status === 'active' ? 'Attivo' : 'Archiviato'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center gap-4">
                   {p?.biometricProtected && <Fingerprint size={16} className="text-primary/60" title="Protetto con biometria" />}
                   <ChevronRight className="text-text-dim group-hover:text-primary group-hover:translate-x-1 transition-all" size={24} />
                </div>
              </button>
            );
          })
        ) : (
          <div className="glass-card p-24 flex flex-col items-center justify-center text-center space-y-6 border border-dashed border-border">
            <div className="w-20 h-20 bg-surface rounded-full flex items-center justify-center text-text-dim/20">
              <Search size={40} />
            </div>
            <div className="space-y-2">
              <h3 className="text-xl font-bold text-text">Nessun fascicolo trovato</h3>
              <p className="text-text-muted text-sm max-w-xs mx-auto">Affina i filtri di ricerca o crea una nuova pratica digitale per iniziare.</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

PracticesList.propTypes = {
  practices: PropTypes.array,
  onSelect: PropTypes.func,
  onNewPractice: PropTypes.func,
};