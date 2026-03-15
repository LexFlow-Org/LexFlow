/**
 * Sidebar LexFlow
 *  Desktop (≥1024px): sidebar classica sempre visibile
 *  Mobile  (<1024px): Liquid Curtain fullscreen
 *
 *  Animazioni Liquid Curtain unificate con LaFagiolata
 */

import { useEffect, useState, useCallback, useRef } from 'react';
import PropTypes from 'prop-types';
import { NavLink, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutDashboard, Briefcase, CalendarClock,
  CalendarDays, Settings, Lock, ShieldCheck, X, Menu,
  Clock, Users, Sun, Moon
} from 'lucide-react';
import logo from '../assets/logo.png';
import { useIsMobile } from '../hooks/useIsMobile';

// ── Nav items per il Liquid Curtain (mobile) ───────────────────────────────
const navItemsMobile = [
  { path: '/',           label: 'Dashboard',    icon: LayoutDashboard },
  { path: '/agenda',     label: 'Agenda',       icon: CalendarDays },
  { path: '/scadenze',   label: 'Scadenze',     icon: CalendarClock },
  { path: '/pratiche',   label: 'Fascicoli',    icon: Briefcase },
  { path: '/ore',        label: 'Gestione Ore', icon: Clock },
  { path: '/contatti',   label: 'Contatti & Conflitti', icon: Users },
  { path: '/settings',   label: 'Impostazioni', icon: Settings },
];

// ── Nav sections per la sidebar desktop ──────────────────────────────────
const sections = [
  { items: [{ path: '/', label: 'Dashboard', icon: LayoutDashboard }] },
  {
    title: 'Quotidiano',
    items: [
      { path: '/agenda',   label: 'Agenda',    icon: CalendarDays },
      { path: '/scadenze', label: 'Scadenze',  icon: CalendarClock },
    ],
  },
  {
    title: 'Studio',
    items: [
      { path: '/pratiche',  label: 'Fascicoli',  icon: Briefcase },
      { path: '/contatti',  label: 'Contatti & Conflitti', icon: Users },
    ],
  },
  {
    title: 'Amministrazione',
    items: [
      { path: '/ore',       label: 'Gestione Ore', icon: Clock },
    ],
  },
  {
    title: 'Configurazione',
    items: [{ path: '/settings', label: 'Impostazioni', icon: Settings }],
  },
];

// ══════════════════════════════════════════════════════════════════════════
//  LIQUID CURTAIN variants
// ══════════════════════════════════════════════════════════════════════════
const curtainVariants = {
  hidden: {
    y: '-100%',
    borderBottomLeftRadius: '100% 50%',
    borderBottomRightRadius: '100% 50%',
    opacity: 1,
  },
  visible: {
    y: '0%',
    borderBottomLeftRadius: '0% 0%',
    borderBottomRightRadius: '0% 0%',
    opacity: 1,
    transition: { duration: 1.8, ease: [0.22, 1, 0.36, 1] },
  },
  exit: {
    y: '-100%',
    borderBottomLeftRadius: '100% 50%',
    borderBottomRightRadius: '100% 50%',
    transition: { duration: 0.8, ease: [0.4, 0, 0.2, 1] },
  },
};

const contentVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: {
    opacity: 1, y: 0,
    transition: { delay: 1.4, duration: 1, ease: [0.22, 1, 0.36, 1] },
  },
  exit: {
    opacity: 0, scale: 0.98,
    transition: { duration: 0.3, ease: [0.4, 0, 0.2, 1] },
  },
};

const contentContainerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: { staggerChildren: 0.08, delayChildren: 0.1 },
  },
};

const itemVariants = {
  hidden:  { opacity: 0, y: 20, scale: 0.95 },
  visible: {
    opacity: 1, y: 0, scale: 1,
    transition: { duration: 0.5, ease: [0.22, 1, 0.36, 1] },
  },
};

// ══════════════════════════════════════════════════════════════════════════
//  DESKTOP SIDEBAR
// ══════════════════════════════════════════════════════════════════════════

function DesktopNavItem({ item }) {
  const location = useLocation();
  const isActive =
    location.pathname === item.path ||
    (item.path === '/' && location.pathname === '');
  return (
    <NavLink
      to={item.path}
      className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-300 group relative cursor-pointer ${
        isActive
          ? 'bg-primary shadow-lg shadow-primary/20 scale-[1.02] sidebar-nav-active'
          : 'text-text-dim hover:text-text hover:bg-primary-soft'
      }`}
    >
      {isActive && (
        <div className="absolute left-0 top-3 bottom-3 w-1 rounded-r-full sidebar-nav-active-bar" />
      )}
      <item.icon
        size={20}
        className={`transition-all duration-300 ${
          isActive ? 'sidebar-nav-active' : 'group-hover:text-primary group-hover:scale-110'
        }`}
      />
      <span className={`text-sm tracking-wide ${isActive ? 'font-bold' : 'font-medium'}`}>
        {item.label}
      </span>
    </NavLink>
  );
}

DesktopNavItem.propTypes = {
  item: PropTypes.shape({
    path: PropTypes.string.isRequired,
    label: PropTypes.string.isRequired,
    icon: PropTypes.elementType.isRequired,
  }).isRequired,
};

function DesktopSidebar({ version, onLock, theme, onToggleTheme }) {
  const isLight = theme === 'light';

  return (
    <aside className="w-68 h-screen flex flex-col flex-shrink-0 z-20 pt-14 relative bg-sidebar-bg shadow-[1px_0_0_0_var(--border)]">
      <div className="absolute top-0 left-0 w-full h-32 bg-primary/5 blur-[80px] -z-10 pointer-events-none" />

      {/* Logo */}
      <div className="h-20 flex items-center px-8 mb-6">
        <div className="flex items-center gap-4">
          <div className="relative">
            <div className="absolute inset-0 bg-primary/20 blur-lg rounded-full" />
            <img src={logo} alt="LexFlow" className="w-10 h-10 object-contain relative z-10" />
          </div>
          <div className="flex flex-col">
            <span className="text-2xl font-black tracking-tighter text-text leading-none">LexFlow</span>
            <span className="text-[9px] font-extrabold text-primary uppercase tracking-[3px] mt-1 sidebar-brand">Law Suite</span>
          </div>
        </div>
      </div>

      {/* Nav — scrollbar adattiva: visibile solo su hover se serve */}
      <nav className="flex-1 px-4 py-2 space-y-5 overflow-y-auto sidebar-scroll">
        {sections.map((section, sIdx) => (
          <div key={section.title || 'main'} className={`space-y-1 ${sIdx > 0 && section.title ? 'pt-2' : ''}`}>
            {section.title && (
              <div className="px-4 mb-2 mt-1 text-xs font-black text-text-dim/60 uppercase tracking-[3px]">
                {section.title}
              </div>
            )}
            {section.items.map(item => <DesktopNavItem key={item.path} item={item} />)}
          </div>
        ))}
      </nav>

      {/* Toggle Tema — fuori dal nav per evitare clipping */}
      <div className="flex justify-center px-4 py-3 flex-shrink-0">
        <button
          onClick={onToggleTheme}
          className="w-10 h-10 flex items-center justify-center rounded-full text-primary hover:text-primary hover:bg-primary/10 transition-all"
          title={isLight ? 'Tema scuro' : 'Tema chiaro'}
        >
          {isLight ? <Moon size={22} strokeWidth={2.5} /> : <Sun size={22} strokeWidth={2.5} />}
        </button>
      </div>

      {/* Footer */}
      <div className="p-6 bg-sidebar-bg">
        <button
          onClick={onLock}
          className="w-full flex items-center justify-center gap-3 px-4 py-3 rounded-2xl text-danger bg-danger-soft border border-danger-border hover:bg-danger-soft transition-all duration-300 group"
        >
          <Lock size={18} className="transition-transform group-hover:-rotate-12" />
          <span className="font-black text-[11px] uppercase tracking-widest">Blocca Vault</span>
        </button>
        <div className="flex items-center justify-between px-1 mt-4">
          <div className="flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
            <span className="text-[10px] font-bold uppercase tracking-tight text-text-dim/80">v{version}</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-border bg-bg-surface">
              <ShieldCheck size={11} className="text-primary" />
              <span className="text-[8px] font-black uppercase tracking-widest text-text-dim/70">AES-256 GCM</span>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
}

DesktopSidebar.propTypes = {
  version: PropTypes.string,
  onLock: PropTypes.func,
  theme: PropTypes.string,
  onToggleTheme: PropTypes.func,
};

// ══════════════════════════════════════════════════════════════════════════
//  MOBILE SIDEBAR — Liquid Curtain fullscreen
// ══════════════════════════════════════════════════════════════════════════
function MobileSidebar({ isOpen, onToggle, version, onLock, theme, onToggleTheme }) {
  const location = useLocation();
  const [isClosing, setIsClosing] = useState(false);
  const isLight = theme === 'light';

  // Refs per evitare stale closures negli effect
  const isClosingRef = useRef(false);
  const onToggleRef = useRef(onToggle);
  useEffect(() => { onToggleRef.current = onToggle; }, [onToggle]);

  // Chiusura con delay animazione
  const handleClose = useCallback(() => {
    if (isClosingRef.current) return;
    isClosingRef.current = true;
    setIsClosing(true);
    setTimeout(() => {
      onToggleRef.current(false);
      isClosingRef.current = false;
      setIsClosing(false);
    }, 300);
  }, []); // dipendenze stabili grazie ai ref

  // Auto-close su cambio di route
  useEffect(() => {
    if (isOpen) handleClose();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname]);

  // Scroll lock
  useEffect(() => {
    if (isOpen) {
      const scrollbarWidth = window.innerWidth - document.documentElement.clientWidth;
      document.body.style.setProperty('--scrollbar-width', `${scrollbarWidth}px`);
      document.body.dataset.scrollLocked = '';
      document.body.style.overflow = 'hidden';
    } else {
      delete document.body.dataset.scrollLocked;
      document.body.style.overflow = '';
      document.body.style.removeProperty('--scrollbar-width');
    }
    return () => {
      delete document.body.dataset.scrollLocked;
      document.body.style.overflow = '';
      document.body.style.removeProperty('--scrollbar-width');
    };
  }, [isOpen]);

  const handleLock = useCallback(() => {
    handleClose();
    setTimeout(onLock, 350);
  }, [handleClose, onLock]);
  return (
    <AnimatePresence mode="wait">
      {isOpen && !isClosing && (
        <>
          {/* ── CURTAIN — tenda dall'alto ── */}
          <motion.div
            key="lexflow-curtain"
            className="curtain-bg z-[100]"
            variants={curtainVariants}
            initial="hidden"
            animate="visible"
            exit="exit"
            aria-hidden="true"
          />

          {/* ── PULSANTE X — appare dopo 0.6s ── */}
          <motion.div
            key="lexflow-close"
            className="fixed top-4 right-4 z-[110]"
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.8 }}
            transition={{ delay: 0.6, duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
          >
            <motion.button
              onClick={handleClose}
              aria-label="Chiudi menu"
              whileHover={{ rotate: 90 }}
              transition={{ duration: 0.3 }}
              className="curtain-close-btn"
            >
              <X size={22} />
            </motion.button>
          </motion.div>

          {/* ── CONTENUTO — fade-in dopo la curtain ── */}
          <motion.div
            key="lexflow-content"
            className="fixed inset-0 z-[101] h-dvh w-full overflow-y-auto"
            style={{ WebkitOverflowScrolling: 'touch' }}
            variants={contentVariants}
            initial="hidden"
            animate="visible"
            exit="exit"
          >
            {/* Glow ambientale primario */}
            <div className="curtain-glow" />

            {/* Cascade container — stagger 0.08s */}
            <motion.div
              variants={contentContainerVariants}
              initial="hidden"
              animate="visible"
              className="curtain-container"
              role="navigation"
              aria-label="Menu principale"
            >
              {/* ── Header logo ── */}
              <motion.div
                variants={itemVariants}
                className="flex flex-col items-center mb-5"
              >
                <div className="relative mb-2.5">
                  <div className="absolute -inset-2 bg-primary/18 rounded-full blur-[14px]" />
                  <img src={logo} alt="LexFlow" className="w-12 h-12 object-contain relative z-[1]" />
                </div>
                <h2 className="curtain-brand-title">LexFlow</h2>
                <p className="curtain-brand-sub">Law Suite</p>
              </motion.div>

              {/* ── Linea separatrice ── */}
              <motion.div variants={itemVariants} className="curtain-divider" />

              {/* ── Nav items — cascade ── */}
              {navItemsMobile.map((item) => {
                const isActive =
                  location.pathname === item.path ||
                  (item.path === '/' && location.pathname === '');
                return (
                  <motion.div
                    key={item.path}
                    variants={itemVariants}
                    className="w-full max-w-80 py-0.5"
                  >
                    <NavLink
                      to={item.path}
                      onClick={handleClose}
                      data-active={isActive}
                      className="curtain-nav-link"
                    >
                      <item.icon
                        size={20}
                        className={`transition-transform duration-300 ${isActive ? 'scale-115' : 'scale-100'}`}
                      />
                      <span className="relative inline-block">
                        {item.label}
                        <span className="underline-bar" />
                      </span>
                    </NavLink>
                  </motion.div>
                );
              })}

              {/* ── Separatore ── */}
              <motion.div variants={itemVariants} className="curtain-divider-subtle" />

              {/* ── Blocca Vault ── */}
              <motion.div variants={itemVariants} className="w-full max-w-80">
                <button onClick={handleLock} className="curtain-lock-btn">
                  <Lock size={16} />
                  Blocca Vault
                </button>
              </motion.div>

              {/* ── Toggle Tema ── */}
              <motion.div variants={itemVariants} className="w-full max-w-80 mt-2">
                <button onClick={onToggleTheme} className="curtain-theme-btn">
                  {isLight ? <Moon size={16} /> : <Sun size={16} />}
                  {isLight ? 'Tema Scuro' : 'Tema Chiaro'}
                </button>
              </motion.div>

              {/* ── Footer versione + badge ── */}
              <motion.div
                variants={itemVariants}
                className="mt-4 text-center flex flex-col gap-1.5 items-center"
              >
                <div className="curtain-badge">
                  <ShieldCheck size={12} className="text-primary" />
                  <span className="curtain-badge-text">AES-256 GCM Secure</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="curtain-status-dot" />
                  <span className="curtain-version">v{version}</span>
                </div>
              </motion.div>
            </motion.div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}

MobileSidebar.propTypes = {
  isOpen: PropTypes.bool,
  onToggle: PropTypes.func,
  version: PropTypes.string,
  onLock: PropTypes.func,
  theme: PropTypes.string,
  onToggleTheme: PropTypes.func,
};

// ══════════════════════════════════════════════════════════════════════════
//  HAMBURGER BUTTON — visibile solo su mobile (gestito in App.jsx)
// ══════════════════════════════════════════════════════════════════════════
export function HamburgerButton({ onClick }) {
  return (
    <button onClick={onClick} aria-label="Apri menu" className="hamburger-btn">
      <Menu size={22} />
    </button>
  );
}

HamburgerButton.propTypes = {
  onClick: PropTypes.func,
};

// ══════════════════════════════════════════════════════════════════════════
//  EXPORT — switch automatico Desktop / Mobile
// ══════════════════════════════════════════════════════════════════════════
export default function Sidebar({ version, onLock, isOpen, onToggle, theme, onToggleTheme }) {
  const isMobile = useIsMobile(1024);

  if (isMobile) {
    return (
      <MobileSidebar
        isOpen={isOpen}
        onToggle={onToggle}
        version={version}
        onLock={onLock}
        theme={theme}
        onToggleTheme={onToggleTheme}
      />
    );
  }

  return <DesktopSidebar version={version} onLock={onLock} theme={theme} onToggleTheme={onToggleTheme} />;
}

Sidebar.propTypes = {
  version: PropTypes.string,
  onLock: PropTypes.func,
  isOpen: PropTypes.bool,
  onToggle: PropTypes.func,
  theme: PropTypes.string,
  onToggleTheme: PropTypes.func,
};