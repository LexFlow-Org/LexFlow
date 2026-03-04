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
  Shield, Clock, Users
} from 'lucide-react';
import logo from '../assets/logo.png';

// ── Hook breakpoint mobile ──────────────────────────────────────────────────
export function useIsMobile(breakpoint = 1024) {
  const [isMobile, setIsMobile] = useState(
    globalThis.window === undefined ? false : globalThis.window.innerWidth < breakpoint
  );
  useEffect(() => {
    const handler = () => setIsMobile(window.innerWidth < breakpoint);
    window.addEventListener('resize', handler);
    return () => window.removeEventListener('resize', handler);
  }, [breakpoint]);
  return isMobile;
}

// ── Nav items per il Liquid Curtain (mobile) ───────────────────────────────
const navItemsMobile = [
  { path: '/',           label: 'Dashboard',    icon: LayoutDashboard },
  { path: '/agenda',     label: 'Agenda',       icon: CalendarDays },
  { path: '/scadenze',   label: 'Scadenze',     icon: CalendarClock },
  { path: '/pratiche',   label: 'Fascicoli',    icon: Briefcase },
  { path: '/conflitti',  label: 'Conflitti',    icon: Shield },
  { path: '/ore',        label: 'Gestione Ore', icon: Clock },
  { path: '/contatti',   label: 'Contatti',     icon: Users },
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
      { path: '/conflitti', label: 'Conflitti',   icon: Shield },
      { path: '/contatti',  label: 'Contatti',    icon: Users },
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
      className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-300 group relative ${
        isActive
          ? 'bg-primary text-white shadow-lg shadow-primary/20 scale-[1.02]'
          : 'text-text-dim hover:text-white hover:bg-white/5'
      }`}
    >
      {isActive && (
        <div className="absolute left-0 top-3 bottom-3 w-1 bg-white rounded-r-full shadow-[0_0_8px_white]" />
      )}
      <item.icon
        size={20}
        className={`transition-all duration-300 ${
          isActive ? 'text-white' : 'group-hover:text-primary group-hover:scale-110'
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

function DesktopSidebar({ version, onLock }) {

  return (
    <aside className="w-68 h-screen bg-[#08090f] border-r border-white/5 flex flex-col flex-shrink-0 z-20 pt-14 relative">
      <div className="absolute top-0 left-0 w-full h-32 bg-primary/5 blur-[80px] -z-10 pointer-events-none" />

      {/* Logo */}
      <div className="h-20 flex items-center px-8 mb-6">
        <div className="flex items-center gap-4">
          <div className="relative">
            <div className="absolute inset-0 bg-primary/20 blur-lg rounded-full" />
            <img src={logo} alt="LexFlow" className="w-10 h-10 object-contain relative z-10" />
          </div>
          <div className="flex flex-col">
            <span className="text-2xl font-black tracking-tighter text-white leading-none">LexFlow</span>
            <span className="text-[9px] font-bold text-primary uppercase tracking-[3px] mt-1">Law Suite</span>
          </div>
        </div>
      </div>

      {/* Nav — scrollbar adattiva: visibile solo su hover se serve */}
      <nav className="flex-1 px-4 py-2 space-y-5 overflow-y-auto sidebar-scroll">
        {sections.map((section) => (
          <div key={section.title || 'main'} className="space-y-1">
            {section.title && (
              <div className="px-4 mb-2 text-[10px] font-black text-text-dim/40 uppercase tracking-[3px]">
                {section.title}
              </div>
            )}
            {section.items.map(item => <DesktopNavItem key={item.path} item={item} />)}
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="p-6 border-t border-white/5 bg-[#0a0b12]">
        <button
          onClick={onLock}
          className="w-full flex items-center justify-center gap-3 px-4 py-3 rounded-2xl text-red-500 bg-red-500/10 border border-red-500/20 hover:bg-red-500/20 transition-all duration-300 group mb-6"
        >
          <Lock size={18} className="transition-transform group-hover:-rotate-12" />
          <span className="font-black text-[11px] uppercase tracking-widest">Blocca Vault</span>
        </button>
        <div className="flex flex-col gap-3 px-2">
          <div className="flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-[10px] font-bold text-text-dim/60 uppercase tracking-tighter">Versione {version}</span>
          </div>
          <div className="flex items-center gap-2 px-3 py-1.5 bg-white/5 rounded-lg border border-white/5">
            <ShieldCheck size={12} className="text-primary" />
            <span className="text-[9px] font-black text-text-dim uppercase tracking-widest">AES-256 GCM Secure</span>
          </div>
        </div>
      </div>
    </aside>
  );
}

DesktopSidebar.propTypes = {
  version: PropTypes.string,
  onLock: PropTypes.func,
};

// ══════════════════════════════════════════════════════════════════════════
//  MOBILE SIDEBAR — Liquid Curtain fullscreen
// ══════════════════════════════════════════════════════════════════════════
function MobileSidebar({ isOpen, onToggle, version, onLock }) {
  const location = useLocation();
  const [isClosing, setIsClosing] = useState(false);

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
            style={{
              position: 'fixed', inset: 0, zIndex: 100,
              background: '#08090f',
              transformOrigin: 'top center',
              boxShadow: '0 8px 32px -8px rgba(0,0,0,0.6)',
            }}
            variants={curtainVariants}
            initial="hidden"
            animate="visible"
            exit="exit"
            aria-hidden="true"
          />

          {/* ── PULSANTE X — appare dopo 0.6s ── */}
          <motion.div
            key="lexflow-close"
            style={{ position: 'fixed', top: 16, right: 16, zIndex: 110 }}
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
              style={{
                background: 'rgba(255,255,255,0.06)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 12, width: 44, height: 44,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: '#e2e4ef', cursor: 'pointer',
              }}
            >
              <X size={22} />
            </motion.button>
          </motion.div>

          {/* ── CONTENUTO — fade-in dopo la curtain ── */}
          <motion.div
            key="lexflow-content"
            style={{
              position: 'fixed', inset: 0, zIndex: 101,
              height: '100dvh', width: '100%',
              overflowY: 'auto', WebkitOverflowScrolling: 'touch',
            }}
            variants={contentVariants}
            initial="hidden"
            animate="visible"
            exit="exit"
          >
            {/* Glow ambientale primario */}
            <div style={{
              position: 'absolute', inset: 0, pointerEvents: 'none',
              background: 'radial-gradient(ellipse at top center, rgba(212,169,64,0.07) 0%, transparent 60%)',
            }} />

            {/* Cascade container — stagger 0.08s */}
            <motion.div
              variants={contentContainerVariants}
              initial="hidden"
              animate="visible"
              style={{
                minHeight: '100%',
                display: 'flex', flexDirection: 'column',
                alignItems: 'center', justifyContent: 'center',
                padding: '40px 24px 40px',
              }}
              role="navigation"
              aria-label="Menu principale"
            >
              {/* ── Header logo ── */}
              <motion.div
                variants={itemVariants}
                style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: 20 }}
              >
                <div style={{ position: 'relative', marginBottom: 10 }}>
                  <div style={{
                    position: 'absolute', inset: -8,
                    background: 'rgba(212,169,64,0.18)', borderRadius: '50%',
                    filter: 'blur(14px)',
                  }} />
                  <img
                    src={logo} alt="LexFlow"
                    style={{ width: 48, height: 48, objectFit: 'contain', position: 'relative', zIndex: 1 }}
                  />
                </div>
                <h2 style={{
                  fontSize: 24, fontWeight: 900, color: '#fff',
                  letterSpacing: '-0.04em', lineHeight: 1, margin: 0,
                }}>
                  LexFlow
                </h2>
                <p style={{
                  fontSize: 9, fontWeight: 700, color: '#d4a940',
                  textTransform: 'uppercase', letterSpacing: '3px', margin: '4px 0 0',
                }}>
                  Law Suite
                </p>
              </motion.div>

              {/* ── Linea separatrice ── */}
              <motion.div
                variants={itemVariants}
                style={{
                  width: '100%', maxWidth: 280, height: 1,
                  background: 'linear-gradient(90deg, transparent, rgba(212,169,64,0.3), transparent)',
                  marginBottom: 16,
                }}
              />

              {/* ── Nav items — cascade ── */}
              {navItemsMobile.map((item) => {
                const isActive =
                  location.pathname === item.path ||
                  (item.path === '/' && location.pathname === '');
                return (
                  <motion.div
                    key={item.path}
                    variants={itemVariants}
                    style={{ width: '100%', maxWidth: 320, padding: '2px 0' }}
                  >
                    <NavLink
                      to={item.path}
                      onClick={handleClose}
                      style={{
                        display: 'flex', flexDirection: 'column',
                        alignItems: 'center', gap: 4,
                        width: '100%', padding: '10px 0',
                        textDecoration: 'none', position: 'relative',
                        color: isActive ? '#d4a940' : '#e2e4ef',
                        fontWeight: isActive ? 700 : 500,
                        transition: 'color 0.3s',
                      }}
                    >
                      <item.icon
                        size={20}
                        style={{
                          transition: 'transform 0.3s ease',
                          transform: isActive ? 'scale(1.15)' : 'scale(1)',
                        }}
                      />
                      <span style={{
                        fontSize: 15, letterSpacing: '0.02em',
                        position: 'relative', display: 'inline-block',
                      }}>
                        {item.label}
                        {/* Underline animato */}
                        <span style={{
                          position: 'absolute', bottom: -4, left: 0,
                          width: '100%', height: 2,
                          background: '#d4a940', borderRadius: 1,
                          display: 'block',
                          transform: isActive ? 'scaleX(1)' : 'scaleX(0)',
                          transformOrigin: 'center',
                          transition: 'transform 0.3s ease',
                        }} />
                      </span>
                    </NavLink>
                  </motion.div>
                );
              })}

              {/* ── Separatore ── */}
              <motion.div
                variants={itemVariants}
                style={{
                  width: '100%', maxWidth: 280, height: 1,
                  background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.06), transparent)',
                  margin: '12px 0',
                }}
              />

              {/* ── Blocca Vault ── */}
              <motion.div variants={itemVariants} style={{ width: '100%', maxWidth: 320 }}>
                <button
                  onClick={handleLock}
                  style={{
                    width: '100%', display: 'flex',
                    alignItems: 'center', justifyContent: 'center',
                    gap: 10, padding: '12px 24px', borderRadius: 14,
                    background: 'rgba(248,113,113,0.1)',
                    border: '1px solid rgba(248,113,113,0.2)',
                    color: '#f87171', cursor: 'pointer',
                    fontWeight: 700, fontSize: 12,
                    textTransform: 'uppercase', letterSpacing: '0.1em',
                    transition: 'background 0.2s',
                  }}
                >
                  <Lock size={16} />
                  Blocca Vault
                </button>
              </motion.div>

              {/* ── Footer versione + badge ── */}
              <motion.div
                variants={itemVariants}
                style={{
                  marginTop: 16, textAlign: 'center',
                  display: 'flex', flexDirection: 'column',
                  gap: 6, alignItems: 'center',
                }}
              >
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '6px 14px',
                  background: 'rgba(255,255,255,0.04)',
                  borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)',
                }}>
                  <ShieldCheck size={12} color="#d4a940" />
                  <span style={{
                    fontSize: 9, fontWeight: 900, color: '#7c8099',
                    textTransform: 'uppercase', letterSpacing: '0.15em',
                  }}>
                    AES-256 GCM Secure
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div style={{
                    width: 6, height: 6, borderRadius: '50%',
                    background: '#10b981', boxShadow: '0 0 6px #10b981',
                  }} />
                  <span style={{ fontSize: 11, color: 'rgba(124,128,153,0.6)', fontWeight: 600 }}>
                    v{version}
                  </span>
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
};

// ══════════════════════════════════════════════════════════════════════════
//  HAMBURGER BUTTON — visibile solo su mobile (gestito in App.jsx)
// ══════════════════════════════════════════════════════════════════════════
export function HamburgerButton({ onClick }) {
  return (
    <button
      onClick={onClick}
      aria-label="Apri menu"
      style={{
        position: 'fixed', top: 12, right: 16, zIndex: 90,
        background: 'rgba(19,20,30,0.9)',
        backdropFilter: 'blur(8px)',
        WebkitBackdropFilter: 'blur(8px)',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: 12, width: 44, height: 44,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        color: '#e2e4ef', cursor: 'pointer',
        transition: 'background 0.2s',
        touchAction: 'manipulation',
      }}
    >
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
export default function Sidebar({ version, onLock, isOpen, onToggle }) {
  const isMobile = useIsMobile(1024);

  if (isMobile) {
    return (
      <MobileSidebar
        isOpen={isOpen}
        onToggle={onToggle}
        version={version}
        onLock={onLock}
      />
    );
  }

  return <DesktopSidebar version={version} onLock={onLock} />;
}

Sidebar.propTypes = {
  version: PropTypes.string,
  onLock: PropTypes.func,
  isOpen: PropTypes.bool,
  onToggle: PropTypes.func,
};