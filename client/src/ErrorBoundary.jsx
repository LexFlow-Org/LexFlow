import React from 'react';
import PropTypes from 'prop-types';

const SECRET_PATTERNS = [
  'password', 'passwd', 'key', 'token', 'dek', 'kek',
  'recovery', 'secret', 'hmac', 'private', 'credential',
];

const sanitizeError = (err) => {
  if (!err) return '';
  const msg = String(err?.message || err);
  const lower = msg.toLowerCase();
  if (SECRET_PATTERNS.some((p) => lower.includes(p))) {
    return '[REDACTED — internal error]';
  }
  return msg.slice(0, 200);
};

// Limit reset attempts to break infinite loop if the same error keeps re-throwing
const MAX_RESET_ATTEMPTS = 3;

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, resetAttempts: 0 };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    // Console output is sanitized too — never echo raw secrets to devtools
    console.error('Uncaught error:', sanitizeError(error), errorInfo?.componentStack || '');
    // TODO: forward sanitized error to a Tauri-side persistent log channel
    //       (cross-cutting — implement once a logger command is wired in src-tauri)
  }

  handleReload = () => {
    globalThis.location.reload();
  };

  handleReset = () => {
    this.setState((prev) => {
      if (prev.resetAttempts >= MAX_RESET_ATTEMPTS) {
        // Stop trying — force a hard reload instead
        globalThis.location.reload();
        return prev;
      }
      return {
        hasError: false,
        error: null,
        resetAttempts: prev.resetAttempts + 1,
      };
    });
  };

  render() {
    if (this.state.hasError) {
      const isProd = import.meta.env?.PROD;
      const errorMessage = isProd
        ? 'Errore interno (vedi log)'
        : sanitizeError(this.state.error);
      const exhaustedAttempts = this.state.resetAttempts >= MAX_RESET_ATTEMPTS;

      return (
        <div className="h-screen w-screen bg-background flex flex-col items-center justify-center text-white p-8 text-center">
          <div className="w-16 h-16 bg-danger-soft rounded-full flex items-center justify-center mb-6">
            <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-danger" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          </div>
          <h1 className="text-2xl font-bold mb-2">Qualcosa è andato storto</h1>
          <p className="text-text-muted mb-6 max-w-md">
            Si è verificato un errore imprevisto nell&apos;interfaccia. Nessun dato è stato perso, ma è necessario ricaricare la vista.
          </p>
          <div className="bg-card p-4 rounded border border-border mb-6 text-left w-full max-w-lg overflow-auto max-h-40">
            <code className="text-xs text-danger font-mono">
              {errorMessage}
            </code>
          </div>
          <button
            onClick={this.handleReload}
            className="px-6 py-2 bg-primary hover:bg-primary-hover text-black rounded-lg transition-colors font-medium"
          >
            Ricarica applicazione
          </button>
          {!exhaustedAttempts && (
            <button
              onClick={this.handleReset}
              className="px-6 py-2 bg-surface hover:bg-card-hover text-text-muted rounded-lg transition-colors font-medium mt-3"
            >
              Torna alla vista precedente
            </button>
          )}
        </div>
      );
    }

    return this.props.children;
  }
}

ErrorBoundary.propTypes = {
  children: PropTypes.node,
};

export default ErrorBoundary;
