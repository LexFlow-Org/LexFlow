import React from 'react';
import PropTypes from 'prop-types';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("Uncaught error:", error, errorInfo);
  }

  handleReload = () => {
    globalThis.location.reload();
  };

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="h-screen w-screen bg-background flex flex-col items-center justify-center text-white p-8 text-center">
          <div className="w-16 h-16 bg-danger-soft rounded-full flex items-center justify-center mb-6">
            <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-danger"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          </div>
          <h1 className="text-2xl font-bold mb-2">Qualcosa è andato storto</h1>
          <p className="text-text-muted mb-6 max-w-md">
            Si è verificato un errore imprevisto nell'interfaccia. Nessun dato è stato perso, ma è necessario ricaricare la vista.
          </p>
          <div className="bg-card p-4 rounded border border-border mb-6 text-left w-full max-w-lg overflow-auto max-h-40">
            <code className="text-xs text-danger font-mono">
              {this.state.error?.toString()}
            </code>
          </div>
          <button 
            onClick={this.handleReload}
            className="px-6 py-2 bg-primary hover:bg-primary-hover text-black rounded-lg transition-colors font-medium"
          >
            Ricarica applicazione
          </button>
          <button 
            onClick={this.handleReset}
            className="px-6 py-2 bg-surface hover:bg-card-hover text-text-muted rounded-lg transition-colors font-medium mt-3"
          >
            Torna alla vista precedente
          </button>
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