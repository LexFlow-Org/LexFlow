import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { HashRouter } from 'react-router-dom'
import './index.css'
import App from './App.jsx'
import ErrorBoundary from './ErrorBoundary'

const root = document.getElementById('root');

createRoot(root).render(
  <StrictMode>
    <ErrorBoundary>
      <HashRouter>
        <App />
      </HashRouter>
    </ErrorBoundary>
  </StrictMode>,
)

// Rivela l'app dopo il primo paint — elimina il flash nero→bianco
// Due rAF annidati = aspetta che React abbia effettivamente renderizzato nel DOM
requestAnimationFrame(() => {
  requestAnimationFrame(() => {
    root.classList.add('app-mounted');
  });
})