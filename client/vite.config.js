import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [
    react(), 
    tailwindcss() // <--- QUESTO era il pezzo mancante per il CSS!
  ],
  
  // Base path per il build. Usa '/' per Tauri v2 (evita problemi di caricamento delle risorse)
  base: '/',

  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
    dedupe: ['react', 'react-dom'],
  },

  build: {
    outDir: 'dist',
    emptyOutDir: true,
    minify: 'terser',
    terserOptions: {
      // SECURITY (Audit 2026-03-14): drop_console removes ALL console.* calls in production.
      // This prevents leaking sensitive data (vault contents, keys, user info) to the
      // WebView dev console. Backend diagnostics use the Rust panic logger + crash.log.
      compress: { drop_console: true, drop_debugger: true },
      mangle: { toplevel: true },
    },
    // Cache busting: content-hash in ALL output filenames.
    // Guarantees that after an app update the WebView loads fresh assets
    // even if its HTTP cache wasn't cleared by the native side.
    rollupOptions: {
      output: {
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
        manualChunks: {
          'vendor-react': ['react', 'react-dom', 'react-router-dom'],
          'vendor-ui': ['lucide-react', 'react-hot-toast'],
          'vendor-motion': ['framer-motion'],
          'vendor-tauri': ['@tauri-apps/api', '@tauri-apps/plugin-notification'],
          // PERF: jspdf + jspdf-autotable (~403KB) removed from manual chunks.
          // They are now lazy-loaded via dynamic import() on first PDF export,
          // so they never appear in the initial bundle.
        },
      },
    },
  },

  server: {
    port: 5173,
    strictPort: true,
  },
});