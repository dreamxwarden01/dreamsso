import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    // No inline module-preload polyfill -> the strict `script-src 'self'` CSP the
    // BFF sends needs no 'unsafe-inline'/hash for scripts.
    modulePreload: { polyfill: false },
  },
  server: {
    port: 5173,
    // Optional HMR mode: run Vite and proxy the BFF's auth/api to :4000. The
    // canonical local URL is still account-dev (BFF serving the built dist).
    proxy: {
      '/api': 'http://localhost:4001',
      '/auth': 'http://localhost:4001',
    },
  },
});
