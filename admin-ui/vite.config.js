import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Served by the SSO at /admin (gated shell + public /admin/assets). The form
// imports the SHARED normalization module from ../src so client and server rules
// literally cannot drift.
export default defineConfig({
  plugins: [react()],
  base: '/admin/',
  build: {
    outDir: 'dist',
    // No inline module-preload polyfill -> strict `script-src 'self'` CSP holds.
    modulePreload: { polyfill: false },
  },
});
