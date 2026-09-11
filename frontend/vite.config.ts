import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    // Keep the original Host header: the control service compares the request
    // Origin against Host and rejects a mismatch with 403, and rewrites would
    // make the browser's Origin (5173) disagree with the forwarded Host (7331).
    proxy: {
      '/api': { target: 'http://127.0.0.1:7331' },
      '/rpc': { target: 'http://127.0.0.1:7331' },
    },
  },
  build: { target: 'es2022' },
});
