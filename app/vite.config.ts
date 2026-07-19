import { fileURLToPath, URL } from 'node:url';
import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

// The generated `passbook_wasm.js` loader fetches its sibling `.wasm` via a
// `new URL(..., import.meta.url)` — Vite handles that as an asset out of the box.
// `base: './'` keeps the built app portable (works from any static path,
// including inside a desktop shell later).
export default defineConfig({
  base: './',
  // SECURITY, not preference. localStorage is per-ORIGIN, and the vault holds
  // the device Secret Key and member X25519 secret as plaintext strings (see
  // docs/security/known-limitations.md §10). On Vite's default port this origin
  // is shared with every other project started with `npm run dev` — a real
  // `localhost:5173` was found holding another app's auth token and JWT
  // alongside a Keyward vault, which means any script in that unrelated app
  // could read `keyward.passbook.secretkey.v1`. A dedicated port gives the
  // vault an origin of its own. `strictPort` so a collision fails loudly
  // instead of silently landing back on a shared one.
  server: { port: 5183, strictPort: true },
  preview: { port: 5183, strictPort: true },
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
});
