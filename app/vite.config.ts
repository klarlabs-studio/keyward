import { fileURLToPath, URL } from 'node:url';
import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

// The generated `passbook_wasm.js` loader fetches its sibling `.wasm` via a
// `new URL(..., import.meta.url)` — Vite handles that as an asset out of the box.
// `base: './'` keeps the built app portable (works from any static path,
// including inside a desktop shell later).
export default defineConfig({
  base: './',
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
});
