<script setup lang="ts">
// The search bar, on-device vault pill, theme toggle, lock button, and the
// "New item" action (which asks the shell to open the add dialog).

import { computed } from 'vue';
import { useVaultStore } from '@/stores/vault';

const vault = useVaultStore();
const emit = defineEmits<{
  (e: 'new-item'): void;
  (e: 'view-kit'): void;
  (e: 'import'): void;
  (e: 'export'): void;
  (e: 'sync'): void;
  (e: 'share'): void;
  (e: 'toggle-nav'): void;
}>();

const placeholder = computed(
  () => `Search ${vault.counts.all} item${vault.counts.all === 1 ? '' : 's'}…`,
);

function toggleTheme(): void {
  const root = document.documentElement;
  const current =
    root.dataset.theme ??
    (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  root.dataset.theme = current === 'dark' ? 'light' : 'dark';
}
</script>

<template>
  <div class="top">
    <button class="icon-btn nav-toggle" title="Menu" aria-label="Open menu" @click="emit('toggle-nav')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
        <path d="M4 6h16M4 12h16M4 18h16" />
      </svg>
    </button>
    <label class="search">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3" />
      </svg>
      <input
        type="search"
        :placeholder="placeholder"
        aria-label="Search vault"
        :value="vault.query"
        @input="vault.setQuery(($event.target as HTMLInputElement).value)"
      />
    </label>
    <div class="spacer"></div>
    <div class="vault-pill">
      <span class="dot"></span>Family vault · {{ vault.syncEnabled ? 'cloud' : 'on-device' }}
      <span v-if="vault.secretKeyProtected" class="pill-2skd" title="Protected by a device Secret Key (2SKD)">· 2SKD</span>
    </div>
    <button
      v-if="vault.secretKeyProtected"
      class="icon-btn"
      title="Emergency Kit"
      aria-label="Emergency Kit"
      @click="emit('view-kit')"
    >
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 3l7 3v6c0 5-3.5 8-7 9-3.5-1-7-4-7-9V6z" />
        <path d="M9 12l2 2 4-4" />
      </svg>
    </button>
    <button class="icon-btn" title="Toggle theme" aria-label="Toggle theme" @click="toggleTheme">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8Z" />
      </svg>
    </button>
    <button class="icon-btn" title="Import vault" aria-label="Import vault" @click="emit('import')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 15V3m0 12-4-4m4 4 4-4" />
        <path d="M4 21h16" />
      </svg>
    </button>
    <button class="icon-btn" title="Export vault" aria-label="Export vault" @click="emit('export')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 3v12m0-12 4 4m-4-4-4 4" />
        <path d="M4 21h16" />
      </svg>
    </button>
    <button
      class="icon-btn"
      :class="{ 'sync-on': vault.syncEnabled, 'sync-err': vault.syncStatus === 'error' }"
      :title="vault.syncEnabled ? 'Cloud sync settings' : 'Set up cloud sync'"
      aria-label="Sync settings"
      @click="emit('sync')"
    >
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M17.5 19a5 5 0 0 0 .5-9.9A6 6 0 0 0 6.5 8 4.5 4.5 0 0 0 7 17h10.5Z" />
      </svg>
    </button>
    <button class="icon-btn" title="Family sharing" aria-label="Family sharing" @click="emit('share')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="9" cy="8" r="3" />
        <path d="M3 20a6 6 0 0 1 12 0" />
        <path d="M16 5.5a3 3 0 0 1 0 5.5M17 20a6 6 0 0 0-3-5.2" />
      </svg>
    </button>
    <button class="icon-btn" title="Lock vault" aria-label="Lock vault" @click="vault.lock()">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="4" y="10" width="16" height="10" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" />
      </svg>
    </button>
    <button class="btn-add" @click="emit('new-item')">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round">
        <path d="M12 5v14M5 12h14" />
      </svg>
      <span class="label">New item</span>
    </button>
  </div>
</template>

<style scoped>
.pill-2skd {
  color: var(--accent-ink);
  font-weight: 700;
  letter-spacing: 0.02em;
}
.icon-btn.sync-on {
  color: var(--accent-ink);
}
.icon-btn.sync-err {
  color: var(--weak);
}
/* The hamburger only exists on the narrow layout, where the rail is a drawer. */
.nav-toggle {
  display: none;
  flex: none;
}
@media (max-width: 900px) {
  .nav-toggle {
    display: grid;
  }
}
</style>
