<script setup lang="ts">
// The category rail: All / Favorites, the four content categories with live
// counts, and the Watchtower chip badged with the open-issue count.

import { useVaultStore, type Filter } from '@/stores/vault';

const vault = useVaultStore();
</script>

<template>
  <nav class="nav">
    <div class="grp">Vault</div>
    <button class="navitem" :class="{ active: vault.filter === 'all' }" @click="vault.setFilter('all')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="3" y="4" width="18" height="16" rx="2" /><path d="M3 9h18" />
      </svg>
      All items <span class="count">{{ vault.counts.all }}</span>
    </button>
    <button class="navitem" :class="{ active: vault.filter === 'fav' }" @click="vault.setFilter('fav')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="m12 3 2.9 6 6.6.6-5 4.3 1.5 6.4L12 17l-6 3.3 1.5-6.4-5-4.3 6.6-.6z" />
      </svg>
      Favorites <span class="count">{{ vault.counts.fav }}</span>
    </button>

    <div class="grp">Categories</div>
    <button class="navitem" :class="{ active: vault.filter === 'Login' }" @click="vault.setFilter('Login' as Filter)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="4" y="10" width="16" height="10" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" />
      </svg>
      Logins <span class="count">{{ vault.counts.Login }}</span>
    </button>
    <button
      class="navitem"
      :class="{ active: vault.filter === 'SecureNote' }"
      @click="vault.setFilter('SecureNote' as Filter)"
    >
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M5 3h9l5 5v13H5z" /><path d="M14 3v5h5M8 13h8M8 17h6" />
      </svg>
      Secure notes <span class="count">{{ vault.counts.SecureNote }}</span>
    </button>
    <button class="navitem" :class="{ active: vault.filter === 'Card' }" @click="vault.setFilter('Card' as Filter)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="3" y="5" width="18" height="14" rx="2" /><path d="M3 10h18" />
      </svg>
      Cards <span class="count">{{ vault.counts.Card }}</span>
    </button>
    <button
      class="navitem"
      :class="{ active: vault.filter === 'Identity' }"
      @click="vault.setFilter('Identity' as Filter)"
    >
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="8" r="4" /><path d="M4 21c0-4 4-6 8-6s8 2 8 6" />
      </svg>
      Identities <span class="count">{{ vault.counts.Identity }}</span>
    </button>

    <div class="grp">Security</div>
    <button
      class="wt-chip"
      :class="{ active: vault.filter === 'watchtower' }"
      @click="vault.setFilter('watchtower')"
    >
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 3l7 3v6c0 5-3.5 8-7 9-3.5-1-7-4-7-9V6z" />
      </svg>
      Watchtower <span class="n">{{ vault.issues.length }}</span>
    </button>
  </nav>
</template>
