<script setup lang="ts">
// The category rail: All / Favorites, the four content categories with live
// counts, and the Watchtower chip badged with the open-issue count.

import { useVaultStore, type Filter } from '@/stores/vault';
import { useShareStore } from '@/stores/share';
import type { GroupRef } from '@/lib/sharing';

const vault = useVaultStore();
const share = useShareStore();
defineProps<{ open?: boolean }>();
const emit = defineEmits<{ (e: 'navigate'): void }>();

// Set a personal filter, return the main view to the personal vault, and signal
// navigation so the mobile drawer can close.
function choose(f: Filter): void {
  vault.setFilter(f);
  share.showPersonal();
  emit('navigate');
}

// A personal filter is only "active" when the personal vault is the one shown.
function pActive(f: Filter): boolean {
  return !share.mainGroupId && vault.filter === f;
}

// Open a family vault in the main view.
function openFamily(g: GroupRef): void {
  share.showInMain(g);
  emit('navigate');
}
</script>

<template>
  <nav class="nav" :class="{ open }">
    <div class="grp">Vault</div>
    <button class="navitem" :class="{ active: pActive('all') }" @click="choose('all')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="3" y="4" width="18" height="16" rx="2" /><path d="M3 9h18" />
      </svg>
      All items <span class="count">{{ vault.counts.all }}</span>
    </button>
    <button class="navitem" :class="{ active: pActive('fav') }" @click="choose('fav')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="m12 3 2.9 6 6.6.6-5 4.3 1.5 6.4L12 17l-6 3.3 1.5-6.4-5-4.3 6.6-.6z" />
      </svg>
      Favorites <span class="count">{{ vault.counts.fav }}</span>
    </button>

    <div class="grp">Categories</div>
    <button class="navitem" :class="{ active: pActive('Login') }" @click="choose('Login' as Filter)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="4" y="10" width="16" height="10" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" />
      </svg>
      Logins <span class="count">{{ vault.counts.Login }}</span>
    </button>
    <button
      class="navitem"
      :class="{ active: pActive('SecureNote') }"
      @click="choose('SecureNote' as Filter)"
    >
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M5 3h9l5 5v13H5z" /><path d="M14 3v5h5M8 13h8M8 17h6" />
      </svg>
      Secure notes <span class="count">{{ vault.counts.SecureNote }}</span>
    </button>
    <button class="navitem" :class="{ active: pActive('Card') }" @click="choose('Card' as Filter)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="3" y="5" width="18" height="14" rx="2" /><path d="M3 10h18" />
      </svg>
      Cards <span class="count">{{ vault.counts.Card }}</span>
    </button>
    <button
      class="navitem"
      :class="{ active: pActive('Identity') }"
      @click="choose('Identity' as Filter)"
    >
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="8" r="4" /><path d="M4 21c0-4 4-6 8-6s8 2 8 6" />
      </svg>
      Identities <span class="count">{{ vault.counts.Identity }}</span>
    </button>

    <div class="grp">Security</div>
    <button
      class="wt-chip"
      :class="{ active: pActive('watchtower') }"
      @click="choose('watchtower')"
    >
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 3l7 3v6c0 5-3.5 8-7 9-3.5-1-7-4-7-9V6z" />
      </svg>
      Watchtower <span class="n">{{ vault.issues.length }}</span>
    </button>

    <template v-if="share.groups.length">
      <div class="grp">Family vaults</div>
      <button
        v-for="g in share.groups"
        :key="g.groupId"
        class="navitem"
        :class="{ active: share.mainGroupId === g.groupId }"
        @click="openFamily(g)"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="9" cy="8" r="3" />
          <path d="M3 20a6 6 0 0 1 12 0" />
          <path d="M16 5.5a3 3 0 0 1 0 5.5M17 20a6 6 0 0 0-3-5.2" />
        </svg>
        {{ g.name }}
      </button>
    </template>
  </nav>
</template>
