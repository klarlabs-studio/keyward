<script setup lang="ts">
// The middle pane: the filtered list of vault entries with coloured avatars,
// subtitle, category badge and favourite star. Selecting a row drives the detail.

import { useVaultStore, avatarColor, initials, subtitleOf } from '@/stores/vault';
import { categoryOf, type Entry } from '@/lib/passbook-types';

const vault = useVaultStore();

function badgeLabel(entry: Entry): string {
  const cat = categoryOf(entry);
  return cat === 'SecureNote' ? 'Note' : cat;
}
</script>

<template>
  <div class="list">
    <div class="list-head">
      <h2>{{ vault.listTitle }}</h2>
      <span v-if="vault.filter !== 'watchtower'">{{ vault.filtered.length }}</span>
    </div>
    <p v-if="vault.filtered.length === 0" class="empty">
      {{
        vault.counts.all === 0
          ? 'Your vault is empty — add your first item with “New item”.'
          : 'No items match.'
      }}
    </p>
    <button
      v-for="entry in vault.filtered"
      :key="entry.id"
      class="row"
      :class="{ active: entry.id === vault.selectedId }"
      @click="vault.select(entry.id)"
    >
      <div class="avatar" :style="{ background: avatarColor(entry.id) }">{{ initials(entry.title) }}</div>
      <div class="meta">
        <div class="t">{{ entry.title }}</div>
        <div class="s">{{ subtitleOf(entry) }}</div>
      </div>
      <span v-if="categoryOf(entry) !== 'Login'" class="cat-badge">{{ badgeLabel(entry) }}</span>
      <svg v-if="entry.favorite" class="fav" width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
        <path d="m12 3 2.9 6 6.6.6-5 4.3 1.5 6.4L12 17l-6 3.3 1.5-6.4-5-4.3 6.6-.6z" />
      </svg>
    </button>
  </div>
</template>
