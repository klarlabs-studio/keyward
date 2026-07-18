<script setup lang="ts">
// The middle pane when a family vault is active: its shared items, reusing the
// personal list's row styling. Selecting a row drives FamilyDetail. Header lets
// you jump back to the personal vault or open the sharing manager.

import { useShareStore } from '@/stores/share';
import { avatarColor, initials, subtitleOf } from '@/stores/vault';

const s = useShareStore();
const emit = defineEmits<{ (e: 'manage'): void }>();
</script>

<template>
  <div class="list">
    <div class="list-head">
      <h2>{{ s.mainVault?.name ?? 'Family vault' }}</h2>
      <span v-if="s.mainVault?.hasAccess">{{ s.mainVault.entries.length }}</span>
    </div>

    <div class="fam-bar">
      <button class="linkish" @click="s.showPersonal()">‹ Personal vault</button>
      <button class="linkish" @click="emit('manage')">Manage &amp; invite</button>
    </div>

    <p v-if="!s.mainVault" class="empty">Opening the family vault…</p>

    <p v-else-if="s.mainVault.removed" class="empty">
      You've been removed from this family vault.
    </p>

    <p v-else-if="!s.mainVault.hasAccess" class="empty">
      Waiting for a member to grant this device access. Ask them to open the family
      vault, then <a href="#" @click.prevent="s.reloadActive()">reload</a>.
    </p>

    <template v-else>
      <p v-if="s.mainVault.entries.length === 0" class="empty">
        No shared items yet — add one from “Manage &amp; invite”.
      </p>
      <button
        v-for="entry in s.mainVault.entries"
        :key="entry.id"
        class="row"
        :class="{ active: entry.id === s.selectedSharedId }"
        @click="s.selectShared(entry.id)"
      >
        <div class="avatar" :style="{ background: avatarColor(entry.id) }">
          {{ initials(entry.title) }}
        </div>
        <div class="meta">
          <div class="t">{{ entry.title }}</div>
          <div class="s">{{ subtitleOf(entry) }}</div>
        </div>
      </button>
    </template>
  </div>
</template>

<style scoped>
.fam-bar {
  display: flex;
  justify-content: space-between;
  gap: 0.5rem;
  padding: 0 1rem 0.5rem;
}
.linkish {
  font-size: 0.78rem;
  font-weight: 600;
  color: var(--accent-ink);
}
.linkish:hover {
  text-decoration: underline;
}
.empty a {
  color: var(--accent-ink);
  font-weight: 600;
  text-decoration: underline;
}
</style>
