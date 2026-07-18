<script setup lang="ts">
// The detail pane for a selected shared item, reusing the personal detail card
// styling. Logins get reveal + copy; a Remove button (shared with the family).

import { computed, ref, watch } from 'vue';
import { useShareStore } from '@/stores/share';
import { avatarColor, initials, subtitleOf } from '@/stores/vault';
import { copyText } from '@/composables/useToast';

const s = useShareStore();
const revealPw = ref(false);

const entry = computed(() => s.selectedShared);
const login = computed(() =>
  entry.value && 'Login' in entry.value.content ? entry.value.content.Login : null,
);

watch(
  () => s.selectedSharedId,
  () => {
    revealPw.value = false;
  },
);

function webHref(url: string): string {
  return /^https?:\/\//i.test(url) ? url : `https://${url}`;
}
</script>

<template>
  <div class="detail">
    <p v-if="!entry" class="detail-empty">Select a shared item to view its details.</p>

    <div v-else class="card">
      <div class="card-hd">
        <div class="avatar" :style="{ background: avatarColor(entry.id) }">
          {{ initials(entry.title) }}
        </div>
        <div class="hd-meta">
          <h2>{{ entry.title }}</h2>
          <div class="sub">{{ subtitleOf(entry) }}</div>
        </div>
        <div class="hd-actions">
          <button class="mini danger" title="Remove from family vault" @click="s.removeEntry(entry.id)">
            Remove
          </button>
        </div>
      </div>

      <template v-if="login">
        <div v-if="login.username" class="field">
          <div class="lbl">Username</div>
          <div class="val">{{ login.username }}</div>
          <div class="act">
            <button class="mini" title="Copy" @click="copyText(login.username)">Copy</button>
          </div>
        </div>

        <div class="field">
          <div class="lbl">Password</div>
          <div class="val mono">{{ revealPw ? login.password : '••••••••••••' }}</div>
          <div class="act">
            <button class="mini" @click="revealPw = !revealPw">{{ revealPw ? 'Hide' : 'Show' }}</button>
            <button class="mini" title="Copy" @click="copyText(login.password)">Copy</button>
          </div>
        </div>

        <div v-if="login.urls.length" class="field">
          <div class="lbl">Website</div>
          <div class="val">
            <a class="link" :href="webHref(login.urls[0])" target="_blank" rel="noopener noreferrer">{{
              login.urls[0]
            }}</a>
          </div>
        </div>
      </template>

      <div v-else-if="'SecureNote' in entry.content" class="field">
        <div class="lbl">Note</div>
        <div class="val note-body">{{ entry.content.SecureNote }}</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.hd-meta {
  display: flex;
  flex-direction: column;
}
.mono {
  font-family: var(--mono);
}
.note-body {
  white-space: pre-wrap;
  line-height: 1.6;
}
</style>
