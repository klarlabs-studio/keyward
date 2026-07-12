<script setup lang="ts">
// The security dashboard: a circular score gauge plus issue cards derived from
// the real WASM Watchtower pass. Each card jumps to the affected entry.

import { computed } from 'vue';
import { useVaultStore } from '@/stores/vault';
import type { Issue } from '@/lib/passbook-types';

const vault = useVaultStore();

const RADIUS = 34;
const CIRC = 2 * Math.PI * RADIUS;

const scoreColor = computed(() =>
  vault.score >= 80 ? 'var(--strong)' : vault.score >= 55 ? 'var(--warn)' : 'var(--weak)',
);
const dashOffset = computed(() => CIRC * (1 - vault.score / 100));

const weakCount = computed(() => vault.issues.filter((i) => i.kind === 'weak').length);
const reusedCount = computed(() => vault.issues.filter((i) => i.kind === 'reused').length);

const passkeyCount = computed(
  () => vault.entries.filter((e) => 'Login' in e.content && e.content.Login.has_passkey).length,
);

function titleOf(id: string): string {
  return vault.entries.find((e) => e.id === id)?.title ?? id;
}
function reusedTitles(ids: string[]): string {
  return ids.map(titleOf).join(' · ');
}

function jumpTo(id: string): void {
  vault.setFilter('all');
  vault.select(id);
}

// Stable key for a card in the issue list.
function issueKey(issue: Issue, index: number): string {
  if (issue.kind === 'reused') return `reused-${issue.ids.join('-')}`;
  return `${issue.kind}-${issue.id}-${index}`;
}
</script>

<template>
  <div class="detail">
    <div class="wt">
      <div class="wt-top">
        <svg class="gauge" viewBox="0 0 76 76">
          <circle class="bg" cx="38" cy="38" r="34" />
          <circle
            class="fg"
            cx="38"
            cy="38"
            r="34"
            :style="{ stroke: scoreColor, strokeDasharray: CIRC, strokeDashoffset: dashOffset }"
          />
        </svg>
        <div class="wt-score">
          <b :style="{ color: scoreColor }">{{ vault.score }}</b>
          <span>Vault security score</span>
        </div>
        <div style="margin-left: auto; text-align: right; color: var(--muted); font-size: 0.82rem">
          <div><b style="color: var(--weak)">{{ weakCount }}</b> weak</div>
          <div><b style="color: var(--warn)">{{ reusedCount }}</b> reused</div>
        </div>
      </div>

      <template v-if="vault.issues.length">
        <h3>Action needed</h3>
        <div v-for="(issue, index) in vault.issues" :key="issueKey(issue, index)" class="issue">
          <template v-if="issue.kind === 'weak'">
            <span class="pill weak">Weak</span>
            <div class="txt">
              <b>{{ titleOf(issue.id) }}</b>
              <div>Password is only {{ issue.bits }} bits — easily guessed.</div>
            </div>
            <button @click="jumpTo(issue.id)">Fix →</button>
          </template>
          <template v-else-if="issue.kind === 'reused'">
            <span class="pill reused">Reused</span>
            <div class="txt">
              <b>{{ reusedTitles(issue.ids) }}</b>
              <div>The same password is used across {{ issue.ids.length }} logins.</div>
            </div>
            <button @click="jumpTo(issue.ids[0])">Review →</button>
          </template>
          <template v-else>
            <span class="pill missing">2FA</span>
            <div class="txt">
              <b>{{ titleOf(issue.id) }}</b>
              <div>No two-factor authentication — add a one-time code.</div>
            </div>
            <button @click="jumpTo(issue.id)">Review →</button>
          </template>
        </div>
      </template>

      <template v-if="passkeyCount > 0">
        <h3>Looking good</h3>
        <div class="issue">
          <span class="pill" style="background: var(--strong-soft); color: var(--strong)">Passkeys</span>
          <div class="txt">
            <b>{{ passkeyCount }} {{ passkeyCount === 1 ? 'login uses' : 'logins use' }} passkeys</b>
            <div>Phishing-resistant sign-in enabled where supported.</div>
          </div>
        </div>
      </template>
    </div>
  </div>
</template>
