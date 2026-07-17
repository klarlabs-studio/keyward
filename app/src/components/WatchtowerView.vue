<script setup lang="ts">
// The security dashboard: a circular score gauge plus issue cards derived from
// the real WASM Watchtower pass. Each card jumps to the affected entry.

import { computed, ref } from 'vue';
import { useVaultStore } from '@/stores/vault';
import { breachCount } from '@/lib/passbook';
import type { Issue } from '@/lib/passbook-types';

const vault = useVaultStore();

// On-demand breach scan across every login (HIBP k-anonymity, sequential).
const scanning = ref(false);
const scanned = ref(false);
const scanError = ref(false);
const progress = ref({ done: 0, total: 0 });
const compromised = ref<{ id: string; title: string; count: number }[]>([]);

async function scanBreaches(): Promise<void> {
  const logins = vault.entries.filter(
    (e) => 'Login' in e.content && e.content.Login.password.length > 0,
  );
  scanning.value = true;
  scanError.value = false;
  compromised.value = [];
  progress.value = { done: 0, total: logins.length };
  try {
    for (const e of logins) {
      if ('Login' in e.content) {
        const n = await breachCount(e.content.Login.password);
        if (n > 0) compromised.value.push({ id: e.id, title: e.title, count: n });
      }
      progress.value.done += 1;
    }
    scanned.value = true;
  } catch {
    scanError.value = true;
  } finally {
    scanning.value = false;
  }
}

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

      <h3>Breach check</h3>
      <div v-if="!scanned && !scanning && !scanError" class="issue">
        <span class="pill" style="background: var(--accent-soft); color: var(--accent-ink)">HIBP</span>
        <div class="txt">
          <b>Check for compromised passwords</b>
          <div>Compares every password to HaveIBeenPwned — only a hash prefix leaves your device.</div>
        </div>
        <button @click="scanBreaches">Scan →</button>
      </div>
      <div v-else-if="scanning" class="issue">
        <span class="pill" style="background: var(--accent-soft); color: var(--accent-ink)">HIBP</span>
        <div class="txt">
          <b>Scanning… {{ progress.done }}/{{ progress.total }}</b>
          <div>Checking each password against known breaches.</div>
        </div>
      </div>
      <template v-else-if="scanError">
        <div class="issue">
          <span class="pill missing">Offline</span>
          <div class="txt">
            <b>Couldn't reach the breach service</b>
            <div>The HaveIBeenPwned check needs a network connection.</div>
          </div>
          <button @click="scanBreaches">Retry →</button>
        </div>
      </template>
      <template v-else>
        <div v-for="c in compromised" :key="'pwned-' + c.id" class="issue">
          <span class="pill weak">Pwned</span>
          <div class="txt">
            <b>{{ c.title }}</b>
            <div>Found in {{ c.count.toLocaleString() }} known breaches — change it.</div>
          </div>
          <button @click="jumpTo(c.id)">Fix →</button>
        </div>
        <div v-if="compromised.length === 0" class="issue">
          <span class="pill" style="background: var(--strong-soft); color: var(--strong)">Clean</span>
          <div class="txt">
            <b>No breached passwords found</b>
            <div>None of your passwords appear in known breaches.</div>
          </div>
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
