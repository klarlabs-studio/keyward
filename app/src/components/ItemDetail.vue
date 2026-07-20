<script setup lang="ts">
// The detail pane: the selected entry rendered as a card, with per-category
// fields. Login passwords get a strength bar + reveal + copy; a live TOTP field
// when a secret is present; website links and a passkey line.

import { computed, ref, watch } from 'vue';
import { useVaultStore, avatarColor, initials, subtitleOf } from '@/stores/vault';
import { copyText } from '@/composables/useToast';
import { breachCount } from '@/lib/passbook';
import TotpField from './TotpField.vue';

const vault = useVaultStore();

const revealPw = ref(false);
const revealCvv = ref(false);

type BreachState = 'idle' | 'checking' | 'safe' | 'pwned' | 'error';
const breach = ref<{ state: BreachState; count: number }>({ state: 'idle', count: 0 });

// Reset masked fields + breach status whenever the selection changes.
watch(
  () => vault.selectedId,
  () => {
    revealPw.value = false;
    revealCvv.value = false;
    breach.value = { state: 'idle', count: 0 };
  },
);

/**
 * Check the login password against HaveIBeenPwned via k-anonymity — only a SHA-1
 * prefix leaves the device. Degrades to an error state if the service is down.
 */
async function checkBreach(): Promise<void> {
  if (!login.value) return;
  breach.value = { state: 'checking', count: 0 };
  try {
    const n = await breachCount(login.value.password);
    breach.value = n > 0 ? { state: 'pwned', count: n } : { state: 'safe', count: 0 };
  } catch {
    breach.value = { state: 'error', count: 0 };
  }
}

const entry = computed(() => vault.selected);

const login = computed(() => (entry.value && 'Login' in entry.value.content ? entry.value.content.Login : null));
const card = computed(() => (entry.value && 'Card' in entry.value.content ? entry.value.content.Card : null));
const identity = computed(() =>
  entry.value && 'Identity' in entry.value.content ? entry.value.content.Identity : null,
);
const note = computed(() =>
  entry.value && 'SecureNote' in entry.value.content ? entry.value.content.SecureNote : null,
);

const bits = computed(() => (entry.value ? (vault.strengths[entry.value.id] ?? 0) : 0));

function strengthColor(b: number): string {
  return b >= 80 ? 'var(--strong)' : b >= 55 ? 'var(--warn)' : 'var(--weak)';
}

/** Build a safe href — only prepend https:// when the URL has no scheme. */
function webHref(url: string): string {
  return /^https?:\/\//i.test(url) ? url : `https://${url}`;
}
function strengthLabel(b: number): string {
  return b >= 80 ? 'Excellent' : b >= 55 ? 'Fair' : 'Weak';
}
</script>

<template>
  <div class="detail">
    <template v-if="entry">
      <div class="card">
        <div class="card-hd">
          <div class="avatar" :style="{ background: avatarColor(entry.id) }">{{ initials(entry.title) }}</div>
          <div>
            <h1>{{ entry.title }}</h1>
            <div class="sub">{{ subtitleOf(entry) }}</div>
          </div>
          <div class="hd-actions">
            <button
              class="mini"
              :title="entry.favorite ? 'Unfavorite' : 'Favorite'"
              @click="vault.toggleFavorite(entry.id)"
            >
              <svg
                viewBox="0 0 24 24"
                :fill="entry.favorite ? 'var(--warn)' : 'none'"
                stroke="currentColor"
                stroke-width="2"
              >
                <path d="m12 3 2.9 6 6.6.6-5 4.3 1.5 6.4L12 17l-6 3.3 1.5-6.4-5-4.3 6.6-.6z" />
              </svg>
            </button>
            <button class="mini" title="Delete item" @click="vault.remove(entry.id)">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M4 7h16M9 7V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2M6 7l1 13h10l1-13" />
              </svg>
            </button>
          </div>
        </div>

        <!-- Login -->
        <template v-if="login">
          <div class="field">
            <div class="lbl">Username</div>
            <div class="val">{{ login.username }}</div>
            <div class="act">
              <button class="mini" title="Copy" @click="copyText(login.username)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" />
                </svg>
              </button>
            </div>
          </div>

          <div class="field">
            <div class="lbl">Password</div>
            <div class="val">
              <span class="mono">{{ revealPw ? login.password : '••••••••••••' }}</span>
              <div class="strength" style="margin-top: 0.35rem">
                <div class="bar">
                  <i :style="{ width: Math.min(100, bits) + '%', background: strengthColor(bits) }"></i>
                </div>
                <small :style="{ color: strengthColor(bits) }">{{ strengthLabel(bits) }} · {{ bits }} bits</small>
              </div>
              <div class="breach">
                <button
                  type="button"
                  class="linkbtn"
                  :disabled="breach.state === 'checking'"
                  @click="checkBreach"
                >
                  {{ breach.state === 'checking' ? 'Checking…' : 'Check for breaches' }}
                </button>
                <span v-if="breach.state === 'pwned'" class="breach-bad">
                  Found in {{ breach.count.toLocaleString() }} breaches — change it
                </span>
                <span v-else-if="breach.state === 'safe'" class="breach-ok">
                  ✓ Not found in known breaches
                </span>
                <span v-else-if="breach.state === 'error'" class="breach-err">
                  Couldn't reach the breach service
                </span>
              </div>
            </div>
            <div class="act">
              <button class="mini" :title="revealPw ? 'Hide' : 'Reveal'" @click="revealPw = !revealPw">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z" /><circle cx="12" cy="12" r="3" />
                </svg>
              </button>
              <button class="mini" title="Copy" @click="copyText(login.password)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" />
                </svg>
              </button>
            </div>
          </div>

          <TotpField v-if="login.totp_secret" :key="entry.id" :secret="login.totp_secret" />

          <div v-if="login.urls.length" class="field">
            <div class="lbl">Website</div>
            <div class="val">
              <a class="link" :href="webHref(login.urls[0])" target="_blank" rel="noopener noreferrer">{{
                login.urls[0]
              }}</a>
            </div>
            <div class="act">
              <button class="mini" title="Copy" @click="copyText(login.urls[0])">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" />
                </svg>
              </button>
            </div>
          </div>

          <div v-if="login.passkeys.length > 0" class="field">
            <div class="lbl">Passkey</div>
            <div class="val">
              <span style="color: var(--strong); font-weight: 600">✓ Passkey saved</span> · phishing-resistant
            </div>
          </div>
        </template>

        <!-- Card -->
        <template v-else-if="card">
          <div class="field">
            <div class="lbl">Cardholder</div>
            <div class="val">{{ card.cardholder }}</div>
            <div class="act">
              <button class="mini" title="Copy" @click="copyText(card.cardholder)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" />
                </svg>
              </button>
            </div>
          </div>
          <div class="field">
            <div class="lbl">Number</div>
            <div class="val mono">{{ card.number }}</div>
            <div class="act">
              <button class="mini" title="Copy" @click="copyText(card.number)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" />
                </svg>
              </button>
            </div>
          </div>
          <div class="field">
            <div class="lbl">Expires</div>
            <div class="val">{{ card.expiry }}</div>
          </div>
          <div class="field">
            <div class="lbl">CVV</div>
            <div class="val mono">{{ revealCvv ? card.cvv : '•••' }}</div>
            <div class="act">
              <button class="mini" :title="revealCvv ? 'Hide' : 'Reveal'" @click="revealCvv = !revealCvv">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z" /><circle cx="12" cy="12" r="3" />
                </svg>
              </button>
              <button class="mini" title="Copy" @click="copyText(card.cvv)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" />
                </svg>
              </button>
            </div>
          </div>
        </template>

        <!-- Identity -->
        <template v-else-if="identity">
          <div class="field">
            <div class="lbl">Name</div>
            <div class="val">{{ identity.full_name }}</div>
            <div class="act">
              <button class="mini" title="Copy" @click="copyText(identity.full_name)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" />
                </svg>
              </button>
            </div>
          </div>
          <div class="field">
            <div class="lbl">Email</div>
            <div class="val">{{ identity.email }}</div>
            <div class="act">
              <button class="mini" title="Copy" @click="copyText(identity.email)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" />
                </svg>
              </button>
            </div>
          </div>
          <div class="field">
            <div class="lbl">Phone</div>
            <div class="val">{{ identity.phone }}</div>
            <div class="act">
              <button class="mini" title="Copy" @click="copyText(identity.phone)">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" />
                </svg>
              </button>
            </div>
          </div>
          <div class="field">
            <div class="lbl">Address</div>
            <div class="val">{{ identity.address }}</div>
          </div>
        </template>

        <!-- Secure note -->
        <template v-else-if="note !== null">
          <div class="field">
            <div class="lbl">Note</div>
            <div
              class="val"
              style="white-space: pre-wrap; overflow: visible; font-family: var(--mono); font-size: 0.85rem; line-height: 1.7"
            >
              {{ note }}
            </div>
          </div>
        </template>

        <div v-if="entry.tags.length" class="field">
          <div class="lbl">Tags</div>
          <div class="val">
            <div class="tags">
              <span v-for="t in entry.tags" :key="t" class="tag">{{ t }}</span>
            </div>
          </div>
        </div>
      </div>
    </template>

    <p v-else class="empty">Select an item to view its details.</p>
  </div>
</template>

<style scoped>
.breach {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-top: 0.4rem;
  flex-wrap: wrap;
  font-size: 0.78rem;
}
.linkbtn {
  color: var(--accent-ink);
  font-weight: 600;
  font-size: 0.78rem;
  padding: 0;
}
.linkbtn:hover:not(:disabled) {
  text-decoration: underline;
}
.linkbtn:disabled {
  color: var(--faint);
  cursor: default;
}
.breach-bad {
  color: var(--weak);
  font-weight: 600;
}
.breach-ok {
  color: var(--strong);
  font-weight: 600;
}
.breach-err {
  color: var(--muted);
}
</style>
