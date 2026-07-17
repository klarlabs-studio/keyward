<script setup lang="ts">
// The unlock gate in front of the vault. On a fresh device (no vault yet) this is
// the "create your vault" step; afterwards it opens the sealed blob. A device that
// has the vault but not its Secret Key gets the "add this device" prompt. The
// master password is handed straight to the store (which owns the crypto).

import { computed, ref } from 'vue';
import { useVaultStore } from '@/stores/vault';

const vault = useVaultStore();
const master = ref('');
const secretKey = ref('');

// First run on this device: no vault exists yet, so we create one.
const creating = computed(() => !vault.needsSecretKey && !vault.hasVault);

async function submit(): Promise<void> {
  if (!master.value || vault.busy) return;
  if (vault.needsSecretKey) {
    if (!secretKey.value) return;
    await vault.addDevice(master.value, secretKey.value);
  } else {
    await vault.unlock(master.value);
  }
}
</script>

<template>
  <div class="unlock">
    <form class="unlock-card" @submit.prevent="submit">
      <div class="mark mark-lg">
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2.2"
          stroke-linecap="round"
          stroke-linejoin="round"
        >
          <rect x="4" y="10" width="16" height="10" rx="2" />
          <path d="M8 10V7a4 4 0 0 1 8 0v3" />
        </svg>
      </div>
      <h1>Passbook</h1>
      <p class="tagline">
        {{
          vault.needsSecretKey
            ? 'This device needs your Secret Key to open the vault.'
            : creating
              ? 'Create your vault — encrypted on this device.'
              : 'Your vault — encrypted on this device.'
        }}
      </p>

      <label class="pw">
        <span>{{ creating ? 'Choose a master password' : 'Master password' }}</span>
        <input
          v-model="master"
          type="password"
          :autocomplete="creating ? 'new-password' : 'current-password'"
          :placeholder="creating ? 'Choose a strong master password' : 'Enter master password'"
          aria-label="Master password"
          autofocus
        />
      </label>

      <label v-if="vault.needsSecretKey" class="pw pw-key">
        <span>Secret Key</span>
        <input
          v-model="secretKey"
          type="text"
          spellcheck="false"
          autocapitalize="characters"
          placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
          aria-label="Secret Key"
        />
      </label>

      <p v-if="vault.unlockError" class="err" role="alert">{{ vault.unlockError }}</p>

      <button
        class="btn-unlock"
        type="submit"
        :disabled="!master || (vault.needsSecretKey && !secretKey) || vault.busy"
      >
        <span v-if="vault.busy" class="spinner" aria-hidden="true"></span>
        {{
          vault.busy
            ? vault.needsSecretKey
              ? 'Adding device…'
              : creating
                ? 'Creating…'
                : 'Unlocking…'
            : vault.needsSecretKey
              ? 'Add this device'
              : creating
                ? 'Create vault'
                : 'Unlock'
        }}
      </button>

      <div v-if="vault.needsSecretKey" class="hint">
        Find your Secret Key in the Emergency Kit you saved when the vault was
        created. It never leaves your devices.
      </div>
      <div v-else-if="creating" class="hint">
        This creates your encrypted vault on this device and generates a device
        <b>Secret Key</b> (2SKD) — you'll get an Emergency Kit to save. Choose a
        strong master password; it is never stored and <b>can't be recovered</b>.
      </div>
    </form>
  </div>
</template>

<style scoped>
.unlock {
  height: 100vh;
  display: grid;
  place-items: center;
  background: var(--paper);
  padding: 1.5rem;
}
.unlock-card {
  width: min(360px, 100%);
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 18px;
  box-shadow: var(--shadow);
  padding: 2rem 1.8rem;
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
}
.mark-lg {
  width: 46px;
  height: 46px;
  border-radius: 13px;
}
.mark-lg svg {
  width: 26px;
  height: 26px;
}
.unlock-card h1 {
  margin: 0.9rem 0 0.2rem;
  font-size: 1.4rem;
  letter-spacing: -0.02em;
}
.tagline {
  margin: 0 0 1.4rem;
  color: var(--muted);
  font-size: 0.86rem;
}
.pw {
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  text-align: left;
}
.pw > span {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  font-weight: 600;
  color: var(--faint);
}
.pw input {
  border: 1px solid var(--line);
  background: var(--surface-2);
  border-radius: 10px;
  padding: 0.6rem 0.8rem;
  color: var(--ink);
  font-size: 0.95rem;
  outline: none;
}
.pw input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-soft);
}
.pw-key {
  margin-top: 0.8rem;
}
.pw-key input {
  font-family: var(--mono);
  font-size: 0.82rem;
  letter-spacing: 0.02em;
}
.err {
  width: 100%;
  margin: 0.8rem 0 0;
  color: var(--weak);
  background: var(--weak-soft);
  border-radius: 9px;
  padding: 0.5rem 0.7rem;
  font-size: 0.82rem;
  text-align: left;
}
.btn-unlock {
  width: 100%;
  margin-top: 1.1rem;
  background: var(--accent);
  color: #fff;
  border-radius: 10px;
  padding: 0.6rem 0.9rem;
  font-weight: 650;
  font-size: 0.95rem;
  box-shadow: var(--shadow);
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
}
.btn-unlock:hover:not(:disabled) {
  background: var(--accent-ink);
}
.btn-unlock:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
.spinner {
  width: 15px;
  height: 15px;
  border-radius: 50%;
  border: 2px solid rgba(255, 255, 255, 0.4);
  border-top-color: #fff;
  animation: spin 0.7s linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
.hint {
  margin-top: 1.3rem;
  font-size: 0.78rem;
  color: var(--faint);
  line-height: 1.6;
}
.hint code {
  font-family: var(--mono);
  background: var(--surface-2);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 0.05rem 0.35rem;
  color: var(--muted);
}
@media (prefers-reduced-motion: reduce) {
  .spinner {
    animation: none;
  }
}
</style>
