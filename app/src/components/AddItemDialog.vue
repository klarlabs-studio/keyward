<script setup lang="ts">
// A modal for adding a Login: title / username / password (with live strength) /
// URL / TOTP secret / favourite. Saves through the store's real crypto path.
// No native alert()/confirm() — validation is inline and non-blocking.

import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { useVaultStore } from '@/stores/vault';
import { strengthBits } from '@/lib/passbook';

const vault = useVaultStore();
const emit = defineEmits<{ (e: 'close'): void }>();

const title = ref('');
const username = ref('');
const password = ref('');
const url = ref('');
const totp = ref('');
const favorite = ref(false);
const saving = ref(false);

const bits = ref(0);
watch(password, async (pw) => {
  bits.value = pw ? await strengthBits(pw) : 0;
});

const canSave = computed(() => title.value.trim().length > 0 && !saving.value);

function strengthColor(b: number): string {
  return b >= 80 ? 'var(--strong)' : b >= 55 ? 'var(--warn)' : 'var(--weak)';
}
function strengthLabel(b: number): string {
  return b >= 80 ? 'Excellent' : b >= 55 ? 'Fair' : 'Weak';
}

async function save(): Promise<void> {
  if (!canSave.value) return;
  saving.value = true;
  await vault.addLogin({
    title: title.value.trim(),
    login: {
      username: username.value.trim(),
      password: password.value,
      urls: url.value.trim() ? [url.value.trim()] : [],
      totp_secret: totp.value.trim() ? totp.value.trim() : null,
      has_passkey: false,
    },
    tags: [],
    favorite: favorite.value,
  });
  saving.value = false;
  emit('close');
}

function onKey(e: KeyboardEvent): void {
  if (e.key === 'Escape') emit('close');
}
onMounted(() => window.addEventListener('keydown', onKey));
onBeforeUnmount(() => window.removeEventListener('keydown', onKey));
</script>

<template>
  <div class="backdrop" @click.self="emit('close')">
    <div class="dialog" role="dialog" aria-modal="true" aria-label="Add login">
      <div class="dlg-hd">
        <h2>New login</h2>
        <button class="icon-btn" title="Close" aria-label="Close" @click="emit('close')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M6 6l12 12M18 6 6 18" />
          </svg>
        </button>
      </div>

      <div class="dlg-body">
        <label class="fld">
          <span>Title</span>
          <input v-model="title" type="text" placeholder="e.g. GitHub" autofocus />
        </label>
        <label class="fld">
          <span>Username</span>
          <input v-model="username" type="text" placeholder="name@example.com" />
        </label>
        <label class="fld">
          <span>Password</span>
          <input v-model="password" type="text" placeholder="Password" />
          <div v-if="password" class="strength" style="margin-top: 0.4rem">
            <div class="bar">
              <i :style="{ width: Math.min(100, bits) + '%', background: strengthColor(bits) }"></i>
            </div>
            <small :style="{ color: strengthColor(bits) }">{{ strengthLabel(bits) }} · {{ bits }} bits</small>
          </div>
        </label>
        <label class="fld">
          <span>Website</span>
          <input v-model="url" type="text" placeholder="example.com" />
        </label>
        <label class="fld">
          <span>One-time code secret</span>
          <input v-model="totp" type="text" placeholder="Base32 TOTP secret (optional)" />
        </label>
        <label class="chk">
          <input v-model="favorite" type="checkbox" />
          <span>Add to favorites</span>
        </label>
      </div>

      <div class="dlg-ft">
        <button class="btn-ghost" @click="emit('close')">Cancel</button>
        <button class="btn-add" :disabled="!canSave" @click="save">Save login</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.backdrop {
  position: fixed;
  inset: 0;
  background: rgba(10, 16, 15, 0.45);
  display: grid;
  place-items: center;
  z-index: 40;
  padding: 1rem;
}
.dialog {
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 16px;
  box-shadow: var(--shadow);
  width: min(440px, 100%);
  max-height: 90vh;
  overflow-y: auto;
}
.dlg-hd {
  display: flex;
  align-items: center;
  padding: 1.1rem 1.3rem;
  border-bottom: 1px solid var(--line);
}
.dlg-hd h2 {
  margin: 0;
  font-size: 1.1rem;
  letter-spacing: -0.01em;
}
.dlg-hd .icon-btn {
  margin-left: auto;
}
.dlg-body {
  padding: 1.1rem 1.3rem;
  display: flex;
  flex-direction: column;
  gap: 0.85rem;
}
.fld {
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
}
.fld > span {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  font-weight: 600;
  color: var(--faint);
}
.fld input {
  border: 1px solid var(--line);
  background: var(--surface-2);
  border-radius: 9px;
  padding: 0.5rem 0.7rem;
  color: var(--ink);
  font-size: 0.9rem;
  outline: none;
}
.fld input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-soft);
}
.chk {
  display: flex;
  align-items: center;
  gap: 0.55rem;
  color: var(--muted);
  font-size: 0.88rem;
}
.dlg-ft {
  display: flex;
  justify-content: flex-end;
  gap: 0.6rem;
  padding: 1rem 1.3rem;
  border-top: 1px solid var(--line);
}
.btn-ghost {
  padding: 0.44rem 0.9rem;
  border-radius: 9px;
  font-weight: 600;
  font-size: 0.85rem;
  color: var(--muted);
  border: 1px solid var(--line);
}
.btn-ghost:hover {
  background: var(--surface-2);
  color: var(--ink);
}
.btn-add:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
</style>
