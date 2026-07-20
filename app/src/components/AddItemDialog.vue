<script setup lang="ts">
// A modal for adding a Login: title / username / password (with live strength) /
// URL / TOTP secret / favourite. Saves through the store's real crypto path.
// No native alert()/confirm() — validation is inline and non-blocking.

import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { useVaultStore } from '@/stores/vault';
import { generatePassphrase, generatePassword, strengthBits } from '@/lib/passbook';

const vault = useVaultStore();
const emit = defineEmits<{ (e: 'close'): void }>();

const title = ref('');
const username = ref('');
const password = ref('');
const url = ref('');
const totp = ref('');
const favorite = ref(false);
const saving = ref(false);

// Password generator.
const showGen = ref(false);
const passphrase = ref(false);
const words = ref(5);
const gen = ref({
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: true,
});

async function doGenerate(): Promise<void> {
  password.value = passphrase.value
    ? await generatePassphrase(words.value)
    : await generatePassword(gen.value);
}

async function toggleGen(): Promise<void> {
  showGen.value = !showGen.value;
  if (showGen.value && !password.value) await doGenerate();
}

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
      passkeys: [],
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
          <div class="pw-row">
            <input v-model="password" type="text" placeholder="Password" />
            <button type="button" class="mini" title="Generate" aria-label="Generate password" @click="toggleGen">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M4 20 20 4M14 4h6v6" /><path d="M8 8 6 6M18 18l-2-2" />
              </svg>
            </button>
          </div>
          <div v-if="password" class="strength" style="margin-top: 0.4rem">
            <div class="bar">
              <i :style="{ width: Math.min(100, bits) + '%', background: strengthColor(bits) }"></i>
            </div>
            <small :style="{ color: strengthColor(bits) }">{{ strengthLabel(bits) }} · {{ bits }} bits</small>
          </div>

          <div v-if="showGen" class="gen">
            <div class="gen-top">
              <label class="chk"><input v-model="passphrase" type="checkbox" /><span>Passphrase</span></label>
              <button type="button" class="btn-ghost sm" @click="doGenerate">Regenerate</button>
            </div>
            <template v-if="!passphrase">
              <div class="gen-len">
                <span>Length</span>
                <input v-model.number="gen.length" type="range" min="8" max="40" @input="doGenerate" />
                <b>{{ gen.length }}</b>
              </div>
              <div class="gen-classes">
                <label class="chk"><input v-model="gen.uppercase" type="checkbox" @change="doGenerate" />A–Z</label>
                <label class="chk"><input v-model="gen.lowercase" type="checkbox" @change="doGenerate" />a–z</label>
                <label class="chk"><input v-model="gen.digits" type="checkbox" @change="doGenerate" />0–9</label>
                <label class="chk"><input v-model="gen.symbols" type="checkbox" @change="doGenerate" />!@#</label>
                <label class="chk"><input v-model="gen.avoidAmbiguous" type="checkbox" @change="doGenerate" />No look-alikes</label>
              </div>
            </template>
            <template v-else>
              <div class="gen-len">
                <span>Words</span>
                <input v-model.number="words" type="range" min="3" max="8" @input="doGenerate" />
                <b>{{ words }}</b>
              </div>
            </template>
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
.pw-row {
  display: flex;
  gap: 0.4rem;
  align-items: stretch;
}
.pw-row input {
  flex: 1;
}
.pw-row .mini {
  width: 36px;
  border: 1px solid var(--line);
  border-radius: 9px;
  display: grid;
  place-items: center;
  color: var(--muted);
  flex: none;
}
.pw-row .mini:hover {
  background: var(--surface-2);
  color: var(--accent-ink);
}
.pw-row .mini svg {
  width: 16px;
  height: 16px;
}
.gen {
  margin-top: 0.55rem;
  padding: 0.7rem 0.8rem;
  border: 1px solid var(--line);
  border-radius: 10px;
  background: var(--surface-2);
  display: flex;
  flex-direction: column;
  gap: 0.55rem;
}
.gen-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.gen-len {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  font-size: 0.8rem;
  color: var(--muted);
}
.gen-len input[type='range'] {
  flex: 1;
  accent-color: var(--accent);
}
.gen-len b {
  color: var(--ink);
  font-variant-numeric: tabular-nums;
  min-width: 1.5rem;
  text-align: right;
}
.gen-classes {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem 0.9rem;
}
.gen-classes .chk {
  font-size: 0.8rem;
}
.btn-ghost.sm {
  padding: 0.28rem 0.6rem;
  border-radius: 8px;
  border: 1px solid var(--line);
  font-size: 0.78rem;
  font-weight: 600;
  color: var(--muted);
}
.btn-ghost.sm:hover {
  background: var(--surface);
  color: var(--ink);
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
