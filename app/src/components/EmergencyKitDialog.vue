<script setup lang="ts">
// Shows the device Secret Key — the second factor of 2SKD. In `firstRun` mode it
// is a one-time reveal the user must acknowledge (they cannot recover the vault
// without it); otherwise it is a re-viewable "Emergency Kit" opened from the top
// bar. The key is copyable and downloadable as a text kit. It never leaves the
// device except when the user deliberately exports it.

import { onBeforeUnmount, onMounted } from 'vue';
import { copyText } from '@/composables/useToast';

const props = defineProps<{ secretKey: string; firstRun?: boolean }>();
const emit = defineEmits<{ (e: 'close'): void }>();

function downloadKit(): void {
  const body = [
    'Keyward Passbook — Emergency Kit',
    '',
    'Your Secret Key (keep this safe and offline):',
    props.secretKey,
    '',
    'You need this Secret Key together with your master password to unlock your',
    'vault on a new device. Keyward cannot recover it for you.',
    '',
    `Generated: ${new Date().toISOString()}`,
  ].join('\n');
  const url = URL.createObjectURL(new Blob([body], { type: 'text/plain' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = 'keyward-passbook-emergency-kit.txt';
  a.click();
  URL.revokeObjectURL(url);
}

function onKey(e: KeyboardEvent): void {
  // In first-run mode the user must acknowledge explicitly; Escape is disabled.
  if (e.key === 'Escape' && !props.firstRun) emit('close');
}
onMounted(() => window.addEventListener('keydown', onKey));
onBeforeUnmount(() => window.removeEventListener('keydown', onKey));
</script>

<template>
  <div class="backdrop" @click.self="!firstRun && emit('close')">
    <div class="dialog" role="dialog" aria-modal="true" aria-label="Emergency Kit">
      <div class="kit-hd">
        <div class="mark mark-kit">
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <path d="M12 3l7 3v6c0 5-3.5 8-7 9-3.5-1-7-4-7-9V6z" />
            <path d="M9 12l2 2 4-4" />
          </svg>
        </div>
        <div>
          <h2>{{ firstRun ? 'Save your Emergency Kit' : 'Emergency Kit' }}</h2>
          <p class="sub">Your vault's Secret Key — the second factor that protects it.</p>
        </div>
      </div>

      <div class="kit-body">
        <div class="keybox">
          <code class="key">{{ secretKey }}</code>
        </div>

        <div class="kit-actions">
          <button class="btn-ghost" @click="copyText(secretKey)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="9" y="9" width="11" height="11" rx="2" />
              <path d="M5 15V5a2 2 0 0 1 2-2h10" />
            </svg>
            Copy
          </button>
          <button class="btn-ghost" @click="downloadKit">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 3v12m0 0 4-4m-4 4-4-4" />
              <path d="M4 21h16" />
            </svg>
            Download kit
          </button>
        </div>

        <p class="warn">
          <b>Store this somewhere safe and offline.</b> You need it — together with
          your master password — to unlock your vault on a new device. It is never
          sent to any server, so <b>it cannot be recovered</b> if lost.
        </p>
      </div>

      <div class="kit-ft">
        <button v-if="firstRun" class="btn-add" @click="emit('close')">
          I've saved my Emergency Kit
        </button>
        <button v-else class="btn-add" @click="emit('close')">Done</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.backdrop {
  position: fixed;
  inset: 0;
  background: rgba(10, 16, 15, 0.5);
  display: grid;
  place-items: center;
  z-index: 45;
  padding: 1rem;
}
.dialog {
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 16px;
  box-shadow: var(--shadow);
  width: min(460px, 100%);
  max-height: 90vh;
  overflow-y: auto;
}
.kit-hd {
  display: flex;
  gap: 0.9rem;
  align-items: flex-start;
  padding: 1.3rem 1.4rem;
  border-bottom: 1px solid var(--line);
}
.mark-kit {
  width: 40px;
  height: 40px;
  border-radius: 11px;
  flex: none;
}
.mark-kit svg {
  width: 22px;
  height: 22px;
}
.kit-hd h2 {
  margin: 0;
  font-size: 1.15rem;
  letter-spacing: -0.01em;
}
.kit-hd .sub {
  margin: 0.2rem 0 0;
  color: var(--muted);
  font-size: 0.82rem;
}
.kit-body {
  padding: 1.2rem 1.4rem;
}
.keybox {
  background: var(--accent-soft);
  border: 1px solid var(--accent);
  border-radius: 12px;
  padding: 1rem;
  text-align: center;
}
.key {
  font-family: var(--mono);
  font-size: 1.02rem;
  letter-spacing: 0.06em;
  color: var(--accent-ink);
  font-weight: 600;
  word-break: break-all;
}
.kit-actions {
  display: flex;
  gap: 0.6rem;
  margin-top: 0.9rem;
}
.kit-actions .btn-ghost {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.4rem;
  padding: 0.5rem 0.9rem;
  border-radius: 9px;
  font-weight: 600;
  font-size: 0.85rem;
  color: var(--muted);
  border: 1px solid var(--line);
}
.kit-actions .btn-ghost:hover {
  background: var(--surface-2);
  color: var(--ink);
}
.kit-actions svg {
  width: 15px;
  height: 15px;
}
.warn {
  margin: 1.1rem 0 0;
  background: var(--warn-soft);
  color: var(--warn);
  border-radius: 10px;
  padding: 0.7rem 0.85rem;
  font-size: 0.82rem;
  line-height: 1.55;
}
.warn b {
  color: var(--warn);
  font-weight: 700;
}
.kit-ft {
  display: flex;
  justify-content: flex-end;
  padding: 1rem 1.4rem;
  border-top: 1px solid var(--line);
}
.kit-ft .btn-add {
  padding: 0.5rem 1rem;
  border-radius: 9px;
  font-weight: 650;
  font-size: 0.88rem;
}
</style>
