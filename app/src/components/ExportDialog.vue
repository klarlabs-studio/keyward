<script setup lang="ts">
// Export the vault to a portable file — no lock-in. Proctor JSON is full-fidelity
// (and re-importable), Bitwarden JSON is portable, CSV is universal but lossy.
// Exports are PLAINTEXT by design; the dialog says so plainly.

import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { useVaultStore } from '@/stores/vault';
import { buildExport, type ExportFormat } from '@/lib/export';
import { copyText, toast } from '@/composables/useToast';

const vault = useVaultStore();
const emit = defineEmits<{ (e: 'close'): void }>();

const format = ref<ExportFormat>('proctor');

const OPTIONS: { value: ExportFormat; label: string; note: string }[] = [
  { value: 'proctor', label: 'Proctor (JSON)', note: 'Full fidelity — re-importable into Proctor.' },
  { value: 'bitwarden', label: 'Bitwarden (JSON)', note: 'Unencrypted Bitwarden export shape.' },
  { value: 'csv', label: 'CSV', note: 'Universal, but lossy (logins map best).' },
];

const file = computed(() => buildExport(vault.entries, format.value));

function download(): void {
  const url = URL.createObjectURL(new Blob([file.value.content], { type: file.value.mime }));
  const a = document.createElement('a');
  a.href = url;
  a.download = file.value.filename;
  a.click();
  URL.revokeObjectURL(url);
  toast(`Exported ${vault.entries.length} items`);
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
    <div class="dialog" role="dialog" aria-modal="true" aria-label="Export vault">
      <div class="dlg-hd">
        <h2>Export vault</h2>
        <button class="icon-btn" title="Close" aria-label="Close" @click="emit('close')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M6 6l12 12M18 6 6 18" />
          </svg>
        </button>
      </div>

      <div class="dlg-body">
        <div class="opts" role="radiogroup" aria-label="Export format">
          <label v-for="opt in OPTIONS" :key="opt.value" class="opt" :class="{ sel: format === opt.value }">
            <input v-model="format" type="radio" name="fmt" :value="opt.value" />
            <div>
              <b>{{ opt.label }}</b>
              <span>{{ opt.note }}</span>
            </div>
          </label>
        </div>

        <p class="count">{{ vault.entries.length }} items will be exported.</p>

        <p class="warn">
          <b>This file is unencrypted.</b> Every password, code, and secret is in
          plain text. Store it somewhere safe and delete it when you're done.
        </p>
      </div>

      <div class="dlg-ft">
        <button class="btn-ghost" @click="copyText(file.content)">Copy</button>
        <button class="btn-add" @click="download">Download</button>
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
  width: min(460px, 100%);
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
.opts {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}
.opt {
  display: flex;
  align-items: flex-start;
  gap: 0.6rem;
  padding: 0.7rem 0.8rem;
  border: 1px solid var(--line);
  border-radius: 10px;
  cursor: pointer;
}
.opt.sel {
  border-color: var(--accent);
  background: var(--accent-soft);
}
.opt input {
  margin-top: 0.15rem;
  accent-color: var(--accent);
}
.opt b {
  display: block;
  font-weight: 600;
  font-size: 0.9rem;
}
.opt span {
  color: var(--muted);
  font-size: 0.8rem;
}
.count {
  margin: 0;
  color: var(--muted);
  font-size: 0.83rem;
}
.warn {
  margin: 0;
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
</style>
