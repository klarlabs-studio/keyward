<script setup lang="ts">
// Import a vault from another manager. Paste an export or pick a file; the format
// is auto-detected (overridable), a live preview shows how many items will come
// in, and Import merges them (deduping exact matches). Parsing is entirely local.

import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { useVaultStore } from '@/stores/vault';
import { nowUnix } from '@/lib/passbook';
import { detectFormat, parseImport, type ImportFormat, type ImportResult } from '@/lib/import';
import { toast } from '@/composables/useToast';

const vault = useVaultStore();
const emit = defineEmits<{ (e: 'close'): void }>();

const text = ref('');
const override = ref<'auto' | ImportFormat>('auto');
const fileName = ref('');
const importing = ref(false);

const FORMAT_LABEL: Record<ImportFormat, string> = {
  proctor: 'Proctor (JSON)',
  bitwarden: 'Bitwarden (JSON)',
  lastpass: 'LastPass (CSV)',
  '1password': '1Password (CSV)',
  csv: 'Generic CSV',
};

// Live preview: parse on every change, surfacing the count or the parse error.
const preview = ref<{ result?: ImportResult; error?: string }>({});
watch([text, override], () => {
  if (!text.value.trim()) {
    preview.value = {};
    return;
  }
  try {
    const forced = override.value === 'auto' ? undefined : override.value;
    preview.value = { result: parseImport(text.value, nowUnix(), forced) };
  } catch (err) {
    preview.value = { error: err instanceof Error ? err.message : String(err) };
  }
});

const detected = computed(() => (text.value.trim() ? detectFormat(text.value) : null));
const canImport = computed(() => !importing.value && (preview.value.result?.entries.length ?? 0) > 0);

async function onFile(e: Event): Promise<void> {
  const input = e.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;
  fileName.value = file.name;
  text.value = await file.text();
}

async function runImport(): Promise<void> {
  if (!canImport.value || !preview.value.result) return;
  importing.value = true;
  const added = await vault.importEntries(preview.value.result.entries);
  importing.value = false;
  toast(added > 0 ? `Imported ${added} item${added === 1 ? '' : 's'}` : 'Nothing new to import');
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
    <div class="dialog" role="dialog" aria-modal="true" aria-label="Import vault">
      <div class="dlg-hd">
        <h2>Import from another manager</h2>
        <button class="icon-btn" title="Close" aria-label="Close" @click="emit('close')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M6 6l12 12M18 6 6 18" />
          </svg>
        </button>
      </div>

      <div class="dlg-body">
        <div class="row">
          <label class="file-btn">
            <input type="file" accept=".json,.csv,.txt" @change="onFile" />
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 3v12m0-12 4 4m-4-4-4 4" />
              <path d="M4 21h16" />
            </svg>
            Choose file
          </label>
          <span v-if="fileName" class="fname">{{ fileName }}</span>
          <div class="spacer"></div>
          <label class="fmt">
            <span>Format</span>
            <select v-model="override">
              <option value="auto">Auto-detect</option>
              <option value="proctor">Proctor</option>
              <option value="bitwarden">Bitwarden</option>
              <option value="lastpass">LastPass</option>
              <option value="1password">1Password</option>
              <option value="csv">Generic CSV</option>
            </select>
          </label>
        </div>

        <textarea
          v-model="text"
          class="paste"
          aria-label="Paste export"
          placeholder="…or paste your export here (Bitwarden JSON, or a CSV from LastPass / 1Password / another manager)."
          spellcheck="false"
        ></textarea>

        <p v-if="preview.error" class="status err">{{ preview.error }}</p>
        <p v-else-if="preview.result" class="status ok">
          Detected <b>{{ FORMAT_LABEL[preview.result.format] }}</b> ·
          <b>{{ preview.result.entries.length }}</b> item{{ preview.result.entries.length === 1 ? '' : 's' }} ready
          <template v-if="preview.result.skipped">· {{ preview.result.skipped }} skipped</template>
        </p>
        <p v-else-if="detected" class="status hint">Looks like {{ FORMAT_LABEL[detected] }}.</p>
      </div>

      <div class="dlg-ft">
        <button class="btn-ghost" @click="emit('close')">Cancel</button>
        <button class="btn-add" :disabled="!canImport" @click="runImport">
          {{ importing ? 'Importing…' : 'Import' }}
        </button>
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
  width: min(560px, 100%);
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
.row {
  display: flex;
  align-items: center;
  gap: 0.7rem;
}
.file-btn {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.45rem 0.8rem;
  border: 1px solid var(--line);
  border-radius: 9px;
  font-weight: 600;
  font-size: 0.85rem;
  color: var(--muted);
  cursor: pointer;
}
.file-btn:hover {
  background: var(--surface-2);
  color: var(--ink);
}
.file-btn input {
  display: none;
}
.file-btn svg {
  width: 15px;
  height: 15px;
}
.fname {
  font-size: 0.8rem;
  color: var(--muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 160px;
}
.spacer {
  flex: 1;
}
.fmt {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.78rem;
  color: var(--faint);
}
.fmt select {
  border: 1px solid var(--line);
  background: var(--surface-2);
  border-radius: 8px;
  padding: 0.3rem 0.5rem;
  color: var(--ink);
  font-size: 0.82rem;
}
.paste {
  width: 100%;
  min-height: 150px;
  resize: vertical;
  border: 1px solid var(--line);
  background: var(--surface-2);
  border-radius: 10px;
  padding: 0.7rem 0.8rem;
  color: var(--ink);
  font-family: var(--mono);
  font-size: 0.8rem;
  line-height: 1.5;
  outline: none;
}
.paste:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-soft);
}
.status {
  margin: 0;
  font-size: 0.83rem;
  border-radius: 9px;
  padding: 0.5rem 0.7rem;
}
.status.ok {
  color: var(--accent-ink);
  background: var(--accent-soft);
}
.status.err {
  color: var(--weak);
  background: var(--weak-soft);
}
.status.hint {
  color: var(--muted);
  background: var(--surface-2);
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
