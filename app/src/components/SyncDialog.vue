<script setup lang="ts">
// Settings › Sync. Choose where the vault lives: on this device only, or mirrored
// to a zero-knowledge cloud server. The server only ever stores the opaque sealed
// blob — the master password and Secret Key never leave the device. From here you
// can enable sync, run a manual sync, provision a token for a second device, and
// switch back to on-device only.

import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { useVaultStore } from '@/stores/vault';
import type { DeviceInfo } from '@/lib/sync';
import { copyText } from '@/composables/useToast';

const vault = useVaultStore();
const emit = defineEmits<{ (e: 'close'): void }>();

type Mode = 'device' | 'cloud';
const mode = ref<Mode>(vault.syncEnabled ? 'cloud' : 'device');

const serverUrl = ref('http://localhost:8787');
const email = ref('');
const busy = ref(false);
// The device token minted by "Add a device", shown once for the user to carry.
const newToken = ref<string | null>(null);

// The account's linked devices, loaded when cloud sync is on.
const devices = ref<DeviceInfo[]>([]);
const devicesLoading = ref(false);
// The id of the device currently being revoked, to disable just its button.
const revokingId = ref<string | null>(null);

/** True if `d` is this browser: the server's flag, or the locally stored id. */
function isCurrentDevice(d: DeviceInfo): boolean {
  return d.current || (vault.syncInfo?.deviceId != null && vault.syncInfo.deviceId === d.id);
}

/** A short "added N ago" label from a unix-seconds timestamp. */
function addedAgo(epoch: number): string {
  const secs = Math.max(0, Math.floor(Date.now() / 1000 - epoch));
  if (secs < 60) return 'added just now';
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `added ${mins} minute${mins === 1 ? '' : 's'} ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `added ${hours} hour${hours === 1 ? '' : 's'} ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `added ${days} day${days === 1 ? '' : 's'} ago`;
  const months = Math.floor(days / 30);
  if (months < 12) return `added ${months} month${months === 1 ? '' : 's'} ago`;
  const years = Math.floor(days / 365);
  return `added ${years} year${years === 1 ? '' : 's'} ago`;
}

async function loadDevices(): Promise<void> {
  if (!vault.syncEnabled) return;
  devicesLoading.value = true;
  devices.value = await vault.loadDevices();
  devicesLoading.value = false;
}

async function doRevoke(d: DeviceInfo): Promise<void> {
  if (revokingId.value || isCurrentDevice(d)) return;
  revokingId.value = d.id;
  const ok = await vault.revokeDevice(d.id);
  revokingId.value = null;
  if (ok) await loadDevices();
}

const statusText = computed(() => {
  switch (vault.syncStatus) {
    case 'syncing':
      return 'Syncing…';
    case 'synced':
      return vault.lastSyncedVersion
        ? `Up to date · version ${vault.lastSyncedVersion}`
        : 'Up to date';
    case 'error':
      return 'Last sync failed — try again';
    default:
      return vault.lastSyncedVersion ? `Version ${vault.lastSyncedVersion}` : 'Not synced yet';
  }
});

async function doEnable(): Promise<void> {
  if (busy.value || !serverUrl.value.trim()) return;
  busy.value = true;
  const ok = await vault.enableSync(serverUrl.value.trim(), email.value.trim() || undefined);
  busy.value = false;
  if (!ok) mode.value = 'cloud'; // keep the form visible so the user can retry
}

async function doSyncNow(): Promise<void> {
  if (busy.value) return;
  busy.value = true;
  await vault.syncNow();
  busy.value = false;
}

async function doAddDevice(): Promise<void> {
  if (busy.value) return;
  busy.value = true;
  newToken.value = await vault.addSyncDevice();
  busy.value = false;
  if (newToken.value) await loadDevices();
}

function doDisable(): void {
  vault.disableSync();
  newToken.value = null;
  mode.value = 'device';
}

function onKey(e: KeyboardEvent): void {
  if (e.key === 'Escape') emit('close');
}
onMounted(() => {
  window.addEventListener('keydown', onKey);
  if (vault.syncEnabled) void loadDevices();
});
onBeforeUnmount(() => window.removeEventListener('keydown', onKey));
</script>

<template>
  <div class="backdrop" @click.self="emit('close')">
    <div class="dialog" role="dialog" aria-modal="true" aria-label="Sync settings">
      <div class="dlg-hd">
        <h2>Sync</h2>
        <button class="icon-btn" title="Close" aria-label="Close" @click="emit('close')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M6 6l12 12M18 6 6 18" />
          </svg>
        </button>
      </div>

      <div class="dlg-body">
        <div class="opts" role="radiogroup" aria-label="Storage">
          <label class="opt" :class="{ sel: mode === 'device' }">
            <input v-model="mode" type="radio" name="storage" value="device" />
            <div>
              <b>On-device only</b>
              <span>Your vault never leaves this browser. No account, no server.</span>
            </div>
          </label>
          <label class="opt" :class="{ sel: mode === 'cloud' }">
            <input v-model="mode" type="radio" name="storage" value="cloud" />
            <div>
              <b>Cloud sync</b>
              <span>Mirror the encrypted vault to a zero-knowledge server to use it on more devices.</span>
            </div>
          </label>
        </div>

        <!-- Enabled: account, manual sync, add-a-device, disable. -->
        <template v-if="vault.syncEnabled && mode === 'cloud'">
          <div class="panel">
            <div class="kv">
              <span class="k">Server</span>
              <code class="v">{{ vault.syncInfo?.serverUrl }}</code>
            </div>
            <div class="kv">
              <span class="k">Account</span>
              <code class="v">{{ vault.syncInfo?.accountId }}</code>
            </div>
            <div class="kv">
              <span class="k">Status</span>
              <span class="v status" :class="vault.syncStatus">{{ statusText }}</span>
            </div>
          </div>

          <button class="btn-add wide" :disabled="busy" @click="doSyncNow">
            {{ busy ? 'Working…' : 'Sync now' }}
          </button>

          <div class="adddev">
            <button class="btn-ghost wide" :disabled="busy" @click="doAddDevice">
              Add a device
            </button>
            <template v-if="newToken">
              <div class="keybox">
                <code class="key">{{ newToken }}</code>
              </div>
              <div class="tok-actions">
                <button class="btn-ghost" @click="copyText(newToken)">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="9" y="9" width="11" height="11" rx="2" />
                    <path d="M5 15V5a2 2 0 0 1 2-2h10" />
                  </svg>
                  Copy device token
                </button>
              </div>
              <p class="note">
                Enter this device token on the other device to link it to this account,
                alongside your <b>Secret Key</b> and master password. It is shown once.
              </p>
            </template>
          </div>

          <div class="devices">
            <div class="devices-hd">
              <h3>Devices</h3>
              <button
                class="icon-btn"
                title="Refresh devices"
                aria-label="Refresh devices"
                :disabled="devicesLoading"
                @click="loadDevices"
              >
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M20 11A8 8 0 1 0 12 20M20 4v7h-7" />
                </svg>
              </button>
            </div>

            <p v-if="devicesLoading && devices.length === 0" class="note">Loading devices…</p>
            <p v-else-if="devices.length === 0" class="note">No devices linked yet.</p>
            <ul v-else class="dev-list">
              <li v-for="d in devices" :key="d.id" class="dev">
                <div class="dev-main">
                  <b class="dev-label">{{ d.label }}</b>
                  <span class="dev-meta">{{ addedAgo(d.created_epoch) }}</span>
                </div>
                <span v-if="isCurrentDevice(d)" class="badge">This device</span>
                <button
                  v-else
                  class="btn-ghost sm danger"
                  :disabled="revokingId === d.id"
                  @click="doRevoke(d)"
                >
                  {{ revokingId === d.id ? 'Revoking…' : 'Revoke' }}
                </button>
              </li>
            </ul>
          </div>
        </template>

        <!-- Enabled, but the user picked "On-device only": confirm switching off. -->
        <template v-else-if="vault.syncEnabled && mode === 'device'">
          <p class="note">
            Turning off cloud sync stops mirroring changes to the server. Your vault
            and its Secret Key stay on this device.
          </p>
          <button class="btn-ghost wide danger" @click="doDisable">Turn off cloud sync</button>
        </template>

        <!-- Not enabled, cloud chosen: registration form. -->
        <template v-else-if="!vault.syncEnabled && mode === 'cloud'">
          <label class="field">
            <span>Server URL</span>
            <input
              v-model="serverUrl"
              type="url"
              spellcheck="false"
              placeholder="http://localhost:8787"
            />
          </label>
          <label class="field">
            <span>Email <em>(optional)</em></span>
            <input v-model="email" type="email" spellcheck="false" placeholder="you@example.com" />
          </label>
          <p class="note">
            A new account is created on the server. It only ever stores your
            <b>encrypted</b> vault — never your master password or Secret Key.
          </p>
          <button class="btn-add wide" :disabled="busy || !serverUrl.trim()" @click="doEnable">
            {{ busy ? 'Enabling…' : 'Enable cloud sync' }}
          </button>
        </template>

        <!-- Not enabled, on-device chosen: the default resting state. -->
        <template v-else>
          <p class="note">
            Your vault is stored only in this browser. Pick <b>Cloud sync</b> above to
            mirror it to a server and use it on more devices.
          </p>
        </template>
      </div>

      <div class="dlg-ft">
        <button class="btn-ghost" @click="emit('close')">Done</button>
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
.panel {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 0.8rem 0.9rem;
}
.kv {
  display: flex;
  align-items: baseline;
  gap: 0.6rem;
  font-size: 0.83rem;
}
.kv .k {
  color: var(--faint);
  width: 4.5rem;
  flex: none;
}
.kv .v {
  color: var(--ink);
  word-break: break-all;
}
.kv code.v {
  font-family: var(--mono);
  font-size: 0.78rem;
}
.status.synced {
  color: var(--accent-ink);
}
.status.error {
  color: var(--weak);
}
.status.syncing {
  color: var(--muted);
}
.field {
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
  font-size: 0.83rem;
}
.field span {
  color: var(--faint);
}
.field em {
  font-style: normal;
  color: var(--muted);
}
.field input {
  border: 1px solid var(--line);
  background: var(--surface-2);
  border-radius: 9px;
  padding: 0.5rem 0.65rem;
  color: var(--ink);
  font-size: 0.86rem;
  outline: none;
}
.field input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-soft);
}
.adddev {
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
}
.keybox {
  background: var(--accent-soft);
  border: 1px solid var(--accent);
  border-radius: 12px;
  padding: 0.85rem;
  text-align: center;
}
.key {
  font-family: var(--mono);
  font-size: 0.9rem;
  letter-spacing: 0.04em;
  color: var(--accent-ink);
  font-weight: 600;
  word-break: break-all;
}
.tok-actions {
  display: flex;
}
.tok-actions .btn-ghost {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.4rem;
}
.tok-actions svg {
  width: 15px;
  height: 15px;
}
.note {
  margin: 0;
  color: var(--muted);
  font-size: 0.82rem;
  line-height: 1.55;
}
.devices {
  display: flex;
  flex-direction: column;
  gap: 0.55rem;
  border-top: 1px solid var(--line);
  padding-top: 0.85rem;
}
.devices-hd {
  display: flex;
  align-items: center;
}
.devices-hd h3 {
  margin: 0;
  font-size: 0.9rem;
  font-weight: 600;
  letter-spacing: -0.01em;
}
.devices-hd .icon-btn {
  margin-left: auto;
}
.devices-hd .icon-btn svg {
  width: 15px;
  height: 15px;
}
.dev-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
}
.dev {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  padding: 0.6rem 0.75rem;
  border: 1px solid var(--line);
  border-radius: 10px;
}
.dev-main {
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
  min-width: 0;
  flex: 1;
}
.dev-label {
  font-weight: 600;
  font-size: 0.86rem;
  color: var(--ink);
  word-break: break-word;
}
.dev-meta {
  color: var(--muted);
  font-size: 0.78rem;
}
.badge {
  flex: none;
  font-size: 0.72rem;
  font-weight: 600;
  color: var(--accent-ink);
  background: var(--accent-soft);
  border: 1px solid var(--accent);
  border-radius: 999px;
  padding: 0.2rem 0.55rem;
}
.btn-ghost.sm {
  flex: none;
  padding: 0.3rem 0.65rem;
  font-size: 0.8rem;
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
.btn-ghost:disabled,
.btn-add:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.wide {
  width: 100%;
  text-align: center;
}
.btn-add.wide {
  padding: 0.55rem 0.9rem;
}
.btn-ghost.danger {
  color: var(--weak);
  border-color: var(--weak-soft);
}
.btn-ghost.danger:hover {
  background: var(--weak-soft);
  color: var(--weak);
}
</style>
