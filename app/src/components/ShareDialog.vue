<script setup lang="ts">
// Family sharing — the management surface. Create or join a family vault, invite
// members (single-use code shared out-of-band), see the member directory, add and
// read shared logins, and remove members (which rotates the vault key). Sharing
// rides on cloud sync, so it prompts to enable that first if it is off.

import { onBeforeUnmount, onMounted, ref } from 'vue';
import { useShareStore } from '@/stores/share';
import { generatePassword } from '@/lib/passbook';
import { copyText } from '@/composables/useToast';

const s = useShareStore();
const emit = defineEmits<{ (e: 'close'): void }>();

const yourName = ref(s.identity?.name ?? '');
const vaultName = ref('Family vault');
const inviteInput = ref('');

// Add-login mini form for the open shared vault.
const addTitle = ref('');
const addUser = ref('');
const addPass = ref('');

onMounted(() => s.refresh());

async function create(): Promise<void> {
  if (!yourName.value.trim()) return;
  await s.createVault(yourName.value, vaultName.value);
}

async function join(): Promise<void> {
  if (!yourName.value.trim() || !inviteInput.value.trim()) return;
  const ok = await s.join(inviteInput.value, yourName.value, 'Family vault');
  if (ok) inviteInput.value = '';
}

async function genPass(): Promise<void> {
  addPass.value = await generatePassword({
    length: 20,
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: true,
    avoidAmbiguous: true,
  });
}

async function addItem(): Promise<void> {
  if (!addTitle.value.trim() || !addPass.value) return;
  const ok = await s.addLogin({
    title: addTitle.value.trim(),
    login: {
      username: addUser.value.trim(),
      password: addPass.value,
      urls: [],
      totp_secret: null,
      has_passkey: false,
    },
  });
  if (ok) {
    addTitle.value = '';
    addUser.value = '';
    addPass.value = '';
  }
}

function onKey(e: KeyboardEvent): void {
  if (e.key === 'Escape') emit('close');
}
onMounted(() => window.addEventListener('keydown', onKey));
onBeforeUnmount(() => window.removeEventListener('keydown', onKey));
</script>

<template>
  <div class="backdrop" @click.self="emit('close')">
    <div class="dialog" role="dialog" aria-modal="true" aria-label="Family sharing">
      <div class="dlg-hd">
        <h2>
          <button v-if="s.active" class="back" title="Back" aria-label="Back" @click="s.close()">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M15 18l-6-6 6-6" />
            </svg>
          </button>
          {{ s.active ? s.active.name : 'Family sharing' }}
        </h2>
        <button class="icon-btn" title="Close" aria-label="Close" @click="emit('close')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M6 6l12 12M18 6 6 18" />
          </svg>
        </button>
      </div>

      <div class="dlg-body">
        <!-- Sharing needs cloud sync. -->
        <p v-if="!s.available" class="note warn">
          Family sharing runs over cloud sync. Turn on <b>Cloud sync</b> first, then
          come back here to create or join a family vault.
        </p>

        <!-- Home: pick / create / join a family vault. -->
        <template v-else-if="!s.active">
          <div v-if="s.groups.length" class="section">
            <div class="lbl">Your family vaults</div>
            <button
              v-for="g in s.groups"
              :key="g.groupId"
              class="row-btn"
              @click="s.open(g.groupId, g.name)"
            >
              <span class="dot"></span>{{ g.name }}
              <span class="chev">›</span>
            </button>
          </div>

          <div class="section">
            <div class="lbl">Your name (shown to family)</div>
            <input v-model="yourName" class="in" placeholder="e.g. Alex" />
          </div>

          <div class="section">
            <div class="lbl">Create a family vault</div>
            <div class="inline">
              <input v-model="vaultName" class="in" placeholder="Family vault" />
              <button class="btn-add" :disabled="s.busy || !yourName.trim()" @click="create">
                Create
              </button>
            </div>
          </div>

          <div class="section">
            <div class="lbl">Join with an invite</div>
            <input v-model="inviteInput" class="in" placeholder="Paste the invite code" />
            <button
              class="btn-ghost full"
              :disabled="s.busy || !yourName.trim() || !inviteInput.trim()"
              @click="join"
            >
              Join family vault
            </button>
          </div>
        </template>

        <!-- An open family vault. -->
        <template v-else>
          <div v-if="s.active.removed" class="section">
            <p class="note warn">
              You've been removed from this family vault, so its items are no longer
              available on this device.
            </p>
            <button class="btn-ghost full" @click="s.leave(s.active.groupId)">
              Remove it from this device
            </button>
          </div>

          <p v-else-if="!s.active.hasAccess" class="note warn">
            You've joined, but a member hasn't granted your device access yet. Ask
            them to open this family vault, then
            <a href="#" @click.prevent="s.reloadActive()">reload</a>.
          </p>

          <div v-if="!s.active.removed" class="section">
            <div class="lbl">Members ({{ s.active.members.length }})</div>
            <div v-for="m in s.active.members" :key="m.member_id" class="member">
              <span class="dot"></span>
              <span class="m-name">{{ m.name || m.member_id }}</span>
              <span v-if="m.is_owner" class="tag">Owner</span>
              <span v-else-if="m.member_id === s.identity?.id" class="tag you">You</span>
              <button
                v-if="s.isOwner && !m.is_owner"
                class="mini danger"
                title="Remove member"
                @click="s.revoke(m.member_id)"
              >
                Remove
              </button>
            </div>
          </div>

          <div v-if="!s.active.removed" class="section">
            <div class="lbl">Invite someone</div>
            <button class="btn-ghost full" :disabled="s.busy" @click="s.createInvite()">
              Create an invite code
            </button>
            <div v-if="s.invite" class="invite">
              <code>{{ s.invite.code }}</code>
              <button class="mini" title="Copy" @click="copyText(s.invite.code)">Copy</button>
              <p class="hint">
                Share this once, over a channel your family trusts (in person, a private
                message). It expires and can be used once.
              </p>
            </div>
          </div>

          <template v-if="s.active.hasAccess">
            <div class="section">
              <div class="lbl">Shared items ({{ s.active.entries.length }})</div>
              <p v-if="!s.active.entries.length" class="empty">No shared items yet.</p>
              <div v-for="e in s.active.entries" :key="e.id" class="item">
                <div class="i-body">
                  <b>{{ e.title }}</b>
                  <span v-if="'Login' in e.content">{{ e.content.Login.username }}</span>
                </div>
                <button
                  v-if="'Login' in e.content"
                  class="mini"
                  title="Copy password"
                  @click="copyText(e.content.Login.password)"
                >
                  Copy
                </button>
                <button class="mini danger" title="Remove" @click="s.removeEntry(e.id)">×</button>
              </div>
            </div>

            <div class="section add">
              <div class="lbl">Add a login</div>
              <input v-model="addTitle" class="in" placeholder="Title (e.g. Home Wi-Fi)" />
              <input v-model="addUser" class="in" placeholder="Username (optional)" />
              <div class="inline">
                <input v-model="addPass" class="in" placeholder="Password" />
                <button class="btn-ghost" title="Generate" @click="genPass">Generate</button>
              </div>
              <button
                class="btn-add full"
                :disabled="s.busy || !addTitle.trim() || !addPass"
                @click="addItem"
              >
                Add to family vault
              </button>
            </div>
          </template>
        </template>
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
  width: min(480px, 100%);
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
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.dlg-hd .icon-btn {
  margin-left: auto;
}
.back {
  display: grid;
  place-items: center;
  color: var(--muted);
}
.back svg {
  width: 18px;
  height: 18px;
}
.dlg-body {
  padding: 1.1rem 1.3rem;
  display: flex;
  flex-direction: column;
  gap: 1.1rem;
}
.section {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}
.lbl {
  font-size: 0.7rem;
  font-weight: 700;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: var(--muted);
}
.in {
  width: 100%;
  border: 1px solid var(--line);
  border-radius: 9px;
  padding: 0.5rem 0.7rem;
  background: var(--surface-2);
  color: var(--ink);
  font-size: 0.9rem;
}
.in:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-soft);
}
.inline {
  display: flex;
  gap: 0.5rem;
}
.inline .in {
  flex: 1;
  min-width: 0;
}
.btn-add {
  background: var(--accent);
  color: #fff;
  padding: 0.5rem 0.9rem;
  border-radius: 9px;
  font-weight: 600;
  font-size: 0.85rem;
  white-space: nowrap;
}
.btn-add:disabled {
  opacity: 0.5;
}
.btn-ghost {
  padding: 0.5rem 0.9rem;
  border-radius: 9px;
  font-weight: 600;
  font-size: 0.85rem;
  color: var(--muted);
  border: 1px solid var(--line);
  white-space: nowrap;
}
.btn-ghost:hover {
  background: var(--surface-2);
  color: var(--ink);
}
.btn-ghost:disabled {
  opacity: 0.5;
}
.full {
  width: 100%;
}
.row-btn {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.6rem 0.7rem;
  border: 1px solid var(--line);
  border-radius: 9px;
  font-size: 0.9rem;
  color: var(--ink);
  text-align: left;
}
.row-btn:hover {
  background: var(--surface-2);
}
.row-btn .chev {
  margin-left: auto;
  color: var(--faint);
}
.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--accent);
  flex: none;
}
.member {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.9rem;
}
.m-name {
  color: var(--ink);
}
.tag {
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.03em;
  text-transform: uppercase;
  color: var(--accent-ink);
  background: var(--accent-soft);
  padding: 0.1rem 0.4rem;
  border-radius: 999px;
}
.tag.you {
  color: var(--muted);
  background: var(--surface-2);
}
.mini {
  margin-left: auto;
  font-size: 0.78rem;
  font-weight: 600;
  color: var(--muted);
  border: 1px solid var(--line);
  border-radius: 7px;
  padding: 0.22rem 0.5rem;
}
.mini:hover {
  background: var(--surface-2);
  color: var(--ink);
}
.mini.danger:hover {
  color: var(--weak);
  border-color: var(--weak);
}
.member .mini {
  margin-left: auto;
}
.invite {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem;
  background: var(--surface-2);
  border: 1px solid var(--line);
  border-radius: 9px;
  padding: 0.6rem 0.7rem;
}
.invite code {
  font-family: var(--mono);
  font-size: 0.8rem;
  word-break: break-all;
  flex: 1;
  min-width: 0;
}
.invite .hint {
  flex-basis: 100%;
  margin: 0;
  font-size: 0.76rem;
  color: var(--muted);
  line-height: 1.5;
}
.item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.45rem 0;
  border-bottom: 1px solid var(--line);
}
.i-body {
  display: flex;
  flex-direction: column;
  min-width: 0;
}
.i-body b {
  font-size: 0.88rem;
}
.i-body span {
  font-size: 0.78rem;
  color: var(--muted);
}
.empty {
  margin: 0;
  color: var(--muted);
  font-size: 0.83rem;
}
.add {
  border-top: 1px solid var(--line);
  padding-top: 1rem;
}
.note {
  margin: 0;
  border-radius: 10px;
  padding: 0.7rem 0.85rem;
  font-size: 0.83rem;
  line-height: 1.55;
}
.note.warn {
  background: var(--warn-soft);
  color: var(--warn);
}
.note a {
  color: inherit;
  font-weight: 700;
  text-decoration: underline;
}
</style>
