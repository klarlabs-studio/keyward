<script setup lang="ts">
// Family sharing — the management surface. Create or join a family vault, invite
// members (single-use code shared out-of-band), see the member directory, add and
// read shared logins, and remove members (which rotates the vault key). Sharing
// rides on cloud sync, so it prompts to enable that first if it is off.

import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
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

onMounted(() => {
  s.refresh();
  s.loadAccount();
});

async function create(): Promise<void> {
  if (!yourName.value.trim()) return;
  await s.createVault(yourName.value, vaultName.value);
}

/** What each plan includes. Prices are set per-deployment, so none are shown here. */
const PLANS = [
  {
    id: 'free',
    name: 'Free',
    features: ['Personal vault', 'Up to 2 devices', 'Watchtower checks', 'Self-host, unlimited'],
  },
  {
    id: 'individual',
    name: 'Individual',
    features: ['Unlimited devices', 'AI credential broker', 'Priority sync'],
  },
  {
    id: 'family',
    name: 'Family',
    features: ['Everything in Individual', 'Shared family vaults', 'Invite your family'],
  },
];

const currentPlan = computed(() => s.account?.plan ?? 'free');

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
        <!-- Honesty: the sharing crypto has not had a formal external review yet. -->
        <p class="note proto">
          <b>Prototype.</b> Family sharing works, but its cryptography hasn't had an
          independent security review yet. Don't trust it with irreplaceable secrets
          until it has.
        </p>

        <!-- Current plan (once cloud sync is on). -->
        <div v-if="s.available" class="planline">
          <span class="dot"></span>Plan: <b>{{ s.planName }}</b>
          <span v-if="s.account" class="pmuted">
            · {{ s.account.devices }}<template v-if="s.account.device_limit"> / {{ s.account.device_limit }}</template>
            device{{ s.account.devices === 1 ? '' : 's' }}
          </span>
        </div>

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

          <div v-if="s.canShare" class="section">
            <div class="lbl">Create a family vault</div>
            <div class="inline">
              <input v-model="vaultName" class="in" placeholder="Family vault" />
              <button class="btn-add" :disabled="s.busy || !yourName.trim()" @click="create">
                Create
              </button>
            </div>
          </div>

          <!-- Free / Individual: creating a family vault needs the Family plan. -->
          <div v-else class="section">
            <div class="lbl">Create a family vault</div>
            <p class="note upgrade">
              Creating a family vault is a <b>Family plan</b> feature. Upgrade to share
              vaults with your family — you can still <b>join</b> a vault someone invites
              you to on any plan.
            </p>

            <div class="plans">
              <div
                v-for="p in PLANS"
                :key="p.id"
                class="plan"
                :class="{ cur: p.id === currentPlan }"
              >
                <div class="p-hd">
                  <b>{{ p.name }}</b>
                  <span v-if="p.id === currentPlan" class="tag you">Current</span>
                </div>
                <ul>
                  <li v-for="f in p.features" :key="f">{{ f }}</li>
                </ul>
              </div>
            </div>

            <button class="btn-add full" :disabled="s.busy" @click="s.upgrade()">
              Upgrade to Family
            </button>
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
            <b>You're in — waiting for the key.</b> Your family's secrets can only be
            unlocked by someone who already has them, so nothing here is readable
            until one of them opens this vault once. Ask any member to open Proctor,
            then <a href="#" @click.prevent="s.reloadActive()">check again</a>.
          </p>

          <!--
            The wrapped-key set could not be authenticated. Distinct from a
            changed vault key: that asks "is this key the one I accepted?", this
            asks "did a member actually write this at all?" — the question a
            relay minting its own key and wrapping it to everyone would otherwise
            pass unchallenged.
          -->
          <div
            v-if="s.active.keysTrust === 'bad-signature' || s.active.keysTrust === 'unknown-signer'"
            class="section keychanged"
          >
            <div class="lbl">These shared keys can't be trusted</div>
            <p class="kc-body" v-if="s.active.keysTrust === 'bad-signature'">
              The keys for this vault carry a signature that <b>doesn't check out</b>. That is
              not something that happens by accident — it means the keys were changed by
              someone who isn't a member you've trusted.
            </p>
            <p class="kc-body" v-else>
              These keys were signed by <b>someone this device doesn't recognise</b>. It could
              be a family member you haven't trusted yet — or it could be the server.
              There's no way to tell from here.
            </p>
            <p class="kc-check">
              Nothing has been read and nothing has been shared. Contact your family out of
              band — a call or in person, not through this app — before using this vault
              again.
            </p>
          </div>

          <!--
            Pre-signing vault: readable, but nobody has proven authorship. Offered
            as an upgrade rather than a block, because blocking every vault that
            predates signing would strand real families — and the vault-key pin
            still catches a substitution in the meantime.
          -->
          <div v-if="s.active.keysTrust === 'unsigned'" class="section pending">
            <div class="lbl">These shared keys aren't signed yet</div>
            <p class="pending-why">
              This vault was set up before Proctor signed shared keys, so there's no way to
              prove who wrote them. Signing them now means your family can verify every
              change from here on.
            </p>
            <p class="pending-why">
              Only do this if the items below look right and the safety number matches what
              your family sees. You're vouching for these keys — this device can't check
              them for you.
            </p>
            <button class="approve" :disabled="s.busy" @click="s.adoptUnsignedKeys()">
              These are my family's keys — sign them
            </button>
          </div>

          <!--
            The shared vault key changed. Entries are deliberately not shown and
            nothing is re-sealed until the user decides: re-sealing under a key
            we have not accepted is exactly what hands a substituting relay the
            plaintext.
          -->
          <div v-if="s.active.vaultKeyChanged" class="section keychanged">
            <div class="lbl">This vault's key changed</div>
            <p class="kc-body">
              The shared key protecting these items is not the one this device saw last time.
              <b>Usually that means somebody removed a member</b> — removing someone replaces
              the key so they can't read anything new.
            </p>
            <p class="kc-body">
              But a compromised server would look identical from here. Until you accept it,
              nothing is read and nothing is re-encrypted.
            </p>
            <p class="kc-check">
              Ask your family, out of band — a call or in person, not through this app —
              whether someone was just removed. If nobody was, <b>do not accept</b>: tell the
              others and stop using this vault.
            </p>
            <button class="approve danger" :disabled="s.busy" @click="s.acceptRotatedKey()">
              Someone was removed — accept the new key
            </button>
          </div>

          <!--
            Pending approvals. Nothing has been shared with these people yet.

            This exists because granting used to happen silently on every load,
            against whatever key the server reported — which meant the server
            could add a member and be handed the vault key. Approval is now an
            explicit act, and it is irreversible in practice: undoing it means
            rotating the vault key and re-sealing every item.
          -->
          <div
            v-if="!s.active.removed && s.active.pendingApproval.length > 0"
            class="section pending"
          >
            <div class="lbl">Waiting for your approval ({{ s.active.pendingApproval.length }})</div>
            <p class="pending-why">
              Nothing has been shared with them yet. Check the safety number below with them
              directly — in person or by phone, not through this app — before approving.
            </p>
            <div v-for="p in s.active.pendingApproval" :key="p.memberId" class="member pending-row">
              <span class="dot" :class="{ warn: p.state === 'changed' }"></span>
              <span class="m-name">{{ p.name }}</span>
              <span v-if="p.state === 'changed'" class="tag danger">Key changed</span>
              <span v-else class="tag">New</span>
              <button
                class="approve"
                :class="{ danger: p.state === 'changed' }"
                :disabled="s.busy"
                @click="s.approveMember(p.memberId, p.publicKey)"
              >
                Approve
              </button>
            </div>
            <p v-if="s.active.pendingApproval.some((p) => p.state === 'changed')" class="danger-note">
              A member’s key changed. That happens legitimately when someone reinstalls or
              switches device — but it is also exactly what a compromised server would do to
              read your shared items. Confirm with them out of band before approving.
            </p>
          </div>

          <div v-if="!s.active.removed" class="section">
            <div class="lbl">Members ({{ s.active.members.length }})</div>
            <div v-for="m in s.active.members" :key="m.member_id" class="member">
              <span class="dot"></span>
              <span class="m-name">{{ m.name || m.member_id }}</span>
              <span v-if="m.role === 'owner'" class="tag">Owner</span>
              <span v-else-if="m.role === 'admin'" class="tag">Admin</span>
              <span v-if="m.member_id === s.identity?.id" class="tag you">You</span>
              <!-- Owner can promote/demote; owners themselves are immutable. -->
              <button
                v-if="s.isOwner && m.role !== 'owner'"
                class="mini"
                :title="m.role === 'admin' ? 'Demote to member' : 'Promote to admin'"
                @click="s.setRole(m.member_id, m.role === 'admin' ? 'member' : 'admin')"
              >
                {{ m.role === 'admin' ? 'Demote' : 'Make admin' }}
              </button>
              <!-- Admin or Owner can remove; an Owner is never removable. -->
              <button
                v-if="s.canManageMembers && m.role !== 'owner'"
                class="mini danger"
                title="Remove member"
                @click="s.revoke(m.member_id)"
              >
                Remove
              </button>
            </div>

            <!-- Out-of-band verification: the one attack ciphertext can't reveal. -->
            <div v-if="s.active.safety" class="safety">
              <div class="s-num">{{ s.active.safety }}</div>
              <p class="hint">
                <b>Safety number.</b> Compare this with your family in person or on a
                call. If everyone sees the same number, no one has been secretly added
                — if it differs, stop and don't share anything.
              </p>
              <p class="hint">
                This number <b>changed in this version</b> — it now also covers the keys
                that prove who changed your shared items. If it doesn't match one you
                wrote down before, that's expected. Compare a fresh one with your family:
                what matters is that you all see the same number today.
              </p>
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
            <!-- Recovery: the answer to "I lost my Emergency Kit". -->
            <div class="section">
              <div class="lbl">Recovery</div>
              <p v-if="s.myRecovery" class="note ok">
                <b>{{ s.myRecovery.toName || 'A family member' }}</b> holds a sealed copy
                of your Secret Key. If you lose your Emergency Kit, ask them to read it
                back — they still can't open your vault without your master password.
              </p>
              <template v-else>
                <p class="hint">
                  Lose your Emergency Kit and your vault is gone. Pick a family member to
                  hold a sealed copy of your Secret Key — only they can open it, and it
                  still isn't enough to unlock your vault without your master password.
                </p>
                <button
                  v-for="m in s.active.members.filter((x) => x.member_id !== s.identity?.id)"
                  :key="m.member_id"
                  class="btn-ghost full"
                  :disabled="s.busy"
                  @click="s.setRecoveryContact(m)"
                >
                  Make {{ m.name || m.member_id }} my recovery contact
                </button>
                <p v-if="s.active.members.length < 2" class="empty">
                  Invite someone first — you need a family member to hold it.
                </p>
              </template>

              <template v-if="s.recoveryHeld.length">
                <div class="lbl" style="margin-top: 0.6rem">Recovery keys you hold</div>
                <div v-for="r in s.recoveryHeld" :key="r.for" class="member">
                  <span class="dot"></span>
                  <span class="m-name">{{ r.forName || r.for }}</span>
                  <button class="mini" :disabled="s.busy" @click="s.revealRecovery(r)">
                    Reveal
                  </button>
                </div>
                <div v-if="s.revealedRecovery" class="invite">
                  <code>{{ s.revealedRecovery.secret }}</code>
                  <button class="mini" title="Copy" @click="copyText(s.revealedRecovery.secret)">
                    Copy
                  </button>
                  <button class="mini" @click="s.hideRecovery()">Hide</button>
                  <p class="hint">
                    {{ s.revealedRecovery.forName }}'s Secret Key — read it back to them
                    over a channel you trust. They also need their master password.
                  </p>
                </div>
              </template>
            </div>

            <div class="section">
              <div class="lbl">Shared items ({{ s.sharedItems.length }})</div>
              <p v-if="!s.sharedItems.length" class="empty">No shared items yet.</p>
              <div v-for="e in s.sharedItems" :key="e.id" class="item">
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
.note.proto {
  background: var(--accent-soft);
  color: var(--accent-ink);
  border: 1px solid var(--accent);
}
.note.proto b {
  color: var(--accent-ink);
}
.note.upgrade {
  background: var(--accent-soft);
  color: var(--accent-ink);
}
.note.ok {
  background: var(--surface-2);
  color: var(--ink);
  border: 1px solid var(--line);
}
.section > .hint {
  margin: 0;
  font-size: 0.79rem;
  color: var(--muted);
  line-height: 1.55;
}
.note.upgrade b {
  color: var(--accent-ink);
}
.plans {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}
.plan {
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 0.6rem 0.75rem;
}
.plan.cur {
  border-color: var(--accent);
  background: var(--accent-soft);
}
.p-hd {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.88rem;
}
.plan ul {
  margin: 0.35rem 0 0;
  padding-left: 1.05rem;
  color: var(--muted);
  font-size: 0.8rem;
  line-height: 1.6;
}
.safety {
  margin-top: 0.35rem;
  border: 1px solid var(--line);
  border-radius: 9px;
  padding: 0.6rem 0.7rem;
  background: var(--surface-2);
}
.s-num {
  font-family: var(--mono);
  font-size: 0.86rem;
  letter-spacing: 0.04em;
  color: var(--ink);
  word-spacing: 0.3em;
}
.safety .hint {
  margin: 0.35rem 0 0;
  font-size: 0.76rem;
  color: var(--muted);
  line-height: 1.5;
}
.planline {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.83rem;
  color: var(--ink);
}
.planline b {
  font-weight: 700;
}
.pmuted {
  color: var(--muted);
}
.note a {
  color: inherit;
  font-weight: 700;
  text-decoration: underline;
}

/* Pending approvals — deliberately visually distinct from the member list:
   these people have NOT been given access, and the difference must be obvious
   at a glance rather than inferred from a label. */
.pending {
  border: 1px solid var(--warn-border, #d9a441);
  border-radius: 8px;
  padding: 0.75rem;
  background: color-mix(in srgb, var(--warn-border, #d9a441) 8%, transparent);
}
.pending-why {
  margin: 0.25rem 0 0.6rem;
  font-size: 0.85rem;
  opacity: 0.85;
}
.pending-row {
  gap: 0.5rem;
}
.dot.warn {
  background: var(--danger, #d64545);
}
.tag.danger {
  background: var(--danger, #d64545);
  color: #fff;
}
.approve {
  margin-left: auto;
  padding: 0.25rem 0.7rem;
  border-radius: 6px;
  cursor: pointer;
}
.approve.danger {
  border-color: var(--danger, #d64545);
  color: var(--danger, #d64545);
}
.approve:disabled {
  opacity: 0.5;
  cursor: default;
}
.danger-note {
  margin: 0.6rem 0 0;
  font-size: 0.82rem;
  color: var(--danger, #d64545);
}

/* Vault-key change — the most consequential decision in this dialog, so it is
   styled as a stop rather than a notice. */
.keychanged {
  border: 1px solid var(--danger, #d64545);
  border-radius: 8px;
  padding: 0.85rem;
  background: color-mix(in srgb, var(--danger, #d64545) 8%, transparent);
}
.kc-body {
  margin: 0.4rem 0;
  font-size: 0.88rem;
  line-height: 1.45;
}
.kc-check {
  margin: 0.6rem 0 0.75rem;
  font-size: 0.88rem;
  line-height: 1.45;
  color: var(--danger, #d64545);
}
</style>
