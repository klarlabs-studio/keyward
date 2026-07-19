// The family-sharing session store: this device's member identity, the family
// vaults it belongs to, the currently-open one (decrypted in memory), and every
// group mutation (which reseals via WASM and pushes to the zero-knowledge relay).
// Kept separate from the personal-vault store so the personal 3-pane is untouched.

import { defineStore } from 'pinia';
import type { Entry, Login } from '../lib/passbook-types';
import { getSecretKey, nowUnix } from '../lib/passbook';
import * as share from '../lib/sharing';
import type { FamilyVault, GroupRef, MemberIdentity } from '../lib/sharing';
import { fetchAccount, planLabel, startCheckout, type AccountInfo } from '../lib/account';
import { toast } from '../composables/useToast';

interface ShareState {
  available: boolean;
  identity: MemberIdentity | null;
  groups: GroupRef[];
  active: FamilyVault | null;
  busy: boolean;
  // The last minted invite, shown once to copy out-of-band.
  invite: { code: string; expiresEpoch: number } | null;
  // Which family vault (if any) is currently shown in the MAIN 3-pane view.
  // null = the personal vault is shown.
  mainGroupId: string | null;
  // The selected shared entry in the main view.
  selectedSharedId: string | null;
  // The account's entitlements (plan + device usage), or null if unknown.
  account: AccountInfo | null;
  // A Secret Key just revealed from a recovery blob, shown until dismissed.
  revealedRecovery: { forName: string; secret: string } | null;
}

export const useShareStore = defineStore('share', {
  state: (): ShareState => ({
    available: share.sharingAvailable(),
    identity: share.memberIdentity(),
    groups: share.joinedGroups(),
    active: null,
    busy: false,
    invite: null,
    mainGroupId: null,
    selectedSharedId: null,
    account: null,
    revealedRecovery: null,
  }),

  getters: {
    isOwner(s): boolean {
      const id = s.identity?.id;
      return !!s.active?.members.some((m) => m.role === 'owner' && m.member_id === id);
    },
    /** Whether I may invite/remove members in the open vault (Admin or Owner). */
    canManageMembers(s): boolean {
      const id = s.identity?.id;
      const me = s.active?.members.find((m) => m.member_id === id);
      return !!me && share.canManageMembers(me.role);
    },
    /** Whether this account may create/own a family vault (Family plan). */
    canShare(s): boolean {
      return s.account?.can_share ?? false;
    },
    /** Human label for the current plan (defaults to Free when unknown). */
    planName(s): string {
      return planLabel(s.account?.plan ?? 'free');
    },
    /** Real shared items (recovery blobs are infrastructure, not items). */
    sharedItems(s) {
      return s.active ? share.visibleEntries(s.active.entries) : [];
    },
    /** Recovery blobs family members entrusted to me. */
    recoveryHeld(s) {
      const id = s.identity?.id;
      return s.active && id ? share.recoveryHeldBy(s.active.entries, id) : [];
    },
    /** My own recovery contact, if set. */
    myRecovery(s) {
      const id = s.identity?.id;
      return s.active && id ? share.myRecoveryContact(s.active.entries, id) : null;
    },
    /** The family vault shown in the main view (loaded and matching), or null. */
    mainVault(s): FamilyVault | null {
      return s.active && s.active.groupId === s.mainGroupId ? s.active : null;
    },
    /** The selected shared entry in the main view. */
    selectedShared(s): Entry | null {
      if (!s.active || s.active.groupId !== s.mainGroupId) return null;
      return s.active.entries.find((e) => e.id === s.selectedSharedId) ?? null;
    },
  },

  actions: {
    /** Re-read availability + local registry (call when the sync state changes). */
    refresh() {
      this.available = share.sharingAvailable();
      this.identity = share.memberIdentity();
      this.groups = share.joinedGroups();
    },

    /** Load the account's entitlements from the server (best-effort). */
    async loadAccount() {
      this.account = await fetchAccount();
    },

    /**
     * Start hosted Stripe Checkout for the Family plan and redirect. On a
     * deployment without billing (e.g. self-host) this explains rather than fails
     * silently, and re-checks the plan in case it changed elsewhere.
     */
    async upgrade() {
      this.busy = true;
      try {
        const result = await startCheckout();
        if ('url' in result) {
          window.location.href = result.url;
          return;
        }
        if (result.error === 'no-sync') {
          toast('Turn on cloud sync first.');
        } else if (result.error === 'not-configured') {
          toast('This server has no billing configured — upgrade via your cloud provider.');
        } else {
          toast('Could not start checkout — please try again.');
        }
        await this.loadAccount();
      } finally {
        this.busy = false;
      }
    },

    /** Create a new family vault owned by this device, and open it. */
    async createVault(memberName: string, vaultName: string): Promise<boolean> {
      this.busy = true;
      try {
        const groupId = await share.createFamilyVault(memberName, vaultName);
        this.refresh();
        await this.open(groupId, vaultName || 'Family vault');
        toast('Family vault created');
        return true;
      } catch (e) {
        toast(e instanceof Error ? e.message : 'Could not create the family vault');
        return false;
      } finally {
        this.busy = false;
      }
    },

    /** Join a family vault from a shareable invite (`groupId.code`), and open it. */
    async join(invite: string, memberName: string, vaultName: string): Promise<boolean> {
      this.busy = true;
      try {
        const groupId = await share.joinFamilyVault(invite, memberName, vaultName);
        this.refresh();
        await this.open(groupId, vaultName || 'Family vault');
        toast('Joined the family vault');
        return true;
      } catch (e) {
        toast(e instanceof Error ? e.message : 'Could not join');
        return false;
      } finally {
        this.busy = false;
      }
    },

    /** Load a family vault (decrypting its content) and make it the active one. */
    async open(groupId: string, name: string): Promise<void> {
      this.busy = true;
      this.invite = null;
      try {
        this.active = await share.loadFamily(groupId, name);
        // Opening is what completes a pending invite (only a device holding the
        // key can grant access). Say so, so the owner knows it happened.
        const granted = this.active.justGranted;
        if (granted.length > 0) {
          toast(
            granted.length === 1
              ? `${granted[0]} can now open this vault`
              : `${granted.length} members can now open this vault`,
          );
        }
      } catch (e) {
        toast(e instanceof Error ? e.message : 'Could not open the family vault');
      } finally {
        this.busy = false;
      }
    },

    /** Reload the currently-open vault (e.g. after another member changed it). */
    async reloadActive(): Promise<void> {
      if (this.active) await this.open(this.active.groupId, this.active.name);
    },

    close() {
      this.active = null;
      this.invite = null;
    },

    /** Show a family vault in the main 3-pane view (loading it if needed). */
    async showInMain(ref: GroupRef): Promise<void> {
      await this.open(ref.groupId, ref.name);
      this.mainGroupId = ref.groupId;
      const first = this.active?.entries[0]?.id ?? null;
      this.selectedSharedId = first;
    },

    /** Return the main view to the personal vault. */
    showPersonal() {
      this.mainGroupId = null;
      this.selectedSharedId = null;
    },

    /** Select a shared entry in the main view. */
    selectShared(id: string) {
      this.selectedSharedId = id;
    },

    /** Mint a single-use invite for the open vault and surface it to copy. */
    async createInvite(): Promise<void> {
      if (!this.active) return;
      this.busy = true;
      try {
        const { code, expiresEpoch } = await share.inviteToFamily(this.active.groupId);
        this.invite = { code: share.formatInvite(this.active.groupId, code), expiresEpoch };
      } catch (e) {
        toast(e instanceof Error ? e.message : 'Could not create an invite');
      } finally {
        this.busy = false;
      }
    },

    /** Add a login to the open family vault and push it to the relay. */
    async addLogin(input: { title: string; login: Login }): Promise<boolean> {
      if (!this.active || !this.active.hasAccess) return false;
      this.busy = true;
      try {
        const entry: Entry = {
          id: `e${Date.now().toString(36)}`,
          title: input.title,
          tags: [],
          favorite: false,
          updated_epoch: nowUnix(),
          content: { Login: input.login },
        };
        const next = [entry, ...this.active.entries];
        const version = await share.saveFamilyEntries(
          this.active.groupId,
          next,
          this.active.contentVersion,
        );
        this.active.entries = next;
        this.active.contentVersion = version;
        this.selectedSharedId = entry.id;
        return true;
      } catch (e) {
        toast(e instanceof Error ? e.message : 'Could not add the item');
        return false;
      } finally {
        this.busy = false;
      }
    },

    /** Remove a shared item and push the change. */
    async removeEntry(id: string): Promise<void> {
      if (!this.active || !this.active.hasAccess) return;
      this.busy = true;
      try {
        const next = this.active.entries.filter((e) => e.id !== id);
        const version = await share.saveFamilyEntries(
          this.active.groupId,
          next,
          this.active.contentVersion,
        );
        this.active.entries = next;
        this.active.contentVersion = version;
        if (this.selectedSharedId === id) {
          this.selectedSharedId = next[0]?.id ?? null;
        }
      } catch (e) {
        toast(e instanceof Error ? e.message : 'Could not remove the item');
      } finally {
        this.busy = false;
      }
    },

    /**
     * Name a family member as my recovery contact: seal this device's Secret Key
     * to them and store it in the shared vault. If I ever lose my Emergency Kit,
     * they can read it back to me — they still can't open my vault without my
     * master password.
     */
    async setRecoveryContact(contact: share.GroupMemberView): Promise<void> {
      if (!this.active?.hasAccess || !this.identity) return;
      const secretKey = getSecretKey();
      if (!secretKey) {
        toast('No Secret Key on this device to protect.');
        return;
      }
      this.busy = true;
      try {
        const next = await share.withRecoveryContact(
          this.active.entries,
          this.identity,
          contact,
          secretKey,
          this.active.groupId,
        );
        const version = await share.saveFamilyEntries(
          this.active.groupId,
          next,
          this.active.contentVersion,
        );
        this.active.entries = next;
        this.active.contentVersion = version;
        toast(`${contact.name || 'They'} can now help you recover your Secret Key`);
      } catch (e) {
        toast(e instanceof Error ? e.message : 'Could not set the recovery contact');
      } finally {
        this.busy = false;
      }
    },

    /** Open a recovery blob a family member entrusted to me. */
    async revealRecovery(payload: share.RecoveryPayload): Promise<void> {
      if (!this.identity) return;
      this.busy = true;
      try {
        this.revealedRecovery = {
          forName: payload.forName,
          secret: await share.revealRecovery(payload, this.identity.secret),
        };
      } catch (e) {
        toast(e instanceof Error ? e.message : 'Could not open that recovery key');
      } finally {
        this.busy = false;
      }
    },

    /** Clear a revealed Secret Key from memory/screen. */
    hideRecovery() {
      this.revealedRecovery = null;
    },

    /** Promote/demote a member (Owner only), then reload the directory. */
    /**
     * Approve a pending member and wrap the vault key to them.
     *
     * Only ever called from an explicit click. This is the irreversible step:
     * once their key is wrapped and uploaded, whoever holds the matching secret
     * can read every shared credential, and revoking afterwards means rotating
     * the vault key and re-sealing everything.
     */
    /**
     * Accept a vault key that differs from the one this device pinned.
     *
     * Explicit action only. If the change was a relay substituting its own key
     * rather than a legitimate rotation, this is the step that gives it the
     * plaintext — so the dialog states that before offering the button.
     */
    async acceptRotatedKey(): Promise<void> {
      if (!this.active) return;
      this.busy = true;
      try {
        await share.acceptRotatedVaultKey(this.active.groupId);
        toast('New vault key accepted');
        await this.reloadActive();
      } catch (e) {
        toast(e instanceof Error ? e.message : 'Could not accept the new key');
      } finally {
        this.busy = false;
      }
    },

    async approveMember(memberId: string, publicKey: string): Promise<void> {
      if (!this.active) return;
      this.busy = true;
      try {
        await share.approveMember(this.active.groupId, memberId, publicKey);
        toast('Member approved — they can now open the shared vault');
        await this.reloadActive();
      } catch (e) {
        // Surfaced verbatim: these messages explain WHY nothing was shared
        // (key changed mid-decision, member gone), which the user needs in
        // order to act, and quietly swallowing them would look like success.
        toast(e instanceof Error ? e.message : 'Could not approve that member');
      } finally {
        this.busy = false;
      }
    },

    async setRole(memberId: string, role: share.Role): Promise<void> {
      if (!this.active) return;
      this.busy = true;
      try {
        await share.setMemberRole(this.active.groupId, memberId, role);
        toast(role === 'admin' ? 'Member promoted to admin' : 'Admin demoted to member');
        await this.reloadActive();
      } catch (e) {
        toast(e instanceof Error ? e.message : 'Could not change the role');
      } finally {
        this.busy = false;
      }
    },

    /** Remove a member and rotate the vault key (true revocation), then reload. */
    async revoke(memberId: string): Promise<void> {
      if (!this.active) return;
      this.busy = true;
      try {
        await share.revokeMember(this.active.groupId, memberId, this.active.entries);
        toast('Member removed and vault key rotated');
        await this.reloadActive();
      } catch (e) {
        toast(e instanceof Error ? e.message : 'Could not remove the member');
      } finally {
        this.busy = false;
      }
    },

    /** Stop tracking a vault on this device (does not touch the server). */
    leave(groupId: string) {
      share.forgetGroup(groupId);
      if (this.active?.groupId === groupId) this.close();
      if (this.mainGroupId === groupId) this.showPersonal();
      this.refresh();
    },
  },
});
