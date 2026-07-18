// The family-sharing session store: this device's member identity, the family
// vaults it belongs to, the currently-open one (decrypted in memory), and every
// group mutation (which reseals via WASM and pushes to the zero-knowledge relay).
// Kept separate from the personal-vault store so the personal 3-pane is untouched.

import { defineStore } from 'pinia';
import type { Entry, Login } from '../lib/passbook-types';
import { nowUnix } from '../lib/passbook';
import * as share from '../lib/sharing';
import type { FamilyVault, GroupRef, MemberIdentity } from '../lib/sharing';
import { toast } from '../composables/useToast';

interface ShareState {
  available: boolean;
  identity: MemberIdentity | null;
  groups: GroupRef[];
  active: FamilyVault | null;
  busy: boolean;
  // The last minted invite, shown once to copy out-of-band.
  invite: { code: string; expiresEpoch: number } | null;
}

export const useShareStore = defineStore('share', {
  state: (): ShareState => ({
    available: share.sharingAvailable(),
    identity: share.memberIdentity(),
    groups: share.joinedGroups(),
    active: null,
    busy: false,
    invite: null,
  }),

  getters: {
    isOwner(s): boolean {
      const id = s.identity?.id;
      return !!s.active?.members.some((m) => m.is_owner && m.member_id === id);
    },
  },

  actions: {
    /** Re-read availability + local registry (call when the sync state changes). */
    refresh() {
      this.available = share.sharingAvailable();
      this.identity = share.memberIdentity();
      this.groups = share.joinedGroups();
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
      } catch (e) {
        toast(e instanceof Error ? e.message : 'Could not remove the item');
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
      this.refresh();
    },
  },
});
