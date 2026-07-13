// The single source of truth for the unlocked session: the decrypted entries,
// the current filter/selection, and every mutation (which reseals + persists via
// the WASM core). Components read derived getters and call actions; they never
// touch crypto or storage directly.

import { defineStore } from 'pinia';
import type { Category, Entry, Issue, Login } from '../lib/passbook-types';
import { categoryOf } from '../lib/passbook-types';
import {
  clearSecretKey,
  createVault,
  destroyVault,
  getRawVault,
  getSecretKey,
  hasSecretKey,
  isValidSecretKey,
  newSecretKey,
  nowUnix,
  openVault,
  saveVault,
  setRawVault,
  storeSecretKey,
  vaultExists,
  strengthBits,
  watchtower,
} from '../lib/passbook';
import * as sync from '../lib/sync';
import { SyncConflict, type SyncConfig } from '../lib/sync';
import { toast } from '../composables/useToast';
import { demoEntries } from '../lib/seed';

/** The steady state of cloud sync, surfaced to the UI as a status indicator. */
export type SyncStatus = 'idle' | 'syncing' | 'error' | 'synced';

export type Filter = 'all' | 'fav' | 'watchtower' | Category;

interface VaultState {
  master: string | null;
  entries: Entry[];
  filter: Filter;
  query: string;
  selectedId: string | null;
  issues: Issue[];
  strengths: Record<string, number>;
  unlockError: string | null;
  busy: boolean;
  // A vault exists on this device but its Secret Key does not — the user must
  // supply it (the "add this device" flow) before the vault can be opened.
  needsSecretKey: boolean;
  // Set once, immediately after first-run creation, so the unlock screen can
  // show the Emergency Kit exactly once. Cleared when acknowledged.
  freshSecretKey: string | null;
  // Cloud sync: whether it is configured on this device, its live status, and
  // the last server vault version this device successfully synced.
  syncEnabled: boolean;
  syncStatus: SyncStatus;
  lastSyncedVersion: string | null;
}

export const CATEGORY_LABEL: Record<Category, string> = {
  Login: 'Logins',
  SecureNote: 'Secure notes',
  Card: 'Cards',
  Identity: 'Identities',
};

/** Deterministic avatar colour per entry (so the list has stable identity). */
const AVATAR_COLORS = [
  '#24292f',
  '#0b6b52',
  '#b71d1a',
  '#1f7ae0',
  '#3b3f7a',
  '#5c6663',
  '#0e8a7c',
  '#8a5a1b',
];

export function avatarColor(id: string): string {
  let h = 0;
  for (let i = 0; i < id.length; i += 1) h = (h * 31 + id.charCodeAt(i)) >>> 0;
  return AVATAR_COLORS[h % AVATAR_COLORS.length];
}

export function initials(title: string): string {
  const words = title.trim().split(/\s+/).filter(Boolean);
  if (words.length === 0) return '?';
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return (words[0][0] + words[1][0]).toUpperCase();
}

/** A short subtitle for the list row, derived from the content. */
export function subtitleOf(entry: Entry): string {
  const c = entry.content;
  if ('Login' in c) return c.Login.username;
  if ('Card' in c) return `•••• ${c.Card.number.replace(/\s/g, '').slice(-4)}`;
  if ('Identity' in c) return c.Identity.email || 'Identity';
  return 'Secure note';
}

export const useVaultStore = defineStore('vault', {
  state: (): VaultState => ({
    master: null,
    entries: [],
    filter: 'all',
    query: '',
    selectedId: null,
    issues: [],
    strengths: {},
    unlockError: null,
    busy: false,
    needsSecretKey: false,
    freshSecretKey: null,
    syncEnabled: sync.isSyncEnabled(),
    syncStatus: 'idle',
    lastSyncedVersion: sync.syncConfig()?.lastVersion ?? null,
  }),

  getters: {
    locked: (s) => s.master === null,
    hasVault: () => vaultExists(),
    // Whether this device holds a Secret Key (i.e. the vault is 2SKD-protected).
    secretKeyProtected: () => hasSecretKey(),
    // The device Secret Key, for the Emergency Kit view (only meaningful unlocked).
    secretKey: () => getSecretKey(),
    // The stored sync configuration (account id, server URL, …), or null.
    syncInfo: (): SyncConfig | null => sync.syncConfig(),

    counts(s): Record<string, number> {
      const by: Record<string, number> = {
        all: s.entries.length,
        fav: s.entries.filter((e) => e.favorite).length,
        Login: 0,
        SecureNote: 0,
        Card: 0,
        Identity: 0,
      };
      for (const e of s.entries) by[categoryOf(e)] += 1;
      return by;
    },

    filtered(s): Entry[] {
      let list = s.entries;
      if (s.filter === 'fav') list = list.filter((e) => e.favorite);
      else if (s.filter !== 'all' && s.filter !== 'watchtower') {
        list = list.filter((e) => categoryOf(e) === s.filter);
      }
      const q = s.query.trim().toLowerCase();
      if (q) {
        list = list.filter((e) =>
          (e.title + ' ' + subtitleOf(e) + ' ' + e.tags.join(' ')).toLowerCase().includes(q),
        );
      }
      return list;
    },

    selected(s): Entry | null {
      return s.entries.find((e) => e.id === s.selectedId) ?? null;
    },

    listTitle(s): string {
      if (s.filter === 'watchtower') return 'Watchtower';
      if (s.filter === 'all') return 'All items';
      if (s.filter === 'fav') return 'Favorites';
      return CATEGORY_LABEL[s.filter];
    },

    score(s): number {
      let weak = 0;
      let reused = 0;
      for (const issue of s.issues) {
        if (issue.kind === 'weak') weak += 1;
        else if (issue.kind === 'reused') reused += 1;
      }
      return Math.max(0, Math.round(100 - weak * 22 - reused * 14));
    },
  },

  actions: {
    /**
     * Unlock the vault. On first run this generates a device Secret Key, seeds
     * the demo vault sealed with 2SKD, and surfaces the Emergency Kit once. On a
     * device that has the vault but not its Secret Key, it flips `needsSecretKey`
     * so the UI can prompt for it (the "add this device" flow).
     */
    async unlock(master: string) {
      this.busy = true;
      this.unlockError = null;
      try {
        // With cloud sync on, adopt the server's blob first so this device opens
        // the latest vault (and can prompt for the Secret Key if it lacks it).
        if (this.syncEnabled) {
          await this.adoptRemote();
        }
        if (!vaultExists()) {
          const key = await newSecretKey();
          storeSecretKey(key);
          await createVault(demoEntries(nowUnix()), master, key);
          this.freshSecretKey = key;
        } else if (!hasSecretKey()) {
          this.needsSecretKey = true;
          return;
        }
        this.entries = await openVault(master, getSecretKey());
        this.master = master;
        this.selectFirst();
        await this.refreshSecurity();
        // A brand-new vault created while sync is on must be uploaded once.
        if (this.syncEnabled) {
          await this.pushCurrent();
        }
      } catch {
        this.unlockError = 'Wrong master password, or the vault is corrupt.';
      } finally {
        this.busy = false;
      }
    },

    /**
     * Add this device: store the supplied Secret Key, then unlock. Used when a
     * vault is present but the device has no Secret Key yet.
     */
    async addDevice(master: string, secretKey: string) {
      this.busy = true;
      this.unlockError = null;
      try {
        if (!(await isValidSecretKey(secretKey))) {
          this.unlockError = 'That Secret Key is not valid — check the Emergency Kit.';
          return;
        }
        storeSecretKey(secretKey);
        this.entries = await openVault(master, secretKey);
        this.master = master;
        this.needsSecretKey = false;
        this.selectFirst();
        await this.refreshSecurity();
      } catch {
        // Wrong key/master: drop the just-stored key so the prompt reappears clean.
        clearSecretKey();
        this.unlockError = 'Wrong master password or Secret Key for this vault.';
      } finally {
        this.busy = false;
      }
    },

    /** Dismiss the one-time Emergency Kit shown after first-run creation. */
    acknowledgeKit() {
      this.freshSecretKey = null;
    },

    lock() {
      this.master = null;
      this.entries = [];
      this.issues = [];
      this.strengths = {};
      this.query = '';
      this.freshSecretKey = null;
    },

    /** Wipe the local vault AND the device Secret Key entirely (irreversible). */
    reset() {
      destroyVault();
      this.needsSecretKey = false;
      this.lock();
    },

    setFilter(filter: Filter) {
      this.filter = filter;
      if (filter !== 'watchtower') this.selectFirst();
    },

    setQuery(q: string) {
      this.query = q;
      this.selectFirst();
    },

    select(id: string) {
      this.selectedId = id;
    },

    selectFirst() {
      const list = this.filtered;
      this.selectedId = list.length ? list[0].id : null;
    },

    /** Persist the current entries (resealed with the device Secret Key) and
     * recompute security signals. */
    async persist() {
      if (this.master === null) return;
      await saveVault(this.entries, this.master, getSecretKey());
      await this.refreshSecurity();
      // Mirror the resealed blob to the cloud when sync is enabled. Never let a
      // sync failure surface as a failed local save — the vault is already
      // persisted on this device by the time we get here.
      if (this.syncEnabled) {
        await this.pushCurrent();
      }
    },

    async refreshSecurity() {
      this.issues = await watchtower(this.entries);
      const strengths: Record<string, number> = {};
      for (const e of this.entries) {
        if ('Login' in e.content) {
          strengths[e.id] = await strengthBits(e.content.Login.password);
        }
      }
      this.strengths = strengths;
    },

    async toggleFavorite(id: string) {
      const e = this.entries.find((x) => x.id === id);
      if (!e) return;
      e.favorite = !e.favorite;
      e.updated_epoch = nowUnix();
      await this.persist();
    },

    async addLogin(input: {
      title: string;
      login: Login;
      tags: string[];
      favorite: boolean;
    }) {
      const entry: Entry = {
        id: `e${Date.now().toString(36)}`,
        title: input.title,
        tags: input.tags,
        favorite: input.favorite,
        updated_epoch: nowUnix(),
        content: { Login: input.login },
      };
      this.entries.unshift(entry);
      this.selectedId = entry.id;
      await this.persist();
    },

    async remove(id: string) {
      this.entries = this.entries.filter((e) => e.id !== id);
      this.selectFirst();
      await this.persist();
    },

    /**
     * Merge imported entries into the vault (newest first) and persist. Returns
     * the number actually added after skipping exact duplicates already present.
     */
    async importEntries(incoming: Entry[]): Promise<number> {
      const seen = new Set(this.entries.map((e) => entryKey(e)));
      const fresh = incoming.filter((e) => {
        const k = entryKey(e);
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      });
      if (fresh.length === 0) return 0;
      this.entries = [...fresh, ...this.entries];
      this.filter = 'all';
      this.query = '';
      this.selectFirst();
      await this.persist();
      return fresh.length;
    },

    // ----- Cloud sync -------------------------------------------------------

    /**
     * Enable cloud sync: register an account on `serverUrl`, then upload the
     * current sealed vault. Resilient — on failure sync stays disabled and the
     * local vault is untouched. Returns true on success.
     */
    async enableSync(serverUrl: string, email?: string): Promise<boolean> {
      this.syncStatus = 'syncing' as SyncStatus;
      try {
        await sync.register(serverUrl, email);
        this.syncEnabled = true;
        await this.pushCurrent();
        if (this.syncStatus !== 'error') this.syncStatus = 'synced';
        toast('Cloud sync enabled');
        return true;
      } catch {
        sync.disableSync();
        this.syncEnabled = false;
        this.syncStatus = 'error';
        toast('Could not enable cloud sync — check the server URL');
        return false;
      }
    },

    /**
     * Provision a second device token for this account (the "add a device"
     * flow). Returns the token to show the user, or null on failure.
     */
    async addSyncDevice(): Promise<string | null> {
      try {
        return await sync.addDevice();
      } catch {
        this.syncStatus = 'error';
        toast('Could not add a device');
        return null;
      }
    },

    /** Turn off cloud sync on this device (local vault and Secret Key stay). */
    disableSync() {
      sync.disableSync();
      this.syncEnabled = false;
      this.syncStatus = 'idle';
      this.lastSyncedVersion = null;
    },

    /** Full round-trip: pull the remote vault (adopting it if present), then push. */
    async syncNow() {
      if (!this.syncEnabled || this.master === null) return;
      this.syncStatus = 'syncing' as SyncStatus;
      try {
        const remote = await sync.pull();
        if (remote !== null) {
          await this.adoptBlob(remote.blob, remote.version);
        }
        await this.pushCurrent();
        if (this.syncStatus !== 'error') {
          this.syncStatus = 'synced';
          toast('Synced with cloud');
        }
      } catch {
        this.syncStatus = 'error';
        toast('Cloud sync failed — your changes are safe on this device');
      }
    },

    /**
     * Push the current sealed blob to the server. On a version conflict, pull the
     * remote blob and adopt it (reloading entries) so this device converges on the
     * latest vault. Network errors set 'error' status but never lose local data.
     */
    async pushCurrent() {
      const raw = getRawVault();
      if (raw === null) return;
      this.syncStatus = 'syncing';
      try {
        const version = await sync.push(raw);
        this.lastSyncedVersion = version;
        this.syncStatus = 'synced';
      } catch (err) {
        if (err instanceof SyncConflict) {
          await this.resolveConflict();
        } else {
          this.syncStatus = 'error';
          toast('Cloud sync failed — your changes are safe on this device');
        }
      }
    },

    /** Pull the remote vault after a conflict and reload from it (remote wins). */
    async resolveConflict() {
      try {
        const remote = await sync.pull();
        if (remote !== null && this.master !== null) {
          await this.adoptBlob(remote.blob, remote.version);
          this.syncStatus = 'synced';
          toast('Vault updated on another device — reloaded');
        } else {
          this.syncStatus = 'error';
        }
      } catch {
        this.syncStatus = 'error';
        toast('Cloud sync failed — your changes are safe on this device');
      }
    },

    /**
     * At unlock, pull the server's blob and adopt it locally (before opening) so
     * this device sees the latest vault. Resilient: a network error just leaves
     * the local blob in place and flags the status.
     */
    async adoptRemote() {
      try {
        const remote = await sync.pull();
        if (remote !== null) {
          setRawVault(remote.blob);
          this.lastSyncedVersion = remote.version;
        }
      } catch {
        this.syncStatus = 'error';
      }
    },

    /**
     * Overwrite the local sealed blob with `blob`, re-open it with the current
     * master + Secret Key, and swap in the decrypted entries. Used by conflict
     * resolution and `syncNow` once the session is unlocked.
     */
    async adoptBlob(blob: string, version: string | null) {
      if (this.master === null) return;
      setRawVault(blob);
      this.entries = await openVault(this.master, getSecretKey());
      this.lastSyncedVersion = version;
      this.selectFirst();
      await this.refreshSecurity();
    },
  },
});

/** Dedupe key: title + category + the identifying field, case-insensitive. */
function entryKey(e: Entry): string {
  const c = e.content;
  let detail = '';
  if ('Login' in c) detail = `${c.Login.username}|${c.Login.password}`;
  else if ('Card' in c) detail = c.Card.number;
  else if ('Identity' in c) detail = c.Identity.email;
  else if ('SecureNote' in c) detail = c.SecureNote;
  return `${categoryOf(e)}|${e.title}|${detail}`.toLowerCase();
}
