// The single source of truth for the unlocked session: the decrypted entries,
// the current filter/selection, and every mutation (which reseals + persists via
// the WASM core). Components read derived getters and call actions; they never
// touch crypto or storage directly.

import { defineStore } from 'pinia';
import type { Category, Entry, Issue, Login } from '../lib/passbook-types';
import { categoryOf } from '../lib/passbook-types';
import {
  createVault,
  destroyVault,
  nowUnix,
  openVault,
  saveVault,
  strengthBits,
  vaultExists,
  watchtower,
} from '../lib/passbook';
import { demoEntries } from '../lib/seed';

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
  }),

  getters: {
    locked: (s) => s.master === null,
    hasVault: () => vaultExists(),

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
    /** Unlock an existing vault (or seed + create the demo one on first run). */
    async unlock(master: string) {
      this.busy = true;
      this.unlockError = null;
      try {
        if (!vaultExists()) {
          await createVault(demoEntries(nowUnix()), master);
        }
        this.entries = await openVault(master);
        this.master = master;
        this.selectFirst();
        await this.refreshSecurity();
      } catch {
        this.unlockError = 'Wrong master password, or the vault is corrupt.';
      } finally {
        this.busy = false;
      }
    },

    lock() {
      this.master = null;
      this.entries = [];
      this.issues = [];
      this.strengths = {};
      this.query = '';
    },

    /** Wipe the local vault entirely (irreversible). */
    reset() {
      destroyVault();
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

    /** Persist the current entries and recompute security signals. */
    async persist() {
      if (this.master === null) return;
      await saveVault(this.entries, this.master);
      await this.refreshSecurity();
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
  },
});
