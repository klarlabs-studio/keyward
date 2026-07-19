// Trust state for family sharing: which member keys, vault keys, and wrapped-key
// epochs this account has accepted.
//
// WHY THIS MODULE EXISTS. All of it used to live in localStorage. That had two
// failures, one dull and one sharp:
//
//   Clearing browser data wiped every pin and floor while the account and group
//   membership survived on the relay. The device came back looking brand new,
//   silently trusted on first use again, and every warning sharing.ts can raise
//   was disarmed — with nothing shown to the user. Not an attack; it happens by
//   accident, which is worse, because nobody investigates it.
//
//   And a second device started from nothing. Every member was 'unknown', so the
//   user was asked to approve people they had already approved elsewhere. Trust
//   decisions that have to be repeated get made carelessly, which turns the
//   approval gate into a formality.
//
// Trust state now lives inside the SYNCED, ENCRYPTED vault as a reserved entry
// (the same pattern recovery blobs already use in the shared vault). It is
// therefore covered by the vault's AEAD and 2SKD: the relay stores it as opaque
// ciphertext and cannot read or edit it, it survives a browser wipe, and it
// reaches every device the account unlocks on.
//
// localStorage remains as a CACHE, so the UI can read trust state synchronously
// and so a device that has not synced yet still knows what it knew. The vault is
// authoritative; the cache is never trusted over it on merge.

import type { Entry } from './passbook-types';

/** Reserved entry id/title holding this account's trust state.
 *
 * The id changed with the rename and that is safe, unlike the storage keys
 * below: `isTrustEntry` matches on the TITLE as well, so an entry written under
 * the old id is still recognised, and the write path replaces every trust entry
 * it finds rather than appending. An old vault therefore converges on the new
 * id the first time anything is written, with no migration step. The title is
 * the stable identifier here; do not make matching id-only. */
const TRUST_ENTRY_ID = 'keyward-trust-state';
const TRUST_TITLE = '__trust__';

/** Cache key. Bumped from the four separate v1/v2 keys this replaces.
 *
 * FROZEN — the `keyward.` prefix is deliberate and must not be renamed. These
 * keys address data already sitting in real browsers; renaming them orphans
 * every pin and floor on every existing device, which is exactly the silent
 * re-TOFU that `knowsNothingAbout` exists to catch. The prefix records what the
 * product was called when the key was written, which is what a storage key is
 * supposed to do. */
const CACHE = 'keyward.passbook.trust.v1';

/** What we have accepted for one member: their X25519 and Ed25519 public keys. */
export interface PinnedKeys {
  public_key: string;
  /** Empty when pinned before signing existed, or not yet published. An empty
   *  pin verifies nothing and fails closed. */
  signing_key: string;
}

/** How far this account has accepted a group's wrapped-key sets, and which one. */
export interface EpochPin {
  epoch: number;
  /** Truncated SHA-256 of the accepted set, to tell same-epoch forks apart. */
  digest: string;
}

/** Everything this account has decided to trust. */
export interface TrustState {
  /** groupId -> memberId -> accepted keys. */
  pins: Record<string, Record<string, PinnedKeys>>;
  /** groupId -> fingerprint of the accepted vault key. */
  vaultKeys: Record<string, string>;
  /** Groups known to use signed wrapped-key sets. Once seen, always required. */
  signed: string[];
  /** groupId -> highest verified epoch and its digest. */
  epochs: Record<string, EpochPin>;
}

function empty(): TrustState {
  return { pins: {}, vaultKeys: {}, signed: [], epochs: {} };
}

// ----- In-memory state, cache, and persistence ------------------------------

// Initialised below, AFTER the LEGACY table and readCache() exist. Calling
// readCache() here instead throws on `LEGACY` (const, so no hoisting) and kills
// the module at import — taking all of family sharing with it. Neither vue-tsc
// nor the bundler catches that; only running it does.
let state: TrustState = empty();

/**
 * Persist the current state into the vault. Registered by the vault store,
 * which owns the master password and the save path.
 *
 * Null before unlock: trust state is still readable from cache then (the UI
 * renders before the vault opens), but nothing can be written, which is correct
 * — a trust decision made against a locked vault has nowhere durable to go.
 */
let persist: ((entry: Entry) => Promise<void>) | null = null;

/** Called by the vault store once it can save. */
export function setPersister(fn: (entry: Entry) => Promise<void>): void {
  persist = fn;
}

export function clearPersister(): void {
  persist = null;
}

/**
 * The four localStorage keys this module replaces.
 *
 * Migrated once, on first load, rather than dropped. Without this every
 * existing device would come back holding no trust state at all — silently
 * re-trusting on first use, with every warning disarmed. That is precisely the
 * wipe `knowsNothingAbout` exists to detect, and shipping it deliberately would
 * be worse than the bug it reports.
 *
 * These keep the `proctor.` prefix ON PURPOSE, and are the one place the
 * Keyward rename does not reach. They name bytes that are already sitting in
 * real localStorage, written before the rename; renaming them here would not
 * rename anything on disk, it would just make this migration look for keys that
 * were never written and silently find nothing — which is exactly the wiped-
 * state bug the comment above says shipping would be worse than.
 */
const LEGACY = {
  pins: 'proctor.passbook.keypins.v1',
  vaultKeys: 'proctor.passbook.vaultkeypins.v1',
  signed: 'proctor.passbook.signedgroups.v1',
  /** v2 carried {epoch, digest}; v1 carried a bare number. Both are read. */
  epochsV2: 'proctor.passbook.epochfloor.v2',
  epochsV1: 'proctor.passbook.epochfloor.v1',
} as const;

function readJson<T>(key: string): T | null {
  const raw = localStorage.getItem(key);
  if (raw === null) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

/** Pull the pre-vault localStorage state forward into one TrustState. */
function migrateLegacy(): TrustState | null {
  const legacyPins =
    readJson<Record<string, Record<string, PinnedKeys | string>>>(LEGACY.pins) ?? {};
  const vaultKeys = readJson<Record<string, string>>(LEGACY.vaultKeys) ?? {};
  const signed = readJson<string[]>(LEGACY.signed) ?? [];
  const epochsV2 = readJson<Record<string, EpochPin>>(LEGACY.epochsV2) ?? {};
  const epochsV1 = readJson<Record<string, number>>(LEGACY.epochsV1) ?? {};

  const found =
    Object.keys(legacyPins).length > 0 ||
    Object.keys(vaultKeys).length > 0 ||
    signed.length > 0 ||
    Object.keys(epochsV2).length > 0 ||
    Object.keys(epochsV1).length > 0;
  if (!found) return null;

  const out = empty();
  out.vaultKeys = { ...vaultKeys };
  out.signed = Array.isArray(signed) ? [...signed] : [];

  for (const [groupId, members] of Object.entries(legacyPins)) {
    out.pins[groupId] = Object.fromEntries(
      // The oldest format stored a bare public-key string, before signing keys
      // existed. An empty signing key verifies nothing and fails closed, which
      // is the correct reading of "we pinned this before signing existed".
      Object.entries(members).map(([id, pin]) => [
        id,
        typeof pin === 'string' ? { public_key: pin, signing_key: '' } : pin,
      ]),
    );
  }

  // A v1 floor has no digest, so it cannot detect a same-epoch fork. Empty
  // digest never matches a real one, so such a group reports 'forked' once and
  // then settles — a spurious prompt, which is the safe direction to err.
  for (const [groupId, epoch] of Object.entries(epochsV1)) {
    out.epochs[groupId] = { epoch, digest: '' };
  }
  for (const [groupId, pin] of Object.entries(epochsV2)) {
    out.epochs[groupId] = pin;
  }

  return out;
}

function readCache(): TrustState {
  if (typeof localStorage === 'undefined') return empty();
  const raw = localStorage.getItem(CACHE);
  if (raw === null) {
    const migrated = migrateLegacy();
    if (migrated === null) return empty();
    localStorage.setItem(CACHE, JSON.stringify(migrated));
    // Only after the new cache is safely written. Removing them first would
    // lose everything if the write failed.
    for (const key of Object.values(LEGACY)) localStorage.removeItem(key);
    return migrated;
  }
  try {
    const v = JSON.parse(raw) as Partial<TrustState>;
    return {
      pins: v.pins ?? {},
      vaultKeys: v.vaultKeys ?? {},
      signed: Array.isArray(v.signed) ? v.signed : [],
      epochs: v.epochs ?? {},
    };
  } catch {
    return empty();
  }
}

// Load-time initialisation. Must stay below readCache/migrateLegacy/LEGACY.
state = readCache();

function writeCache(): void {
  if (typeof localStorage === 'undefined') return;
  localStorage.setItem(CACHE, JSON.stringify(state));
}

/**
 * Record a change: cache it immediately, then persist to the vault.
 *
 * The cache write is synchronous and unconditional so a failed vault save
 * cannot leave this device acting on state it has forgotten. The consequence is
 * that a failed save loses the decision on OTHER devices until something writes
 * again — visible as being asked to approve twice, which is the safe direction
 * for this to fail in.
 */
async function commit(): Promise<void> {
  writeCache();
  if (persist === null) return;
  await persist(toEntry(state));
}

/** The reserved vault entry carrying `s`. */
function toEntry(s: TrustState): Entry {
  return {
    id: TRUST_ENTRY_ID,
    title: TRUST_TITLE,
    tags: [],
    favorite: false,
    updated_epoch: Math.floor(Date.now() / 1000),
    content: { SecureNote: JSON.stringify(s) },
  };
}

/** True if this entry is the reserved trust-state blob rather than a real item. */
export function isTrustEntry(e: Entry): boolean {
  return e.id === TRUST_ENTRY_ID || e.title === TRUST_TITLE;
}

// ----- Merge ----------------------------------------------------------------

/**
 * Merge the vault's trust state into this device's.
 *
 * Merge rules are chosen so that every automatic resolution moves toward MORE
 * suspicion, and anything genuinely ambiguous is left for the human path that
 * already exists in sharing.ts:
 *
 *   epochs   — highest wins. Monotonic by construction, so this is safe, and
 *              taking the max is what stops a device that synced late from
 *              accepting a set another device has already moved past.
 *   signed   — union. "This group uses signatures" is one-way; a device that
 *              has seen it must never un-learn it.
 *   pins     — union, but a CONFLICT (both sides pinned a different key for the
 *              same member) keeps the local one. Not because local is more
 *              trustworthy, but because keeping it makes the relay-served key
 *              read as 'changed' and routes to explicit approval. Preferring
 *              the remote value would silently adopt a key this device never
 *              agreed to — exactly what pinning exists to prevent.
 *   vaultKeys — same conflict rule, for the same reason: a mismatch surfaces as
 *              "this vault's key changed", which is a human decision.
 *
 * A same-epoch, different-digest conflict is NOT resolved here; it is left to
 * sharing.ts, which reports it as a fork.
 */
export function merge(remote: TrustState): void {
  const merged = empty();

  merged.signed = Array.from(new Set([...state.signed, ...remote.signed]));

  for (const groupId of keysOf(state.epochs, remote.epochs)) {
    const a = state.epochs[groupId];
    const b = remote.epochs[groupId];
    merged.epochs[groupId] = pickHigherEpoch(a, b);
  }

  for (const groupId of keysOf(state.vaultKeys, remote.vaultKeys)) {
    // Local wins on conflict; see above.
    merged.vaultKeys[groupId] = state.vaultKeys[groupId] ?? remote.vaultKeys[groupId];
  }

  for (const groupId of keysOf(state.pins, remote.pins)) {
    const local = state.pins[groupId] ?? {};
    const incoming = remote.pins[groupId] ?? {};
    const group: Record<string, PinnedKeys> = { ...incoming };
    // Local pins overwrite incoming ones, so a conflict keeps the local key.
    for (const [memberId, pin] of Object.entries(local)) group[memberId] = pin;
    merged.pins[groupId] = group;
  }

  state = merged;
  writeCache();
}

function keysOf(a: object, b: object): string[] {
  return Array.from(new Set([...Object.keys(a), ...Object.keys(b)]));
}

function pickHigherEpoch(a: EpochPin | undefined, b: EpochPin | undefined): EpochPin {
  if (a === undefined) return b as EpochPin;
  if (b === undefined) return a;
  return b.epoch > a.epoch ? b : a;
}

/**
 * Adopt the trust state carried in `entries` (called after unlock and after any
 * sync that replaces the entry set). Returns true if a trust entry was present.
 */
export function hydrate(entries: Entry[]): boolean {
  const entry = entries.find(isTrustEntry);
  if (entry === undefined || !('SecureNote' in entry.content)) return false;
  try {
    const parsed = JSON.parse(entry.content.SecureNote) as Partial<TrustState>;
    merge({
      pins: parsed.pins ?? {},
      vaultKeys: parsed.vaultKeys ?? {},
      signed: Array.isArray(parsed.signed) ? parsed.signed : [],
      epochs: parsed.epochs ?? {},
    });
    return true;
  } catch {
    // A corrupt blob must not wipe what this device knows. Keeping the local
    // state means the worst case is stale trust, not absent trust.
    return false;
  }
}

/** Drop in-memory and cached state (called on lock/vault destroy). */
export function reset(): void {
  state = empty();
  if (typeof localStorage !== 'undefined') localStorage.removeItem(CACHE);
}

// ----- Reads (synchronous, for the UI) --------------------------------------

export function pinnedKeys(groupId: string): Record<string, PinnedKeys> {
  return state.pins[groupId] ?? {};
}

export function vaultKeyPin(groupId: string): string | undefined {
  return state.vaultKeys[groupId];
}

export function isSignedGroup(groupId: string): boolean {
  return state.signed.includes(groupId);
}

export function epochPin(groupId: string): EpochPin | undefined {
  return state.epochs[groupId];
}

/** True if nothing at all is known about `groupId` — a wiped or new device. */
export function knowsNothingAbout(groupId: string): boolean {
  return (
    Object.keys(pinnedKeys(groupId)).length === 0 &&
    vaultKeyPin(groupId) === undefined &&
    !isSignedGroup(groupId) &&
    epochPin(groupId) === undefined
  );
}

// ----- Writes ---------------------------------------------------------------

export async function pinMember(
  groupId: string,
  memberId: string,
  publicKey: string,
  signingKey: string,
): Promise<void> {
  state.pins[groupId] = {
    ...(state.pins[groupId] ?? {}),
    [memberId]: { public_key: publicKey, signing_key: signingKey },
  };
  await commit();
}

export async function pinVaultKey(groupId: string, fingerprint: string): Promise<void> {
  state.vaultKeys[groupId] = fingerprint;
  await commit();
}

export async function markSigned(groupId: string): Promise<void> {
  if (isSignedGroup(groupId)) return;
  state.signed = [...state.signed, groupId];
  await commit();
}

/** Record an accepted set. Never lowers the epoch — a floor that can be walked
 *  back is not a floor, and the relay controls what we are shown. */
export async function acceptEpoch(
  groupId: string,
  epoch: number,
  digest: string,
): Promise<void> {
  const current = epochPin(groupId);
  if (current !== undefined && epoch < current.epoch) return;
  state.epochs[groupId] = { epoch, digest };
  await commit();
}

/** Forget everything about a group this account has left. */
export async function forgetGroup(groupId: string): Promise<void> {
  delete state.pins[groupId];
  delete state.vaultKeys[groupId];
  delete state.epochs[groupId];
  state.signed = state.signed.filter((g) => g !== groupId);
  await commit();
}
