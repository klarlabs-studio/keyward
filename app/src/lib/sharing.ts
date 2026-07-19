// Family-sharing client. Ties the WASM sharing crypto (member keypairs, vault-key
// wrapping, content sealing) to the zero-knowledge share-group relay
// (`/v1/groups...`). Everything cryptographic happens here or in WASM; the server
// only ever sees public keys, opaque wrapped keys, and opaque ciphertext.
//
// Sharing rides on cloud sync: each member authenticates to the group relay with
// their own account's device token (from the sync config), so a family shares a
// vault on the server they already sync to. The member's X25519 identity is kept
// in localStorage next to the device Secret Key — consistent with how that 2SKD
// factor is already held on-device (a device compromise is already fatal).

import {
  member_new,
  member_public_key,
  member_signing_new,
  member_signing_public,
  shared_vault_signer,
  shared_vault_epoch,
  rotate_vault_key,
  unwrap_vault_key_unsigned,
  sign_shared_vault,
  group_safety_number,
  generate_vault_key,
  seal_group_content,
  open_group_content,
  share_vault_key,
  unwrap_vault_key,
  grant_group_access,
  seal_recovery,
  open_recovery,
} from '../wasm/pkg/passbook_wasm.js';
import { ensureReady } from './passbook';
import * as trust from './trust';
import { syncConfig } from './sync';
import type { Entry } from './passbook-types';

const MEMBER_STORAGE = 'proctor.passbook.member.v1';
const GROUPS_STORAGE = 'proctor.passbook.groups.v1';
const VERSION_HEADER = 'X-Vault-Version';

/** This device's member identity (public half published; secret stays local). */
export interface MemberIdentity {
  id: string;
  name: string;
  /** X25519 secret (hex) — unwraps every vault shared to this member. */
  secret: string;
  /** X25519 public (hex) — published to groups. */
  public_key: string;
  /**
   * Ed25519 signing secret (hex) — authenticates every wrapped-key set this
   * device writes. Optional only for identities enrolled before signing existed;
   * `ensureMember` mints one on next use.
   */
  signing_secret?: string;
  /** Ed25519 verifying key (hex) — published so others can check what we write. */
  signing_key?: string;
}

/** A group this device belongs to, as tracked locally. */
export interface GroupRef {
  groupId: string;
  name: string;
}

/** A member's role in a group. Owner > Admin > Member (see ADR-0006). */
export type Role = 'owner' | 'admin' | 'member';

/** A member of a group, as the relay's directory reports it. */
export interface GroupMemberView {
  member_id: string;
  account_id: string;
  name: string;
  public_key: string;
  /** Ed25519 verifying key. Empty for members enrolled before signing existed. */
  signing_key?: string;
  role: Role;
  added_epoch: number;
}

/** Admin or Owner — may invite and remove members. */
export function canManageMembers(role: Role): boolean {
  return role === 'admin' || role === 'owner';
}

/**
 * The group's safety number — a fingerprint of the members' public identities.
 * Family members compare it **out of band**; a mismatch means the relay showed
 * someone a different member directory (a substituted or extra public key), which
 * is the one attack the ciphertext alone cannot reveal. See ADR-0004.
 *
 * Covers signing keys as well as X25519 keys, so comparing it also confirms the
 * keys that AUTHENTICATE wrapped-key sets. Note that this changed the number:
 * a family that wrote theirs down before will see a different one now, and the
 * UI must not present that as a mismatch.
 */
export async function safetyNumber(members: GroupMemberView[]): Promise<string> {
  await ensureReady();
  return group_safety_number(recipients(members));
}

// ----- Detecting a wiped trust state ----------------------------------------
//
// Every protection in this file — member pins, the vault-key pin, the epoch
// floor, the "this group has been signed" flag — lives in localStorage. Clearing
// site data wipes all of it while leaving the account and the group membership
// intact, because those live on the relay.
//
// That is not an attack (an attacker who can write localStorage already holds
// the member secret and the device Secret Key stored beside it, and has won).
// It is worse in a duller way: the device comes back looking brand new, silently
// trusts on first use again, and every warning this file can raise is disarmed
// — with nothing shown to the user.
//
// So a group we are joined to, with content on the relay, but no local trust
// state at all is reported. The user is told their device forgot, and asked to
// re-check the safety number rather than being quietly re-TOFU'd.
//
// The durable fix is to keep trust state in the SYNCED, ENCRYPTED vault instead
// of localStorage, so it survives a wipe and propagates to new devices. That is
// a vault-format change and is deliberately not bolted on here.

/** True if we are joined to this group but hold no trust state for it at all. */
function trustStateWiped(groupId: string, members: GroupMemberView[]): boolean {
  if (!trust.knowsNothingAbout(groupId)) return false;
  // A single-member group is genuinely new — there is nothing to have forgotten.
  return members.length > 1;
}

/** A loaded family vault: its members, decrypted entries, and my access state. */
export interface FamilyVault {
  groupId: string;
  name: string;
  members: GroupMemberView[];
  entries: Entry[];
  /** True if I hold a wrapped key and could read the content. */
  hasAccess: boolean;
  /** True if I am no longer in the member directory (revoked/removed). */
  removed: boolean;
  /** Fingerprint of the member directory, for out-of-band comparison. */
  safety: string;
  /** Names of members this load just granted access to (all pre-approved keys). */
  justGranted: string[];
  /**
   * Members awaiting an explicit human decision before the vault key is wrapped
   * to them. Nothing has been sent for these; they are waiting on the user.
   */
  pendingApproval: PendingMember[];
  /**
   * The shared vault key differs from the one this device previously accepted.
   *
   * Usually a legitimate rotation someone else performed (revoking a member
   * rotates the key). But it is also exactly what a relay substituting its own
   * key looks like, and the two cannot be told apart from here — so entries are
   * left unread until a human decides, rather than silently re-sealing content
   * under a key we have not accepted.
   */
  vaultKeyChanged?: boolean;
  /**
   * Whether the wrapped-key set could be authenticated to a pinned member.
   *
   * Anything other than `'verified'` means the vault key came from a set nobody
   * has proven authorship of — which is the whole substitution attack. The UI
   * must say which case it is: `'unsigned'` calls for an upgrade prompt,
   * `'bad-signature'` for an alarm.
   */
  keysTrust?: KeysTrust;
  /**
   * This device holds no trust state for a group it is a member of — typically
   * browser data was cleared. Every pin and floor is gone, so first-use trust
   * is about to be re-established silently unless the user is told.
   */
  trustWiped?: boolean;
  keysVersion: string | null;
  contentVersion: string | null;
}

/** A member whose key we have not accepted, and so have not wrapped the vault key to. */
export interface PendingMember {
  memberId: string;
  name: string;
  publicKey: string;
  /**
   * `'unknown'` — first time we have seen this member; normal for a new joiner.
   * `'changed'` — we previously accepted a DIFFERENT key under this member id.
   *   That is either a genuine re-enrolment (new device, lost key) or a relay
   *   substituting its own key to read the vault. The two are indistinguishable
   *   from here, which is exactly why it must be a human decision, confirmed
   *   out of band rather than in the app.
   */
  state: TrustState;
}

// ----- Member identity ------------------------------------------------------

/** The stored member identity, or null if this device has none yet. */
export function memberIdentity(): MemberIdentity | null {
  const raw = localStorage.getItem(MEMBER_STORAGE);
  if (raw === null) return null;
  try {
    const m = JSON.parse(raw) as Partial<MemberIdentity>;
    // signing_secret is deliberately NOT required: an identity enrolled before
    // signing existed is still valid for reading, and rejecting it here would
    // lock those members out of vaults they legitimately hold keys to.
    if (m.id && m.name && m.secret && m.public_key) return m as MemberIdentity;
  } catch {
    // fall through
  }
  return null;
}

/** Get or create this device's member identity (a fresh X25519 keypair). */
export async function ensureMember(name: string): Promise<MemberIdentity> {
  const existing = memberIdentity();
  if (existing) {
    // Keep the display name current without changing the keypair.
    if (name.trim() && name.trim() !== existing.name) {
      const updated = { ...existing, name: name.trim() };
      localStorage.setItem(MEMBER_STORAGE, JSON.stringify(updated));
      return updated;
    }
    if (existing.signing_secret) return existing;
    // Upgrade an identity from before signing existed. Only the signing key is
    // minted — rotating the X25519 secret would orphan every vault already
    // shared to this member.
    await ensureReady();
    const minted = JSON.parse(member_signing_new()) as {
      signing_key: string;
      signing_secret: string;
    };
    const upgraded = { ...existing, ...minted };
    localStorage.setItem(MEMBER_STORAGE, JSON.stringify(upgraded));
    return upgraded;
  }
  await ensureReady();
  const id = `m${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
  const created = JSON.parse(member_new(id, name.trim() || 'Me')) as MemberIdentity;
  localStorage.setItem(MEMBER_STORAGE, JSON.stringify(created));
  return created;
}

/** Recompute a public key (hex) from a stored secret (hex). */
export async function publicKeyOf(secretHex: string): Promise<string> {
  await ensureReady();
  return member_public_key(secretHex);
}

/** Recompute a verifying key (hex) from a stored signing secret (hex). */
export async function signingKeyOf(signingSecretHex: string): Promise<string> {
  await ensureReady();
  return member_signing_public(signingSecretHex);
}

/** The `{id, secret, signing_secret}` shape the WASM signing calls want. */
function authorOf(member: MemberIdentity): string {
  return JSON.stringify({
    id: member.id,
    name: member.name,
    secret: member.secret,
    signing_secret: member.signing_secret ?? '',
  });
}

// ----- Local group registry -------------------------------------------------

export function joinedGroups(): GroupRef[] {
  const raw = localStorage.getItem(GROUPS_STORAGE);
  if (raw === null) return [];
  try {
    const list = JSON.parse(raw) as GroupRef[];
    return Array.isArray(list) ? list.filter((g) => g && g.groupId) : [];
  } catch {
    return [];
  }
}

function rememberGroup(ref: GroupRef): void {
  const groups = joinedGroups().filter((g) => g.groupId !== ref.groupId);
  groups.push(ref);
  localStorage.setItem(GROUPS_STORAGE, JSON.stringify(groups));
}

export async function forgetGroup(groupId: string): Promise<void> {
  const groups = joinedGroups().filter((g) => g.groupId !== groupId);
  localStorage.setItem(GROUPS_STORAGE, JSON.stringify(groups));
  await trust.forgetGroup(groupId);
}

// ----- Trust-on-first-use key pinning ---------------------------------------
//
// THE PROBLEM THIS SOLVES. The relay is untrusted by design, but the client
// used to wrap the shared vault key to whatever public key the relay listed for
// a member, with no verification and no user involvement. A malicious or
// compromised relay could append one fabricated member row holding a key it
// controls; the next time any member opened the vault, their client would wrap
// K_vault to that key and upload it. The relay then unwraps and reads every
// shared credential. ADR-0004 claimed a grant was "a human decision" — it was
// an unattended background action on every load.
//
// The fix is to remember which key we have already accepted for each member,
// and to refuse to wrap to anything else without the user explicitly saying so.
// A relay can still LIST whatever it likes; it just cannot get a key wrapped to
// it. Trust is established once, on first sight, and any later change is a
// blocking event rather than a silent one.
//
// This is TOFU, not verification: the very first key we see for a member is
// taken on faith, so a relay hostile from the outset can still substitute at
// that moment. The safety number is what closes that, by letting members
// compare fingerprints out of band. Member-signed directory entries would
// remove the residual entirely — see docs/security/known-limitations.md.

// Storage now lives in `trust.ts`, inside the SYNCED, ENCRYPTED vault rather
// than localStorage. See that file for why. What remains here is the policy:
// what a pin MEANS, and what to do when one does not match.

/** What we have accepted for a member. Re-exported so callers need one import. */
export type { PinnedKeys } from './trust';

/** The keys pinned for `groupId` (memberId -> accepted keys). */
export function pinnedKeys(groupId: string): Record<string, trust.PinnedKeys> {
  return trust.pinnedKeys(groupId);
}

/** True once this account has seen a signed wrapped-key set for `groupId`.
 *
 *  Once seen, an unsigned set for that group is a DOWNGRADE, not history, and is
 *  refused. Same reasoning as HSTS: the insecure path stays open only until the
 *  secure one has been observed. */
export function requiresSignature(groupId: string): boolean {
  return trust.isSignedGroup(groupId);
}

/**
 * A fingerprint of the vault key — never the key itself.
 *
 * Storing the raw key would put a second copy of the most sensitive value at
 * rest for no benefit; a truncated digest is enough to notice it changed, and is
 * useless to anyone who reads it.
 */
async function vaultKeyFingerprint(vaultKeyHex: string): Promise<string> {
  const bytes = new TextEncoder().encode(vaultKeyHex);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest).slice(0, 8))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Record the vault key this account accepts for a group. */
async function pinVaultKey(groupId: string, vaultKeyHex: string): Promise<void> {
  await trust.pinVaultKey(groupId, await vaultKeyFingerprint(vaultKeyHex));
}

/**
 * Whether the vault key differs from the one previously accepted.
 *
 * `null` means no pin yet (first load) — nothing to compare against.
 */
async function vaultKeyChanged(groupId: string, vaultKeyHex: string): Promise<boolean | null> {
  const pinned = trust.vaultKeyPin(groupId);
  if (pinned === undefined) return null;
  return pinned !== (await vaultKeyFingerprint(vaultKeyHex));
}

/** A stable fingerprint of a wrapped-key set, for telling same-epoch forks apart. */
async function keysDigest(sharedJson: string): Promise<string> {
  const bytes = new TextEncoder().encode(sharedJson);
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hash).slice(0, 8))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** The highest verified epoch this account has accepted for a group. */
export function epochFloor(groupId: string): number {
  return trust.epochPin(groupId)?.epoch ?? 0;
}

/**
 * How a verified set ranks against what has already been accepted.
 *
 * Only meaningful once the SIGNATURE has been checked — the epoch lives inside
 * the signed payload, so it means nothing before then.
 */
type EpochVerdict = 'current' | 'rolled-back' | 'forked';

async function rankEpoch(
  groupId: string,
  sharedJson: string,
  epoch: number,
): Promise<EpochVerdict> {
  const pin = trust.epochPin(groupId);
  if (pin === undefined) return 'current';
  if (epoch < pin.epoch) return 'rolled-back';
  if (epoch > pin.epoch) return 'current';
  // Same epoch. An identical set is just a re-read; a DIFFERENT one at the same
  // epoch means two sets claim to be the same version of the truth.
  return (await keysDigest(sharedJson)) === pin.digest ? 'current' : 'forked';
}

async function acceptEpoch(groupId: string, sharedJson: string, epoch: number): Promise<void> {
  await trust.acceptEpoch(groupId, epoch, await keysDigest(sharedJson));
}

/** How a relay-served member compares against what we have pinned. */
export type TrustState =
  /** Key matches what we already accepted — safe to wrap to. */
  | 'pinned'
  /** Never seen before. Needs the user to accept it before we wrap anything. */
  | 'unknown'
  /** Pinned before under a DIFFERENT key. Either a real re-enrolment or an
   *  attempted substitution — never resolved automatically. */
  | 'changed';

export function trustStateOf(
  groupId: string,
  member: { member_id: string; public_key: string; signing_key?: string },
): TrustState {
  const pinned = pinnedKeys(groupId)[member.member_id];
  if (pinned === undefined) return 'unknown';
  if (pinned.public_key !== member.public_key) return 'changed';
  // A signing key appearing where we pinned none is first sight of that key, not
  // a change — every member pinned before signing existed is in that state, and
  // treating it as a substitution would lock out every existing family at once.
  // A DIFFERENT non-empty key is a real change and needs the same human decision
  // as a moved X25519 key.
  const seen = member.signing_key ?? '';
  if (pinned.signing_key !== '' && seen !== '' && pinned.signing_key !== seen) return 'changed';
  return 'pinned';
}

/** Adopt a signing key first seen for an already-trusted member (see above). */
async function backfillSigningPin(groupId: string, member: GroupMemberView): Promise<void> {
  const pinned = pinnedKeys(groupId)[member.member_id];
  const seen = member.signing_key ?? '';
  if (pinned && pinned.signing_key === '' && seen !== '' && pinned.public_key === member.public_key) {
    await trust.pinMember(groupId, member.member_id, member.public_key, seen);
  }
}

// ----- Group relay HTTP -----------------------------------------------------

/** The server base URL + this device's bearer token, or throw if sync is off. */
function relay(): { base: string; token: string } {
  const cfg = syncConfig();
  if (cfg === null) {
    throw new Error('Family sharing needs cloud sync — enable it first.');
  }
  return { base: cfg.serverUrl, token: cfg.deviceToken };
}

/** True once family sharing is usable (cloud sync configured). */
export function sharingAvailable(): boolean {
  return syncConfig() !== null;
}

function authJson(token: string): HeadersInit {
  return { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
}

async function createGroupOnServer(member: MemberIdentity): Promise<string> {
  const { base, token } = relay();
  const res = await fetch(`${base}/v1/groups`, {
    method: 'POST',
    headers: authJson(token),
    body: JSON.stringify({
      member_id: member.id,
      name: member.name,
      public_key: member.public_key,
      signing_key: member.signing_key ?? '',
    }),
  });
  if (!res.ok) throw new Error(`Could not create the family vault (HTTP ${res.status}).`);
  return ((await res.json()) as { group_id: string }).group_id;
}

/** Fetch the group directory, or null if I am no longer a member (403/404). */
async function getGroup(groupId: string): Promise<{
  members: GroupMemberView[];
  keys_version: number;
  content_version: number;
} | null> {
  const { base, token } = relay();
  const res = await fetch(`${base}/v1/groups/${encodeURIComponent(groupId)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (res.status === 403 || res.status === 404) return null;
  if (!res.ok) throw new Error(`Could not load the family vault (HTTP ${res.status}).`);
  return res.json();
}

/** Fetch the opaque SharedVault (wrapped keys) JSON, or null if none uploaded. */
async function getKeys(groupId: string): Promise<{ json: string; version: string | null } | null> {
  const { base, token } = relay();
  const res = await fetch(`${base}/v1/groups/${encodeURIComponent(groupId)}/keys`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`Could not load keys (HTTP ${res.status}).`);
  return { json: await res.text(), version: res.headers.get(VERSION_HEADER) };
}

async function putKeys(groupId: string, json: string, ifMatch: string | null): Promise<string> {
  const { base, token } = relay();
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/octet-stream',
  };
  if (ifMatch !== null) headers['If-Match'] = ifMatch;
  const res = await fetch(`${base}/v1/groups/${encodeURIComponent(groupId)}/keys`, {
    method: 'PUT',
    headers,
    body: json,
  });
  if (!res.ok) throw new Error(`Could not upload keys (HTTP ${res.status}).`);
  return res.headers.get(VERSION_HEADER) ?? (await res.text());
}

/** Fetch the opaque ContentBlob JSON, or null if none uploaded. */
async function getContent(
  groupId: string,
): Promise<{ json: string; version: string | null } | null> {
  const { base, token } = relay();
  const res = await fetch(`${base}/v1/groups/${encodeURIComponent(groupId)}/vault`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`Could not load shared items (HTTP ${res.status}).`);
  return { json: await res.text(), version: res.headers.get(VERSION_HEADER) };
}

async function putContent(groupId: string, json: string, ifMatch: string | null): Promise<string> {
  const { base, token } = relay();
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/octet-stream',
  };
  if (ifMatch !== null) headers['If-Match'] = ifMatch;
  const res = await fetch(`${base}/v1/groups/${encodeURIComponent(groupId)}/vault`, {
    method: 'PUT',
    headers,
    body: json,
  });
  if (!res.ok) throw new Error(`Could not save shared items (HTTP ${res.status}).`);
  return res.headers.get(VERSION_HEADER) ?? (await res.text());
}

// ----- High-level operations ------------------------------------------------

/** Map the relay's member view to the shape WASM wants. */
function recipients(members: GroupMemberView[]): string {
  return JSON.stringify(
    members.map((m) => ({
      id: m.member_id,
      name: m.name,
      public_key: m.public_key,
      signing_key: m.signing_key ?? '',
    })),
  );
}

/**
 * Resolve the PINNED identity of whoever signed `sharedJson`, ready to verify
 * against.
 *
 * Deliberately built from the local pin, never from the relay's directory: the
 * signature exists to authenticate a blob the relay served, so checking it
 * against a key the same relay also served would prove nothing.
 *
 * Returns null when the set is unsigned, or when the signer is someone this
 * device has no pinned signing key for — both cases the caller must handle
 * explicitly rather than read through.
 */
function pinnedSignerFor(
  groupId: string,
  sharedJson: string,
  me: MemberIdentity,
): { id: string; signer: string } | null {
  const signerId = shared_vault_signer(sharedJson);
  if (!signerId) return null;
  if (signerId === me.id) {
    // We signed it ourselves; verify against our own key, which needs no pin.
    return {
      id: signerId,
      signer: JSON.stringify({
        id: me.id,
        name: me.name,
        public_key: me.public_key,
        signing_key: me.signing_key ?? '',
      }),
    };
  }
  const pin = pinnedKeys(groupId)[signerId];
  if (!pin || pin.signing_key === '') return null;
  return {
    id: signerId,
    signer: JSON.stringify({
      id: signerId,
      name: '',
      public_key: pin.public_key,
      signing_key: pin.signing_key,
    }),
  };
}

/** This device's own public identity, in the shape a verify call wants. */
function selfSigner(me: MemberIdentity): string {
  return JSON.stringify({
    id: me.id,
    name: me.name,
    public_key: me.public_key,
    signing_key: me.signing_key ?? '',
  });
}

/** Why a wrapped-key set could not be authenticated. */
export type KeysTrust =
  /** Signed by a member whose key we have pinned, and the signature verifies. */
  | 'verified'
  /** No signature. Only possible for a group predating signing (a downgrade on
   *  a group we have seen signed is refused outright, not reported here). */
  | 'unsigned'
  /** Signed by someone we hold no pinned signing key for — we cannot tell
   *  whether it is a real member or the relay. */
  | 'unknown-signer'
  /** A signature is present and does NOT verify. This is tampering. */
  | 'bad-signature'
  /** Verified, but OLDER than a set this device already accepted — the relay
   *  served a stale set. Nothing is forged, which is exactly why the epoch,
   *  not the signature, is what catches it. */
  | 'rolled-back'
  /** Verified and at the SAME epoch as one already accepted, but a different
   *  set. Two writes claim to be the same version of the truth — a concurrent
   *  write the relay failed to serialize, or the relay splitting the family
   *  onto two vault keys deliberately. */
  | 'forked';

/**
 * Create a new family vault owned by this device. Generates a fresh vault key,
 * seals an empty content set under it, wraps the key to the owner, and uploads
 * both. Returns the new group id.
 */
export async function createFamilyVault(memberName: string, vaultName: string): Promise<string> {
  await ensureReady();
  const member = await ensureMember(memberName);
  const groupId = await createGroupOnServer(member);

  const vaultKey = generate_vault_key();
  // Trusted by construction: we generated it locally, it has not been near the
  // relay. Pinning here means any later change is a real change.
  await pinVaultKey(groupId, vaultKey);
  const shared = share_vault_key(
    vaultKey,
    JSON.stringify([
      {
        id: member.id,
        name: member.name,
        public_key: member.public_key,
        signing_key: member.signing_key ?? '',
      },
    ]),
    authorOf(member),
  );
  await trust.markSigned(groupId);
  await acceptEpoch(groupId, shared, shared_vault_epoch(shared));
  const content = seal_group_content(JSON.stringify([]), vaultKey);
  const kv = await putKeys(groupId, shared, null);
  await putContent(groupId, content, null);
  void kv;
  rememberGroup({ groupId, name: vaultName.trim() || 'Family vault' });
  return groupId;
}

// ----- Recovery contacts ----------------------------------------------------
//
// Losing the Emergency Kit (the device Secret Key) otherwise means losing the
// vault forever. A member can seal their Secret Key to a family member, who can
// hand it back later. The contact still cannot open the vault: the Secret Key is
// only one of the two 2SKD factors and the master password is never shared.
//
// The sealed blob rides inside the shared vault's content as a reserved entry, so
// it syncs with the family and needs no new server endpoint. Every member can see
// the ciphertext; only the addressed contact can open it.

/** Reserved entry title marking a recovery blob (hidden from the item list). */
const RECOVERY_TITLE = '__recovery__';

/** What a recovery entry carries (stored as the entry's SecureNote body). */
interface RecoveryPayload {
  /** member_id of the person being recovered (the sealer). */
  for: string;
  forName: string;
  /** member_id of the contact who can open it. */
  to: string;
  toName: string;
  /** The `SealedBox` JSON. */
  sealed: string;
}

/** True if this entry is a reserved recovery blob rather than a real item. */
export function isRecoveryEntry(e: Entry): boolean {
  return e.title === RECOVERY_TITLE;
}

/** Real, user-visible shared items (recovery blobs filtered out). */
export function visibleEntries(entries: Entry[]): Entry[] {
  return entries.filter((e) => !isRecoveryEntry(e));
}

function payloadOf(e: Entry): RecoveryPayload | null {
  if (!isRecoveryEntry(e) || !('SecureNote' in e.content)) return null;
  try {
    return JSON.parse(e.content.SecureNote) as RecoveryPayload;
  } catch {
    return null;
  }
}

/** Recovery blobs addressed to me — the ones I can open for a family member. */
export function recoveryHeldBy(entries: Entry[], myMemberId: string): RecoveryPayload[] {
  return entries
    .map(payloadOf)
    .filter((p): p is RecoveryPayload => p !== null && p.to === myMemberId);
}

/** My own recovery contact, if I've set one. */
export function myRecoveryContact(entries: Entry[], myMemberId: string): RecoveryPayload | null {
  return entries.map(payloadOf).find((p) => p !== null && p.for === myMemberId) ?? null;
}

/**
 * Seal `secretKey` to `contact` and return the entries with the recovery blob
 * added (replacing any previous one for me). The caller persists them.
 */
export async function withRecoveryContact(
  entries: Entry[],
  me: MemberIdentity,
  contact: GroupMemberView,
  secretKey: string,
  groupId: string,
): Promise<Entry[]> {
  await ensureReady();

  // HARDEST GATE IN THE CLIENT, because this is the only path where a
  // shared-vault compromise becomes a PERSONAL-vault compromise.
  //
  // This seals the device Secret Key — one of the two 2SKD factors — to the
  // contact's public key. If that key is one the relay controls, the relay ends
  // up holding the Secret Key AND the personal SealedVault it already stores,
  // collapsing 2SKD to a single offline guess of the master password.
  //
  // Unlike a normal grant, an unpinned key here is refused outright rather than
  // queued for approval: there is no safe "accept and continue" for handing
  // over an authentication factor, and the recovery flow is rare and
  // deliberate, so requiring the contact to be an already-trusted member costs
  // nothing real.
  const state = trustStateOf(groupId, contact);
  if (state !== 'pinned') {
    throw new Error(
      state === 'changed'
        ? `${contact.name || 'That member'}’s key has changed since you last trusted it. ` +
          'Nothing was shared. Confirm the new safety number with them in person or by phone, ' +
          're-approve them as a member, and only then set them as a recovery contact.'
        : `${contact.name || 'That member'} is not a trusted member on this device yet. ` +
          'Approve them and confirm the safety number with them out of band before making ' +
          'them a recovery contact — this step hands them a factor of your own vault.',
    );
  }

  const sealed = seal_recovery(
    JSON.stringify({ id: contact.member_id, name: contact.name, public_key: contact.public_key }),
    secretKey,
  );
  const payload: RecoveryPayload = {
    for: me.id,
    forName: me.name,
    to: contact.member_id,
    toName: contact.name,
    sealed,
  };
  const entry: Entry = {
    id: `rec-${me.id}`,
    title: RECOVERY_TITLE,
    tags: [],
    favorite: false,
    updated_epoch: Math.floor(Date.now() / 1000),
    content: { SecureNote: JSON.stringify(payload) },
  };
  // Replace any previous recovery blob for me.
  const others = entries.filter((e) => payloadOf(e)?.for !== me.id);
  return [...others, entry];
}

/** Open a recovery blob addressed to me, returning the family member's Secret Key. */
export async function revealRecovery(payload: RecoveryPayload, mySecret: string): Promise<string> {
  await ensureReady();
  return open_recovery(payload.sealed, mySecret);
}

export type { RecoveryPayload };

/** Compose the shareable invite string: the group id + the single-use code. */
export function formatInvite(groupId: string, code: string): string {
  return `${groupId}.${code}`;
}

/** Split a shareable invite string back into its group id and code. */
export function parseInvite(invite: string): { groupId: string; code: string } {
  const trimmed = invite.trim();
  const dot = trimmed.indexOf('.');
  if (dot <= 0 || dot === trimmed.length - 1) {
    throw new Error('That does not look like a valid invite.');
  }
  return { groupId: trimmed.slice(0, dot), code: trimmed.slice(dot + 1) };
}

/**
 * Redeem a shareable invite (`groupId.code`) to join a family vault on the
 * device's sync server. After this the device is in the member directory but has
 * no wrapped key yet — an existing member must grant access (see
 * {@link loadFamily}'s auto-reconcile) before the content is readable. Returns
 * the joined group id.
 */
export async function joinFamilyVault(
  invite: string,
  memberName: string,
  vaultName: string,
): Promise<string> {
  const { groupId, code } = parseInvite(invite);
  const { base, token } = relay();
  const member = await ensureMember(memberName);
  const res = await fetch(`${base}/v1/groups/${encodeURIComponent(groupId)}/members`, {
    method: 'POST',
    headers: authJson(token),
    body: JSON.stringify({
      code,
      member_id: member.id,
      name: member.name,
      public_key: member.public_key,
      signing_key: member.signing_key ?? '',
    }),
  });
  if (res.status === 403) throw new Error('That invite is invalid, used, or expired.');
  if (res.status === 404) throw new Error('No such family vault for that invite.');
  if (!res.ok) throw new Error(`Could not join (HTTP ${res.status}).`);
  rememberGroup({ groupId, name: vaultName.trim() || 'Family vault' });
  return groupId;
}

/** Mint a single-use invite for a group; returns the code to share out-of-band. */
export async function inviteToFamily(
  groupId: string,
  ttlSeconds = 24 * 60 * 60,
): Promise<{ code: string; expiresEpoch: number }> {
  const { base, token } = relay();
  const res = await fetch(`${base}/v1/groups/${encodeURIComponent(groupId)}/invites`, {
    method: 'POST',
    headers: authJson(token),
    body: JSON.stringify({ ttl_seconds: ttlSeconds }),
  });
  if (!res.ok) throw new Error(`Could not create an invite (HTTP ${res.status}).`);
  const body = (await res.json()) as { invite_code: string; expires_epoch: number };
  return { code: body.invite_code, expiresEpoch: body.expires_epoch };
}

/**
 * Load a family vault: fetch the directory, keys, and content. If I hold access
 * AND there are joined members without a wrapped key yet, grant them access and
 * re-upload the keys (the zero-knowledge "an online member completes the invite"
 * step). Returns the decrypted entries or a no-access marker.
 */
export async function loadFamily(groupId: string, name: string): Promise<FamilyVault> {
  await ensureReady();
  const member = memberIdentity();
  if (!member) throw new Error('This device has no sharing identity yet.');

  const group = await getGroup(groupId);
  if (group === null) {
    // Not in the directory any more — revoked/removed.
    return {
      groupId,
      name,
      members: [],
      entries: [],
      hasAccess: false,
      removed: true,
      safety: '',
      justGranted: [],
      pendingApproval: [],
      keysVersion: null,
      contentVersion: null,
    };
  }
  let keys = await getKeys(groupId);
  const base: FamilyVault = {
    groupId,
    name,
    members: group.members,
    entries: [],
    hasAccess: false,
    removed: false,
    justGranted: [],
    pendingApproval: [],
    // Computed from the directory the relay just served us — comparing it
    // out of band is what catches a substituted key.
    safety: await safetyNumber(group.members),
    trustWiped: trustStateWiped(groupId, group.members),
    keysVersion: keys?.version ?? null,
    contentVersion: null,
  };
  if (!keys) return base;

  // AUTHENTICATE THE WRAPPED-KEY SET BEFORE USING IT.
  //
  // Unwrapping alone proves only that somebody wrapped a key to us. Producing a
  // wrap needs nothing but our PUBLIC key, so the relay can mint its own vault
  // key, wrap it correctly to every real member, and overwrite the blob — and
  // every member decrypts happily. The signature is what makes that forgeable
  // only by a member whose key we have pinned.
  const signed = pinnedSignerFor(groupId, keys.json, member);
  let vaultKey: string;
  if (signed === null) {
    const signerId = shared_vault_signer(keys.json);
    if (signerId) {
      // Signed, but by someone we hold no pinned signing key for. Could be a
      // member we have never completed a trust decision with — or the relay.
      // Indistinguishable from here, so we stop.
      return { ...base, keysTrust: 'unknown-signer' };
    }
    if (requiresSignature(groupId)) {
      // We have seen this group signed before. An unsigned set now is a
      // downgrade, not history.
      return { ...base, keysTrust: 'bad-signature' };
    }
    // Genuinely predates signing. Readable, but nobody has proven authorship —
    // surfaced so the UI can ask a member to adopt and sign it.
    try {
      vaultKey = unwrap_vault_key_unsigned(keys.json, member.secret, member.id);
    } catch {
      return base; // joined but not yet granted access
    }
    base.keysTrust = 'unsigned';
  } else {
    await trust.markSigned(groupId);
    try {
      vaultKey = unwrap_vault_key(keys.json, member.secret, member.id, signed.signer);
    } catch (err) {
      const msg = String(err);
      // Not a recipient yet is an ordinary state; a failed signature is not.
      if (msg.includes('signature') || msg.includes('unsigned')) {
        return { ...base, keysTrust: 'bad-signature' };
      }
      return base; // joined but not yet granted access
    }
    // Verified — so the epoch inside the signed payload is now trustworthy.
    // Check it BEFORE using the key: a replayed set decrypts perfectly, since
    // nothing about it was forged.
    const epoch = shared_vault_epoch(keys.json);
    const verdict = await rankEpoch(groupId, keys.json, epoch);
    if (verdict !== 'current') {
      return { ...base, keysTrust: verdict === 'forked' ? 'forked' : 'rolled-back' };
    }
    await acceptEpoch(groupId, keys.json, epoch);
    base.keysTrust = 'verified';
  }

  // Has the vault key itself changed since this device last accepted one?
  //
  // This is the check that makes wholesale substitution visible. A relay can
  // mint its own key, wrap it correctly to every genuine member public key, and
  // overwrite both blobs; everyone still decrypts, and the safety number is
  // unchanged because it covers only member ids and public keys. Without this,
  // nothing anywhere notices.
  //
  // A change is NOT reported as an attack. A legitimate rotation — any member
  // revoking someone — also changes the key, and this device may not have
  // initiated it. The two are indistinguishable from here, so it is surfaced
  // as a decision with the benign explanation stated first.
  const keyChanged = await vaultKeyChanged(groupId, vaultKey);
  if (keyChanged === true) {
    return {
      ...base,
      members: group.members,
      // Deliberately NOT granting access: entries are left unread and nothing
      // is re-sealed under a key we have not accepted. Re-sealing would hand
      // the relay the plaintext it is fishing for.
      hasAccess: false,
      vaultKeyChanged: true,
    };
  }
  if (keyChanged === null) {
    // First load on this device: trust on first use, same as member keys.
    await pinVaultKey(groupId, vaultKey);
  }

  // Reconcile members who lack a wrap — but ONLY to keys we have already
  // accepted. This loop used to wrap K_vault to every relay-listed key with no
  // check at all, which is precisely how a hostile relay reads a shared vault:
  // list one fabricated member, and the next honest load hands over the key.
  //
  // Now:
  //   'pinned'  -> we have accepted this exact key before; grant automatically.
  //   'unknown' -> first sight; surfaced for explicit approval, nothing sent.
  //   'changed' -> the key moved under an id we already trusted; surfaced as a
  //                warning and NEVER auto-approved.
  //
  // Note the ordering: nothing is uploaded until the decision is made. The old
  // flow computed a safety number for display *after* it had already granted,
  // so a user following the instruction ("if it differs, stop") stopped after
  // the key had left.
  const wrappedIds = wrappedMemberIds(keys.json);
  const missing = group.members.filter(
    (m) => !wrappedIds.has(m.member_id) && m.member_id !== member.id,
  );
  const grantedNames: string[] = [];
  const pendingApproval: PendingMember[] = [];
  const toGrant: GroupMemberView[] = [];

  for (const m of missing) {
    const state = trustStateOf(groupId, m);
    if (state === 'pinned') {
      toGrant.push(m);
    } else {
      pendingApproval.push({
        memberId: m.member_id,
        name: m.name || m.member_id,
        publicKey: m.public_key,
        state,
      });
    }
  }

  // Never extend a set we could not authenticate. Granting would re-sign the
  // attacker's vault key with a real member's key, laundering it into something
  // every other member accepts.
  if (toGrant.length > 0 && base.keysTrust !== 'verified') {
    for (const m of toGrant) {
      pendingApproval.push({
        memberId: m.member_id,
        name: m.name || m.member_id,
        publicKey: m.public_key,
        state: trustStateOf(groupId, m),
      });
    }
    toGrant.length = 0;
  }

  if (toGrant.length > 0) {
    let updated = keys.json;
    for (const m of toGrant) {
      updated = grant_group_access(
        updated,
        authorOf(member),
        JSON.stringify({
          id: m.member_id,
          name: m.name,
          public_key: m.public_key,
          signing_key: m.signing_key ?? '',
        }),
        signed?.signer ?? selfSigner(member),
      );
      grantedNames.push(m.name || m.member_id);
    }
    const newVersion = await putKeys(groupId, updated, keys.version);
    await acceptEpoch(groupId, updated, shared_vault_epoch(updated));
    keys = { json: updated, version: newVersion };
    base.keysVersion = newVersion;
  }

  // Pin everyone already holding a wrap. They were granted under an earlier
  // policy (or by another device), so recording their current key now is what
  // makes a LATER substitution detectable. Existing wraps are not re-issued.
  for (const m of group.members) {
    if (wrappedIds.has(m.member_id) && trustStateOf(groupId, m) === 'unknown') {
      await trust.pinMember(groupId, m.member_id, m.public_key, m.signing_key ?? '');
    } else {
      await backfillSigningPin(groupId, m);
    }
  }

  const content = await getContent(groupId);
  const entries: Entry[] = content
    ? (JSON.parse(open_group_content(content.json, vaultKey)) as Entry[])
    : [];
  return {
    ...base,
    entries,
    hasAccess: true,
    justGranted: grantedNames,
    pendingApproval,
    contentVersion: content?.version ?? null,
  };
}

/** The set of member ids currently wrapped in a SharedVault JSON. */
function wrappedMemberIds(sharedJson: string): Set<string> {
  try {
    const parsed = JSON.parse(sharedJson) as { wrapped?: { member_id: string }[] };
    return new Set((parsed.wrapped ?? []).map((w) => w.member_id));
  } catch {
    return new Set();
  }
}

/** Re-seal `entries` for the family vault and push the content blob. */
/**
 * Accept `memberId`'s current public key and wrap the vault key to them.
 *
 * This is the human decision ADR-0004 always described and the code never
 * actually required. It must be called from an explicit user action — never
 * from a load, a watcher, or a retry — because approving is exactly the
 * irreversible step: once the key is wrapped and uploaded, whoever holds the
 * matching secret can read every shared credential, and un-approving cannot
 * take that back (it requires rotating the vault key and re-sealing).
 *
 * `expectedPublicKey` is what the user was shown when they decided. If the
 * relay has served something different since, this refuses rather than
 * approving a key nobody looked at — closing the window between display and
 * confirmation.
 */
export async function approveMember(
  groupId: string,
  memberId: string,
  expectedPublicKey: string,
): Promise<void> {
  await ensureReady();
  const member = memberIdentity();
  if (member === null) throw new Error('No member identity on this device.');

  // Re-fetch rather than trusting whatever the UI is holding: the decision must
  // be made against the directory as it is NOW.
  const group = await getGroup(groupId);
  const target = group?.members.find((m) => m.member_id === memberId);
  if (target === undefined) {
    throw new Error('That member is no longer in the group.');
  }
  if (target.public_key !== expectedPublicKey) {
    throw new Error(
      'This member’s key changed while you were deciding. Nothing was shared. Re-check the safety number before approving.',
    );
  }

  const keys = await getKeys(groupId);
  if (keys === null) throw new Error('This vault has no keys to share yet.');

  // Authenticate the set we are about to extend. Approving into a forged set
  // would sign the attacker's vault key with a real member's key.
  const signed = pinnedSignerFor(groupId, keys.json, member);
  if (signed === null) {
    if (shared_vault_signer(keys.json) !== null || requiresSignature(groupId)) {
      throw new Error(
        'The shared keys for this vault could not be verified as coming from a member you trust. ' +
          'Nothing was shared. Check the safety number with your family before approving anyone.',
      );
    }
  }

  const updated = grant_group_access(
    keys.json,
    authorOf(member),
    JSON.stringify({
      id: target.member_id,
      name: target.name,
      public_key: target.public_key,
      signing_key: target.signing_key ?? '',
    }),
    signed?.signer ?? selfSigner(member),
  );
  await putKeys(groupId, updated, keys.version);
  await acceptEpoch(groupId, updated, shared_vault_epoch(updated));
  await trust.markSigned(groupId);
  // Pin only AFTER the grant lands, so a failed upload does not leave us
  // trusting a key we never actually shared to.
  await trust.pinMember(groupId, memberId, target.public_key, target.signing_key ?? '');
}

/**
 * Accept a changed vault key for a group.
 *
 * Called only from an explicit user action, after they have established that a
 * member was legitimately removed (which rotates the key). Accepting means this
 * device will read and re-seal content under the new key — so if the change was
 * in fact a relay substituting its own key, this is the step that hands over
 * the plaintext. The UI must say so plainly before offering it.
 */
export async function acceptRotatedVaultKey(groupId: string): Promise<void> {
  await ensureReady();
  const member = memberIdentity();
  if (member === null) throw new Error('No member identity on this device.');
  const keys = await getKeys(groupId);
  if (keys === null) throw new Error('This vault has no keys yet.');
  const signed = pinnedSignerFor(groupId, keys.json, member);
  if (signed === null && (shared_vault_signer(keys.json) !== null || requiresSignature(groupId))) {
    throw new Error(
      'The shared keys for this vault could not be verified as coming from a member you trust.',
    );
  }
  if (signed !== null) {
    const epoch = shared_vault_epoch(keys.json);
    const verdict = await rankEpoch(groupId, keys.json, epoch);
    if (verdict === 'rolled-back') {
      throw new Error(
        'These shared keys are older than ones this device already accepted. ' +
          'That is a stale copy being served back to you, not a normal change. ' +
          'Nothing was read. Check with your family before continuing.',
      );
    }
    if (verdict === 'forked') {
      throw new Error(
        'Two different versions of this vault\u2019s keys claim to be the same one. ' +
          'Nothing was read. Reload, and if it persists, check with your family ' +
          'before sharing anything.',
      );
    }
    await acceptEpoch(groupId, keys.json, epoch);
  }
  const vaultKey =
    signed === null
      ? unwrap_vault_key_unsigned(keys.json, member.secret, member.id)
      : unwrap_vault_key(keys.json, member.secret, member.id, signed.signer);
  await pinVaultKey(groupId, vaultKey);
}

export async function saveFamilyEntries(
  groupId: string,
  entries: Entry[],
  contentVersion: string | null,
): Promise<string> {
  await ensureReady();
  const member = memberIdentity();
  if (!member) throw new Error('This device has no sharing identity yet.');
  const keys = await getKeys(groupId);
  if (!keys) throw new Error('This family vault has no keys yet.');
  const signed = pinnedSignerFor(groupId, keys.json, member);
  if (signed === null && (shared_vault_signer(keys.json) !== null || requiresSignature(groupId))) {
    throw new Error(
      'The shared keys for this vault could not be verified as coming from a member you trust.',
    );
  }
  if (signed !== null) {
    const epoch = shared_vault_epoch(keys.json);
    const verdict = await rankEpoch(groupId, keys.json, epoch);
    if (verdict === 'rolled-back') {
      throw new Error(
        'These shared keys are older than ones this device already accepted. ' +
          'That is a stale copy being served back to you, not a normal change. ' +
          'Nothing was read. Check with your family before continuing.',
      );
    }
    if (verdict === 'forked') {
      throw new Error(
        'Two different versions of this vault\u2019s keys claim to be the same one. ' +
          'Nothing was read. Reload, and if it persists, check with your family ' +
          'before sharing anything.',
      );
    }
    await acceptEpoch(groupId, keys.json, epoch);
  }
  const vaultKey =
    signed === null
      ? unwrap_vault_key_unsigned(keys.json, member.secret, member.id)
      : unwrap_vault_key(keys.json, member.secret, member.id, signed.signer);
  const content = seal_group_content(JSON.stringify(entries), vaultKey);
  return putContent(groupId, content, contentVersion);
}

/**
 * Change a member's role (Owner only, enforced server-side). Owners' roles are
 * immutable — the server rejects that with 403.
 */
export async function setMemberRole(
  groupId: string,
  memberId: string,
  role: Role,
): Promise<void> {
  const { base, token } = relay();
  const res = await fetch(
    `${base}/v1/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(memberId)}/role`,
    { method: 'POST', headers: authJson(token), body: JSON.stringify({ role }) },
  );
  if (res.status === 403) throw new Error('Only the owner can change roles.');
  if (!res.ok) throw new Error(`Could not change role (HTTP ${res.status}).`);
}

/**
 * Remove a member and ROTATE the vault key for true revocation: drop their wrap,
 * generate a fresh key, re-wrap it to the remaining members, re-seal the current
 * entries under it, and push both. The removed member keeps only what they had
 * already read.
 */
export async function revokeMember(
  groupId: string,
  memberId: string,
  currentEntries: Entry[],
): Promise<void> {
  const { base, token } = relay();
  const member = memberIdentity();
  if (!member) throw new Error('This device has no sharing identity yet.');

  // 1. Drop them from the server directory.
  const del = await fetch(
    `${base}/v1/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(memberId)}`,
    { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } },
  );
  if (del.status === 403) throw new Error('Only the owner can remove members.');
  if (!del.ok) throw new Error(`Could not remove member (HTTP ${del.status}).`);

  // 2. Rotate: fresh key, re-wrap to the remaining directory, re-seal content.
  const group = await getGroup(groupId);
  if (group === null) throw new Error('You are not a member of this family vault.');
  const remaining = group.members.filter((m) => m.member_id !== memberId);
  const newKey = generate_vault_key();
  const keys = await getKeys(groupId);
  if (keys === null) throw new Error('This vault has no keys to rotate.');
  // Rotate FROM the current set so the new one carries a higher epoch. Building
  // a fresh set instead would restart at epoch 1, and the relay could replay the
  // pre-revocation set — which outranks it — to hand the removed member their
  // access straight back.
  const shared = rotate_vault_key(keys.json, newKey, recipients(remaining), authorOf(member));
  const content = seal_group_content(JSON.stringify(currentEntries), newKey);

  await putKeys(groupId, shared, keys.version);
  const existingContent = await getContent(groupId);
  await putContent(groupId, content, existingContent?.version ?? null);

  // We rotated deliberately, so accept the new key here. Without this, our own
  // revoke would trip the substitution check on the next load and look like an
  // attack — training the user to click through the warning, which is worse
  // than not having it.
  await pinVaultKey(groupId, newKey);
  await trust.markSigned(groupId);
  await acceptEpoch(groupId, shared, shared_vault_epoch(shared));
}

/**
 * Adopt an unsigned, pre-signing wrapped-key set: sign it as this device without
 * changing a single wrap, so every other member can authenticate it from here on.
 *
 * An explicit user action, never automatic. Signing says "I vouch that these are
 * my family's keys" — and this device cannot actually verify that, because the
 * set predates the mechanism that would let it. What it CAN do is pin the vault
 * key it has been reading all along, so from this point a substitution is
 * detectable. The UI must ask the user to confirm the safety number with their
 * family out of band first.
 */
export async function adoptUnsignedKeys(groupId: string): Promise<void> {
  await ensureReady();
  const member = await ensureMember(memberIdentity()?.name ?? 'Me');
  const keys = await getKeys(groupId);
  if (keys === null) throw new Error('This vault has no keys yet.');
  if (shared_vault_signer(keys.json) !== null) {
    throw new Error('These keys are already signed — reload the vault.');
  }
  if (requiresSignature(groupId)) {
    throw new Error(
      'These keys lost a signature they previously had. Do not adopt them — ' +
        'check with your family before going further.',
    );
  }
  // Confirm we can actually read the set before vouching for it.
  const vaultKey = unwrap_vault_key_unsigned(keys.json, member.secret, member.id);
  const signed = sign_shared_vault(keys.json, authorOf(member));
  await putKeys(groupId, signed, keys.version);
  await acceptEpoch(groupId, signed, shared_vault_epoch(signed));
  await pinVaultKey(groupId, vaultKey);
  await trust.pinMember(groupId, member.id, member.public_key, member.signing_key ?? '');
  await trust.markSigned(groupId);
}
