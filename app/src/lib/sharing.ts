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
 */
export async function safetyNumber(members: GroupMemberView[]): Promise<string> {
  await ensureReady();
  return group_safety_number(
    JSON.stringify(
      members.map((m) => ({ id: m.member_id, name: m.name, public_key: m.public_key })),
    ),
  );
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
    return existing;
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

export function forgetGroup(groupId: string): void {
  const groups = joinedGroups().filter((g) => g.groupId !== groupId);
  localStorage.setItem(GROUPS_STORAGE, JSON.stringify(groups));
  const pins = allPins();
  delete pins[groupId];
  localStorage.setItem(PINS_STORAGE, JSON.stringify(pins));
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

const PINS_STORAGE = 'proctor.passbook.keypins.v1';

/** groupId -> memberId -> the public key we have accepted for that member. */
type PinMap = Record<string, Record<string, string>>;

function allPins(): PinMap {
  const raw = localStorage.getItem(PINS_STORAGE);
  if (raw === null) return {};
  try {
    const v = JSON.parse(raw) as PinMap;
    return v && typeof v === 'object' ? v : {};
  } catch {
    return {};
  }
}

/** The keys pinned for `groupId` (memberId -> public key). */
export function pinnedKeys(groupId: string): Record<string, string> {
  return allPins()[groupId] ?? {};
}

/** Pin `publicKey` as the accepted key for `memberId` in `groupId`. */
function pinKey(groupId: string, memberId: string, publicKey: string): void {
  const pins = allPins();
  pins[groupId] = { ...(pins[groupId] ?? {}), [memberId]: publicKey };
  localStorage.setItem(PINS_STORAGE, JSON.stringify(pins));
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
  member: { member_id: string; public_key: string },
): TrustState {
  const pinned = pinnedKeys(groupId)[member.member_id];
  if (pinned === undefined) return 'unknown';
  return pinned === member.public_key ? 'pinned' : 'changed';
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
    body: JSON.stringify({ member_id: member.id, name: member.name, public_key: member.public_key }),
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

/** Map the relay's member view to the `{id,name,public_key}` shape WASM wants. */
function recipients(members: GroupMemberView[]): string {
  return JSON.stringify(
    members.map((m) => ({ id: m.member_id, name: m.name, public_key: m.public_key })),
  );
}

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
  const shared = share_vault_key(
    vaultKey,
    JSON.stringify([{ id: member.id, name: member.name, public_key: member.public_key }]),
  );
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
    keysVersion: keys?.version ?? null,
    contentVersion: null,
  };
  if (!keys) return base;

  // Do I have a wrapped key?
  let vaultKey: string;
  try {
    vaultKey = unwrap_vault_key(keys.json, member.secret, member.id);
  } catch {
    return base; // joined but not yet granted access
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

  if (toGrant.length > 0) {
    let updated = keys.json;
    for (const m of toGrant) {
      updated = grant_group_access(
        updated,
        member.secret,
        member.id,
        JSON.stringify({ id: m.member_id, name: m.name, public_key: m.public_key }),
      );
      grantedNames.push(m.name || m.member_id);
    }
    const newVersion = await putKeys(groupId, updated, keys.version);
    keys = { json: updated, version: newVersion };
    base.keysVersion = newVersion;
  }

  // Pin everyone already holding a wrap. They were granted under an earlier
  // policy (or by another device), so recording their current key now is what
  // makes a LATER substitution detectable. Existing wraps are not re-issued.
  for (const m of group.members) {
    if (wrappedIds.has(m.member_id) && trustStateOf(groupId, m) === 'unknown') {
      pinKey(groupId, m.member_id, m.public_key);
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

  const updated = grant_group_access(
    keys.json,
    member.secret,
    member.id,
    JSON.stringify({ id: target.member_id, name: target.name, public_key: target.public_key }),
  );
  await putKeys(groupId, updated, keys.version);
  // Pin only AFTER the grant lands, so a failed upload does not leave us
  // trusting a key we never actually shared to.
  pinKey(groupId, memberId, target.public_key);
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
  const vaultKey = unwrap_vault_key(keys.json, member.secret, member.id);
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
  const shared = share_vault_key(newKey, recipients(remaining));
  const content = seal_group_content(JSON.stringify(currentEntries), newKey);

  const keys = await getKeys(groupId);
  await putKeys(groupId, shared, keys?.version ?? null);
  const existingContent = await getContent(groupId);
  await putContent(groupId, content, existingContent?.version ?? null);
}
