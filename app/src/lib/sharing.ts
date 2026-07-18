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
  generate_vault_key,
  seal_group_content,
  open_group_content,
  share_vault_key,
  unwrap_vault_key,
  grant_group_access,
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

/** A member of a group, as the relay's directory reports it. */
export interface GroupMemberView {
  member_id: string;
  account_id: string;
  name: string;
  public_key: string;
  is_owner: boolean;
  added_epoch: number;
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
  keysVersion: string | null;
  contentVersion: string | null;
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

  // Auto-reconcile: grant any member in the directory who lacks a wrap.
  const wrappedIds = wrappedMemberIds(keys.json);
  const missing = group.members.filter((m) => !wrappedIds.has(m.member_id));
  if (missing.length > 0) {
    let updated = keys.json;
    for (const m of missing) {
      updated = grant_group_access(
        updated,
        member.secret,
        member.id,
        JSON.stringify({ id: m.member_id, name: m.name, public_key: m.public_key }),
      );
    }
    const newVersion = await putKeys(groupId, updated, keys.version);
    keys = { json: updated, version: newVersion };
    base.keysVersion = newVersion;
  }

  const content = await getContent(groupId);
  const entries: Entry[] = content
    ? (JSON.parse(open_group_content(content.json, vaultKey)) as Entry[])
    : [];
  return { ...base, entries, hasAccess: true, contentVersion: content?.version ?? null };
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
