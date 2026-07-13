// Cloud-sync client for the Proctor Passbook vault. The server is zero-knowledge:
// it only ever stores the opaque sealed-vault blob (the exact localStorage
// string), never plaintext. This module owns the sync configuration and the
// HTTP contract with the sync server; the store decides *when* to push/pull.
//
// Config lives in localStorage under `proctor.passbook.sync.v1`:
//   { serverUrl, accountId, deviceToken, lastVersion }
// The device token is a bearer credential for this device; `lastVersion` is the
// server vault version this device last saw, used for optimistic concurrency
// (If-Match) so two devices editing at once produce a 409 rather than a silent
// clobber.

const SYNC_STORAGE = 'proctor.passbook.sync.v1';
const VERSION_HEADER = 'X-Vault-Version';

export interface SyncConfig {
  serverUrl: string;
  accountId: string;
  deviceToken: string;
  // The last server version this device successfully pushed/pulled, or null if
  // it has never synced a vault yet (so the first push omits If-Match).
  lastVersion: string | null;
}

/** Thrown by `push` when the server rejects the write on a version conflict. */
export class SyncConflict extends Error {
  constructor(public readonly serverVersion: string | null) {
    super('The vault was changed on another device.');
    this.name = 'SyncConflict';
  }
}

/** The stored sync configuration, or null if sync has never been enabled. */
export function syncConfig(): SyncConfig | null {
  const raw = localStorage.getItem(SYNC_STORAGE);
  if (raw === null) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<SyncConfig>;
    if (
      typeof parsed.serverUrl === 'string' &&
      typeof parsed.accountId === 'string' &&
      typeof parsed.deviceToken === 'string'
    ) {
      return {
        serverUrl: parsed.serverUrl,
        accountId: parsed.accountId,
        deviceToken: parsed.deviceToken,
        lastVersion: typeof parsed.lastVersion === 'string' ? parsed.lastVersion : null,
      };
    }
  } catch {
    // Corrupt config: treat as disabled rather than crashing the app.
  }
  return null;
}

/** True once cloud sync is configured for this device. */
export function isSyncEnabled(): boolean {
  return syncConfig() !== null;
}

function writeConfig(config: SyncConfig): void {
  localStorage.setItem(SYNC_STORAGE, JSON.stringify(config));
}

/** Update just the last-seen server version, preserving the rest of the config. */
function rememberVersion(version: string | null): void {
  const config = syncConfig();
  if (config === null) return;
  writeConfig({ ...config, lastVersion: version });
}

/** Normalise a base URL: strip a trailing slash so we can append `/v1/...`. */
function normalizeUrl(url: string): string {
  return url.trim().replace(/\/+$/, '');
}

function authHeaders(config: SyncConfig): HeadersInit {
  return { Authorization: `Bearer ${config.deviceToken}` };
}

/**
 * Register a new account on `serverUrl` (optionally attaching `email`), store the
 * returned account id + device token as the sync config, and return the config.
 * This is the "enable cloud sync on the first device" flow.
 */
export async function register(serverUrl: string, email?: string): Promise<SyncConfig> {
  const base = normalizeUrl(serverUrl);
  if (!base) throw new Error('A server URL is required.');
  const res = await fetch(`${base}/v1/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(email ? { email } : {}),
  });
  if (!res.ok) {
    throw new Error(`Registration failed (HTTP ${res.status}).`);
  }
  const body = (await res.json()) as { account_id: string; device_token: string };
  const config: SyncConfig = {
    serverUrl: base,
    accountId: body.account_id,
    deviceToken: body.device_token,
    lastVersion: null,
  };
  writeConfig(config);
  return config;
}

/**
 * Provision a second device token for the same account (the "add a device"
 * flow). Returns the new token, which the user carries to the other device.
 */
export async function addDevice(): Promise<string> {
  const config = syncConfig();
  if (config === null) throw new Error('Cloud sync is not enabled on this device.');
  const res = await fetch(`${config.serverUrl}/v1/devices`, {
    method: 'POST',
    headers: authHeaders(config),
  });
  if (!res.ok) {
    throw new Error(`Could not add a device (HTTP ${res.status}).`);
  }
  const body = (await res.json()) as { device_token: string };
  return body.device_token;
}

/** Disable cloud sync on this device by clearing its config (local data stays). */
export function disableSync(): void {
  localStorage.removeItem(SYNC_STORAGE);
}

/**
 * Push the raw sealed blob to the server with optimistic concurrency. Uses
 * `If-Match: <lastVersion>` (omitted for the first push). On success updates the
 * stored version. On a 409 conflict throws `SyncConflict` carrying the server's
 * current version so the caller can pull-and-merge.
 */
export async function push(rawBlob: string): Promise<string> {
  const config = syncConfig();
  if (config === null) throw new Error('Cloud sync is not enabled on this device.');
  const headers: Record<string, string> = {
    ...(authHeaders(config) as Record<string, string>),
    'Content-Type': 'application/octet-stream',
  };
  if (config.lastVersion !== null) {
    headers['If-Match'] = config.lastVersion;
  }
  const res = await fetch(`${config.serverUrl}/v1/vault`, {
    method: 'PUT',
    headers,
    body: rawBlob,
  });
  if (res.status === 409) {
    throw new SyncConflict(res.headers.get(VERSION_HEADER));
  }
  if (!res.ok) {
    throw new Error(`Push failed (HTTP ${res.status}).`);
  }
  // The new version is in the header; fall back to the body for resilience.
  const version = res.headers.get(VERSION_HEADER) ?? (await res.text());
  rememberVersion(version);
  return version;
}

/**
 * Pull the current sealed blob from the server. Returns `{ blob, version }`, or
 * null if the server has no vault yet (404). Records the version as last-seen.
 */
export async function pull(): Promise<{ blob: string; version: string | null } | null> {
  const config = syncConfig();
  if (config === null) throw new Error('Cloud sync is not enabled on this device.');
  const res = await fetch(`${config.serverUrl}/v1/vault`, {
    method: 'GET',
    headers: authHeaders(config),
  });
  if (res.status === 404) {
    return null;
  }
  if (!res.ok) {
    throw new Error(`Pull failed (HTTP ${res.status}).`);
  }
  const blob = await res.text();
  const version = res.headers.get(VERSION_HEADER);
  rememberVersion(version);
  return { blob, version };
}
