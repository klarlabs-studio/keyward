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
  // This device's own id on the server, when known. The server's `current` flag
  // on GET /v1/devices is the source of truth for "this device"; this is a local
  // fallback so the UI can still identify itself if that flag is ever missing.
  deviceId?: string | null;
}

/** One device linked to the account, as returned by GET /v1/devices. */
export interface DeviceInfo {
  id: string;
  label: string;
  created_epoch: number;
  // True for the device making the request (i.e. this browser).
  current: boolean;
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
        deviceId: typeof parsed.deviceId === 'string' ? parsed.deviceId : null,
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
 * Derive a short, human-friendly label for the current device from the browser's
 * user agent (e.g. "Chrome on macOS"). A best-effort default the caller can send
 * when registering or adding a device so the devices list is legible.
 */
export function defaultDeviceLabel(): string {
  const ua = typeof navigator !== 'undefined' ? navigator.userAgent : '';
  if (!ua) return 'Web vault';

  let browser = 'Browser';
  if (/\bEdg\//.test(ua)) browser = 'Edge';
  else if (/\bOPR\/|\bOpera\b/.test(ua)) browser = 'Opera';
  else if (/\bFirefox\//.test(ua)) browser = 'Firefox';
  else if (/\bChrome\//.test(ua)) browser = 'Chrome';
  else if (/\bSafari\//.test(ua)) browser = 'Safari';

  let os = '';
  if (/\bWindows\b/.test(ua)) os = 'Windows';
  else if (/\b(iPhone|iPad|iPod)\b/.test(ua)) os = 'iOS';
  else if (/\bMac OS X\b|\bMacintosh\b/.test(ua)) os = 'macOS';
  else if (/\bAndroid\b/.test(ua)) os = 'Android';
  else if (/\bLinux\b/.test(ua)) os = 'Linux';

  return os ? `${browser} on ${os}` : browser;
}

/**
 * Register a new account on `serverUrl` (optionally attaching `email`), store the
 * returned account id + device token as the sync config, and return the config.
 * This is the "enable cloud sync on the first device" flow.
 */
export async function register(
  serverUrl: string,
  email?: string,
  label?: string,
): Promise<SyncConfig> {
  const base = normalizeUrl(serverUrl);
  if (!base) throw new Error('A server URL is required.');
  const deviceLabel = label?.trim() || defaultDeviceLabel();
  const payload: Record<string, string> = { label: deviceLabel };
  if (email) payload.email = email;
  const res = await fetch(`${base}/v1/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`Registration failed (HTTP ${res.status}).`);
  }
  const body = (await res.json()) as {
    account_id: string;
    device_token: string;
    device_id?: string;
  };
  const config: SyncConfig = {
    serverUrl: base,
    accountId: body.account_id,
    deviceToken: body.device_token,
    lastVersion: null,
    deviceId: body.device_id ?? null,
  };
  writeConfig(config);
  return config;
}

/**
 * Link THIS device to an existing account using a device token minted elsewhere
 * (via "add a device"). Validates the token against the server, then stores it as
 * this device's sync config. The caller then pulls the account's vault and
 * unlocks it with the master password + Secret Key. This is the cross-device
 * migration / "restore from cloud" flow.
 */
export async function linkAccount(serverUrl: string, deviceToken: string): Promise<SyncConfig> {
  const base = normalizeUrl(serverUrl);
  if (!base) throw new Error('A server URL is required.');
  const token = deviceToken.trim();
  if (!token) throw new Error('A device token is required.');
  // Validate the token by asking the server for this account's devices.
  const res = await fetch(`${base}/v1/devices`, {
    method: 'GET',
    headers: { Authorization: `Bearer ${token}` },
  });
  if (res.status === 401) throw new Error('That device token was not accepted by the server.');
  if (!res.ok) throw new Error(`Could not reach the server (HTTP ${res.status}).`);
  const config: SyncConfig = {
    serverUrl: base,
    accountId: '',
    deviceToken: token,
    lastVersion: null,
    deviceId: null,
  };
  writeConfig(config);
  return config;
}

/**
 * Provision a second device token for the same account (the "add a device"
 * flow). Returns the new token, which the user carries to the other device.
 */
export async function addDevice(label?: string): Promise<string> {
  const config = syncConfig();
  if (config === null) throw new Error('Cloud sync is not enabled on this device.');
  const deviceLabel = label?.trim() || defaultDeviceLabel();
  const res = await fetch(`${config.serverUrl}/v1/devices`, {
    method: 'POST',
    headers: { ...(authHeaders(config) as Record<string, string>), 'Content-Type': 'application/json' },
    body: JSON.stringify({ label: deviceLabel }),
  });
  if (!res.ok) {
    throw new Error(`Could not add a device (HTTP ${res.status}).`);
  }
  const body = (await res.json()) as { device_token: string; device_id?: string };
  return body.device_token;
}

/**
 * List every device linked to this account. Each carries a `current` flag set by
 * the server for the device making the request, so the UI can mark "this device"
 * and forbid revoking it.
 */
export async function listDevices(): Promise<DeviceInfo[]> {
  const config = syncConfig();
  if (config === null) throw new Error('Cloud sync is not enabled on this device.');
  const res = await fetch(`${config.serverUrl}/v1/devices`, {
    method: 'GET',
    headers: authHeaders(config),
  });
  if (!res.ok) {
    throw new Error(`Could not load devices (HTTP ${res.status}).`);
  }
  const body = (await res.json()) as { devices?: DeviceInfo[] };
  return body.devices ?? [];
}

/**
 * Revoke another device's token (the lost-device flow). That device can no longer
 * sync until it is re-linked. Throws on any non-2xx response, including a 404 for
 * an unknown device id.
 */
export async function revokeDevice(id: string): Promise<void> {
  const config = syncConfig();
  if (config === null) throw new Error('Cloud sync is not enabled on this device.');
  const res = await fetch(`${config.serverUrl}/v1/devices/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    headers: authHeaders(config),
  });
  if (!res.ok) {
    throw new Error(`Could not revoke device (HTTP ${res.status}).`);
  }
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
