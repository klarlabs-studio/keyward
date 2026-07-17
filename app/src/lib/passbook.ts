// Typed async wrapper around the `passbook-wasm` crypto core. Everything the app
// does with real cryptography — sealing, opening, TOTP, strength, Watchtower —
// goes through here, so the UI never re-implements crypto and the WASM boundary
// stays in one place.
//
// The vault is stored locally as a single sealed (encrypted) JSON blob in
// `localStorage`. The master password never leaves this module's call stack, and
// only ciphertext is persisted.

import init, {
  generate_pp,
  generate_pw,
  generate_secret_key,
  open_vault,
  password_sha1,
  password_strength,
  seal_vault,
  secret_key_is_valid,
  totp_code,
  totp_seconds_remaining,
  watchtower_json,
} from '../wasm/pkg/passbook_wasm.js';
import type { Entry, Issue } from './passbook-types';

const STORAGE_KEY = 'proctor.passbook.vault.v1';
// The device Secret Key (2SKD factor). It is not secret *from this device* — it
// lives here so the vault can be unlocked with just the typed master — but it
// never leaves the device, so a stolen sealed vault is uncrackable without it.
const SECRET_KEY_STORAGE = 'proctor.passbook.secretkey.v1';

let ready: Promise<void> | null = null;

/** Load and instantiate the WASM module exactly once. */
export function ensureReady(): Promise<void> {
  if (!ready) {
    // Vite serves the .wasm as an asset URL; hand it to the generated loader.
    ready = init(new URL('../wasm/pkg/passbook_wasm_bg.wasm', import.meta.url)).then(
      () => undefined,
    );
  }
  return ready;
}

/** Wall-clock seconds since the epoch (the unit the TOTP functions expect). */
export function nowUnix(): number {
  return Math.floor(Date.now() / 1000);
}

/** True once a sealed vault exists in local storage. */
export function vaultExists(): boolean {
  return localStorage.getItem(STORAGE_KEY) !== null;
}

/**
 * The raw sealed vault blob exactly as persisted (the opaque `SealedVault` JSON
 * string), or null if none exists. Used by cloud sync to move the ciphertext
 * without re-sealing it.
 */
export function getRawVault(): string | null {
  return localStorage.getItem(STORAGE_KEY);
}

/**
 * Overwrite the local sealed vault with a raw blob (e.g. one pulled from the
 * sync server). The blob is opaque ciphertext — callers must re-open it with the
 * master password + Secret Key to use it.
 */
export function setRawVault(s: string): void {
  localStorage.setItem(STORAGE_KEY, s);
}

/** Remove the local sealed vault AND the device Secret Key (full reset). */
export function destroyVault(): void {
  localStorage.removeItem(STORAGE_KEY);
  localStorage.removeItem(SECRET_KEY_STORAGE);
}

/** The device Secret Key (Emergency-Kit format), or null if none is stored. */
export function getSecretKey(): string | null {
  return localStorage.getItem(SECRET_KEY_STORAGE);
}

/** True once a device Secret Key is present on this device. */
export function hasSecretKey(): boolean {
  return getSecretKey() !== null;
}

/** Persist a device Secret Key (e.g. after generating one or adding a device). */
export function storeSecretKey(key: string): void {
  localStorage.setItem(SECRET_KEY_STORAGE, key);
}

/** Remove only the device Secret Key, leaving the sealed vault intact. */
export function clearSecretKey(): void {
  localStorage.removeItem(SECRET_KEY_STORAGE);
}

/** Generate a fresh device Secret Key (does not store it). */
export async function newSecretKey(): Promise<string> {
  await ensureReady();
  return generate_secret_key();
}

/** True if `key` is a well-formed Secret Key (32 hex digits, grouping ignored). */
export async function isValidSecretKey(key: string): Promise<boolean> {
  await ensureReady();
  return secret_key_is_valid(key);
}

/**
 * Seal `entries` under `master` (+ optional device Secret Key) and persist the
 * ciphertext locally. Throws if sealing fails (it should not for well-formed
 * input). Pass `null`/omit `secretKey` for a master-only vault.
 */
export async function saveVault(
  entries: Entry[],
  master: string,
  secretKey?: string | null,
): Promise<void> {
  await ensureReady();
  const sealed = seal_vault(JSON.stringify(entries), master, secretKey ?? undefined);
  localStorage.setItem(STORAGE_KEY, sealed);
}

/**
 * Open the locally-stored sealed vault with `master` (+ optional Secret Key).
 * Throws on a wrong master password, a missing/wrong Secret Key, or any
 * tampering — the caller turns that into an "unlock failed" message without
 * learning anything more specific.
 */
export async function openVault(master: string, secretKey?: string | null): Promise<Entry[]> {
  await ensureReady();
  const sealed = localStorage.getItem(STORAGE_KEY);
  if (sealed === null) {
    throw new Error('No vault on this device yet.');
  }
  const json = open_vault(sealed, master, secretKey ?? undefined);
  return JSON.parse(json) as Entry[];
}

/** Create a brand-new sealed vault from `entries` (first-run). */
export async function createVault(
  entries: Entry[],
  master: string,
  secretKey?: string | null,
): Promise<void> {
  await ensureReady();
  await saveVault(entries, master, secretKey);
}

/** Estimate a password's strength in bits. */
export async function strengthBits(password: string): Promise<number> {
  await ensureReady();
  return password_strength(password);
}

/** The current 6-digit TOTP code for a base32 secret, or null if invalid. */
export async function totpCode(secretBase32: string): Promise<string | null> {
  await ensureReady();
  return totp_code(secretBase32, nowUnix()) ?? null;
}

/** Seconds left in the current 30-second TOTP window (for the countdown ring). */
export async function totpSecondsRemaining(): Promise<number> {
  await ensureReady();
  return totp_seconds_remaining(nowUnix());
}

/** Options for the password generator. */
export interface GenOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  avoidAmbiguous: boolean;
}

/** Generate a random password from the given character-class options. */
export async function generatePassword(o: GenOptions): Promise<string> {
  await ensureReady();
  return generate_pw(o.length, o.lowercase, o.uppercase, o.digits, o.symbols, o.avoidAmbiguous);
}

/** Generate a passphrase of `words` random words joined by `separator`. */
export async function generatePassphrase(words: number, separator = '-'): Promise<string> {
  await ensureReady();
  return generate_pp(words, separator);
}

/**
 * Check a password against HaveIBeenPwned via k-anonymity: only the first 5 chars
 * of its SHA-1 (computed locally in WASM) are sent; the full password never
 * leaves the device. Returns how many times it appears in known breaches
 * (0 = not found). Throws on a network/HTTP failure so the caller can degrade.
 */
export async function breachCount(password: string): Promise<number> {
  await ensureReady();
  const hash = password_sha1(password); // uppercase hex SHA-1
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { 'Add-Padding': 'true' },
  });
  if (!res.ok) throw new Error(`Breach check failed (HTTP ${res.status}).`);
  const body = await res.text();
  for (const line of body.split('\n')) {
    const [suf, count] = line.trim().split(':');
    if (suf === suffix) return Number.parseInt(count, 10) || 0;
  }
  return 0;
}

/** Run Watchtower over `entries`, returning the parsed findings. */
export async function watchtower(entries: Entry[]): Promise<Issue[]> {
  await ensureReady();
  const raw = watchtower_json(JSON.stringify(entries));
  const parsed = JSON.parse(raw) as Issue[] | { error: string };
  if (Array.isArray(parsed)) {
    return parsed;
  }
  throw new Error(`Watchtower failed: ${parsed.error}`);
}
