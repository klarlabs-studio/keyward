// Typed async wrapper around the `passbook-wasm` crypto core. Everything the app
// does with real cryptography — sealing, opening, TOTP, strength, Watchtower —
// goes through here, so the UI never re-implements crypto and the WASM boundary
// stays in one place.
//
// The vault is stored locally as a single sealed (encrypted) JSON blob in
// `localStorage`. The master password never leaves this module's call stack, and
// only ciphertext is persisted.

import init, {
  open_vault,
  password_strength,
  seal_vault,
  totp_code,
  totp_seconds_remaining,
  watchtower_json,
} from '../wasm/pkg/passbook_wasm.js';
import type { Entry, Issue } from './passbook-types';

const STORAGE_KEY = 'proctor.passbook.vault.v1';

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

/** Remove the local sealed vault (used by "reset" / sign-out flows). */
export function destroyVault(): void {
  localStorage.removeItem(STORAGE_KEY);
}

/**
 * Seal `entries` under `master` and persist the ciphertext locally.
 * Throws if sealing fails (it should not for well-formed input).
 */
export async function saveVault(entries: Entry[], master: string): Promise<void> {
  await ensureReady();
  const sealed = seal_vault(JSON.stringify(entries), master);
  localStorage.setItem(STORAGE_KEY, sealed);
}

/**
 * Open the locally-stored sealed vault with `master`. Throws on a wrong master
 * password or any tampering — the caller turns that into an "unlock failed"
 * message without learning anything more specific.
 */
export async function openVault(master: string): Promise<Entry[]> {
  await ensureReady();
  const sealed = localStorage.getItem(STORAGE_KEY);
  if (sealed === null) {
    throw new Error('No vault on this device yet.');
  }
  const json = open_vault(sealed, master);
  return JSON.parse(json) as Entry[];
}

/** Create a brand-new sealed vault from `entries` (first-run / demo seeding). */
export async function createVault(entries: Entry[], master: string): Promise<void> {
  await ensureReady();
  await saveVault(entries, master);
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
