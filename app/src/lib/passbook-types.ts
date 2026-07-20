// TypeScript mirror of the `keyward-passbook` serde model. These shapes must
// round-trip byte-for-byte through `seal_vault` / `open_vault`, so they mirror
// the Rust `Entry` / `Content` derives exactly (Content is externally tagged).

// Mirror of the Rust `PasskeyCredential` value object. A synced (multi-device)
// passkey the vault stores for a login. `private_key` is opaque secret material
// filled by the WebAuthn ceremony slice — this shape only defines where it goes.
export interface PasskeyCredential {
  credential_id: string;
  rp_id: string;
  user_handle: string;
  created_epoch: number;
  private_key: string;
}

export interface Login {
  username: string;
  password: string;
  urls: string[];
  totp_secret: string | null;
  // A login may have a password and/or one or more synced passkeys. Optional so
  // vaults sealed before this field existed (which lack the key) still parse —
  // mirrors `#[serde(default)]` on the Rust side.
  passkeys: PasskeyCredential[];
}

export interface Card {
  cardholder: string;
  number: string;
  expiry: string;
  cvv: string;
}

export interface Identity {
  full_name: string;
  email: string;
  phone: string;
  address: string;
}

// Rust `enum Content` with default (external) tagging.
export type Content =
  | { Login: Login }
  | { SecureNote: string }
  | { Card: Card }
  | { Identity: Identity };

export interface Entry {
  id: string;
  title: string;
  tags: string[];
  favorite: boolean;
  updated_epoch: number;
  content: Content;
}

export type Category = 'Login' | 'SecureNote' | 'Card' | 'Identity';

/** The externally-tagged key of an entry's content is its category. */
export function categoryOf(entry: Entry): Category {
  return Object.keys(entry.content)[0] as Category;
}

/** A Watchtower finding, mirroring the WASM `watchtower_json` tagged output. */
export type Issue =
  | { kind: 'weak'; id: string; bits: number }
  | { kind: 'reused'; ids: string[] }
  | { kind: 'missing2fa'; id: string };
