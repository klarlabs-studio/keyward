// TypeScript mirror of the `proctor-passbook` serde model. These shapes must
// round-trip byte-for-byte through `seal_vault` / `open_vault`, so they mirror
// the Rust `Entry` / `Content` derives exactly (Content is externally tagged).

export interface Login {
  username: string;
  password: string;
  urls: string[];
  totp_secret: string | null;
  has_passkey: boolean;
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
