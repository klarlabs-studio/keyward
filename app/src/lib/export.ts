// Exporters that serialize the vault to a portable file — so there's no lock-in.
// Native Proctor JSON is full-fidelity; Bitwarden JSON round-trips back through
// our own importer and into Bitwarden; CSV is a lossy, universal fallback.
//
// Exports contain secrets in PLAINTEXT by design (that is the point of an
// export). The UI warns accordingly; nothing here is encrypted.

import type { Entry } from './passbook-types';
import { categoryOf } from './passbook-types';

export type ExportFormat = 'proctor' | 'bitwarden' | 'csv';

export interface ExportFile {
  filename: string;
  mime: string;
  content: string;
}

/** Native, full-fidelity Proctor JSON — the exact entry model. */
function toProctorJson(entries: Entry[]): string {
  return JSON.stringify({ version: 1, exported: 'proctor-passbook', entries }, null, 2);
}

/** Bitwarden-compatible JSON (unencrypted export shape), for portability. */
function toBitwardenJson(entries: Entry[]): string {
  const items = entries.map((e) => {
    const base = {
      type: 1,
      name: e.title,
      favorite: e.favorite,
      notes: null as string | null,
    };
    const c = e.content;
    if ('Login' in c) {
      return {
        ...base,
        login: {
          username: c.Login.username || null,
          password: c.Login.password || null,
          totp: c.Login.totp_secret,
          uris: c.Login.urls.map((uri) => ({ uri })),
        },
      };
    }
    if ('SecureNote' in c) {
      return { ...base, type: 2, notes: c.SecureNote, secureNote: { type: 0 } };
    }
    if ('Card' in c) {
      const [expMonth = '', expYear = ''] = c.Card.expiry.split('/');
      return {
        ...base,
        type: 3,
        card: {
          cardholderName: c.Card.cardholder,
          number: c.Card.number,
          code: c.Card.cvv,
          expMonth,
          expYear,
        },
      };
    }
    // Identity
    const [firstName = '', ...rest] = c.Identity.full_name.split(' ');
    return {
      ...base,
      type: 4,
      identity: {
        firstName,
        lastName: rest.join(' '),
        email: c.Identity.email,
        phone: c.Identity.phone,
        address1: c.Identity.address,
      },
    };
  });
  return JSON.stringify({ encrypted: false, items }, null, 2);
}

/** Quote a CSV field when it contains a comma, quote, or newline. */
function csvField(value: string): string {
  return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

/** Universal CSV. Logins map fully; other types summarise into `notes`. */
function toCsv(entries: Entry[]): string {
  const header = ['title', 'username', 'password', 'url', 'totp', 'notes', 'favorite', 'category'];
  const rows = entries.map((e) => {
    const c = e.content;
    let username = '';
    let password = '';
    let url = '';
    let totp = '';
    let notes = '';
    if ('Login' in c) {
      username = c.Login.username;
      password = c.Login.password;
      url = c.Login.urls[0] ?? '';
      totp = c.Login.totp_secret ?? '';
    } else if ('SecureNote' in c) {
      notes = c.SecureNote;
    } else if ('Card' in c) {
      notes = `${c.Card.cardholder} ${c.Card.number} exp ${c.Card.expiry} cvv ${c.Card.cvv}`;
    } else {
      notes = `${c.Identity.full_name} ${c.Identity.email} ${c.Identity.phone} ${c.Identity.address}`;
    }
    return [e.title, username, password, url, totp, notes, e.favorite ? '1' : '0', categoryOf(e)]
      .map(csvField)
      .join(',');
  });
  return [header.join(','), ...rows].join('\n');
}

export function buildExport(entries: Entry[], format: ExportFormat): ExportFile {
  switch (format) {
    case 'proctor':
      return {
        filename: 'proctor-passbook-export.json',
        mime: 'application/json',
        content: toProctorJson(entries),
      };
    case 'bitwarden':
      return {
        filename: 'proctor-passbook-bitwarden.json',
        mime: 'application/json',
        content: toBitwardenJson(entries),
      };
    case 'csv':
      return {
        filename: 'proctor-passbook-export.csv',
        mime: 'text/csv',
        content: toCsv(entries),
      };
  }
}
