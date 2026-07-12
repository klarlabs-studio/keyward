// Importers that turn a password-manager export into `Entry[]`, ready to seal
// into the vault. Supported: Bitwarden (JSON), LastPass (CSV), 1Password (CSV),
// and a best-effort generic CSV. Everything is parsed locally — an export never
// leaves the browser.

import type { Card, Entry, Identity, Login } from './passbook-types';

export type ImportFormat = 'bitwarden' | 'lastpass' | '1password' | 'csv';

export interface ImportResult {
  format: ImportFormat;
  entries: Entry[];
  skipped: number;
}

let importSeq = 0;
function makeId(now: number): string {
  importSeq += 1;
  return `imp-${now.toString(36)}-${importSeq.toString(36)}`;
}

// ---------------------------------------------------------------------------
// CSV parsing (RFC 4180-ish: quoted fields, "" escapes, newlines in quotes)
// ---------------------------------------------------------------------------

export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;
  const src = text.replace(/\r\n?/g, '\n');

  for (let i = 0; i < src.length; i += 1) {
    const c = src[i];
    if (inQuotes) {
      if (c === '"') {
        if (src[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ',') {
      row.push(field);
      field = '';
    } else if (c === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += c;
    }
  }
  // Flush the trailing field/row unless the file ended on a newline.
  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter((r) => r.some((cell) => cell.trim() !== ''));
}

/** Map a header row to indices by a set of accepted (lowercased) column names. */
function columnIndex(header: string[], names: string[]): number {
  const lower = header.map((h) => h.trim().toLowerCase());
  for (const name of names) {
    const idx = lower.indexOf(name);
    if (idx !== -1) return idx;
  }
  return -1;
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------

export function detectFormat(text: string): ImportFormat {
  const trimmed = text.trimStart();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const data = JSON.parse(trimmed);
      if (data && Array.isArray(data.items)) return 'bitwarden';
    } catch {
      // fall through to CSV sniffing
    }
  }
  const header = (parseCsv(text)[0] ?? []).map((h) => h.trim().toLowerCase());
  const has = (n: string) => header.includes(n);
  if (has('url') && has('username') && has('password') && (has('grouping') || has('totp'))) {
    return 'lastpass';
  }
  if (has('otpauth') || has('archived') || (has('title') && has('otp'))) {
    return '1password';
  }
  return 'csv';
}

// ---------------------------------------------------------------------------
// Bitwarden JSON
// ---------------------------------------------------------------------------

interface BwUri {
  uri?: string;
}
interface BwItem {
  type: number;
  name?: string;
  notes?: string | null;
  favorite?: boolean;
  login?: { username?: string | null; password?: string | null; totp?: string | null; uris?: BwUri[] | null };
  card?: {
    cardholderName?: string;
    number?: string;
    code?: string;
    expMonth?: string;
    expYear?: string;
  };
  identity?: {
    firstName?: string;
    lastName?: string;
    email?: string;
    phone?: string;
    address1?: string;
    city?: string;
    state?: string;
    country?: string;
  };
}

function parseBitwarden(text: string, now: number): ImportResult {
  const data = JSON.parse(text) as { items?: BwItem[] };
  const items = data.items ?? [];
  const entries: Entry[] = [];
  let skipped = 0;

  for (const item of items) {
    const base = {
      id: makeId(now),
      title: item.name?.trim() || 'Untitled',
      tags: [] as string[],
      favorite: Boolean(item.favorite),
      updated_epoch: now,
    };
    switch (item.type) {
      case 1: {
        const l = item.login ?? {};
        const login: Login = {
          username: l.username ?? '',
          password: l.password ?? '',
          urls: (l.uris ?? []).map((u) => u.uri ?? '').filter(Boolean),
          totp_secret: l.totp ? l.totp : null,
          has_passkey: false,
        };
        entries.push({ ...base, content: { Login: login } });
        break;
      }
      case 2: {
        entries.push({ ...base, content: { SecureNote: item.notes ?? '' } });
        break;
      }
      case 3: {
        const c = item.card ?? {};
        const card: Card = {
          cardholder: c.cardholderName ?? '',
          number: c.number ?? '',
          expiry: c.expMonth || c.expYear ? `${c.expMonth ?? ''}/${c.expYear ?? ''}` : '',
          cvv: c.code ?? '',
        };
        entries.push({ ...base, content: { Card: card } });
        break;
      }
      case 4: {
        const i = item.identity ?? {};
        const identity: Identity = {
          full_name: [i.firstName, i.lastName].filter(Boolean).join(' '),
          email: i.email ?? '',
          phone: i.phone ?? '',
          address: [i.address1, i.city, i.state, i.country].filter(Boolean).join(', '),
        };
        entries.push({ ...base, content: { Identity: identity } });
        break;
      }
      default:
        skipped += 1;
    }
  }
  return { format: 'bitwarden', entries, skipped };
}

// ---------------------------------------------------------------------------
// LastPass CSV — url,username,password,totp,extra,name,grouping,fav
// (secure notes have url === "http://sn" with the body in `extra`)
// ---------------------------------------------------------------------------

function parseLastpass(rows: string[][], now: number): ImportResult {
  const header = rows[0];
  const iUrl = columnIndex(header, ['url']);
  const iUser = columnIndex(header, ['username']);
  const iPass = columnIndex(header, ['password']);
  const iTotp = columnIndex(header, ['totp']);
  const iExtra = columnIndex(header, ['extra', 'notes']);
  const iName = columnIndex(header, ['name', 'title']);
  const iFav = columnIndex(header, ['fav', 'favorite']);
  const entries: Entry[] = [];

  for (const row of rows.slice(1)) {
    const cell = (i: number) => (i >= 0 ? (row[i] ?? '').trim() : '');
    const base = {
      id: makeId(now),
      title: cell(iName) || 'Untitled',
      tags: [] as string[],
      favorite: cell(iFav) === '1',
      updated_epoch: now,
    };
    if (cell(iUrl) === 'http://sn') {
      entries.push({ ...base, content: { SecureNote: cell(iExtra) } });
    } else {
      const login: Login = {
        username: cell(iUser),
        password: cell(iPass),
        urls: cell(iUrl) ? [cell(iUrl)] : [],
        totp_secret: cell(iTotp) || null,
        has_passkey: false,
      };
      entries.push({ ...base, content: { Login: login } });
    }
  }
  return { format: 'lastpass', entries, skipped: 0 };
}

// ---------------------------------------------------------------------------
// 1Password / generic CSV — fuzzy header mapping, all treated as logins
// ---------------------------------------------------------------------------

function parseCsvLogins(rows: string[][], format: ImportFormat, now: number): ImportResult {
  const header = rows[0];
  const iTitle = columnIndex(header, ['title', 'name']);
  const iUser = columnIndex(header, ['username', 'user', 'login', 'email']);
  const iPass = columnIndex(header, ['password', 'pass']);
  const iUrl = columnIndex(header, ['url', 'uri', 'website', 'site']);
  const iTotp = columnIndex(header, ['otpauth', 'otp', 'totp', 'one-time password', 'onetimepassword']);
  const iFav = columnIndex(header, ['favorite', 'fav']);
  const entries: Entry[] = [];
  let skipped = 0;

  for (const row of rows.slice(1)) {
    const cell = (i: number) => (i >= 0 ? (row[i] ?? '').trim() : '');
    const title = cell(iTitle) || cell(iUrl) || cell(iUser);
    if (!title && !cell(iPass)) {
      skipped += 1;
      continue;
    }
    const login: Login = {
      username: cell(iUser),
      password: cell(iPass),
      urls: cell(iUrl) ? [cell(iUrl)] : [],
      totp_secret: cell(iTotp) || null,
      has_passkey: false,
    };
    entries.push({
      id: makeId(now),
      title: title || 'Untitled',
      tags: [],
      favorite: cell(iFav) === '1' || cell(iFav).toLowerCase() === 'true',
      updated_epoch: now,
      content: { Login: login },
    });
  }
  return { format, entries, skipped };
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/** Parse an export into entries. Throws with a friendly message on failure. */
export function parseImport(text: string, now: number, forced?: ImportFormat): ImportResult {
  if (!text.trim()) throw new Error('Nothing to import — the file is empty.');
  const format = forced ?? detectFormat(text);
  try {
    if (format === 'bitwarden') return parseBitwarden(text, now);
    const rows = parseCsv(text);
    if (rows.length < 2) throw new Error('No rows found below the header.');
    if (format === 'lastpass') return parseLastpass(rows, now);
    return parseCsvLogins(rows, format, now);
  } catch (err) {
    throw new Error(
      `Could not parse this ${format} export: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}
