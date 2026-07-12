// Ad-hoc round-trip check: export each format, re-import, assert nothing is lost.
import { buildExport } from '../src/lib/export';
import { parseImport } from '../src/lib/import';
import type { Entry } from '../src/lib/passbook-types';

const now = 1_700_000_000;
const entries: Entry[] = [
  {
    id: 'a',
    title: 'GitHub',
    tags: ['dev'],
    favorite: true,
    updated_epoch: now,
    content: {
      Login: {
        username: 'felix',
        password: 'p@ss,w"rd\nx',
        urls: ['https://github.com'],
        totp_secret: 'JBSWY3DPEHPK3PXP',
        has_passkey: false,
      },
    },
  },
  { id: 'b', title: 'Note', tags: [], favorite: false, updated_epoch: now, content: { SecureNote: 'line1\nline2' } },
  {
    id: 'c',
    title: 'Visa',
    tags: [],
    favorite: false,
    updated_epoch: now,
    content: { Card: { cardholder: 'Felix G', number: '4539 1488 0343 4417', expiry: '08/29', cvv: '114' } },
  },
  {
    id: 'd',
    title: 'Me',
    tags: [],
    favorite: false,
    updated_epoch: now,
    content: { Identity: { full_name: 'Felix Geelhaar', email: 'f@x.dev', phone: '+49', address: 'Berlin' } },
  },
];

let failures = 0;
function check(name: string, cond: boolean, detail = '') {
  if (!cond) {
    failures += 1;
    console.log(`  FAIL ${name} ${detail}`);
  } else {
    console.log(`  ok   ${name}`);
  }
}

// Proctor JSON: full fidelity — same count, same categories, exact login password.
{
  const out = buildExport(entries, 'proctor');
  const r = parseImport(out.content, now);
  check('proctor format', r.format === 'proctor');
  check('proctor count', r.entries.length === 4, `got ${r.entries.length}`);
  const login = r.entries.find((e) => 'Login' in e.content);
  const pw = login && 'Login' in login.content ? login.content.Login.password : '';
  check('proctor preserves tricky password', pw === 'p@ss,w"rd\nx', JSON.stringify(pw));
  const cats = r.entries.map((e) => Object.keys(e.content)[0]).sort();
  check('proctor all categories', cats.join(',') === 'Card,Identity,Login,SecureNote', cats.join(','));
}

// Bitwarden JSON round-trip: same count, categories preserved.
{
  const out = buildExport(entries, 'bitwarden');
  const r = parseImport(out.content, now);
  check('bitwarden format', r.format === 'bitwarden');
  check('bitwarden count', r.entries.length === 4, `got ${r.entries.length}`);
  const card = r.entries.find((e) => 'Card' in e.content);
  const num = card && 'Card' in card.content ? card.content.Card.number : '';
  check('bitwarden preserves card number', num === '4539 1488 0343 4417', num);
}

// CSV round-trip: logins survive with their tricky password intact.
{
  const out = buildExport(entries, 'csv');
  const r = parseImport(out.content, now);
  check('csv count', r.entries.length === 4, `got ${r.entries.length}`);
  const login = r.entries.find((e) => e.title === 'GitHub');
  const pw = login && 'Login' in login.content ? login.content.Login.password : '';
  check('csv preserves tricky password', pw === 'p@ss,w"rd\nx', JSON.stringify(pw));
}

console.log(failures === 0 ? '\nALL ROUND-TRIPS PASSED' : `\n${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
