// Guards the PREMISE of the "these three secrets cannot become non-extractable
// CryptoKeys" analysis written into passbook.ts, sharing.ts, and sync.ts.
//
// WHY THIS TEST EXISTS AT ALL. The analysis is a negative result: it explains
// why the standard browser mitigation (a `CryptoKey` with `extractable: false`
// persisted in IndexedDB) cannot hold the device Secret Key, the member X25519
// secret, or the sync device token. A negative result rots differently from a
// feature. Nothing breaks when it stops being true — the code keeps working,
// the comments keep reading plausibly, and the reason they were written quietly
// stops applying. Section 10 of docs/security/known-limitations.md then says
// something that is no longer the reason.
//
// So the reasons are asserted, not just written down:
//
//   1. The two WASM-bound secrets are impossible because they cross the FFI as
//      `string`. If that boundary is ever reworked to take a handle, key bytes,
//      or anything that is not a JS string, the option reopens — and this test
//      fails, pointing at the comment that has to be revisited.
//   2. The device token is impossible because it is used only as a bearer
//      header. If it ever grows a second use, the same applies.
//   3. A tripwire for the specific wrong fix: an IndexedDB-backed wrapper that
//      still hands out the plaintext. It is the obvious next idea, it protects
//      nothing (the decryption oracle is on the same origin as the attacker),
//      and its real cost is that it LOOKS like a mitigation. If one appears,
//      this fails rather than letting it be mistaken for the real thing.
//
// This is deliberately static analysis over the source rather than a runtime
// test. There is nothing to execute: the claim is about the SHAPE of the
// boundary, and the honest way to check a claim about shape is to read it.

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const app = join(here, '..');

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (ok) {
    console.log(`  ok   ${name}`);
  } else {
    failures += 1;
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

function read(rel: string): string {
  return readFileSync(join(app, rel), 'utf8');
}

/**
 * The executable part of a source line: '' for anything that is only prose.
 *
 * These files carry long security rationale in both `//` and `/** ... *​/` form,
 * and that prose necessarily NAMES the things being checked ("this device's
 * bearer token", "the member secret"). Matching against it would make every
 * check a test of the comments rather than the code.
 */
/** Every file under `dir`, recursively. `src/wasm/pkg` is generated, so skipped. */
function walk(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'pkg' || e.name === 'node_modules') continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

function codeOf(line: string): string {
  const t = line.trim();
  if (t.startsWith('//') || t.startsWith('/*') || t.startsWith('*')) return '';
  return line.split('//')[0];
}

// ----- 1. The WASM boundary still takes strings -----------------------------
//
// `src/wasm/pkg/` is a build artefact and is gitignored, so a clean checkout
// that has not run `npm run build:wasm` legitimately has no declarations to
// read. That is skipped loudly rather than failed: making `npm test` depend on
// a Rust toolchain would be a worse trade than an occasional visible SKIP. It
// is announced, never silent, so it cannot be mistaken for a pass.
{
  const dts = join(app, 'src/wasm/pkg/passbook_wasm.d.ts');
  if (!existsSync(dts)) {
    console.log(
      '  SKIP the WASM boundary checks — src/wasm/pkg/passbook_wasm.d.ts is absent.\n' +
        '       Run `npm run build:wasm` to check them. These assert WHY the device\n' +
        '       Secret Key and member secret cannot be non-extractable CryptoKeys.',
    );
  } else {
    const decl = readFileSync(dts, 'utf8');

    /** The declared parameter list of a top-level exported function. */
    function params(fn: string): string | null {
      const m = decl.match(new RegExp(`export function ${fn}\\(([^)]*)\\)`));
      return m ? m[1] : null;
    }

    // The device Secret Key (2SKD factor). A `string` parameter cannot be a
    // non-extractable key, because producing the string IS extraction.
    for (const fn of ['seal_vault', 'open_vault']) {
      const p = params(fn);
      check(
        `${fn} still takes the Secret Key as a string (non-extractable stays impossible)`,
        p !== null && /secret_key\??:\s*string/.test(p),
        p ?? 'declaration not found',
      );
    }

    // The member X25519 secret, on all three paths that consume it.
    for (const fn of ['unwrap_vault_key', 'unwrap_vault_key_unsigned', 'open_recovery']) {
      const p = params(fn);
      check(
        `${fn} still takes the member secret as a hex string`,
        p !== null && /member_secret_hex:\s*string/.test(p),
        p ?? 'declaration not found',
      );
    }

    // seal_recovery takes the Secret Key as its `plaintext`: the recovery-contact
    // path moves a 2SKD factor, so it is the same constraint by another name.
    const rec = params('seal_recovery');
    check(
      'seal_recovery still takes the sealed Secret Key as a plaintext string',
      rec !== null && /plaintext:\s*string/.test(rec),
      rec ?? 'declaration not found',
    );
  }
}

// ----- 2. The device token is still only a bearer header --------------------
//
// A bearer credential has to travel as plaintext, so no local key handle can
// protect it. That argument holds only while the token has exactly this one
// use; a second use would need its own analysis.
// The check is two-level, because the token legitimately reaches the group-relay
// helpers through a carrier rather than directly:
//
//   level 1 — every read of the STORED token (`cfg.deviceToken`) is either a
//             Bearer interpolation, or the one documented carrier: `relay()` in
//             sharing.ts, which hands `{ base, token }` to the relay helpers.
//   level 2 — inside sharing.ts, every use of that carried `token` is itself a
//             Bearer header, directly or via `authJson`, which builds one.
//
// Level 1 matches ANY `.deviceToken` read, anywhere under src/, rather than the
// few call sites that exist today. Scoping it to the known accessors was the
// first attempt and it was worthless: a leak written as
// `syncConfig()!.deviceToken` sailed straight through, which is exactly the
// shape an exfiltration bug takes. The allowlist below is therefore of
// PATTERNS, not of files.
//
// `body.device_token` in `addDevice` is deliberately out of scope — that is a
// DIFFERENT value, a token freshly minted for another device, which the user
// carries out of band by design.
{
  const sources = walk(join(app, 'src')).filter((f) => /\.(ts|vue)$/.test(f));
  const stray: string[] = [];
  for (const abs of sources) {
    const rel = abs.slice(app.length + 1);
    for (const line of readFileSync(abs, 'utf8').split('\n')) {
      const code = codeOf(line);
      if (!/\.deviceToken\b/.test(code)) continue;
      const allowed =
        // The one legitimate use: interpolated into an Authorization header.
        /Bearer\s*\$\{[^}]*\.deviceToken\}/.test(code) ||
        // Validating and constructing the config object out of parsed JSON.
        // Reading the field to check its type, or copying it into the config it
        // already belongs to, is not a use of the credential.
        /typeof parsed\.deviceToken/.test(code) ||
        /deviceToken:\s*parsed\.deviceToken/.test(code) ||
        // The documented carrier: relay() in sharing.ts, checked at level 2.
        (rel === 'src/lib/sharing.ts' && /token:\s*cfg\.deviceToken/.test(code));
      if (!allowed) stray.push(`${rel}: ${line.trim()}`);
    }
  }
  check(
    'every read of the stored device token is a Bearer header (or the relay carrier)',
    stray.length === 0,
    stray.join(' | '),
  );

  // Level 2: the carrier does not leak the token anywhere else.
  const sharing = read('src/lib/sharing.ts');
  const carried: string[] = [];
  for (const line of sharing.split('\n')) {
    const code = codeOf(line);
    if (!/\btoken\b/.test(code)) continue;
    const ok =
      /Bearer\s*\$\{token\}/.test(code) || // direct header
      /authJson\(token\)/.test(code) || // header helper, asserted below
      /const \{ base, token \} = relay\(\)/.test(code) || // destructuring the carrier
      /function relay\(\)/.test(code) || // the carrier's own signature
      /token:\s*cfg\.deviceToken/.test(code) || // the carrier's own return
      /function authJson\(token: string\)/.test(code); // the helper's signature
    if (!ok) carried.push(line.trim());
  }
  check(
    'the relay carrier token is used only to build Bearer headers',
    carried.length === 0,
    carried.join(' | '),
  );
  check(
    'authJson builds a Bearer header and nothing else',
    /function authJson\(token: string\): HeadersInit \{\s*return \{ Authorization: `Bearer \$\{token\}`/.test(
      sharing,
    ),
  );
}

// ----- 3. Tripwire: no decorative IndexedDB key wrapper ---------------------
//
// The wrong fix is a wrapper that keeps the secret encrypted under a
// non-extractable AES-GCM key in IndexedDB and then decrypts it on demand. It
// reads like protection and provides none: the attacker runs on the same origin
// as the unwrap, so `await getSecretKey()` returns exactly what
// `localStorage.getItem` returned before. If someone adds one, fail here and
// send them to the reasoning rather than letting it land quietly.
{
  const libs = [
    'src/lib/passbook.ts',
    'src/lib/sharing.ts',
    'src/lib/sync.ts',
    'src/lib/trust.ts',
    'src/lib/account.ts',
  ];
  const offenders: string[] = [];
  for (const rel of libs) {
    const code = read(rel)
      .split('\n')
      .map(codeOf)
      .join('\n');
    if (/indexedDB|extractable\s*:/.test(code)) offenders.push(rel);
  }
  check(
    'no key-material module has grown an IndexedDB/non-extractable wrapper',
    offenders.length === 0,
    offenders.length
      ? `${offenders.join(', ')} — if this is a REAL fix (the secret never becomes a JS ` +
        'string), update the analysis in passbook.ts; if it still hands out the bytes, it ' +
        'is theatre and section 10 of known-limitations.md must not be retired for it.'
      : '',
  );
}

// ----- 4. The documented storage keys are still the real ones ---------------
//
// Section 10 of docs/security/known-limitations.md names these three keys in a
// table. A rename there without a doc update would leave the honest list quietly
// wrong, which is the one thing that document cannot afford to be.
{
  const keys: [string, string, string][] = [
    ['src/lib/passbook.ts', 'keyward.passbook.secretkey.v1', 'device Secret Key'],
    ['src/lib/sharing.ts', 'keyward.passbook.member.v1', 'member X25519 secret'],
    ['src/lib/sync.ts', 'keyward.passbook.sync.v1', 'device bearer token'],
  ];
  for (const [rel, key, what] of keys) {
    check(
      `the ${what} still lives at ${key} (as known-limitations.md §10 states)`,
      read(rel).includes(`'${key}'`),
    );
  }
}

console.log(
  failures === 0 ? '\nALL KEY-MATERIAL CHECKS PASSED' : `\n${failures} FAILURES`,
);
process.exit(failures === 0 ? 0 : 1);
