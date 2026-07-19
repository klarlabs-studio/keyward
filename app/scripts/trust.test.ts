// Trust-state merge and migration checks.
//
// This is where the bugs live. Merging security state across devices has to
// resolve conflicts, and every wrong resolution silently adopts a key the user
// never agreed to. The rule under test is that automatic resolution only ever
// moves toward MORE suspicion, and genuine ambiguity is left to the human path
// in sharing.ts.

import type { Entry } from '../src/lib/passbook-types';

// A localStorage stand-in, since this runs outside a browser.
const store = new Map<string, string>();
(globalThis as unknown as { localStorage: Storage }).localStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => void store.set(k, v),
  removeItem: (k: string) => void store.delete(k),
  clear: () => store.clear(),
  key: (i: number) => Array.from(store.keys())[i] ?? null,
  get length() {
    return store.size;
  },
} as Storage;

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (ok) {
    console.log(`  ok   ${name}`);
  } else {
    failures += 1;
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

const LEGACY_PINS = 'proctor.passbook.keypins.v1';
const LEGACY_VAULT = 'proctor.passbook.vaultkeypins.v1';
const LEGACY_SIGNED = 'proctor.passbook.signedgroups.v1';
const LEGACY_EPOCH2 = 'proctor.passbook.epochfloor.v2';
const CACHE = 'proctor.passbook.trust.v1';

// Seed the pre-vault localStorage layout BEFORE importing the module: it
// migrates at load time, which is the behaviour under test.
store.set(
  LEGACY_PINS,
  JSON.stringify({
    g1: {
      // Oldest format: a bare public-key string, before signing keys existed.
      alice: 'alice-pub',
      bob: { public_key: 'bob-pub', signing_key: 'bob-sign' },
    },
  }),
);
store.set(LEGACY_VAULT, JSON.stringify({ g1: 'vaultfp' }));
store.set(LEGACY_SIGNED, JSON.stringify(['g1']));
store.set(LEGACY_EPOCH2, JSON.stringify({ g1: { epoch: 4, digest: 'dig4' } }));

const trust = await import('../src/lib/trust');

// ----- Migration ------------------------------------------------------------
{
  const pins = trust.pinnedKeys('g1');
  check('migrates a bare-string pin to the current shape', pins.alice?.public_key === 'alice-pub');
  check(
    'a pre-signing pin gets an EMPTY signing key, so it verifies nothing',
    pins.alice?.signing_key === '',
    JSON.stringify(pins.alice),
  );
  check('migrates a full pin unchanged', pins.bob?.signing_key === 'bob-sign');
  check('migrates the vault-key pin', trust.vaultKeyPin('g1') === 'vaultfp');
  check('migrates the signed-group flag', trust.isSignedGroup('g1'));
  check('migrates the epoch pin', trust.epochPin('g1')?.epoch === 4);
  check('legacy keys are removed only after the new cache is written', !store.has(LEGACY_PINS));
  check('the new cache exists', store.has(CACHE));
  check('a migrated group is NOT reported as wiped', !trust.knowsNothingAbout('g1'));
  check('an unknown group IS reported as wiped', trust.knowsNothingAbout('g-unseen'));
}

// ----- Merge ----------------------------------------------------------------
{
  // Remote is another device that has moved further, and disagrees about Alice.
  trust.merge({
    pins: {
      g1: {
        // CONFLICT: remote pinned a different key for a member we already trust.
        alice: { public_key: 'RELAY-SUBSTITUTED', signing_key: 'x' },
        // New member we have never seen — safe to adopt.
        carol: { public_key: 'carol-pub', signing_key: 'carol-sign' },
      },
    },
    vaultKeys: { g1: 'DIFFERENT-VAULT-KEY', g2: 'g2fp' },
    signed: ['g2'],
    epochs: { g1: { epoch: 9, digest: 'dig9' }, g2: { epoch: 1, digest: 'd' } },
  });

  const pins = trust.pinnedKeys('g1');
  check(
    'a conflicting member pin keeps the LOCAL key',
    pins.alice?.public_key === 'alice-pub',
    pins.alice?.public_key,
  );
  check('a non-conflicting remote member is adopted', pins.carol?.public_key === 'carol-pub');
  check(
    'a conflicting vault-key pin keeps the LOCAL fingerprint',
    trust.vaultKeyPin('g1') === 'vaultfp',
    trust.vaultKeyPin('g1'),
  );
  check('a vault-key pin for an unseen group is adopted', trust.vaultKeyPin('g2') === 'g2fp');
  check('signed-group flags union', trust.isSignedGroup('g1') && trust.isSignedGroup('g2'));
  check('the HIGHER epoch wins', trust.epochPin('g1')?.epoch === 9, String(trust.epochPin('g1')?.epoch));
  check('the higher epoch brings its own digest', trust.epochPin('g1')?.digest === 'dig9');
}

{
  // A device that synced late must not drag the floor backwards.
  trust.merge({ pins: {}, vaultKeys: {}, signed: [], epochs: { g1: { epoch: 2, digest: 'old' } } });
  check('a LOWER remote epoch does not lower the floor', trust.epochPin('g1')?.epoch === 9);
}

{
  // Once a group is known to be signed, that must never be un-learned — it is
  // what makes signature-stripping a detectable downgrade.
  trust.merge({ pins: {}, vaultKeys: {}, signed: [], epochs: {} });
  check('an empty remote does not clear the signed flag', trust.isSignedGroup('g1'));
}

// ----- Writes and the epoch floor -------------------------------------------
{
  await trust.acceptEpoch('g1', 3, 'stale');
  check('acceptEpoch refuses to lower the epoch', trust.epochPin('g1')?.epoch === 9);

  await trust.acceptEpoch('g1', 12, 'dig12');
  check('acceptEpoch accepts a higher epoch', trust.epochPin('g1')?.epoch === 12);
}

// ----- Hydration from a vault entry -----------------------------------------
{
  const entry: Entry = {
    id: 'proctor-trust-state',
    title: '__trust__',
    tags: [],
    favorite: false,
    updated_epoch: 1,
    content: {
      SecureNote: JSON.stringify({
        pins: { g3: { dave: { public_key: 'dave-pub', signing_key: 'dave-sign' } } },
        vaultKeys: {},
        signed: [],
        epochs: {},
      }),
    },
  };
  check('hydrate reports finding a trust entry', trust.hydrate([entry]));
  check('hydrate adopts its contents', trust.pinnedKeys('g3').dave?.public_key === 'dave-pub');
  check('the trust entry is recognised as reserved', trust.isTrustEntry(entry));

  // A corrupt blob must not wipe what this device knows: stale trust is
  // recoverable, absent trust silently re-TOFUs.
  const corrupt: Entry = { ...entry, content: { SecureNote: '{not json' } };
  check('hydrate reports failure on a corrupt blob', !trust.hydrate([corrupt]));
  check('a corrupt blob leaves existing state intact', trust.pinnedKeys('g1').alice !== undefined);
}

console.log(failures === 0 ? '\nALL TRUST CHECKS PASSED' : `\n${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
