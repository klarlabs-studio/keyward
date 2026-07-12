// First-run demo vault. These are real `Entry` values that get sealed with the
// actual WASM crypto on first unlock — nothing here is special-cased in the UI.
// A production onboarding flow would import from 1Password/Bitwarden/CSV instead.

import type { Entry } from './passbook-types';

export const DEMO_MASTER = 'correct horse battery staple';

export function demoEntries(now: number): Entry[] {
  return [
    {
      id: 'e1',
      title: 'GitHub',
      tags: ['work', 'dev'],
      favorite: true,
      updated_epoch: now,
      content: {
        Login: {
          username: 'felix@klarlabs.dev',
          password: 'z9$Kq!7pR#mL2vX@eW',
          urls: ['github.com'],
          totp_secret: 'JBSWY3DPEHPK3PXP',
          has_passkey: true,
        },
      },
    },
    {
      id: 'e2',
      title: 'Chase Bank',
      tags: ['family', 'finance'],
      favorite: true,
      updated_epoch: now,
      content: {
        Login: {
          username: 'felixg',
          password: 'summer2024',
          urls: ['chase.com'],
          totp_secret: null,
          has_passkey: false,
        },
      },
    },
    {
      id: 'e3',
      title: 'Netflix',
      tags: ['family', 'shared'],
      favorite: false,
      updated_epoch: now,
      content: {
        Login: {
          username: 'the.geelhaars@icloud.com',
          password: 'summer2024',
          urls: ['netflix.com'],
          totp_secret: null,
          has_passkey: false,
        },
      },
    },
    {
      id: 'e4',
      title: 'iCloud',
      tags: ['personal'],
      favorite: false,
      updated_epoch: now,
      content: {
        Login: {
          username: 'felix@icloud.com',
          password: 'Tq7!vNz2@Lp9#Rk4',
          urls: ['icloud.com'],
          totp_secret: 'KRSXG5CTMVRXEZLU',
          has_passkey: false,
        },
      },
    },
    {
      id: 'e5',
      title: 'Visa · Family',
      tags: ['family', 'finance'],
      favorite: false,
      updated_epoch: now,
      content: {
        Card: {
          cardholder: 'Felix Geelhaar',
          number: '4539 1488 0343 4417',
          expiry: '08/29',
          cvv: '114',
        },
      },
    },
    {
      id: 'e6',
      title: 'Recovery codes',
      tags: ['dev'],
      favorite: false,
      updated_epoch: now,
      content: {
        SecureNote: 'GitHub backup codes\n\n3f8a-91c2\n77de-40ab\n1029-bb31\n(5 more…)',
      },
    },
    {
      id: 'e7',
      title: 'Felix Geelhaar',
      tags: ['personal'],
      favorite: false,
      updated_epoch: now,
      content: {
        Identity: {
          full_name: 'Felix Geelhaar',
          email: 'felix@klarlabs.dev',
          phone: '+49 151 000 0000',
          address: 'Berlin, DE',
        },
      },
    },
  ];
}
