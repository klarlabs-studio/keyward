// Reads the account's entitlements (plan + device usage) from the sync server's
// GET /v1/account, so the UI can reflect the tier and gate paid features (family
// sharing) client-side — matching the server's own 402 enforcement, but with a
// friendly upgrade path instead of an error.

import { syncConfig } from './sync';

export type Plan = 'free' | 'individual' | 'family' | string;

export interface AccountInfo {
  account_id: string;
  plan: Plan;
  /** Whether the plan may create/own a family vault (Family only). */
  can_share: boolean;
  /** Current device count on the account. */
  devices: number;
  /** Max devices for the plan, or null for unlimited. */
  device_limit: number | null;
}

/** Human label for a plan. */
export function planLabel(plan: Plan): string {
  switch (plan) {
    case 'family':
      return 'Family';
    case 'individual':
      return 'Individual';
    case 'free':
      return 'Free';
    default:
      return plan;
  }
}

/**
 * Fetch the account's entitlements, or null if cloud sync is off or the server is
 * unreachable (callers fall back to a conservative "free" assumption).
 */
export async function fetchAccount(): Promise<AccountInfo | null> {
  const cfg = syncConfig();
  if (cfg === null) return null;
  try {
    const res = await fetch(`${cfg.serverUrl}/v1/account`, {
      headers: { Authorization: `Bearer ${cfg.deviceToken}` },
    });
    if (!res.ok) return null;
    return (await res.json()) as AccountInfo;
  } catch {
    return null;
  }
}
