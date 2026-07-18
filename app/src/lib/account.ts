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

/** Why a checkout attempt could not start — drives the message shown to the user. */
export type CheckoutError = 'not-configured' | 'no-sync' | 'failed';

/**
 * Ask the server to create a hosted Stripe Checkout session for the Family plan.
 * Returns the URL to redirect to, or an error reason. The Stripe secret key lives
 * only on the server; the client never sees it.
 */
export async function startCheckout(): Promise<{ url: string } | { error: CheckoutError }> {
  const cfg = syncConfig();
  if (cfg === null) return { error: 'no-sync' };
  try {
    const res = await fetch(`${cfg.serverUrl}/v1/billing/checkout`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${cfg.deviceToken}` },
    });
    // 503 = this deployment has no Stripe configured (e.g. self-hosted).
    if (res.status === 503) return { error: 'not-configured' };
    if (!res.ok) return { error: 'failed' };
    const body = (await res.json()) as { url?: string };
    return body.url ? { url: body.url } : { error: 'failed' };
  } catch {
    return { error: 'failed' };
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
