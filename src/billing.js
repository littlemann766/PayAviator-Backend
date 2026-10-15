import { GoogleAuth, OAuth2Client } from 'google-auth-library';
import { ITEM_STATUS } from './plaid.js';

/** Free plan: one active (non-revoked) Plaid Item per signed-in user. */
export const FREE_BANK_LIMIT = 1;

/** Google Play subscriptionsv2 states that still grant access (CANCELED = auto-renew off, paid through expiry). */
const ENTITLED_STATES = new Set(['SUBSCRIPTION_STATE_ACTIVE', 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD', 'SUBSCRIPTION_STATE_CANCELED']);

export function isEntitlementActive(e, now = Date.now()) {
  if (!e || !ENTITLED_STATES.has(e.state)) return false;
  const exp = e.expiresAt ? new Date(e.expiresAt).getTime() : NaN;
  return Number.isFinite(exp) && exp > now;
}

export const activeItems = items => items.filter(i => i.status !== ITEM_STATUS.REVOKED);

export const PAUSE_REASON = 'plus_ended';

/**
 * Pause rule: without an active entitlement (premium or comp), only the OLDEST non-revoked item stays active; every
 * other non-revoked item is shown as status 'paused' (virtual, computed per request, nothing stored, so it
 * auto-resumes the moment a premium entitlement is active). `items` must be ordered oldest first (store.getItems).
 * Returns copies; paused ones carry status 'paused' and pausedFrom (the real status).
 */
export function applyPause(items, entitled) {
  if (entitled) return items;
  let keptOne = false;
  return items.map(i => {
    if (i.status === ITEM_STATUS.REVOKED) return i;
    if (!keptOne) { keptOne = true; return i; }
    return { ...i, status: ITEM_STATUS.PAUSED, pausedFrom: i.status };
  });
}

export const isPaused = i => i?.status === ITEM_STATUS.PAUSED;

/**
 * Summarise a user's plan. `compUids` (from COMP_FIREBASE_UIDS) marks owner/comp accounts: plan 'comp',
 * unlimited banks, no subscription needed. Any real entitlement is still reported in expiresAt/productId/state.
 */
export async function billingSummary(store, userId, now = Date.now(), { compUids } = {}) {
  const comp = Boolean(compUids && compUids.has(String(userId)));
  const [items, ents] = await Promise.all([store.getItems(userId), store.getEntitlements(userId)]);
  const linked = activeItems(items).length;
  const active = ents.filter(e => isEntitlementActive(e, now))
    .sort((a, b) => new Date(b.expiresAt) - new Date(a.expiresAt))[0] || null;
  return {
    plan: comp ? 'comp' : active ? 'premium' : 'free',
    // What unlocked premium: 'comp' | 'play' | 'stripe' | null (free). Whichever store is active wins; no migration.
    source: comp ? 'comp' : active ? (active.platform === 'stripe' ? 'stripe' : 'play') : null,
    linkedBanks: linked,
    limit: comp || active ? null : FREE_BANK_LIMIT,
    expiresAt: active ? new Date(active.expiresAt).toISOString() : null,
    productId: active?.productId || null,
    state: active?.state || null,
    // Stripe only: true when the user cancelled and premium stays on until periodEnd (stripeState maps
    // cancel_at_period_end=true onto SUBSCRIPTION_STATE_CANCELED). Always false for Play / comp / free.
    cancelAtPeriodEnd: Boolean(!comp && active?.platform === 'stripe' && active.state === 'SUBSCRIPTION_STATE_CANCELED'),
    // Stripe only: end of the current paid period (ISO 8601), else null.
    periodEnd: !comp && active?.platform === 'stripe' && active.expiresAt ? new Date(active.expiresAt).toISOString() : null,
    // Users who linked more than the free limit before it existed keep those banks (they just can't add more).
    // Same condition as before. With the pause rule, grandfathered now means: extra banks exist but are paused (see pausedBanks).
    grandfathered: !comp && !active && linked > FREE_BANK_LIMIT,
    // Active banks that are paused because there is no Plus/comp entitlement (all but the oldest). 0 when entitled.
    pausedBanks: comp || active ? 0 : Math.max(0, linked - FREE_BANK_LIMIT),
  };
}

/** Normalise a subscriptionsv2 resource into our entitlement shape. */
export function entitlementFromPurchase(p, productId) {
  const lines = Array.isArray(p?.lineItems) ? p.lineItems : [];
  const line = lines.find(l => l.productId === productId) || null;
  return {
    productId,
    state: String(p?.subscriptionState || 'SUBSCRIPTION_STATE_UNSPECIFIED'),
    expiresAt: line?.expiryTime ? new Date(line.expiryTime).toISOString() : null,
    acknowledged: p?.acknowledgementState === 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
    productMatches: Boolean(line),
    linkedPurchaseToken: p?.linkedPurchaseToken || null,
  };
}

/** Real Google Play Developer API client (androidpublisher v3). Injected so tests can mock it. */
export function createGooglePlayClient({ serviceAccount, packageName }) {
  const auth = new GoogleAuth({ credentials: serviceAccount, scopes: ['https://www.googleapis.com/auth/androidpublisher'] });
  const base = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${encodeURIComponent(packageName)}/purchases`;
  return {
    async getSubscription(purchaseToken) {
      const client = await auth.getClient();
      const r = await client.request({ url: `${base}/subscriptionsv2/tokens/${encodeURIComponent(purchaseToken)}` });
      return r.data;
    },
    async acknowledge(productId, purchaseToken) {
      const client = await auth.getClient();
      await client.request({ method: 'POST', url: `${base}/subscriptions/${encodeURIComponent(productId)}/tokens/${encodeURIComponent(purchaseToken)}:acknowledge`, data: {} });
    },
  };
}

/** Verifies the OIDC bearer token Pub/Sub attaches to authenticated push requests. */
export function createPubSubVerifier({ audience, serviceAccountEmail }) {
  const client = new OAuth2Client();
  return async authorization => {
    const m = /^Bearer\s+(.+)$/i.exec(String(authorization || ''));
    if (!m) throw new Error('missing bearer');
    const ticket = await client.verifyIdToken({ idToken: m[1], audience });
    const p = ticket.getPayload() || {};
    if (!p.email_verified || (serviceAccountEmail && p.email !== serviceAccountEmail)) throw new Error('unexpected push identity');
    return p;
  };
}
