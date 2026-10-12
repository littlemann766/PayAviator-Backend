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

/** Summarise a user's plan from their items + entitlements. */
export async function billingSummary(store, userId, now = Date.now()) {
  const [items, ents] = await Promise.all([store.getItems(userId), store.getEntitlements(userId)]);
  const linked = activeItems(items).length;
  const active = ents.filter(e => isEntitlementActive(e, now))
    .sort((a, b) => new Date(b.expiresAt) - new Date(a.expiresAt))[0] || null;
  return {
    plan: active ? 'premium' : 'free',
    linkedBanks: linked,
    limit: active ? null : FREE_BANK_LIMIT,
    expiresAt: active ? new Date(active.expiresAt).toISOString() : null,
    productId: active?.productId || null,
    state: active?.state || null,
    // Users who linked more than the free limit before it existed keep those banks (they just can't add more).
    grandfathered: !active && linked > FREE_BANK_LIMIT,
  };
}

/** Throws a 402-shaped error when adding a new bank would exceed the free limit. */
export async function assertCanAddBank(store, userId) {
  const s = await billingSummary(store, userId);
  if (s.plan === 'free' && s.linkedBanks >= FREE_BANK_LIMIT) {
    throw Object.assign(new Error('subscription required'), {
      status: 402, body: { error: 'subscription_required', code: 'SUBSCRIPTION_REQUIRED', limit: FREE_BANK_LIMIT, linked: s.linkedBanks },
    });
  }
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
