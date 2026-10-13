import express from 'express';
import Stripe from 'stripe';

/** Web subscriptions (Stripe Checkout). Entitlements reuse billing_entitlements with platform 'stripe'. */
export const SITE_URL = 'https://payaviator.app';
export const STRIPE_PLATFORM = 'stripe';
export const stripeEntitlementKey = subId => `stripe_sub:${subId}`;

/**
 * Map a Stripe subscription status onto the Play-style states isEntitlementActive() already understands,
 * so /api/billing/status keeps exactly the same shape for both stores.
 */
export function stripeState(sub) {
  switch (sub?.status) {
    case 'active': case 'trialing': return sub.cancel_at_period_end ? 'SUBSCRIPTION_STATE_CANCELED' : 'SUBSCRIPTION_STATE_ACTIVE';
    case 'past_due': return 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD'; // Stripe is retrying the card
    case 'unpaid': return 'SUBSCRIPTION_STATE_ON_HOLD';
    case 'paused': return 'SUBSCRIPTION_STATE_PAUSED';
    case 'incomplete': return 'SUBSCRIPTION_STATE_PENDING';
    case 'canceled': case 'incomplete_expired': return 'SUBSCRIPTION_STATE_EXPIRED';
    default: return 'SUBSCRIPTION_STATE_UNSPECIFIED';
  }
}

/** Period end lives on the item in API 2025-03-31+; older versions put it on the subscription. */
export function stripePeriodEnd(sub) {
  const t = sub?.items?.data?.[0]?.current_period_end ?? sub?.current_period_end;
  return Number.isFinite(t) ? new Date(t * 1000).toISOString() : null;
}

export function entitlementFromStripe(sub, userId) {
  return {
    tokenHash: stripeEntitlementKey(sub.id), userId, platform: STRIPE_PLATFORM,
    productId: sub?.items?.data?.[0]?.price?.id || 'stripe',
    state: stripeState(sub), expiresAt: stripePeriodEnd(sub),
  };
}

export function createStripeClient(secretKey) { return new Stripe(secretKey); }

const idOf = v => (v && typeof v === 'object' ? v.id : v) || null;

/** Public webhook route (must be mounted before any JSON body parser). */
export function stripeWebhookRoute(app, { config, store, stripe, log, limiter }) {
  const ready = () => Boolean(config.stripe?.configured && stripe);
  app.post('/api/billing/stripe/webhook', limiter, express.raw({ type: '*/*', limit: '1mb' }), async (req, res) => {
    if (!ready()) return res.status(503).json({ error: 'stripe_not_configured', code: 'STRIPE_NOT_CONFIGURED' });
    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, req.get('stripe-signature') || '', config.stripe.webhookSecret);
    } catch (e) {
      log.warn('stripe webhook rejected', { reason: e.message });
      return res.status(400).json({ error: 'invalid_signature', code: 'INVALID_SIGNATURE' });
    }
    try {
      if (await store.hasStripeEvent(event.id)) return res.json({ received: true, duplicate: true });
      await handleStripeEvent(event, { store, stripe, log });
      await store.markStripeEvent(event.id, event.type);
      res.json({ received: true });
    } catch (e) {
      log.error('stripe webhook failed', { type: event.type, error_message: e.message });
      res.status(500).json({ error: 'webhook_failed' }); // Stripe retries
    }
  });
}

async function upsertFromSubscription(subId, uidHint, { store, stripe, log }) {
  if (!subId) return;
  // Always re-read the subscription so out-of-order events cannot roll the state back.
  const sub = await stripe.subscriptions.retrieve(subId);
  const customer = idOf(sub.customer);
  const uid = uidHint || sub.metadata?.uid || (customer && await store.getUserByStripeCustomer(customer));
  if (!uid) { log.warn('stripe subscription with unknown uid', { subscription: sub.id }); return; }
  if (customer) await store.putStripeCustomer(uid, customer);
  const ent = entitlementFromStripe(sub, uid);
  await store.putEntitlement(ent);
  log.info('stripe entitlement updated', { state: ent.state });
}

export async function handleStripeEvent(event, deps) {
  const o = event.data?.object || {};
  switch (event.type) {
    case 'checkout.session.completed': {
      if (o.mode !== 'subscription') return;
      const uid = o.client_reference_id || o.metadata?.uid;
      if (uid && idOf(o.customer)) await deps.store.putStripeCustomer(uid, idOf(o.customer));
      return upsertFromSubscription(idOf(o.subscription), uid, deps);
    }
    case 'customer.subscription.created':
    case 'customer.subscription.updated':
    case 'customer.subscription.deleted':
      return upsertFromSubscription(o.id, o.metadata?.uid, deps);
    case 'invoice.payment_failed':
    case 'invoice.paid':
      return upsertFromSubscription(idOf(o.subscription) || idOf(o.parent?.subscription_details?.subscription), o.parent?.subscription_details?.metadata?.uid, deps);
    default: return; // acknowledged, ignored
  }
}

/** Signed-in routes, mounted on the /api/billing router. */
export function stripeRoutes(router, { config, store, stripe, log, summary }) {
  const ready = () => Boolean(config.stripe?.configured && stripe);
  const nc = res => res.status(503).json({ error: 'stripe_not_configured', code: 'STRIPE_NOT_CONFIGURED' });

  router.post('/stripe/checkout', async (req, res) => {
    if (!ready()) return nc(res);
    const plan = String(req.body?.plan || 'monthly').toLowerCase();
    const price = plan === 'yearly' ? config.stripe.priceYearly : plan === 'monthly' ? config.stripe.priceMonthly : null;
    if (!price) return res.status(400).json({ error: 'unknown_plan', code: 'UNKNOWN_PLAN' });
    try {
      const s = await summary(req.userId);
      if (s.plan !== 'free') return res.status(409).json({ error: 'already_premium', code: 'ALREADY_PREMIUM', source: s.source });
      const customer = await store.getStripeCustomer(req.userId);
      const session = await stripe.checkout.sessions.create({
        mode: 'subscription',
        line_items: [{ price, quantity: 1 }],
        client_reference_id: req.userId,
        metadata: { uid: req.userId },
        subscription_data: { metadata: { uid: req.userId } },
        ...(customer ? { customer } : {}),
        success_url: `${SITE_URL}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${SITE_URL}/billing/cancel`,
      });
      res.json({ url: session.url, id: session.id });
    } catch (e) {
      log.error('stripe checkout failed', { error_message: e.message });
      res.status(502).json({ error: 'checkout_failed', code: 'CHECKOUT_FAILED' });
    }
  });

  router.post('/stripe/portal', async (req, res) => {
    if (!ready()) return nc(res);
    try {
      const customer = await store.getStripeCustomer(req.userId);
      if (!customer) return res.status(404).json({ error: 'no_stripe_customer', code: 'NO_STRIPE_CUSTOMER' });
      const session = await stripe.billingPortal.sessions.create({ customer, return_url: `${SITE_URL}/account` });
      res.json({ url: session.url });
    } catch (e) {
      log.error('stripe portal failed', { error_message: e.message });
      res.status(502).json({ error: 'portal_failed', code: 'PORTAL_FAILED' });
    }
  });
}
