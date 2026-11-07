import express from 'express';
import Stripe from 'stripe';
import { isEntitlementActive } from './billing.js';
import { recoveryFlags } from './billingRecovery.js';

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

/** Statuses that can still take money or turn into access. Fully `canceled` and `incomplete_expired` cannot. */
const STRIPE_MAY_BILL = new Set(['active', 'trialing', 'past_due', 'unpaid', 'paused', 'incomplete']);

export function stripeMayStillBill(sub) {
  return STRIPE_MAY_BILL.has(sub?.status);
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

  const already = source => ({ error: 'already_premium', code: 'ALREADY_PREMIUM', source });
  const blocked = (recoveryRequired, source) => ({
    error: 'duplicate_checkout_blocked', code: 'DUPLICATE_CHECKOUT_BLOCKED',
    duplicateCheckoutBlocked: true, recoveryRequired: Boolean(recoveryRequired), ...(source ? { source } : {}),
  });

  router.post('/stripe/checkout', async (req, res) => {
    if (!ready()) return nc(res);
    const plan = String(req.body?.plan || 'monthly').toLowerCase();
    const price = plan === 'yearly' ? config.stripe.priceYearly : plan === 'monthly' ? config.stripe.priceMonthly : null;
    if (!price) return res.status(400).json({ error: 'unknown_plan', code: 'UNKNOWN_PLAN' });
    // Body customer / customerId / email / session id are never ownership proofs and are not read.
    try {
      const out = await store.withBillingLock(req.userId, async () => {
        const s = await summary(req.userId);
        if (s.plan !== 'free') return { status: 409, body: already(s.source) };
        const [hold, entitlements] = await Promise.all([store.getRecoveryHold(req.userId), store.getEntitlements(req.userId)]);
        const flags = recoveryFlags({ hold, entitlements, plan: s.plan });
        if (flags.recoveryRequired || flags.duplicateCheckoutBlocked) return { status: 409, body: blocked(flags.recoveryRequired, flags.recoveryRequired ? 'play' : null) };
        const customer = await store.getStripeCustomer(req.userId);
        if (customer) {
          let listed;
          try { listed = await stripe.subscriptions.list({ customer, status: 'all', limit: 20 }); }
          catch (e) {
            log.error('stripe subscription list failed', { error_message: e.message });
            return { status: 502, body: { error: 'checkout_failed', code: 'CHECKOUT_FAILED' } };
          }
          const subs = Array.isArray(listed?.data) ? listed.data : [];
          if (subs.some(sub => sub?.metadata?.uid && sub.metadata.uid !== req.userId)) {
            return { status: 409, body: blocked(false, 'stripe') };
          }
          const billing = subs.filter(stripeMayStillBill);
          if (billing.length) {
            const sub = billing[0];
            const ent = entitlementFromStripe(sub, req.userId);
            // Only the authenticated uid is written, and only when Stripe metadata does not name someone else
            // (checked above). putEntitlement still will not overwrite a row owned by a different uid.
            await store.putEntitlement(ent);
            const after = await summary(req.userId);
            if (after.plan !== 'free') return { status: 409, body: already(after.source || 'stripe') };
            return { status: 409, body: blocked(false, 'stripe') };
          }
        }
        const existingId = await store.getCheckoutSession(req.userId);
        if (existingId) {
          let sess;
          try { sess = await stripe.checkout.sessions.retrieve(existingId); }
          catch (e) {
            log.error('stripe checkout session retrieve failed', { error_message: e.message });
            return { status: 502, body: { error: 'checkout_failed', code: 'CHECKOUT_FAILED' } };
          }
          if (sess?.client_reference_id && sess.client_reference_id !== req.userId) return { status: 409, body: blocked(false, 'stripe') };
          if (sess?.status === 'open') {
            if (!sess.url) return { status: 502, body: { error: 'checkout_failed', code: 'CHECKOUT_FAILED' } };
            return { status: 200, body: { url: sess.url, id: sess.id } };
          }
          if (sess?.status === 'complete') {
            const subId = idOf(sess.subscription);
            if (!subId) return { status: 409, body: blocked(false, 'stripe') };
            let sub;
            try { sub = await stripe.subscriptions.retrieve(subId); }
            catch (e) {
              log.error('stripe subscription retrieve failed', { error_message: e.message });
              return { status: 502, body: { error: 'checkout_failed', code: 'CHECKOUT_FAILED' } };
            }
            if (sub?.metadata?.uid && sub.metadata.uid !== req.userId) return { status: 409, body: blocked(false, 'stripe') };
            const ent = entitlementFromStripe(sub, req.userId);
            await store.putEntitlement(ent);
            if (isEntitlementActive(ent)) return { status: 409, body: already('stripe') };
            if (stripeMayStillBill(sub)) return { status: 409, body: blocked(false, 'stripe') };
          }
        }
        const rawEmail = req.authClaims?.email;
        const email = typeof rawEmail === 'string' && /^[^\s@]+@[^\s@]+$/.test(rawEmail) ? rawEmail : null;
        const session = await stripe.checkout.sessions.create({
          mode: 'subscription',
          line_items: [{ price, quantity: 1 }],
          client_reference_id: req.userId,
          metadata: { uid: req.userId },
          subscription_data: { metadata: { uid: req.userId } },
          payment_method_types: ['card'], // cards only (no Klarna / BNPL / bank debits)
          ...(customer ? { customer } : (email ? { customer_email: email } : {})),
          success_url: `${SITE_URL}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${SITE_URL}/billing/cancel`,
        });
        if (session?.id) await store.putCheckoutSession(req.userId, session.id);
        return { status: 200, body: { url: session.url, id: session.id } };
      });
      res.status(out.status).json(out.body);
    } catch (e) {
      log.error('stripe checkout failed', { error_message: e.message });
      res.status(502).json({ error: 'checkout_failed', code: 'CHECKOUT_FAILED' });
    }
  });

  router.post('/stripe/portal', async (req, res) => {
    if (!ready()) return nc(res);
    try {
      // Customer id comes only from the signed-in uid. Body customer/email is ignored. No email search.
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
