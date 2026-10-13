import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import Stripe from 'stripe';
import { SignJWT } from 'jose';
import { buildApp, testConfig, JWT_SECRET } from './helpers.js';
import { MemoryStore } from '../src/store.js';
import { stripeState, stripePeriodEnd, stripeEntitlementKey } from '../src/stripeBilling.js';

const WHSEC = 'whsec_test_secret_for_unit_tests_only';
const ENV = { STRIPE_SECRET_KEY: 'sk_test_dummy', STRIPE_WEBHOOK_SECRET: WHSEC, STRIPE_PRICE_MONTHLY: 'price_month', STRIPE_PRICE_YEARLY: 'price_year' };
const webhooks = new Stripe('sk_test_dummy').webhooks; // offline signing/verification helpers only
const token = (sub, claims = {}) => new SignJWT({ email_verified: true, ...claims }).setProtectedHeader({ alg: 'HS256' }).setSubject(sub).setIssuedAt().setExpirationTime('5m').sign(new TextEncoder().encode(JWT_SECRET));
const future = (days = 30) => Math.floor(Date.now() / 1000) + days * 86400;

function fakeStripe(subs = {}) {
  const calls = [];
  return {
    calls, subs, webhooks,
    checkout: { sessions: { create: async p => { calls.push(['checkout', p]); return { id: 'cs_1', url: 'https://checkout.stripe.com/c/cs_1' }; } } },
    billingPortal: { sessions: { create: async p => { calls.push(['portal', p]); return { url: 'https://billing.stripe.com/p/1' }; } } },
    subscriptions: { retrieve: async id => { calls.push(['retrieve', id]); if (!subs[id]) throw new Error('no such sub'); return subs[id]; } },
  };
}
const sub = (o = {}) => ({ id: 'sub_1', customer: 'cus_1', status: 'active', cancel_at_period_end: false, metadata: { uid: 'u1' },
  items: { data: [{ price: { id: 'price_month' }, current_period_end: future() }] }, ...o });

function setup({ env = ENV, subs = { sub_1: sub() }, store = new MemoryStore(), extra = {} } = {}) {
  const stripe = fakeStripe(subs);
  const { app } = buildApp({ config: testConfig({ ...env, ...extra }), store, stripe });
  return { app, store, stripe };
}
function send(app, event, secret = WHSEC) {
  const payload = JSON.stringify(event);
  const header = webhooks.generateTestHeaderString({ payload, secret });
  return request(app).post('/api/billing/stripe/webhook').set('Stripe-Signature', header).set('Content-Type', 'application/json').send(payload);
}
const completed = (id = 'evt_1') => ({ id, type: 'checkout.session.completed', data: { object: { mode: 'subscription', client_reference_id: 'u1', metadata: { uid: 'u1' }, customer: 'cus_1', subscription: 'sub_1' } } });
const status = async (app, uid = 'u1') => (await request(app).get('/api/billing/status').set('Authorization', `Bearer ${await token(uid)}`)).body;

test('no STRIPE_* vars: all stripe routes 503 stripe_not_configured; status unchanged', async () => {
  const { app } = setup({ env: {} });
  const auth = `Bearer ${await token('u1')}`;
  for (const p of ['/api/billing/stripe/checkout', '/api/billing/stripe/portal']) {
    const r = await request(app).post(p).set('Authorization', auth).send({});
    assert.equal(r.status, 503); assert.equal(r.body.error, 'stripe_not_configured');
  }
  assert.equal((await request(app).post('/api/billing/stripe/webhook').send('{}')).status, 503);
  const s = await status(app);
  assert.equal(s.plan, 'free'); assert.equal(s.source, null); assert.equal(s.stripeConfigured, false);
});

test('partial Stripe config is not configured and warns', () => {
  const c = testConfig({ STRIPE_SECRET_KEY: 'sk_test_x' });
  assert.equal(c.stripe.configured, false);
  assert.equal(testConfig(ENV).stripe.configured, true);
});

test('checkout requires auth and creates a subscription session bound to the uid', async () => {
  const { app, stripe } = setup();
  assert.equal((await request(app).post('/api/billing/stripe/checkout').send({})).status, 401);
  const r = await request(app).post('/api/billing/stripe/checkout').set('Authorization', `Bearer ${await token('u1')}`).send({ plan: 'yearly' });
  assert.equal(r.status, 200); assert.equal(r.body.url, 'https://checkout.stripe.com/c/cs_1');
  const p = stripe.calls[0][1];
  assert.equal(p.mode, 'subscription'); assert.equal(p.client_reference_id, 'u1'); assert.equal(p.metadata.uid, 'u1');
  assert.equal(p.subscription_data.metadata.uid, 'u1'); assert.deepEqual(p.line_items, [{ price: 'price_year', quantity: 1 }]);
  assert.match(p.success_url, /^https:\/\/payaviator\.app\//); assert.match(p.cancel_url, /^https:\/\/payaviator\.app\//);
  const m = await request(app).post('/api/billing/stripe/checkout').set('Authorization', `Bearer ${await token('u1')}`).send({});
  assert.equal(stripe.calls[1][1].line_items[0].price, 'price_month', 'monthly is the default'); assert.equal(m.status, 200);
  assert.equal((await request(app).post('/api/billing/stripe/checkout').set('Authorization', `Bearer ${await token('u1')}`).send({ plan: 'weekly' })).status, 400);
  assert.deepEqual(p.payment_method_types, ['card']); assert.equal(p.customer_email, undefined, 'no email claim -> no customer_email');
});

test('checkout passes customer_email for new customers, customer for existing ones', async () => {
  const { app, store, stripe } = setup();
  await request(app).post('/api/billing/stripe/checkout').set('Authorization', `Bearer ${await token('u1', { email: 'a@b.co' })}`).send({});
  let p = stripe.calls[0][1]; assert.equal(p.customer_email, 'a@b.co'); assert.equal(p.customer, undefined);
  await store.putStripeCustomer('u1', 'cus_1');
  await request(app).post('/api/billing/stripe/checkout').set('Authorization', `Bearer ${await token('u1', { email: 'a@b.co' })}`).send({});
  p = stripe.calls[1][1]; assert.equal(p.customer, 'cus_1'); assert.equal(p.customer_email, undefined);
  assert.deepEqual(p.payment_method_types, ['card']);
});

test('webhook rejects bad / missing signatures', async () => {
  const { app } = setup();
  assert.equal((await send(app, completed(), 'whsec_wrong')).status, 400);
  assert.equal((await request(app).post('/api/billing/stripe/webhook').set('Content-Type', 'application/json').send(JSON.stringify(completed()))).status, 400);
});

test('checkout.session.completed unlocks premium (source stripe) and is idempotent', async () => {
  const { app, store, stripe } = setup();
  assert.equal((await send(app, completed())).status, 200);
  const s = await status(app);
  assert.equal(s.plan, 'premium'); assert.equal(s.source, 'stripe'); assert.equal(s.limit, null);
  assert.equal(s.productId, 'price_month'); assert.equal(s.state, 'SUBSCRIPTION_STATE_ACTIVE'); assert.ok(s.expiresAt);
  assert.equal(s.cancelAtPeriodEnd, false); assert.equal(s.periodEnd, s.expiresAt);
  assert.equal(await store.getStripeCustomer('u1'), 'cus_1');
  const dup = await send(app, completed());
  assert.equal(dup.status, 200); assert.equal(dup.body.duplicate, true);
  assert.equal(stripe.calls.filter(c => c[0] === 'retrieve').length, 1, 'duplicate event not reprocessed');
  // already premium -> checkout refused
  const r = await request(app).post('/api/billing/stripe/checkout').set('Authorization', `Bearer ${await token('u1')}`).send({});
  assert.equal(r.status, 409); assert.equal(r.body.source, 'stripe');
});

test('subscription.updated (cancel at period end) keeps premium; deleted ends it', async () => {
  const { app, stripe } = setup();
  await send(app, completed());
  stripe.subs.sub_1 = sub({ cancel_at_period_end: true });
  await send(app, { id: 'evt_2', type: 'customer.subscription.updated', data: { object: stripe.subs.sub_1 } });
  let s = await status(app); assert.equal(s.plan, 'premium'); assert.equal(s.state, 'SUBSCRIPTION_STATE_CANCELED');
  assert.equal(s.cancelAtPeriodEnd, true); assert.ok(s.periodEnd);
  stripe.subs.sub_1 = sub({ status: 'canceled', metadata: {} });
  await send(app, { id: 'evt_3', type: 'customer.subscription.deleted', data: { object: stripe.subs.sub_1 } });
  s = await status(app); assert.equal(s.plan, 'free'); assert.equal(s.source, null); assert.equal(s.limit, 1);
  assert.equal(s.cancelAtPeriodEnd, false); assert.equal(s.periodEnd, null);
});

test('invoice.payment_failed -> grace period while Stripe retries, then unpaid -> free', async () => {
  const { app, stripe } = setup();
  await send(app, completed());
  stripe.subs.sub_1 = sub({ status: 'past_due' });
  await send(app, { id: 'evt_4', type: 'invoice.payment_failed', data: { object: { parent: { subscription_details: { subscription: 'sub_1' } } } } });
  let s = await status(app); assert.equal(s.plan, 'premium'); assert.equal(s.state, 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD');
  stripe.subs.sub_1 = sub({ status: 'unpaid' });
  await send(app, { id: 'evt_5', type: 'invoice.payment_failed', data: { object: { subscription: 'sub_1' } } });
  s = await status(app); assert.equal(s.plan, 'free');
});

test('subscription event resolves uid via stored customer when metadata is missing; unknown uid is acked', async () => {
  const { app, store, stripe } = setup({ subs: { sub_9: sub({ id: 'sub_9', customer: 'cus_9', metadata: {} }) } });
  await store.putStripeCustomer('u9', 'cus_9');
  assert.equal((await send(app, { id: 'evt_6', type: 'customer.subscription.updated', data: { object: stripe.subs.sub_9 } })).status, 200);
  assert.equal((await status(app, 'u9')).source, 'stripe');
  stripe.subs.sub_x = sub({ id: 'sub_x', customer: 'cus_x', metadata: {} });
  assert.equal((await send(app, { id: 'evt_7', type: 'customer.subscription.updated', data: { object: stripe.subs.sub_x } })).status, 200);
});

test('handler failure returns 500 and the event is not marked processed (Stripe retries)', async () => {
  const { app, store } = setup({ subs: {} });
  assert.equal((await send(app, completed('evt_f'))).status, 500);
  assert.equal(await store.hasStripeEvent('evt_f'), false);
});

test('active Play OR active Stripe is premium; no migration needed between them', async () => {
  const store = new MemoryStore();
  const { app } = setup({ store });
  await store.putEntitlement({ tokenHash: 'playhash', userId: 'u1', productId: 'payaviator_premium', platform: 'google_play', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: new Date(Date.now() + 86400e3).toISOString() });
  const ps = await status(app); assert.equal(ps.source, 'play'); assert.equal(ps.cancelAtPeriodEnd, false); assert.equal(ps.periodEnd, null);
  await store.putEntitlement({ tokenHash: 'playhash', userId: 'u1', productId: 'payaviator_premium', platform: 'google_play', state: 'SUBSCRIPTION_STATE_EXPIRED', expiresAt: new Date(Date.now() - 1000).toISOString() });
  assert.equal((await status(app)).plan, 'free');
  await send(app, completed());
  const s = await status(app); assert.equal(s.plan, 'premium'); assert.equal(s.source, 'stripe');
});

test('comp accounts report source comp', async () => {
  const { app } = setup({ extra: { COMP_FIREBASE_UIDS: 'owner1' } });
  const s = await status(app, 'owner1'); assert.equal(s.plan, 'comp'); assert.equal(s.source, 'comp');
});

test('portal: 404 without customer, session after checkout', async () => {
  const { app, stripe } = setup();
  const auth = `Bearer ${await token('u1')}`;
  assert.equal((await request(app).post('/api/billing/stripe/portal').set('Authorization', auth).send({})).status, 404);
  await send(app, completed());
  const r = await request(app).post('/api/billing/stripe/portal').set('Authorization', auth).send({});
  assert.equal(r.status, 200); assert.equal(r.body.url, 'https://billing.stripe.com/p/1');
  assert.equal(stripe.calls.find(c => c[0] === 'portal')[1].customer, 'cus_1');
});

test('state + period-end mapping', () => {
  assert.equal(stripeState({ status: 'trialing' }), 'SUBSCRIPTION_STATE_ACTIVE');
  assert.equal(stripeState({ status: 'incomplete' }), 'SUBSCRIPTION_STATE_PENDING');
  assert.equal(stripeState({ status: 'incomplete_expired' }), 'SUBSCRIPTION_STATE_EXPIRED');
  assert.equal(stripePeriodEnd({ current_period_end: 1700000000 }), new Date(1700000000e3).toISOString());
  assert.equal(stripePeriodEnd({}), null);
  assert.equal(stripeEntitlementKey('sub_1'), 'stripe_sub:sub_1');
});

test('stripe event ids are purged after 30 days', async () => {
  const s = new MemoryStore();
  await s.markStripeEvent('old', 't'); s.stripeEvents.get('old').at = Date.now() - 31 * 86400e3;
  await s.markStripeEvent('new', 't');
  assert.equal(await s.purgeStripeEvents(30), 1);
  assert.equal(await s.hasStripeEvent('old'), false); assert.equal(await s.hasStripeEvent('new'), true);
});
