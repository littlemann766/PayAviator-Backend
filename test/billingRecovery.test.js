import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { SignJWT } from 'jose';
import { buildApp, testConfig, JWT_SECRET } from './helpers.js';
import { sha256Hex } from '../src/crypto.js';
import { loadConfig } from '../src/config.js';
import { classifyAccountLookupError, decideCrossUserRestore, ANDROID_APPLICATION_ID, FIXTURE_ANDROID_PACKAGE, FIXTURE_PLAY_PRODUCT_ID } from '../src/billingRecovery.js';
import Stripe from 'stripe';
import { stripeEntitlementKey } from '../src/stripeBilling.js';

const bearer = async (sub = 'user-1', claims = {}) => `Bearer ${await new SignJWT({ email_verified: true, ...claims }).setProtectedHeader({ alg: 'HS256' }).setSubject(sub).setIssuedAt().setExpirationTime('5m').sign(new TextEncoder().encode(JWT_SECRET))}`;
const SA = JSON.stringify({ client_email: 'play@x.iam.gserviceaccount.com', private_key: '-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n' });
const billingConfig = (extra = {}) => testConfig({ GOOGLE_PLAY_SERVICE_ACCOUNT_JSON: SA, ANDROID_PACKAGE_NAME: 'app.payaviator', GOOGLE_PLAY_PRODUCT_IDS: 'payaviator_premium', ...extra });
const STRIPE = { STRIPE_SECRET_KEY: 'sk_test_dummy', STRIPE_WEBHOOK_SECRET: 'whsec_test_secret_for_unit_tests_only', STRIPE_PRICE_MONTHLY: 'price_month', STRIPE_PRICE_YEARLY: 'price_year' };
const webhooks = new Stripe('sk_test_dummy').webhooks;
const future = (d = 30) => new Date(Date.now() + d * 86400e3).toISOString();
const past = () => new Date(Date.now() - 86400e3).toISOString();

function fakeGoogle(sub) {
  const g = { acks: [], gets: 0,
    async getSubscription() { g.gets++; if (sub instanceof Error) throw sub; return typeof sub === 'function' ? sub() : sub; },
    async acknowledge(productId, token) { g.acks.push({ productId, token }); } };
  return g;
}
const sub = (over = {}) => ({
  subscriptionState: 'SUBSCRIPTION_STATE_ACTIVE', acknowledgementState: 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED',
  lineItems: [{ productId: 'payaviator_premium', expiryTime: future() }], ...over,
});
function authUsers(spec) {
  const calls = [];
  return { calls, async getUser(uid) {
    calls.push(uid);
    const v = spec[uid] || 'unavailable';
    if (v === 'exists') return { uid };
    const e = new Error(v);
    e.code = v === 'deleted' ? 'auth/user-not-found' : (v === 'permission' ? 'auth/insufficient-permission' : 'auth/internal-error');
    throw e;
  } };
}
async function postVerify(app, uid, purchaseToken, extra = {}) {
  return request(app).post('/api/billing/google-play/verify').set('Authorization', await bearer(uid)).send({ productId: 'payaviator_premium', purchaseToken, ...extra });
}

test('account lookup classification and cross-user decision do not treat errors as deletion', () => {
  assert.equal(classifyAccountLookupError({ code: 'auth/user-not-found' }), 'deleted');
  assert.equal(classifyAccountLookupError({ errorInfo: { code: 'auth/user-not-found' } }), 'deleted');
  for (const code of ['auth/insufficient-permission', 'auth/internal-error', 'auth/invalid-credential', '', undefined]) {
    assert.equal(classifyAccountLookupError({ code }), 'unavailable', code || 'empty');
  }
  assert.deepEqual(decideCrossUserRestore({ lookup: 'exists', binding: 'caller', mayBill: true }), { action: 'conflict', recoveryRequired: false, duplicateCheckoutBlocked: false });
  assert.equal(decideCrossUserRestore({ lookup: 'deleted', binding: 'unbound', mayBill: true }).action, 'reassign');
  assert.equal(decideCrossUserRestore({ lookup: 'deleted', binding: 'other', mayBill: true }).action, 'ownership_unconfirmed');
  assert.equal(decideCrossUserRestore({ lookup: 'deleted', binding: 'unbound', mayBill: false }).action, 'conflict');
  assert.equal(decideCrossUserRestore({ lookup: 'unavailable', binding: 'unbound', mayBill: true }).action, 'ownership_unconfirmed');
  assert.equal(decideCrossUserRestore({ lookup: 'unavailable', binding: 'caller', mayBill: false }).action, 'conflict');
  assert.equal(ANDROID_APPLICATION_ID, 'com.payaviator.app');
  assert.notEqual(FIXTURE_ANDROID_PACKAGE, ANDROID_APPLICATION_ID);
  assert.equal(FIXTURE_PLAY_PRODUCT_ID, 'payaviator_premium');
});

test('configured package and product are left as given; fixture is not rewritten to the app id', () => {
  const { config, warnings } = loadConfig({ AUTH_DISABLED: 'true', ANDROID_PACKAGE_NAME: 'app.payaviator', GOOGLE_PLAY_PRODUCT_IDS: 'payaviator_premium', GOOGLE_PLAY_SERVICE_ACCOUNT_JSON: SA });
  assert.equal(config.billing.packageName, 'app.payaviator');
  assert.deepEqual(config.billing.productIds, ['payaviator_premium']);
  assert.ok(warnings.some(w => w.includes('com.payaviator.app') && w.includes('not a verified production package')));
  const prod = loadConfig({ AUTH_DISABLED: 'true', ANDROID_PACKAGE_NAME: 'com.payaviator.app' });
  assert.equal(prod.config.billing.packageName, 'com.payaviator.app');
  assert.ok(!prod.warnings.some(w => /not a verified production package/.test(w)));
});

test('living owner keeps 409 with no Play call, no transfer, and no checkout block', async () => {
  const google = fakeGoogle(sub());
  const lookup = authUsers({ 'user-1': 'exists' });
  const { app, store } = buildApp({ config: billingConfig(STRIPE), googlePlay: google, accountLookup: lookup });
  await store.putEntitlement({ tokenHash: sha256Hex('tok-live'), userId: 'user-1', productId: 'payaviator_premium', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
  await store.putRecoveryHold('user-2', { code: 'OWNERSHIP_UNCONFIRMED', duplicateCheckoutBlocked: true, tokenHash: sha256Hex('tok-live') });
  const r = await postVerify(app, 'user-2', 'tok-live', { email: 'owner@example.com', customerId: 'cus_x', subscriptionState: 'SUBSCRIPTION_STATE_ACTIVE' });
  assert.equal(r.status, 409);
  assert.deepEqual(r.body, { error: 'purchase_in_use', code: 'PURCHASE_IN_USE' });
  assert.equal(google.gets, 0);
  assert.equal((await store.getEntitlementByTokenHash(sha256Hex('tok-live'))).userId, 'user-1');
  assert.equal(await store.getRecoveryHold('user-2'), null);
  assert.equal(lookup.calls.includes('user-2'), false);
});

test('a hold for a different token is not cleared by someone else\'s living purchase', async () => {
  const google = fakeGoogle(sub());
  const { app, store } = buildApp({ config: billingConfig(STRIPE), googlePlay: google, stripe: fakeStripe(), accountLookup: authUsers({ 'user-1': 'exists' }) });
  await store.putEntitlement({ tokenHash: sha256Hex('tok-live'), userId: 'user-1', productId: 'payaviator_premium', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
  await store.putRecoveryHold('user-2', { code: 'OWNERSHIP_UNCONFIRMED', duplicateCheckoutBlocked: true, tokenHash: sha256Hex('other-token') });
  const r = await postVerify(app, 'user-2', 'tok-live');
  assert.equal(r.status, 409);
  assert.equal((await store.getRecoveryHold('user-2')).tokenHash, sha256Hex('other-token'));
  const checkout = await request(app).post('/api/billing/stripe/checkout').set('Authorization', await bearer('user-2')).send({ plan: 'monthly', customer: 'cus_victim', email: 'victim@example.com' });
  assert.equal(checkout.status, 409);
  assert.equal(checkout.body.code, 'DUPLICATE_CHECKOUT_BLOCKED');
  assert.equal(checkout.body.recoveryRequired, true);
});

test('deleted owner plus Play-verified entitled states restores only the entitlement', async () => {
  for (const state of ['SUBSCRIPTION_STATE_ACTIVE', 'SUBSCRIPTION_STATE_IN_GRACE_PERIOD', 'SUBSCRIPTION_STATE_CANCELED']) {
    const token = `tok-${state}`;
    const google = fakeGoogle(sub({ subscriptionState: state, acknowledgementState: state === 'SUBSCRIPTION_STATE_ACTIVE' ? 'ACKNOWLEDGEMENT_STATE_PENDING' : 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED' }));
    const { app, store } = buildApp({ config: billingConfig(), googlePlay: google, accountLookup: authUsers({ 'old-user': 'deleted' }) });
    await store.putItem({ userId: 'old-user', itemId: `bank-${state}`, accessToken: 'access-secret' });
    await store.putEntitlement({ tokenHash: sha256Hex(token), userId: 'old-user', productId: 'payaviator_premium', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
    const r = await postVerify(app, 'new-user', token, { email: 'same@example.com', customerId: 'cus_no', purchase: { subscriptionState: 'SUBSCRIPTION_STATE_EXPIRED' } });
    assert.equal(r.status, 200, state);
    assert.equal(r.body.recovered, true);
    assert.equal(r.body.plan, 'premium');
    assert.equal(r.body.recoveryRequired, false);
    assert.equal((await store.getEntitlementByTokenHash(sha256Hex(token))).userId, 'new-user');
    assert.equal((await store.getEntitlements('old-user')).length, 0);
    assert.equal((await store.getItems('old-user')).length, 1, 'bank link stays on the deleted uid');
    assert.equal((await store.getItems('new-user')).length, 0);
    assert.equal(JSON.stringify(r.body).includes(token), false);
    assert.equal(JSON.stringify(r.body).includes('old-user'), false);
    if (state === 'SUBSCRIPTION_STATE_ACTIVE') assert.equal(google.acks.length, 1);
    else assert.equal(google.acks.length, 0);
    const again = await postVerify(app, 'new-user', token);
    assert.equal(again.status, 200);
    assert.equal(again.body.recovered, undefined);
    assert.equal((await store.getEntitlements('new-user')).length, 1);
  }
});

test('paused, on hold, and pending move without granting and block a second checkout', async () => {
  for (const state of ['SUBSCRIPTION_STATE_PAUSED', 'SUBSCRIPTION_STATE_ON_HOLD', 'SUBSCRIPTION_STATE_PENDING']) {
    const token = `hold-${state}`;
    const { app, store } = buildApp({ config: billingConfig(STRIPE), googlePlay: fakeGoogle(sub({ subscriptionState: state })), stripe: fakeStripe(), accountLookup: authUsers({ old: 'deleted' }) });
    await store.putEntitlement({ tokenHash: sha256Hex(token), userId: 'old', productId: 'payaviator_premium', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
    const r = await postVerify(app, 'new', token);
    assert.equal(r.status, 402, state);
    assert.equal(r.body.recovered, true);
    assert.equal(r.body.plan, 'free');
    assert.equal(r.body.duplicateCheckoutBlocked, true);
    assert.equal(r.body.recoveryRequired, false);
    const checkout = await request(app).post('/api/billing/stripe/checkout').set('Authorization', await bearer('new')).send({});
    assert.equal(checkout.status, 409);
    assert.equal(checkout.body.code, 'DUPLICATE_CHECKOUT_BLOCKED');
  }
});

test('expired, revoked, and unspecified purchases are not transferred and do not block checkout', async () => {
  for (const state of ['SUBSCRIPTION_STATE_EXPIRED', 'SUBSCRIPTION_STATE_PENDING_PURCHASE_CANCELED', 'SUBSCRIPTION_STATE_REVOKED', 'SUBSCRIPTION_STATE_UNSPECIFIED']) {
    const token = `dead-${state}`;
    const stripe = fakeStripe();
    const { app, store } = buildApp({ config: billingConfig(STRIPE), googlePlay: fakeGoogle(sub({ subscriptionState: state, lineItems: [{ productId: 'payaviator_premium', expiryTime: past() }] })), stripe, accountLookup: authUsers({ old: 'deleted' }) });
    await store.putEntitlement({ tokenHash: sha256Hex(token), userId: 'old', productId: 'payaviator_premium', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
    const r = await postVerify(app, 'new', token, { subscriptionState: 'SUBSCRIPTION_STATE_ACTIVE', email: 'old@example.com' });
    assert.equal(r.status, 409, state);
    assert.deepEqual(r.body, { error: 'purchase_in_use', code: 'PURCHASE_IN_USE' });
    assert.equal((await store.getEntitlementByTokenHash(sha256Hex(token))).userId, 'old');
    assert.equal(await store.getRecoveryHold('new'), null);
    const checkout = await request(app).post('/api/billing/stripe/checkout').set('Authorization', await bearer('new')).send({ customerId: 'cus_old' });
    assert.equal(checkout.status, 200, state);
    assert.equal(stripe.calls.some(c => c[0] === 'checkout'), true);
    assert.equal(JSON.stringify(stripe.calls).includes('cus_old'), false);
  }
});

test('auth lookup errors and a Play-confirmed binding to someone else do not transfer', async () => {
  const token = 'tok-unconfirmed';
  const lines = [];
  const log = { info(msg, fields) { lines.push(JSON.stringify({ msg, ...fields })); }, warn(msg, fields) { lines.push(JSON.stringify({ msg, ...fields })); }, error(msg, fields) { lines.push(JSON.stringify({ msg, ...fields })); } };
  const google = fakeGoogle(sub({
    externalAccountIdentifiers: { obfuscatedExternalAccountId: 'not-this-user' },
    subscribeWithGoogleInfo: { emailAddress: 'new@example.com' },
  }));
  const { app, store } = buildApp({ config: billingConfig(STRIPE), googlePlay: google, stripe: fakeStripe(), accountLookup: authUsers({ old: 'permission' }), log });
  await store.putEntitlement({ tokenHash: sha256Hex(token), userId: 'old', productId: 'payaviator_premium', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
  const r = await postVerify(app, 'new', token, { email: 'new@example.com', obfuscatedExternalAccountId: 'new' });
  assert.equal(r.status, 409);
  assert.equal(r.body.recoveryRequired, true);
  assert.equal(r.body.duplicateCheckoutBlocked, true);
  assert.equal(r.body.recoveryCode, 'OWNERSHIP_UNCONFIRMED');
  assert.equal(r.body.error, 'purchase_in_use');
  assert.equal((await store.getEntitlementByTokenHash(sha256Hex(token))).userId, 'old');
  assert.equal(google.acks.length, 0);
  const status = await request(app).get('/api/billing/status').set('Authorization', await bearer('new'));
  assert.equal(status.body.plan, 'free');
  assert.equal(status.body.recoveryRequired, true);
  assert.equal(status.body.duplicateCheckoutBlocked, true);
  assert.equal(JSON.stringify(status.body).includes(token), false);
  assert.equal(JSON.stringify(lines).includes(token), false);
  assert.equal(JSON.stringify(lines).includes('new@example.com'), false);
  const checkout = await request(app).post('/api/billing/stripe/checkout').set('Authorization', await bearer('new')).send({});
  assert.equal(checkout.status, 409);
  assert.equal(checkout.body.code, 'DUPLICATE_CHECKOUT_BLOCKED');
});

test('lookup unavailable with an unbound still-billing purchase blocks transfer and checkout', async () => {
  const token = 'tok-down';
  const { app, store } = buildApp({ config: billingConfig(STRIPE), googlePlay: fakeGoogle(sub()), accountLookup: authUsers({ old: 'unavailable' }) });
  await store.putEntitlement({ tokenHash: sha256Hex(token), userId: 'old', productId: 'payaviator_premium', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
  const r = await postVerify(app, 'new', token);
  assert.equal(r.body.recoveryCode, 'OWNERSHIP_UNCONFIRMED');
  assert.equal((await store.getEntitlementByTokenHash(sha256Hex(token))).userId, 'old');
  assert.equal((await store.getRecoveryHold('new')).tokenHash, sha256Hex(token));
  assert.equal(JSON.stringify(await store.getRecoveryHold('new')).includes(token), false);
});

test('Play binding that matches the signed-in uid allows restore after deletion; a mismatch does not', async () => {
  const ok = fakeGoogle(sub({ externalAccountIdentifiers: { obfuscatedExternalAccountId: 'new' } }));
  let built = buildApp({ config: billingConfig(), googlePlay: ok, accountLookup: authUsers({ old: 'deleted' }) });
  await built.store.putEntitlement({ tokenHash: sha256Hex('bound'), userId: 'old', productId: 'payaviator_premium', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
  let r = await postVerify(built.app, 'new', 'bound');
  assert.equal(r.status, 200);
  assert.equal(r.body.recovered, true);

  const bad = fakeGoogle(sub({ externalAccountIdentifiers: { externalAccountId: 'hashed-or-other-account' } }));
  built = buildApp({ config: billingConfig(), googlePlay: bad, accountLookup: authUsers({ old: 'deleted' }) });
  await built.store.putEntitlement({ tokenHash: sha256Hex('other-bind'), userId: 'old', productId: 'payaviator_premium', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
  r = await postVerify(built.app, 'new', 'other-bind');
  assert.equal(r.status, 409);
  assert.equal(r.body.recoveryRequired, true);
  assert.equal((await built.store.getEntitlementByTokenHash(sha256Hex('other-bind'))).userId, 'old');
});

test('provider failures and product mismatch do not grant or move the row', async () => {
  const cases = [
    [Object.assign(new Error('nope'), { response: { status: 404 } }), 400, 'invalid_purchase'],
    [Object.assign(new Error('GET https://androidpublisher.googleapis.com/androidpublisher/v3/applications/app.payaviator/purchases/subscriptionsv2/tokens/tok-fail-down failed'), { response: { status: 503 } }), 502, 'verify_failed'],
    [sub({ lineItems: [{ productId: 'other', expiryTime: future() }] }), 400, 'product_mismatch'],
  ];
  const lines = [];
  const log = { info() {}, warn() {}, error(msg, fields) { lines.push(JSON.stringify({ msg, ...fields })); } };
  for (const [purchase, status, error] of cases) {
    const token = `tok-fail-${error}`;
    const { app, store } = buildApp({ config: billingConfig(), googlePlay: fakeGoogle(purchase), accountLookup: authUsers({ old: 'deleted' }), log });
    await store.putEntitlement({ tokenHash: sha256Hex(token), userId: 'old', productId: 'payaviator_premium', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
    const r = await postVerify(app, 'new', token);
    assert.equal(r.status, status, error);
    assert.equal(r.body.error, error);
    assert.equal((await store.getEntitlementByTokenHash(sha256Hex(token))).userId, 'old');
    assert.equal((await store.getEntitlements('new')).length, 0);
  }
  assert.equal(JSON.stringify(lines).includes('tok-fail-down'), false);
});

test('replacement token owned by a living user is rejected; a deleted owner can be superseded', async () => {
  const linked = 'old-token-value-12345678';
  let google = fakeGoogle(sub({ linkedPurchaseToken: linked }));
  let built = buildApp({ config: billingConfig(), googlePlay: google, accountLookup: authUsers({ 'user-1': 'exists' }) });
  await built.store.putEntitlement({ tokenHash: sha256Hex(linked), userId: 'user-1', productId: 'payaviator_premium', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
  let r = await postVerify(built.app, 'user-2', 'new-token-value-12345678');
  assert.deepEqual(r.body, { error: 'purchase_in_use', code: 'PURCHASE_IN_USE' });
  assert.equal(await built.store.getEntitlementByTokenHash(sha256Hex('new-token-value-12345678')), null);
  assert.equal((await built.store.getEntitlementByTokenHash(sha256Hex(linked))).state, 'SUBSCRIPTION_STATE_ACTIVE');

  google = fakeGoogle(sub({ linkedPurchaseToken: linked }));
  built = buildApp({ config: billingConfig(), googlePlay: google, accountLookup: authUsers({ 'user-1': 'deleted' }) });
  await built.store.putEntitlement({ tokenHash: sha256Hex(linked), userId: 'user-1', productId: 'payaviator_premium', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
  r = await postVerify(built.app, 'user-2', 'new-token-value-12345678');
  assert.equal(r.status, 200);
  assert.equal(r.body.recovered, true);
  assert.equal((await built.store.getEntitlementByTokenHash(sha256Hex('new-token-value-12345678'))).userId, 'user-2');
  assert.equal((await built.store.getEntitlementByTokenHash(sha256Hex(linked))).state, 'SUPERSEDED');
  assert.equal((await built.store.getEntitlementByTokenHash(sha256Hex(linked))).userId, 'user-1');
});

test('concurrent claims: one successor wins and the other stays on 409', async () => {
  let release;
  const gate = new Promise(res => { release = res; });
  let waiting = 0;
  const google = fakeGoogle(sub());
  const lookup = { async getUser(uid) {
    if (uid !== 'old') return { uid };
    waiting += 1;
    if (waiting === 2) release();
    await gate;
    const e = new Error('gone'); e.code = 'auth/user-not-found'; throw e;
  } };
  const { app, store } = buildApp({ config: billingConfig(), googlePlay: google, accountLookup: lookup });
  await store.putEntitlement({ tokenHash: sha256Hex('race-token'), userId: 'old', productId: 'payaviator_premium', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
  const [a, b] = await Promise.all([postVerify(app, 'new-a', 'race-token'), postVerify(app, 'new-b', 'race-token')]);
  const statuses = [a.status, b.status].sort((x, y) => x - y);
  assert.deepEqual(statuses, [200, 409]);
  const row = await store.getEntitlementByTokenHash(sha256Hex('race-token'));
  assert.ok(row.userId === 'new-a' || row.userId === 'new-b');
  const loser = row.userId === 'new-a' ? 'new-b' : 'new-a';
  assert.equal((await store.getEntitlements(loser)).length, 0);
  assert.equal((await store.getEntitlements('old')).length, 0);
  const winnerBody = a.status === 200 ? a.body : b.body;
  assert.equal(winnerBody.recovered, true);
  assert.equal(JSON.stringify(winnerBody).includes('race-token'), false);
});

test('rtdn after recovery updates the successor, and account deletion does not remove the entitlement', async () => {
  let state = 'SUBSCRIPTION_STATE_ACTIVE';
  const google = fakeGoogle(() => sub({ subscriptionState: state }));
  const pubsubVerifier = async h => { if (h !== 'Bearer good') throw new Error('bad'); };
  const { app, store } = buildApp({
    config: billingConfig({ GOOGLE_PLAY_RTDN_AUDIENCE: 'https://api.payaviator.app/api/billing/google-play/rtdn' }),
    googlePlay: google, pubsubVerifier, accountLookup: authUsers({ old: 'deleted' }),
  });
  await store.putEntitlement({ tokenHash: sha256Hex('rtdn-tok'), userId: 'old', productId: 'payaviator_premium', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
  assert.equal((await postVerify(app, 'new', 'rtdn-tok')).status, 200);
  state = 'SUBSCRIPTION_STATE_EXPIRED';
  const msg = { message: { data: Buffer.from(JSON.stringify({ packageName: 'app.payaviator', subscriptionNotification: { notificationType: 13, purchaseToken: 'rtdn-tok', subscriptionId: 'payaviator_premium' } })).toString('base64') } };
  assert.equal((await request(app).post('/api/billing/google-play/rtdn').set('Authorization', 'Bearer good').send(msg)).status, 204);
  assert.equal((await store.getEntitlementByTokenHash(sha256Hex('rtdn-tok'))).userId, 'new');
  assert.equal((await store.getEntitlementByTokenHash(sha256Hex('rtdn-tok'))).state, 'SUBSCRIPTION_STATE_EXPIRED');
  const del = await request(app).delete('/api/plaid/user').set('Authorization', await bearer('new')).send({});
  assert.equal(del.status, 200);
  assert.equal((await store.getEntitlementByTokenHash(sha256Hex('rtdn-tok'))).userId, 'new');
});

function fakeStripe(subs = {}, sessions = {}) {
  const calls = [];
  return {
    calls, subs, sessions, webhooks,
    checkout: { sessions: {
      create: async p => { calls.push(['checkout', p]); return { id: 'cs_new', url: 'https://checkout.stripe.com/c/cs_new' }; },
      retrieve: async id => { calls.push(['session', id]); if (sessions.throw) throw new Error('stripe down'); return sessions[id] || { id, status: 'expired' }; },
    } },
    billingPortal: { sessions: { create: async p => { calls.push(['portal', p]); return { url: 'https://billing.stripe.com/p/1' }; } } },
    subscriptions: {
      list: async ({ customer } = {}) => {
        calls.push(['list', customer]);
        if (subs.throw) throw new Error('list failed ' + customer);
        return { data: Object.values(subs).filter(s => s && (s.customer?.id || s.customer) === customer) };
      },
      retrieve: async id => { calls.push(['retrieve', id]); if (!subs[id]) throw new Error('missing'); return subs[id]; },
    },
  };
}

test('stripe checkout ignores client customer ids, blocks provider-confirmed duplicates, and fails closed', async () => {
  const period = Math.floor(Date.now() / 1000) + 30 * 86400;
  const active = { id: 'sub_1', customer: 'cus_1', status: 'active', metadata: { uid: 'u1' }, items: { data: [{ price: { id: 'price_month' }, current_period_end: period }] } };
  let stripe = fakeStripe({ sub_1: active });
  let built = buildApp({ config: testConfig(STRIPE), stripe });
  await built.store.putStripeCustomer('u1', 'cus_1');
  let r = await request(built.app).post('/api/billing/stripe/checkout').set('Authorization', await bearer('u1')).send({ plan: 'monthly', customer: 'cus_attacker', email: 'a@b.co' });
  assert.equal(r.status, 409);
  assert.equal(r.body.code, 'ALREADY_PREMIUM');
  assert.equal(r.body.source, 'stripe');
  assert.equal(stripe.calls.some(c => c[0] === 'checkout'), false);
  assert.equal((await built.store.getEntitlements('u1'))[0].tokenHash, stripeEntitlementKey('sub_1'));

  stripe = fakeStripe({ throw: true });
  built = buildApp({ config: testConfig(STRIPE), stripe });
  await built.store.putStripeCustomer('u1', 'cus_1');
  r = await request(built.app).post('/api/billing/stripe/checkout').set('Authorization', await bearer('u1')).send({});
  assert.equal(r.status, 502);
  assert.equal(stripe.calls.some(c => c[0] === 'checkout'), false);

  const foreign = { id: 'sub_v', customer: 'cus_v', status: 'active', metadata: { uid: 'victim' }, items: { data: [{ price: { id: 'price_month' }, current_period_end: period }] } };
  stripe = fakeStripe({ sub_v: foreign });
  built = buildApp({ config: testConfig(STRIPE), stripe });
  await built.store.putStripeCustomer('attacker', 'cus_v');
  r = await request(built.app).post('/api/billing/stripe/checkout').set('Authorization', await bearer('attacker', { email: 'victim@example.com' })).send({ customerId: 'cus_v', email: 'victim@example.com' });
  assert.equal(r.status, 409);
  assert.equal(r.body.code, 'DUPLICATE_CHECKOUT_BLOCKED');
  assert.equal((await built.store.getEntitlements('attacker')).length, 0);
  assert.equal(stripe.calls.some(c => c[0] === 'checkout'), false);

  stripe = fakeStripe({}, { cs_open: { id: 'cs_open', status: 'open', url: 'https://checkout.stripe.com/c/cs_open', client_reference_id: 'u1' } });
  built = buildApp({ config: testConfig(STRIPE), stripe });
  await built.store.putCheckoutSession('u1', 'cs_open');
  r = await request(built.app).post('/api/billing/stripe/checkout').set('Authorization', await bearer('u1')).send({});
  assert.equal(r.status, 200);
  assert.equal(r.body.id, 'cs_open');
  assert.equal(stripe.calls.some(c => c[0] === 'checkout'), false);

  const paused = { id: 'sub_p', customer: 'cus_p', status: 'paused', metadata: { uid: 'u1' }, items: { data: [{ price: { id: 'price_month' }, current_period_end: period }] } };
  stripe = fakeStripe({ sub_p: paused });
  built = buildApp({ config: testConfig(STRIPE), stripe });
  await built.store.putStripeCustomer('u1', 'cus_p');
  r = await request(built.app).post('/api/billing/stripe/checkout').set('Authorization', await bearer('u1')).send({});
  assert.equal(r.status, 409);
  assert.equal(r.body.code, 'DUPLICATE_CHECKOUT_BLOCKED');
  assert.equal((await request(built.app).get('/api/billing/status').set('Authorization', await bearer('u1'))).body.plan, 'free');
});

test('portal and webhooks do not migrate Stripe customers by email or client customer id', async () => {
  const period = Math.floor(Date.now() / 1000) + 30 * 86400;
  const stripe = fakeStripe({ sub_new: { id: 'sub_new', customer: 'cus_new', status: 'active', metadata: { uid: 'attacker' }, items: { data: [{ price: { id: 'price_month' }, current_period_end: period }] } } });
  const { app, store } = buildApp({ config: testConfig(STRIPE), stripe });
  await store.putStripeCustomer('victim', 'cus_victim');
  const portal = await request(app).post('/api/billing/stripe/portal').set('Authorization', await bearer('newbie', { email: 'victim@example.com' })).send({ customer: 'cus_victim', customerId: 'cus_victim', email: 'victim@example.com' });
  assert.equal(portal.status, 404);
  assert.equal(portal.body.code, 'NO_STRIPE_CUSTOMER');
  assert.equal(stripe.calls.some(c => c[0] === 'portal'), false);
  const event = { id: 'evt_email', type: 'checkout.session.completed', data: { object: { mode: 'subscription', customer_email: 'victim@example.com', customer_details: { email: 'victim@example.com' }, client_reference_id: 'attacker', metadata: { uid: 'attacker' }, customer: 'cus_new', subscription: 'sub_new' } } };
  const payload = JSON.stringify(event);
  const header = webhooks.generateTestHeaderString({ payload, secret: STRIPE.STRIPE_WEBHOOK_SECRET });
  const hook = await request(app).post('/api/billing/stripe/webhook').set('Stripe-Signature', header).set('Content-Type', 'application/json').send(payload);
  assert.equal(hook.status, 200);
  assert.equal(await store.getStripeCustomer('victim'), 'cus_victim');
  assert.equal(await store.getStripeCustomer('attacker'), 'cus_new');
  assert.equal((await store.getEntitlements('attacker')).length, 1);
  assert.equal((await store.getEntitlements('victim')).length, 0);
});
