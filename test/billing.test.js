import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { SignJWT } from 'jose';
import { buildApp, fakePlaid, testConfig, JWT_SECRET } from './helpers.js';
import { sha256Hex } from '../src/crypto.js';
import { ITEM_STATUS } from '../src/plaid.js';

const bearer = async (sub = 'user-1') => `Bearer ${await new SignJWT({ email_verified: true }).setProtectedHeader({ alg: 'HS256' }).setSubject(sub).setIssuedAt().setExpirationTime('5m').sign(new TextEncoder().encode(JWT_SECRET))}`;
const SA = JSON.stringify({ client_email: 'play@x.iam.gserviceaccount.com', private_key: '-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n' });
const billingConfig = (extra = {}) => testConfig({ GOOGLE_PLAY_SERVICE_ACCOUNT_JSON: SA, ANDROID_PACKAGE_NAME: 'app.payaviator', GOOGLE_PLAY_PRODUCT_IDS: 'payaviator_premium', ...extra });
const future = (d = 30) => new Date(Date.now() + d * 86400e3).toISOString();
const linkPlaid = () => fakePlaid({
  linkTokenCreate: async () => ({ link_token: 'link-x' }),
  itemPublicTokenExchange: async ({ public_token }) => ({ item_id: `item-${public_token}`, access_token: `access-${public_token}` }),
  accountsGet: async ({ access_token }) => ({ item: { institution_id: 'ins_1' }, accounts: [{ account_id: 'a', mask: access_token.slice(-4) }] }),
  itemRemove: async () => ({}),
});
function fakeGoogle(sub) {
  const g = { acks: [], gets: 0,
    async getSubscription() { g.gets++; if (sub instanceof Error) throw sub; return typeof sub === 'function' ? sub() : sub; },
    async acknowledge(productId, token) { g.acks.push({ productId, token }); } };
  return g;
}
const activeSub = (over = {}) => ({ subscriptionState: 'SUBSCRIPTION_STATE_ACTIVE', acknowledgementState: 'ACKNOWLEDGEMENT_STATE_PENDING',
  lineItems: [{ productId: 'payaviator_premium', expiryTime: future() }], ...over });

test('free user: first bank allowed, second gets 402 on create-link-token and exchange', async () => {
  const plaid = linkPlaid();
  const { app, store } = buildApp({ plaid });
  const auth = await bearer();
  const post = path => request(app).post(path).set('Authorization', auth).set('X-Device-Id', 'device-test-1');
  assert.equal((await post('/api/plaid/create-link-token').send({})).status, 200);
  assert.equal((await post('/api/plaid/exchange-public-token').send({ public_token: 'p1' })).status, 200);
  const r = await post('/api/plaid/create-link-token').send({});
  assert.equal(r.status, 402);
  assert.deepEqual({ error: r.body.error, limit: r.body.limit, linked: r.body.linked }, { error: 'subscription_required', limit: 1, linked: 1 });
  const before = plaid.calls.filter(c => c.method === 'itemPublicTokenExchange').length;
  const ex = await post('/api/plaid/exchange-public-token').send({ public_token: 'p2' });
  assert.equal(ex.status, 402);
  assert.equal(plaid.calls.filter(c => c.method === 'itemPublicTokenExchange').length, before, 'no Plaid exchange over the limit');
  assert.equal((await store.getItems('user-1')).length, 1);
  // Re-sending the already-exchanged token stays idempotent (not blocked).
  assert.equal((await post('/api/plaid/exchange-public-token').send({ public_token: 'p1' })).status, 200);
});

test('update mode / relink of an existing item still works at the limit', async () => {
  const plaid = linkPlaid();
  const { app, store } = buildApp({ plaid });
  await store.putItem({ userId: 'user-1', itemId: 'item-1', accessToken: 'a1' });
  await store.setItemStatus('item-1', ITEM_STATUS.LOGIN_REQUIRED, 'ITEM_LOGIN_REQUIRED');
  const r = await request(app).post('/api/plaid/update-link-token').set('Authorization', await bearer()).send({ item_id: 'item-1' });
  assert.equal(r.status, 200);
});

test('revoked items do not count toward the limit', async () => {
  const { app, store } = buildApp({ plaid: linkPlaid() });
  await store.putItem({ userId: 'user-1', itemId: 'item-1', accessToken: 'a1' });
  await store.revokeItem('item-1');
  assert.equal((await request(app).post('/api/plaid/create-link-token').set('Authorization', await bearer()).set('X-Device-Id', 'device-test-1').send({})).status, 200);
});

test('grandfathered user with 2 banks keeps them, can relink, cannot add a third', async () => {
  const { app, store } = buildApp({ plaid: linkPlaid() });
  await store.putItem({ userId: 'user-1', itemId: 'item-1', accessToken: 'a1' });
  await store.putItem({ userId: 'user-1', itemId: 'item-2', accessToken: 'a2' });
  const auth = await bearer();
  const s = await request(app).get('/api/billing/status').set('Authorization', auth);
  assert.equal(s.status, 200);
  assert.equal(s.body.linkedBanks, 2);
  assert.equal(s.body.grandfathered, true);
  assert.equal((await request(app).post('/api/plaid/update-link-token').set('Authorization', auth).send({ item_id: 'item-2' })).status, 200);
  const r = await request(app).post('/api/plaid/create-link-token').set('Authorization', auth).send({});
  assert.equal(r.status, 402);
  assert.equal(r.body.linked, 2);
  assert.equal((await store.getItems('user-1')).length, 2, 'nothing removed');
});

test('billing not configured: 503 on verify/rtdn, limit still enforced, status works', async () => {
  const { app, store } = buildApp({ plaid: linkPlaid() });
  const auth = await bearer();
  const v = await request(app).post('/api/billing/google-play/verify').set('Authorization', auth).send({ productId: 'payaviator_premium', purchaseToken: 't' });
  assert.equal(v.status, 503);
  assert.equal(v.body.error, 'billing_not_configured');
  assert.equal((await request(app).post('/api/billing/google-play/rtdn').send({})).status, 503);
  await store.putItem({ userId: 'user-1', itemId: 'item-1', accessToken: 'a1' });
  assert.equal((await request(app).post('/api/plaid/create-link-token').set('Authorization', auth).send({})).status, 402);
  const s = await request(app).get('/api/billing/status').set('Authorization', auth);
  assert.deepEqual({ plan: s.body.plan, linkedBanks: s.body.linkedBanks, limit: s.body.limit, expiresAt: s.body.expiresAt, billingConfigured: s.body.billingConfigured },
    { plan: 'free', linkedBanks: 1, limit: 1, expiresAt: null, billingConfigured: false });
});

test('billing endpoints require sign-in', async () => {
  const { app } = buildApp();
  assert.equal((await request(app).get('/api/billing/status')).status, 401);
  assert.equal((await request(app).post('/api/billing/google-play/verify').send({})).status, 401);
});

test('verify: active purchase stores hashed entitlement, acknowledges, unlocks second bank', async () => {
  const google = fakeGoogle(activeSub());
  const { app, store } = buildApp({ config: billingConfig(), plaid: linkPlaid(), googlePlay: google });
  await store.putItem({ userId: 'user-1', itemId: 'item-1', accessToken: 'a1' });
  const auth = await bearer();
  const v = await request(app).post('/api/billing/google-play/verify').set('Authorization', auth).send({ productId: 'payaviator_premium', purchaseToken: 'tok-1' });
  assert.equal(v.status, 200);
  assert.equal(v.body.plan, 'premium');
  assert.equal(v.body.limit, null);
  assert.ok(v.body.expiresAt);
  assert.deepEqual(google.acks, [{ productId: 'payaviator_premium', token: 'tok-1' }]);
  const ent = await store.getEntitlementByTokenHash(sha256Hex('tok-1'));
  assert.equal(ent.userId, 'user-1');
  assert.ok(!JSON.stringify(await store.getEntitlements('user-1')).includes('tok-1'), 'raw token not stored');
  assert.equal((await request(app).post('/api/plaid/create-link-token').set('Authorization', auth).send({})).status, 200);
  assert.equal((await request(app).post('/api/plaid/exchange-public-token').set('Authorization', auth).send({ public_token: 'p2' })).status, 200);
});

test('verify: already-acknowledged purchase is not re-acknowledged', async () => {
  const google = fakeGoogle(activeSub({ acknowledgementState: 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED' }));
  const { app } = buildApp({ config: billingConfig(), googlePlay: google });
  const v = await request(app).post('/api/billing/google-play/verify').set('Authorization', await bearer()).send({ productId: 'payaviator_premium', purchaseToken: 'tok' });
  assert.equal(v.status, 200);
  assert.equal(google.acks.length, 0);
});

test('verify: expired, wrong product, unknown product, invalid token, token reuse by another user', async () => {
  const auth = await bearer();
  let g = fakeGoogle(activeSub({ subscriptionState: 'SUBSCRIPTION_STATE_EXPIRED', lineItems: [{ productId: 'payaviator_premium', expiryTime: future(-1) }] }));
  let { app } = buildApp({ config: billingConfig(), googlePlay: g });
  let r = await request(app).post('/api/billing/google-play/verify').set('Authorization', auth).send({ productId: 'payaviator_premium', purchaseToken: 't' });
  assert.equal(r.status, 402); assert.equal(r.body.error, 'subscription_inactive'); assert.equal(r.body.plan, 'free'); assert.equal(g.acks.length, 0);

  ({ app } = buildApp({ config: billingConfig(), googlePlay: fakeGoogle(activeSub({ lineItems: [{ productId: 'other', expiryTime: future() }] })) }));
  r = await request(app).post('/api/billing/google-play/verify').set('Authorization', auth).send({ productId: 'payaviator_premium', purchaseToken: 't' });
  assert.equal(r.body.error, 'product_mismatch');

  r = await request(app).post('/api/billing/google-play/verify').set('Authorization', auth).send({ productId: 'nope', purchaseToken: 't' });
  assert.equal(r.body.error, 'unknown_product');
  r = await request(app).post('/api/billing/google-play/verify').set('Authorization', auth).send({ productId: 'payaviator_premium' });
  assert.equal(r.status, 400); assert.equal(r.body.error, 'missing_purchase');

  ({ app } = buildApp({ config: billingConfig(), googlePlay: fakeGoogle(Object.assign(new Error('bad'), { response: { status: 400 } })) }));
  r = await request(app).post('/api/billing/google-play/verify').set('Authorization', auth).send({ productId: 'payaviator_premium', purchaseToken: 't' });
  assert.equal(r.status, 400); assert.equal(r.body.error, 'invalid_purchase');

  ({ app } = buildApp({ config: billingConfig(), googlePlay: fakeGoogle(Object.assign(new Error('down'), { response: { status: 503 } })) }));
  r = await request(app).post('/api/billing/google-play/verify').set('Authorization', auth).send({ productId: 'payaviator_premium', purchaseToken: 't' });
  assert.equal(r.status, 502); assert.equal(r.body.error, 'verify_failed');

  const shared = buildApp({ config: billingConfig(), googlePlay: fakeGoogle(activeSub()) });
  assert.equal((await request(shared.app).post('/api/billing/google-play/verify').set('Authorization', auth).send({ productId: 'payaviator_premium', purchaseToken: 'same' })).status, 200);
  r = await request(shared.app).post('/api/billing/google-play/verify').set('Authorization', await bearer('user-2')).send({ productId: 'payaviator_premium', purchaseToken: 'same' });
  assert.equal(r.status, 409); assert.equal(r.body.error, 'purchase_in_use');
});

test('canceled-but-unexpired keeps premium; status reflects expiry', async () => {
  const exp = future(5);
  const { app } = buildApp({ config: billingConfig(), googlePlay: fakeGoogle(activeSub({ subscriptionState: 'SUBSCRIPTION_STATE_CANCELED', acknowledgementState: 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED', lineItems: [{ productId: 'payaviator_premium', expiryTime: exp }] })) });
  const auth = await bearer();
  await request(app).post('/api/billing/google-play/verify').set('Authorization', auth).send({ productId: 'payaviator_premium', purchaseToken: 't' });
  const s = await request(app).get('/api/billing/status').set('Authorization', auth);
  assert.equal(s.body.plan, 'premium');
  assert.equal(s.body.expiresAt, new Date(exp).toISOString());
});

test('rtdn: rejects bad push auth, updates known entitlement on valid push', async () => {
  let state = 'SUBSCRIPTION_STATE_ACTIVE';
  const google = fakeGoogle(() => activeSub({ subscriptionState: state, acknowledgementState: 'ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED' }));
  const pubsubVerifier = async h => { if (h !== 'Bearer good') throw new Error('bad'); };
  const { app, store } = buildApp({ config: billingConfig({ GOOGLE_PLAY_RTDN_AUDIENCE: 'https://api.payaviator.app/api/billing/google-play/rtdn' }), googlePlay: google, pubsubVerifier });
  await request(app).post('/api/billing/google-play/verify').set('Authorization', await bearer()).send({ productId: 'payaviator_premium', purchaseToken: 'tok' });
  const msg = d => ({ message: { data: Buffer.from(JSON.stringify(d)).toString('base64') } });
  const n = { packageName: 'app.payaviator', subscriptionNotification: { notificationType: 13, purchaseToken: 'tok', subscriptionId: 'payaviator_premium' } };
  assert.equal((await request(app).post('/api/billing/google-play/rtdn').set('Authorization', 'Bearer bad').send(msg(n))).status, 401);
  state = 'SUBSCRIPTION_STATE_EXPIRED';
  assert.equal((await request(app).post('/api/billing/google-play/rtdn').set('Authorization', 'Bearer good').send(msg(n))).status, 204);
  assert.equal((await store.getEntitlementByTokenHash(sha256Hex('tok'))).state, 'SUBSCRIPTION_STATE_EXPIRED');
  // Unknown token / other package: acknowledged, ignored.
  assert.equal((await request(app).post('/api/billing/google-play/rtdn').set('Authorization', 'Bearer good').send(msg({ ...n, packageName: 'evil' }))).status, 204);
});

test('invalid service account JSON disables billing with a warning (no crash)', async () => {
  const cfg = testConfig({ GOOGLE_PLAY_SERVICE_ACCOUNT_JSON: '{nope', ANDROID_PACKAGE_NAME: 'app.payaviator' });
  assert.equal(cfg.billing.configured, false);
});
