import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { SignJWT } from 'jose';
import { buildApp, fakePlaid, testConfig, JWT_SECRET } from './helpers.js';
import { MemoryStore } from '../src/store.js';
import { accountFingerprints, KIND } from '../src/freeTier.js';

const token = (sub, claims = { email_verified: true }) => new SignJWT(claims).setProtectedHeader({ alg: 'HS256' }).setSubject(sub).setIssuedAt().setExpirationTime('5m').sign(new TextEncoder().encode(JWT_SECRET));
const future = () => new Date(Date.now() + 30 * 86400e3).toISOString();

// Each public token maps to a bank: public-<inst>-<mask>[-<persistentId>]
function plaidFor() {
  return fakePlaid({
    linkTokenCreate: async () => ({ link_token: 'link-x' }),
    itemPublicTokenExchange: async ({ public_token }) => ({ item_id: `item-${public_token}`, access_token: `access|${public_token}` }),
    accountsGet: async ({ access_token }) => {
      const [, inst, mask, pid] = access_token.split('|')[1].split('-');
      return { item: { institution_id: inst }, accounts: [{ account_id: 'acc', mask, ...(pid ? { persistent_account_id: pid } : {}) }] };
    },
    itemRemove: async () => ({}),
  });
}
const client = app => async (user, device, claims) => {
  const auth = `Bearer ${await token(user, claims)}`;
  const with_ = r => { r.set('Authorization', auth); if (device) r.set('X-Device-Id', device); return r; };
  return {
    link: () => with_(request(app).post('/api/plaid/create-link-token')).send({}),
    exchange: pt => with_(request(app).post('/api/plaid/exchange-public-token')).send({ public_token: pt }),
    del: itemId => with_(request(app).delete(`/api/plaid/items/${itemId}`)).send(),
  };
};

test('email_verified is required for new links and exchange (403)', async () => {
  const { app } = buildApp({ plaid: plaidFor() });
  const c = await client(app)('u1', 'device-aaaa1111', {});
  let r = await c.link(); assert.equal(r.status, 403); assert.equal(r.body.error, 'email_not_verified');
  r = await c.exchange('public-ins1-1111'); assert.equal(r.status, 403);
  const c2 = await client(app)('u1', 'device-aaaa1111', { email_verified: false });
  assert.equal((await c2.link()).status, 403);
});

test('free link without X-Device-Id -> 400 device_id_required; subscriber does not need it', async () => {
  const { app, store } = buildApp({ plaid: plaidFor() });
  const r = await (await client(app)('u1', null)).link();
  assert.equal(r.status, 400); assert.equal(r.body.error, 'device_id_required');
  await store.putEntitlement({ tokenHash: 'h', userId: 'u2', productId: 'p', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
  assert.equal((await (await client(app)('u2', null)).link()).status, 200);
});

test('X-Play-Integrity-Token is accepted and ignored', async () => {
  const { app } = buildApp({ plaid: plaidFor() });
  const r = await request(app).post('/api/plaid/create-link-token').set('Authorization', `Bearer ${await token('u1')}`)
    .set('X-Device-Id', 'device-aaaa1111').set('X-Play-Integrity-Token', 'whatever').send({});
  assert.equal(r.status, 200);
});

test('same bank account on a second email -> item removed at Plaid, not stored, 402 account_already_used_free', async () => {
  const plaid = plaidFor();
  const { app, store } = buildApp({ plaid });
  const mk = client(app);
  assert.equal((await (await mk('u1', 'device-aaaa1111')).exchange('public-ins1-1234')).status, 200);
  const r = await (await mk('u2', 'device-bbbb2222')).exchange('public-ins1-1234--other');
  assert.equal(r.status, 402);
  assert.equal(r.body.error, 'subscription_required');
  assert.equal(r.body.reason, 'account_already_used_free');
  assert.deepEqual(plaid.calls.filter(c => c.method === 'itemRemove').map(c => c.req.access_token), ['access|public-ins1-1234--other']);
  assert.equal((await store.getItems('u2')).length, 0);
  // A different account at a different bank is fine for u2.
  assert.equal((await (await mk('u2', 'device-bbbb2222')).exchange('public-ins2-9999')).status, 200);
});

test('persistent_account_id matches even when institution/mask differ', async () => {
  const { app, store } = buildApp({ plaid: plaidFor() });
  const mk = client(app);
  assert.equal((await (await mk('u1', 'device-aaaa1111')).exchange('public-ins1-1234-PID42')).status, 200);
  const r = await (await mk('u2', 'device-bbbb2222')).exchange('public-ins9-0000-PID42');
  assert.equal(r.body.reason, 'account_already_used_free');
  assert.equal((await store.getItems('u2')).length, 0);
});

test('one free bank per device across users -> 402 device_already_used_free (link and exchange)', async () => {
  const { app } = buildApp({ plaid: plaidFor() });
  const mk = client(app);
  assert.equal((await (await mk('u1', 'device-shared01')).exchange('public-ins1-1111')).status, 200);
  const c2 = await mk('u2', 'device-shared01');
  let r = await c2.link(); assert.equal(r.status, 402); assert.equal(r.body.reason, 'device_already_used_free');
  r = await c2.exchange('public-ins2-2222'); assert.equal(r.status, 402); assert.equal(r.body.reason, 'device_already_used_free');
  // Same user on same device is not blocked by the device check (only by the 1-bank limit, without reason).
  r = await (await mk('u1', 'device-shared01')).link(); assert.equal(r.status, 402); assert.equal(r.body.reason, undefined);
});

test('subscribers skip fingerprint and device checks', async () => {
  const plaid = plaidFor();
  const { app, store } = buildApp({ plaid });
  const mk = client(app);
  await (await mk('u1', 'device-shared01')).exchange('public-ins1-1234');
  await store.putEntitlement({ tokenHash: 'h2', userId: 'u2', productId: 'p', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
  const c2 = await mk('u2', 'device-shared01');
  assert.equal((await c2.link()).status, 200);
  assert.equal((await c2.exchange('public-ins1-1234--sub')).status, 200);
  assert.equal(plaid.calls.filter(c => c.method === 'accountsGet').length, 1, 'no accountsGet for subscriber');
});

test('grandfathered users keep their banks and existing banks are untouched', async () => {
  const { app, store } = buildApp({ plaid: plaidFor() });
  await store.putItem({ userId: 'g', itemId: 'i1', accessToken: 'a' });
  await store.putItem({ userId: 'g', itemId: 'i2', accessToken: 'b' });
  const r = await (await client(app)('g', 'device-gggg0000')).link();
  assert.equal(r.status, 402); assert.equal(r.body.linked, 2);
  assert.equal((await store.getItems('g')).length, 2);
});

test('free_tier_not_configured: 503 for free users, subscribers still link', async () => {
  const config = testConfig({ FREE_TIER_FINGERPRINT_SECRET: '' });
  const { app, store } = buildApp({ config, plaid: plaidFor() });
  const r = await (await client(app)('u1', 'device-aaaa1111')).link();
  assert.equal(r.status, 503); assert.equal(r.body.error, 'free_tier_not_configured');
  await store.putEntitlement({ tokenHash: 'h', userId: 'u2', productId: 'p', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
  assert.equal((await (await client(app)('u2', null)).link()).status, 200);
});

test('only HMAC hashes are stored (no raw device id, mask or persistent id)', async () => {
  const { app, store } = buildApp({ plaid: plaidFor() });
  await (await client(app)('u1', 'device-RAWVALUE')).exchange('public-ins1-4321-PIDRAW');
  const dump = JSON.stringify([...store.claims.values()].map(({ itemId, ...c }) => c));
  for (const raw of ['RAWVALUE', '4321', 'PIDRAW', 'ins1']) assert.ok(!dump.includes(raw), `${raw} not stored`);
  assert.deepEqual([...store.claims.values()].map(c => c.kind).sort(), [KIND.ACCOUNT, KIND.DEVICE, KIND.PERSISTENT_ACCOUNT].sort());
  assert.ok([...store.claims.values()].every(c => /^[0-9a-f]{64}$/.test(c.hash)));
});

test('deleted bank keeps hashes for the cooldown, then purge frees them', async () => {
  const { app, store } = buildApp({ plaid: plaidFor() });
  const mk = client(app);
  assert.equal((await (await mk('u1', 'device-aaaa1111')).exchange('public-ins1-1234')).status, 200);
  assert.equal((await (await mk('u1', 'device-aaaa1111')).del('item-public-ins1-1234')).status, 200);
  assert.equal((await store.getItems('u1')).length, 0);
  assert.equal((await (await mk('u2', 'device-bbbb2222')).exchange('public-ins1-1234--b')).body.reason, 'account_already_used_free', 'still blocked in cooldown');
  assert.equal(await store.purgeFreeTier(30), 0, 'nothing purged before 30 days');
  assert.equal(await store.purgeFreeTier(30, Date.now() + 31 * 86400e3), 2);
  assert.equal((await (await mk('u2', 'device-bbbb2222')).exchange('public-ins1-1234--c')).status, 200);
});

test('account deletion releases hashes into cooldown', async () => {
  const store = new MemoryStore();
  await store.claimFreeTier('u1', 'i1', [{ kind: 'device', hash: 'x' }]);
  await store.deleteUserData('u1');
  assert.ok([...store.claims.values()][0].releasedAt);
  assert.equal(await store.purgeFreeTier(30, Date.now() + 31 * 86400e3), 1);
});

test('accountFingerprints: separate hashes for mask and persistent id; keyed by secret', () => {
  const a = accountFingerprints('s1'.repeat(16), 'ins_1', [{ mask: '1234', persistent_account_id: 'P' }, { mask: null }]);
  assert.equal(a.length, 2);
  const b = accountFingerprints('s2'.repeat(16), 'ins_1', [{ mask: '1234' }]);
  assert.notEqual(a[0].hash, b[0].hash);
});
