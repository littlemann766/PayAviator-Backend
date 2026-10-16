import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { SignJWT } from 'jose';
import { buildApp, fakePlaid, testConfig, JWT_SECRET } from './helpers.js';

const token = sub => new SignJWT({ email_verified: true }).setProtectedHeader({ alg: 'HS256' }).setSubject(sub).setIssuedAt().setExpirationTime('5m').sign(new TextEncoder().encode(JWT_SECRET));
const plaid = () => fakePlaid({
  linkTokenCreate: async () => ({ link_token: 'link-x' }),
  itemPublicTokenExchange: async ({ public_token }) => ({ item_id: `item-${public_token}`, access_token: `access-${public_token}` }),
  accountsGet: async () => ({ item: { institution_id: 'ins1' }, accounts: [{ account_id: 'a', mask: '1111' }] }),
  itemRemove: async () => ({}),
});

test('COMP_FIREBASE_UIDS parses a trimmed comma list', () => {
  const c = testConfig({ COMP_FIREBASE_UIDS: ' ownerA , ownerB,,' });
  assert.deepEqual([...c.billing.compUids], ['ownerA', 'ownerB']);
  assert.equal(testConfig().billing.compUids.size, 0);
});

test('comp user: plan comp, unlimited banks, no device id / integrity, no free-tier claims', async () => {
  const p = plaid();
  const { app, store } = buildApp({ plaid: p, config: testConfig({ COMP_FIREBASE_UIDS: 'owner1', PLAY_INTEGRITY_ENFORCE: 'true' }) });
  const auth = `Bearer ${await token('owner1')}`;
  for (const pt of ['public-a', 'public-b', 'public-c']) {
    assert.equal((await request(app).post('/api/plaid/create-link-token').set('Authorization', auth).send({})).status, 200);
    const r = await request(app).post('/api/plaid/exchange-public-token').set('Authorization', auth).send({ public_token: pt });
    assert.equal(r.status, 200, JSON.stringify(r.body));
  }
  assert.equal(p.calls.filter(c => c.method === 'accountsGet').length, 0, 'no fingerprinting for comp');
  assert.equal(store.claims.size, 0, 'no free-tier claims recorded');
  const s = await request(app).get('/api/billing/status').set('Authorization', auth);
  assert.equal(s.status, 200);
  assert.equal(s.body.plan, 'comp'); assert.equal(s.body.limit, null); assert.equal(s.body.linkedBanks, 3);
  assert.equal(s.body.grandfathered, false); assert.equal(s.body.expiresAt, null);
});

test('non-comp user is unaffected by COMP_FIREBASE_UIDS', async () => {
  const { app } = buildApp({ plaid: plaid(), config: testConfig({ COMP_FIREBASE_UIDS: 'owner1' }) });
  const s = await request(app).get('/api/billing/status').set('Authorization', `Bearer ${await token('u2')}`);
  assert.equal(s.body.plan, 'free'); assert.equal(s.body.limit, 1);
  assert.equal((await request(app).post('/api/plaid/create-link-token').set('Authorization', `Bearer ${await token('u2')}`).send({})).status, 400);
});

test('FOUNDER_FIREBASE_UIDS parses a trimmed list and implies comp', () => {
  const c = testConfig({ COMP_FIREBASE_UIDS: 'e1', FOUNDER_FIREBASE_UIDS: ' f1 ,,' });
  assert.deepEqual([...c.billing.founderUids], ['f1']);
  assert.deepEqual([...c.billing.compUids].sort(), ['e1', 'f1']);
  assert.equal(testConfig().billing.founderUids.size, 0);
});

test('tier field: founder, elite, free, founder-only-in-founder-list', async () => {
  const { app } = buildApp({ plaid: plaid(), config: testConfig({ COMP_FIREBASE_UIDS: 'elite1,both1', FOUNDER_FIREBASE_UIDS: 'both1,founderOnly1' }) });
  const get = async u => (await request(app).get('/api/billing/status').set('Authorization', `Bearer ${await token(u)}`)).body;
  for (const [u, tier] of [['both1', 'founder'], ['founderOnly1', 'founder'], ['elite1', 'elite'], ['rando', 'free']]) {
    const b = await get(u);
    assert.equal(b.tier, tier, u);
    if (tier !== 'free') { assert.equal(b.plan, 'comp'); assert.equal(b.source, 'comp'); assert.equal(b.limit, null); }
    else { assert.equal(b.plan, 'free'); assert.equal(b.source, null); }
  }
});

test('tier plus for a paying (non-comp) user', async () => {
  const { billingSummary } = await import('../src/billing.js');
  const exp = new Date(Date.now() + 86400000).toISOString();
  const store = { getItems: async () => [], getEntitlements: async () => [{ platform: 'stripe', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: exp, productId: 'p' }] };
  const s = await billingSummary(store, 'payer1', Date.now(), { compUids: new Set(['x']), founderUids: new Set(['y']) });
  assert.equal(s.tier, 'plus'); assert.equal(s.plan, 'premium');
});
