import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { SignJWT } from 'jose';
import { buildApp, fakePlaid, testConfig, JWT_SECRET } from './helpers.js';
import { handleWebhook } from '../src/webhooks.js';
import { applyPause } from '../src/billing.js';
import { silentLog } from '../src/log.js';

const bearer = async sub => `Bearer ${await new SignJWT({ email_verified: true }).setProtectedHeader({ alg: 'HS256' }).setSubject(sub).setIssuedAt().setExpirationTime('5m').sign(new TextEncoder().encode(JWT_SECRET))}`;
const future = (d = 30) => new Date(Date.now() + d * 86400e3).toISOString();
const plaidSpy = () => fakePlaid({
  accountsGet: async ({ access_token }) => ({ accounts: [{ account_id: `acc-${access_token}`, mask: access_token.slice(-4), type: 'depository', balances: { current: 1 } }] }),
  itemGet: async () => ({ item: {} }), itemRemove: async () => ({}),
  linkTokenCreate: async () => ({ link_token: 'l' }),
});
async function seed(store, uid = 'u') {
  for (const n of ['1111', '2222', '3333']) { await store.putItem({ userId: uid, itemId: `item-${n}`, accessToken: `tok-${n}`, institutionName: `Bank${n}` }); await new Promise(r => setTimeout(r, 2)); }
}
const ent = (userId, extra = {}) => ({ tokenHash: `h-${userId}-${Math.random()}`, userId, productId: 'p', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future(), ...extra });

test('free user: oldest item active, others paused: summary flags, status counts', async () => {
  const p = plaidSpy(); const { app, store } = buildApp({ plaid: p }); await seed(store);
  const auth = await bearer('u');
  const r = await request(app).get('/api/plaid/accounts').set('Authorization', auth);
  assert.equal(r.status, 200);
  const by = Object.fromEntries(r.body.items.map(i => [i.item_id, i]));
  assert.equal(by['item-1111'].paused, false); assert.equal(by['item-1111'].pause_reason, null); assert.equal(by['item-1111'].status, 'good');
  for (const id of ['item-2222', 'item-3333']) { assert.equal(by[id].status, 'paused'); assert.equal(by[id].paused, true); assert.equal(by[id].pause_reason, 'plus_ended'); assert.equal(by[id].needs_update, false); }
  assert.equal(p.calls.filter(c => c.method === 'accountsGet').length, 1, 'Plaid only called for the first bank');
  assert.deepEqual(r.body.accounts.map(a => a.item_id), ['item-1111']);
  assert.deepEqual(r.body.errors.filter(e => e.code === 'ITEM_PAUSED').map(e => e.item_id).sort(), ['item-2222', 'item-3333']);
  const s = await request(app).get('/api/billing/status').set('Authorization', auth);
  assert.equal(s.body.pausedBanks, 2); assert.equal(s.body.linkedBanks, 3); assert.equal(s.body.plan, 'free');
});

test('transactions refresh and transactions-status make no Plaid calls for paused items', async () => {
  const synced = []; const p = plaidSpy();
  const { app, store } = buildApp({ plaid: p, syncItem: async item => { synced.push(item.itemId); return { item_id: item.itemId }; } }); await seed(store);
  const auth = await bearer('u');
  const t = await request(app).get('/api/plaid/transactions').set('Authorization', auth);
  assert.equal(t.status, 200); assert.deepEqual(synced, ['item-1111']);
  assert.equal(t.body.errors.filter(e => e.code === 'ITEM_PAUSED').length, 2);
  const st = await request(app).get('/api/plaid/transactions-status').set('Authorization', auth);
  assert.equal(p.calls.filter(c => c.method === 'itemGet').length, 1);
  assert.equal(st.body.items.filter(i => i.paused).length, 2);
});

test('webhook SYNC_UPDATES_AVAILABLE: skipped for paused item, runs for active item', async () => {
  const synced = []; const { app, store } = buildApp({ syncItem: async i => { synced.push(i.itemId); } }); void app; await seed(store);
  const mk = itemId => ({ webhook_type: 'TRANSACTIONS', webhook_code: 'SYNC_UPDATES_AVAILABLE', item_id: itemId });
  // build the same isPaused the app uses via a full app-level check: use the real route with a verifier that accepts
  const { app: app2, store: st2 } = buildApp({ webhookVerifier: async () => {}, syncItem: async i => { synced.push(i.itemId); } }); await seed(st2);
  for (const id of ['item-1111', 'item-2222']) {
    const r = await request(app2).post('/api/plaid/webhook').set('content-type', 'application/json').set('plaid-verification', 'x').send(JSON.stringify(mk(id)));
    assert.equal(r.status, 200);
  }
  await new Promise(r => setTimeout(r, 20));
  assert.deepEqual(synced, ['item-1111']);
  // item-level status webhooks still apply to paused items
  const r = await request(app2).post('/api/plaid/webhook').set('content-type', 'application/json').set('plaid-verification', 'x').send(JSON.stringify({ webhook_type: 'ITEM', webhook_code: 'PENDING_EXPIRATION', item_id: 'item-2222' }));
  assert.equal(r.status, 200); assert.equal((await st2.getItemById('item-2222')).status, 'pending_expiration');
  // handleWebhook without isPaused behaves as before
  const out = await handleWebhook(mk('item-2222'), { store: st2, syncItem: async i => { synced.push(`direct-${i.itemId}`); }, log: silentLog });
  await out.background; assert.ok(synced.includes('direct-item-2222'));
});

test('auto-resume: Google Play entitlement active -> nothing paused; entitlement lapses -> paused again', async () => {
  const p = plaidSpy(); const { app, store } = buildApp({ plaid: p }); await seed(store); const auth = await bearer('u');
  await store.putEntitlement(ent('u'));
  let r = await request(app).get('/api/plaid/accounts').set('Authorization', auth);
  assert.equal(r.body.items.filter(i => i.paused).length, 0);
  assert.equal(p.calls.filter(c => c.method === 'accountsGet').length, 3);
  assert.equal((await request(app).get('/api/billing/status').set('Authorization', auth)).body.pausedBanks, 0);
  await store.putEntitlement(ent('u', { tokenHash: [...store.entitlements.keys()][0], state: 'SUBSCRIPTION_STATE_EXPIRED' }));
  r = await request(app).get('/api/plaid/accounts').set('Authorization', auth);
  assert.equal(r.body.items.filter(i => i.paused).length, 2);
});

test('Stripe cancelAtPeriodEnd (CANCELED state, before periodEnd) stays entitled; after periodEnd paused', async () => {
  const { app, store } = buildApp({ plaid: plaidSpy() }); await seed(store, 's'); const auth = await bearer('s');
  await store.putEntitlement({ ...ent('s'), platform: 'stripe', state: 'SUBSCRIPTION_STATE_CANCELED' });
  let s = await request(app).get('/api/billing/status').set('Authorization', auth);
  assert.equal(s.body.cancelAtPeriodEnd, true); assert.equal(s.body.pausedBanks, 0);
  assert.equal((await request(app).get('/api/plaid/accounts').set('Authorization', auth)).body.items.filter(i => i.paused).length, 0);
  const h = [...store.entitlements.keys()][0];
  await store.putEntitlement({ ...ent('s', { expiresAt: new Date(Date.now() - 1000).toISOString() }), tokenHash: h, platform: 'stripe', state: 'SUBSCRIPTION_STATE_CANCELED' });
  s = await request(app).get('/api/billing/status').set('Authorization', auth);
  assert.equal(s.body.pausedBanks, 2);
});

test('comp user: nothing paused', async () => {
  const { app, store } = buildApp({ plaid: plaidSpy(), config: testConfig({ COMP_FIREBASE_UIDS: 'owner' }) }); await seed(store, 'owner');
  const auth = await bearer('owner');
  const r = await request(app).get('/api/plaid/accounts').set('Authorization', auth);
  assert.equal(r.body.items.filter(i => i.paused).length, 0);
  assert.equal((await request(app).get('/api/billing/status').set('Authorization', auth)).body.pausedBanks, 0);
});

test('disconnect still works for paused items; remaining oldest stays active; next-oldest never auto-unpaused beyond rule', async () => {
  const p = plaidSpy(); const { app, store } = buildApp({ plaid: p }); await seed(store); const auth = await bearer('u');
  const d = await request(app).delete('/api/plaid/items/item-2222').set('Authorization', auth);
  assert.equal(d.status, 200); assert.equal(d.body.disconnected, true);
  assert.ok(p.calls.some(c => c.method === 'itemRemove'));
  assert.deepEqual((await store.getItems('u')).map(i => i.itemId), ['item-1111', 'item-3333']);
  // disconnect the active (oldest) one: the next oldest becomes the active one
  await request(app).delete('/api/plaid/items/item-1111').set('Authorization', auth);
  const r = await request(app).get('/api/plaid/accounts').set('Authorization', auth);
  assert.equal(r.body.items.length, 1); assert.equal(r.body.items[0].paused, false);
  assert.equal((await request(app).get('/api/billing/status').set('Authorization', auth)).body.pausedBanks, 0);
});

test('update-link-token: paused item -> 402 ITEM_PAUSED; active item OK', async () => {
  const { app, store } = buildApp({ plaid: plaidSpy() }); await seed(store); const auth = await bearer('u');
  const r = await request(app).post('/api/plaid/update-link-token').set('Authorization', auth).send({ item_id: 'item-3333' });
  assert.equal(r.status, 402); assert.equal(r.body.code, 'ITEM_PAUSED'); assert.equal(r.body.pause_reason, 'plus_ended');
  assert.equal((await request(app).post('/api/plaid/update-link-token').set('Authorization', auth).send({ item_id: 'item-1111' })).status, 200);
});

test('revoked items are ignored by the pause rule; a login_required oldest item still counts as the active one', () => {
  const mk = (id, status) => ({ itemId: id, status });
  const out = applyPause([mk('a', 'revoked'), mk('b', 'login_required'), mk('c', 'good')], false);
  assert.deepEqual(out.map(i => i.status), ['revoked', 'login_required', 'paused']);
  assert.equal(out[2].pausedFrom, 'good');
  assert.deepEqual(applyPause([mk('a', 'good'), mk('b', 'good')], true).map(i => i.status), ['good', 'good']);
});

test('free user with one bank: nothing paused; summary shape for non-paused items', async () => {
  const { app, store } = buildApp({ plaid: plaidSpy() });
  await store.putItem({ userId: 'one', itemId: 'only', accessToken: 'tok-9999' });
  const r = await request(app).get('/api/plaid/accounts').set('Authorization', await bearer('one'));
  assert.equal(r.body.items[0].paused, false);
  assert.equal((await request(app).get('/api/billing/status').set('Authorization', await bearer('one'))).body.pausedBanks, 0);
});
