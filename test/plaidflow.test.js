import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { SignJWT } from 'jose';
import { buildApp, fakePlaid, JWT_SECRET } from './helpers.js';
import { createSyncer } from '../src/sync.js';
import { MemoryStore } from '../src/store.js';
import { withRetry } from '../src/retry.js';
import { silentLog } from '../src/log.js';

const bearer = async (sub = 'user-1') => `Bearer ${await new SignJWT({}).setProtectedHeader({ alg: 'HS256' }).setSubject(sub).setIssuedAt().setExpirationTime('5m').sign(new TextEncoder().encode(JWT_SECRET))}`;
const plaidErr = (status, error_code, error_type = 'API_ERROR') => Object.assign(new Error(error_code), { response: { status, data: { error_code, error_type, request_id: 'req-1', error_message: 'internal detail' } } });

test('link token uses webhook, redirect_uri, days_requested and user from token', async () => {
  const plaid = fakePlaid({ linkTokenCreate: async () => ({ link_token: 'link-1', hosted_link_url: 'https://hosted' }) });
  const { app } = buildApp({ plaid });
  const r = await request(app).post('/api/plaid/create-link-token').set('Authorization', await bearer()).send({});
  assert.equal(r.status, 200);
  const req = plaid.calls[0].req;
  assert.equal(req.user.client_user_id, 'user-1');
  assert.equal(req.webhook, 'https://example.com/api/plaid/webhook');
  assert.equal(req.redirect_uri, 'https://example.com/plaid/oauth-redirect');
  assert.equal(req.transactions.days_requested, 730);
});

test('update-link-token sends access_token and no products', async () => {
  const plaid = fakePlaid({ linkTokenCreate: async () => ({ link_token: 'link-u' }) });
  const { app, store } = buildApp({ plaid });
  await store.putItem({ userId: 'user-1', itemId: 'item-1', accessToken: 'access-sandbox-1' });
  const r = await request(app).post('/api/plaid/update-link-token').set('Authorization', await bearer()).send({ item_id: 'item-1' });
  assert.equal(r.status, 200);
  assert.equal(plaid.calls[0].req.access_token, 'access-sandbox-1');
  assert.equal(plaid.calls[0].req.products, undefined);
  assert.equal((await store.getPending('user-1')).mode, 'update');
});

test('hosted-status exchanges each public token once across all sessions', async () => {
  let n = 0;
  const plaid = fakePlaid({
    linkTokenGet: async () => ({ link_sessions: [
      { finished_at: 'x', results: { item_add_results: [{ public_token: 'public-a', institution: { name: 'Bank A' } }] } },
      { finished_at: 'y', on_success: { public_token: 'public-b', metadata: { institution: { name: 'Bank B' } } } },
    ] }),
    itemPublicTokenExchange: async ({ public_token }) => { n++; if (public_token === 'public-b' && n === 2) throw plaidErr(500, 'INTERNAL_SERVER_ERROR'); return { item_id: `item-${public_token}`, access_token: `access-${public_token}` }; },
  });
  const { app, store } = buildApp({ plaid });
  await store.putPending('user-1', 'link-1');
  const first = await request(app).get('/api/plaid/hosted-status').set('Authorization', await bearer());
  assert.equal(first.status, 502);
  assert.ok(!JSON.stringify(first.body).includes('internal detail'), 'raw Plaid error_message not exposed');
  assert.ok(await store.getPending('user-1'), 'pending kept for retry');
  const second = await request(app).get('/api/plaid/hosted-status').set('Authorization', await bearer());
  assert.equal(second.body.status, 'success');
  assert.equal(second.body.count, 2);
  assert.equal(n, 3, 'public-a not exchanged twice');
  assert.equal((await store.getItems('user-1')).length, 2);
});

test('DELETE keeps the item if /item/remove fails, deletes it and its transactions on success', async () => {
  let fail = true;
  const plaid = fakePlaid({ itemRemove: async () => { if (fail) throw plaidErr(500, 'INTERNAL_SERVER_ERROR'); return {}; } });
  const { app, store } = buildApp({ plaid });
  await store.putItem({ userId: 'user-1', itemId: 'item-1', accessToken: 'access-sandbox-1' });
  await store.applySync('user-1', { itemId: 'item-1' }, { upserts: [{ transaction_id: 't1', date: '2026-01-01' }], removedIds: [], cursor: 'c1' });
  const r1 = await request(app).delete('/api/plaid/items/item-1').set('Authorization', await bearer());
  assert.equal(r1.status, 502);
  assert.equal((await store.getItems('user-1')).length, 1);
  fail = false;
  const r2 = await request(app).delete('/api/plaid/items/item-1').set('Authorization', await bearer());
  assert.equal(r2.status, 200);
  assert.equal((await store.getItems('user-1')).length, 0);
  assert.equal((await store.storedTransactions('user-1')).length, 0);
});

test('DELETE one item also deletes its public-token hash rows and pending update link, leaving other banks intact', async () => {
  const plaid = fakePlaid({ itemRemove: async () => ({}) });
  const { app, store } = buildApp({ plaid });
  await store.putItem({ userId: 'user-1', itemId: 'item-1', accessToken: 'access-sandbox-1' });
  await store.putItem({ userId: 'user-1', itemId: 'item-2', accessToken: 'access-sandbox-2' });
  await store.applySync('user-1', { itemId: 'item-2' }, { upserts: [{ transaction_id: 't2', date: '2026-01-01' }], removedIds: [], cursor: 'c2' });
  await store.markExchanged('h-1a', 'user-1', 'item-1');
  await store.markExchanged('h-1b', 'user-1', 'item-1');
  await store.markExchanged('h-2', 'user-1', 'item-2');
  await store.putPending('user-1', 'link-upd', { mode: 'update', itemId: 'item-1' });

  const r = await request(app).delete('/api/plaid/items/item-1').set('Authorization', await bearer());
  assert.equal(r.status, 200);
  assert.equal(await store.getExchanged('h-1a'), null);
  assert.equal(await store.getExchanged('h-1b'), null);
  assert.ok(await store.getExchanged('h-2'), 'other bank keeps its hash row');
  assert.equal(await store.getPending('user-1'), null);
  assert.deepEqual((await store.getItems('user-1')).map(i => i.itemId), ['item-2']);
  assert.deepEqual((await store.storedTransactions('user-1')).map(t => t.transaction_id), ['t2']);

  // A pending link for a different item (or a new connection) is not touched.
  await store.putItem({ userId: 'user-1', itemId: 'item-3', accessToken: 'access-sandbox-3' });
  await store.putPending('user-1', 'link-add', { mode: 'add' });
  await request(app).delete('/api/plaid/items/item-3').set('Authorization', await bearer());
  assert.deepEqual(await store.getPending('user-1'), { linkToken: 'link-add', mode: 'add', itemId: null });
});

test('sync restarts from saved cursor on TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION', async () => {
  const store = new MemoryStore();
  await store.putItem({ userId: 'u', itemId: 'i', accessToken: 'access-x' });
  const cursors = [];
  let call = 0;
  const plaid = fakePlaid({ transactionsSync: async req => {
    cursors.push(req.cursor ?? null); call++;
    if (call === 1) return { added: [{ transaction_id: 'stale' }], modified: [], removed: [], next_cursor: 'p1', has_more: true };
    if (call === 2) throw plaidErr(400, 'TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION', 'TRANSACTIONS_ERROR');
    if (call === 3) return { added: [{ transaction_id: 't1', date: '2026-01-02' }], modified: [], removed: [], next_cursor: 'p2', has_more: true };
    return { added: [{ transaction_id: 't2', date: '2026-01-03' }], modified: [], removed: [], next_cursor: 'final', has_more: false };
  } });
  const syncItem = createSyncer({ store, plaid, log: silentLog });
  const [item] = await store.getItems('u');
  await syncItem(item);
  assert.deepEqual(cursors, [null, 'p1', null, 'p2']);
  assert.deepEqual((await store.storedTransactions('u')).map(t => t.transaction_id).sort(), ['t1', 't2']);
  assert.equal((await store.getItems('u'))[0].transactionsCursor, 'final');
});

test('sync marks item login_required on ITEM_LOGIN_REQUIRED', async () => {
  const store = new MemoryStore();
  await store.putItem({ userId: 'u', itemId: 'i', accessToken: 'access-x' });
  const plaid = fakePlaid({ transactionsSync: async () => { throw plaidErr(400, 'ITEM_LOGIN_REQUIRED', 'ITEM_ERROR'); } });
  const [item] = await store.getItems('u');
  await assert.rejects(createSyncer({ store, plaid, log: silentLog })(item));
  assert.equal((await store.getItemById('i')).status, 'login_required');
});

test('withRetry retries 429/5xx but not item errors', async () => {
  let n = 0;
  const out = await withRetry(async () => { if (++n < 3) throw plaidErr(429, 'RATE_LIMIT', 'RATE_LIMIT_EXCEEDED'); return 'ok'; }, { sleep: async () => {} });
  assert.equal(out, 'ok'); assert.equal(n, 3);
  let m = 0;
  await assert.rejects(withRetry(async () => { m++; throw plaidErr(400, 'ITEM_LOGIN_REQUIRED', 'ITEM_ERROR'); }, { sleep: async () => {} }));
  assert.equal(m, 1);
});

test('DELETE /api/plaid/user removes items at Plaid and deletes all user rows; keeps failed items', async () => {
  const plaid = fakePlaid({ itemRemove: async ({ access_token }) => { if (access_token === 'access-sandbox-bad') throw plaidErr(500, 'INTERNAL_SERVER_ERROR'); return {}; } });
  const { app, store } = buildApp({ plaid });
  await store.putItem({ userId: 'user-1', itemId: 'ok-1', accessToken: 'access-sandbox-ok' });
  await store.putItem({ userId: 'user-1', itemId: 'bad-1', accessToken: 'access-sandbox-bad' });
  await store.putItem({ userId: 'user-2', itemId: 'other', accessToken: 'access-sandbox-other' });
  await store.applySync('user-1', { itemId: 'ok-1' }, { upserts: [{ transaction_id: 't-ok', date: '2026-01-01' }], removedIds: [], cursor: 'c' });
  await store.applySync('user-1', { itemId: 'bad-1' }, { upserts: [{ transaction_id: 't-bad', date: '2026-01-01' }], removedIds: [], cursor: 'c' });
  await store.markExchanged('h-ok', 'user-1', 'ok-1');
  await store.markExchanged('h-bad', 'user-1', 'bad-1');
  await store.putPending('user-1', 'link-x');

  const r1 = await request(app).delete('/api/plaid/user').set('Authorization', await bearer());
  assert.equal(r1.status, 502);
  assert.deepEqual(r1.body.failed_item_ids, ['bad-1']);
  assert.deepEqual((await store.getItems('user-1')).map(i => i.itemId), ['bad-1']);
  assert.deepEqual((await store.storedTransactions('user-1')).map(t => t.transaction_id), ['t-bad']);
  assert.equal(await store.getExchanged('h-ok'), null);
  assert.ok(await store.getExchanged('h-bad'));
  assert.equal(await store.getPending('user-1'), null);

  plaid.calls.length = 0;
  const handlers = { itemRemove: async () => ({}) };
  const plaid2 = fakePlaid(handlers);
  const { app: app2 } = buildApp({ plaid: plaid2, store });
  const r2 = await request(app2).delete('/api/plaid/user').set('Authorization', await bearer());
  assert.equal(r2.status, 200);
  assert.equal((await store.getItems('user-1')).length, 0);
  assert.equal((await store.storedTransactions('user-1')).length, 0);
  assert.equal(await store.getExchanged('h-bad'), null);
  assert.equal((await store.getItems('user-2')).length, 1, 'other users untouched');
});
