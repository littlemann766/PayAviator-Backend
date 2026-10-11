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
