import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { SignJWT } from 'jose';
import { buildApp, fakePlaid, JWT_SECRET } from './helpers.js';
import { handleWebhook } from '../src/webhooks.js';
import { createSyncer } from '../src/sync.js';
import { MemoryStore } from '../src/store.js';
import { statusForItemError } from '../src/plaid.js';
import { silentLog } from '../src/log.js';

const bearer = async (sub = 'user-1') => `Bearer ${await new SignJWT({}).setProtectedHeader({ alg: 'HS256' }).setSubject(sub).setIssuedAt().setExpirationTime('5m').sign(new TextEncoder().encode(JWT_SECRET))}`;

async function seed(store) {
  await store.putItem({ userId: 'user-1', itemId: 'item-r', accessToken: 'access-sandbox-r', institutionName: 'PNC' });
  await store.putItem({ userId: 'user-1', itemId: 'item-k', accessToken: 'access-sandbox-k', institutionName: 'Keep Bank' });
  await store.applySync('user-1', { itemId: 'item-r' }, { upserts: [{ transaction_id: 't-r', date: '2026-01-02' }], removedIds: [], cursor: 'cur-r' });
  await store.applySync('user-1', { itemId: 'item-k' }, { upserts: [{ transaction_id: 't-k', date: '2026-01-01' }], removedIds: [], cursor: 'cur-k' });
  await store.setNewAccountsAvailable('item-r', true);
  await store.markExchanged('h-r', 'user-1', 'item-r');
  await store.markExchanged('h-k', 'user-1', 'item-k');
  await store.putPending('user-1', 'link-upd', { mode: 'update', itemId: 'item-r' });
}

async function assertPurged(store) {
  const r = await store.getItemById('item-r');
  assert.equal(r.status, 'revoked');
  assert.equal(r.transactionsCursor, null);
  assert.equal(r.newAccountsAvailable, false);
  assert.deepEqual((await store.storedTransactions('user-1')).map(t => t.transaction_id), ['t-k'], 'only the other bank\'s transactions remain');
  assert.equal(await store.getExchanged('h-r'), null);
  assert.ok(await store.getExchanged('h-k'));
  assert.equal(await store.getPending('user-1'), null);
  const k = await store.getItemById('item-k');
  assert.equal(k.status, 'good'); assert.equal(k.transactionsCursor, 'cur-k');
}

for (const code of ['USER_PERMISSION_REVOKED', 'USER_ACCOUNT_REVOKED']) {
  test(`ITEM ${code} webhook purges that item's transactions, cursor, pending link and token hashes`, async () => {
    const store = new MemoryStore();
    await seed(store);
    const plaid = fakePlaid(); // any Plaid call (e.g. /item/remove) would throw
    const out = await handleWebhook({ webhook_type: 'ITEM', webhook_code: code, item_id: 'item-r', error: code === 'USER_PERMISSION_REVOKED' ? { error_code: code } : undefined },
      { store, syncItem: async () => assert.fail('no sync'), log: silentLog, plaid });
    assert.deepEqual(out, {});
    await assertPurged(store);
    assert.equal((await store.getItemById('item-r')).errorCode, code);
    assert.equal(plaid.calls.length, 0, '/item/remove is not called on user revocation');
  });
}

test('ITEM ERROR with a revoked code or OAUTH_USER_REVOKED reason is treated as revoked and purged', async () => {
  assert.equal(statusForItemError('USER_PERMISSION_REVOKED'), 'revoked');
  assert.equal(statusForItemError('ITEM_LOGIN_REQUIRED', 'OAUTH_USER_REVOKED'), 'revoked');
  assert.equal(statusForItemError('ITEM_LOGIN_REQUIRED', 'OAUTH_INVALID_TOKEN'), 'login_required');
  assert.equal(statusForItemError('INSTITUTION_DOWN'), 'error');

  const store = new MemoryStore();
  await seed(store);
  await handleWebhook({ webhook_type: 'ITEM', webhook_code: 'ERROR', item_id: 'item-r',
    error: { error_code: 'ITEM_LOGIN_REQUIRED', error_code_reason: 'OAUTH_USER_REVOKED' } }, { store, syncItem: async () => {}, log: silentLog });
  await assertPurged(store);
  assert.equal((await store.getItemById('item-r')).errorCode, 'ITEM_LOGIN_REQUIRED');
});

test('a sync error reporting USER_PERMISSION_REVOKED purges the item too', async () => {
  const store = new MemoryStore();
  await seed(store);
  const err = Object.assign(new Error('revoked'), { response: { status: 400, data: { error_type: 'ITEM_ERROR', error_code: 'USER_PERMISSION_REVOKED' } } });
  const syncItem = createSyncer({ store, plaid: { call: async () => { throw err; } }, log: silentLog });
  await assert.rejects(syncItem(await store.getItemById('item-r')), /revoked/);
  await assertPurged(store);
});

test('a sync that finishes after revocation is discarded, not written back', async () => {
  const store = new MemoryStore();
  await seed(store);
  let release;
  const gate = new Promise(r => { release = r; });
  const plaid = { call: async () => { await gate; return { added: [{ transaction_id: 't-late', date: '2026-02-01' }], modified: [], removed: [], next_cursor: 'cur-late', has_more: false }; } };
  const syncItem = createSyncer({ store, plaid, log: silentLog });
  const running = syncItem(await store.getItemById('item-r'));
  await store.revokeItem('item-r', 'USER_PERMISSION_REVOKED');
  release();
  const out = await running;
  assert.equal(out.discarded, true);
  assert.equal((await store.getItemById('item-r')).transactionsCursor, null);
  assert.ok(!(await store.storedTransactions('user-1')).some(t => t.transaction_id === 't-late'));
});

test('API after revocation: item listed as revoked with needs_update; reconnect restores it and re-syncs from scratch', async () => {
  const cursorsSeen = [];
  const plaid = fakePlaid({
    accountsGet: async () => ({ accounts: [{ account_id: 'a-k', mask: '1111', type: 'depository', subtype: 'checking', name: 'Chk', balances: { current: 1 } }] }),
    linkTokenCreate: async () => ({ link_token: 'link-fix', hosted_link_url: 'https://hosted/fix' }),
    itemGet: async () => ({ item: { error: null } }),
    transactionsSync: async req => { cursorsSeen.push(req.cursor ?? null); return { added: [{ transaction_id: `t-${cursorsSeen.length}`, date: '2026-03-01' }], modified: [], removed: [], next_cursor: 'fresh', has_more: false }; },
  });
  const store = new MemoryStore();
  const { app } = buildApp({ plaid, store, syncItem: createSyncer({ store, plaid, log: silentLog }) });
  await seed(store);
  await store.revokeItem('item-r', 'USER_PERMISSION_REVOKED');

  const acc = await request(app).get('/api/plaid/accounts').set('Authorization', await bearer());
  assert.equal(acc.status, 200);
  const summary = acc.body.items.find(i => i.item_id === 'item-r');
  assert.equal(summary.status, 'revoked'); assert.equal(summary.needs_update, true);
  assert.equal(summary.institution_name, 'PNC');
  assert.deepEqual(acc.body.errors, [{ item_id: 'item-r', code: 'USER_PERMISSION_REVOKED', needs_update: true }]);

  const tx = await request(app).get('/api/plaid/transactions').set('Authorization', await bearer());
  assert.ok(!tx.body.transactions.some(t => t.item_id === 'item-r' || t.transaction_id === 't-r'));
  assert.ok(tx.body.errors.some(e => e.item_id === 'item-r' && e.needs_update));

  const up = await request(app).post('/api/plaid/update-link-token').set('Authorization', await bearer()).send({ item_id: 'item-r' });
  assert.equal(up.status, 200);
  const done = await request(app).post('/api/plaid/update-complete').set('Authorization', await bearer()).send({ item_id: 'item-r' });
  assert.equal(done.status, 200);
  assert.equal((await store.getItemById('item-r')).status, 'good');

  cursorsSeen.length = 0;
  await request(app).get('/api/plaid/transactions').set('Authorization', await bearer());
  // item-k continues from its cursor; the restored item-r starts over (null cursor).
  assert.ok(cursorsSeen.includes(null));
});
