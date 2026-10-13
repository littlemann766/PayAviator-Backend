// Runs only when TEST_DATABASE_URL points at a disposable Postgres database.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { PgStore } from '../src/store.js';
import { isEncrypted, encryptToken } from '../src/crypto.js';
import { cleanupLegacyItems } from '../src/legacy.js';

const url = process.env.TEST_DATABASE_URL;

test('PgStore: legacy plaintext migration is idempotent; CRUD works', { skip: !url && 'TEST_DATABASE_URL not set' }, async () => {
  const raw = new pg.Pool({ connectionString: url });
  await raw.query('DROP TABLE IF EXISTS plaid_items, plaid_transactions, plaid_pending_links, plaid_exchanged_public_tokens');
  // Schema + plaintext row as written by the old server.js
  await raw.query(`CREATE TABLE plaid_items (user_id TEXT, item_id TEXT PRIMARY KEY, access_token TEXT, institution_id TEXT, institution_name TEXT, created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW())`);
  await raw.query(`INSERT INTO plaid_items(user_id,item_id,access_token) VALUES('u1','legacy-item','access-sandbox-legacy')`);

  const key = crypto.randomBytes(32);
  const store = new PgStore({ url, ssl: false }, key);
  await store.init();
  const stored = (await raw.query(`SELECT access_token FROM plaid_items WHERE item_id='legacy-item'`)).rows[0].access_token;
  assert.ok(isEncrypted(stored));
  await store.init(); // second boot: no double encryption
  assert.equal((await raw.query(`SELECT access_token FROM plaid_items WHERE item_id='legacy-item'`)).rows[0].access_token, stored);
  assert.equal((await store.getItems('u1'))[0].accessToken, 'access-sandbox-legacy');
  assert.equal((await store.getItems('u1'))[0].status, 'good');

  // A Firebase-owned item cannot be taken over by another user...
  const OWNER = 'FirebaseUidOwner0000000000A1';
  await store.putItem({ userId: OWNER, itemId: 'i3', accessToken: 'access-sandbox-3' });
  await store.putItem({ userId: 'FirebaseUidAttacker00000000B2', itemId: 'i3', accessToken: 'access-sandbox-evil' });
  assert.equal((await store.getItemById('i3')).userId, OWNER);
  assert.equal((await store.getItemById('i3')).accessToken, 'access-sandbox-3');
  // ...but an item held by a legacy (pre-Firebase) id moves to the verified user on relink.
  await store.putItem({ userId: 'u1', itemId: 'i2', accessToken: 'access-sandbox-2', institutionName: 'Bank' });
  await store.putItem({ userId: OWNER, itemId: 'i2', accessToken: 'access-sandbox-moved' });
  assert.equal((await store.getItemById('i2')).userId, OWNER);
  await store.putItem({ userId: 'u1', itemId: 'i2', accessToken: 'access-sandbox-2', institutionName: 'Bank' });
  assert.equal((await store.getItemById('i2')).userId, OWNER, 'cannot move back to a legacy id');
  await store.deleteItem(OWNER, 'i3');
  await raw.query(`UPDATE plaid_items SET user_id='u1', access_token=$1 WHERE item_id='i2'`, [(await raw.query(`SELECT access_token FROM plaid_items WHERE item_id='legacy-item'`)).rows[0].access_token]);

  await store.setItemStatus('i2', 'login_required', 'ITEM_LOGIN_REQUIRED');
  await store.setNewAccountsAvailable('i2', true);
  const i2 = await store.getItemById('i2');
  assert.equal(i2.status, 'login_required'); assert.equal(i2.newAccountsAvailable, true);

  await store.applySync('u1', i2, { upserts: [{ transaction_id: 't1', date: '2026-01-01' }, { transaction_id: 't2', date: '2026-01-02' }], removedIds: [], cursor: 'c1' });
  await store.applySync('u1', i2, { upserts: [], removedIds: ['t1'], cursor: 'c2' });
  assert.deepEqual((await store.storedTransactions('u1')).map(t => t.transaction_id), ['t2']);
  assert.equal((await store.getItemById('i2')).transactionsCursor, 'c2');

  await store.putPending('u1', 'link-1', { mode: 'update', itemId: 'i2' });
  assert.deepEqual(await store.getPending('u1'), { linkToken: 'link-1', mode: 'update', itemId: 'i2' });
  await store.markExchanged('h1', 'u1', 'i2'); await store.markExchanged('h1', 'u1', 'i2');
  assert.deepEqual(await store.getExchanged('h1'), { itemId: 'i2', userId: 'u1' });

  await store.deleteItem('u1', 'i2');
  assert.equal(await store.getItemById('i2'), null);
  assert.equal((await raw.query(`SELECT count(*)::int n FROM plaid_transactions WHERE item_id='i2'`)).rows[0].n, 0);
  assert.equal(await store.getExchanged('h1'), null, 'single-bank delete removes its public-token hash rows');
  assert.equal(await store.getPending('u1'), null, 'and its pending update link');
  await store.close(); await raw.end();
});

test('PgStore.deleteUserData and legacy cleanup', { skip: !url && 'TEST_DATABASE_URL not set' }, async () => {
  const key = crypto.randomBytes(32);
  const raw = new pg.Pool({ connectionString: url });
  await raw.query('DROP TABLE IF EXISTS plaid_items, plaid_transactions, plaid_pending_links, plaid_exchanged_public_tokens');
  const store = new PgStore({ url, ssl: false }, key);
  await store.init();
  const fb = 'kX3vT9qLmN2pR7sW1yZ4bC6dE8fG';
  // deleteUserData keeps listed items
  await store.putItem({ userId: fb, itemId: 'a', accessToken: 'access-sandbox-a' });
  await store.putItem({ userId: fb, itemId: 'b', accessToken: 'access-sandbox-b' });
  await store.applySync(fb, { itemId: 'a' }, { upserts: [{ transaction_id: 'ta' }], removedIds: [], cursor: 'c' });
  await store.markExchanged('ha', fb, 'a'); await store.markExchanged('hb', fb, 'b');
  await store.putPending(fb, 'link-1');
  await store.deleteUserData(fb, { keepItemIds: ['b'] });
  assert.deepEqual((await store.getItems(fb)).map(i => i.itemId), ['b']);
  assert.equal((await store.storedTransactions(fb)).length, 0);
  assert.equal(await store.getExchanged('ha'), null);
  assert.ok(await store.getExchanged('hb'));
  assert.equal(await store.getPending(fb), null);

  // legacy cleanup
  await store.putItem({ userId: 'pp-old-1', itemId: 'L1', accessToken: 'access-sandbox-L1' });
  await store.putItem({ userId: 'ppd_OldDeviceId12345678', itemId: 'L2', accessToken: 'access-sandbox-L2' });
  await store.applySync('pp-old-1', { itemId: 'L1' }, { upserts: [{ transaction_id: 'tL1' }], removedIds: [], cursor: 'c' });
  await store.markExchanged('hL1', 'pp-old-1', 'L1');
  await store.putPending('pp-old-1', 'link-old');
  const removed = [];
  const plaid = { call: async (m, req) => { removed.push(req.access_token); if (req.access_token === 'access-sandbox-L2') throw Object.assign(new Error('gone'), { response: { data: { error_code: 'ITEM_NOT_FOUND' } } }); return {}; } };
  const dry = await cleanupLegacyItems({ pool: raw, plaid, key });
  assert.equal(dry.mode, 'dry-run'); assert.equal(dry.legacy_items, 2); assert.equal(dry.firebase_items_kept, 1);
  assert.equal(removed.length, 0, 'dry run calls nothing');
  assert.ok(!JSON.stringify(dry).includes('access-'));
  const res = await cleanupLegacyItems({ pool: raw, plaid, key, apply: true });
  assert.ok(!JSON.stringify(res).includes('access-'));
  assert.equal(res.items_deleted, 2); assert.equal(res.removed_at_plaid, 1); assert.equal(res.already_gone_at_plaid, 1);
  assert.deepEqual(removed.sort(), ['access-sandbox-L1', 'access-sandbox-L2']);
  const left = (await raw.query('SELECT user_id FROM plaid_items')).rows.map(r => r.user_id);
  assert.deepEqual(left, [fb]);
  for (const t of ['plaid_transactions', 'plaid_pending_links']) assert.equal((await raw.query(`SELECT count(*)::int n FROM ${t} WHERE user_id LIKE 'pp%'`)).rows[0].n, 0);
  assert.equal(await store.getExchanged('hL1'), null);
  await store.close(); await raw.end();
});

test('PgStore.revokeItem purges only that item and blocks late syncs', { skip: !url && 'TEST_DATABASE_URL not set' }, async () => {
  const key = crypto.randomBytes(32);
  const raw = new pg.Pool({ connectionString: url });
  await raw.query('DROP TABLE IF EXISTS plaid_items, plaid_transactions, plaid_pending_links, plaid_exchanged_public_tokens');
  const store = new PgStore({ url, ssl: false }, key);
  await store.init();
  await store.putItem({ userId: 'u1', itemId: 'r', accessToken: 'access-sandbox-r' });
  await store.putItem({ userId: 'u1', itemId: 'k', accessToken: 'access-sandbox-k' });
  assert.equal(await store.applySync('u1', { itemId: 'r' }, { upserts: [{ transaction_id: 'tr', date: '2026-01-02' }], removedIds: [], cursor: 'cr' }), true);
  await store.applySync('u1', { itemId: 'k' }, { upserts: [{ transaction_id: 'tk', date: '2026-01-01' }], removedIds: [], cursor: 'ck' });
  await store.setNewAccountsAvailable('r', true);
  await store.markExchanged('hr', 'u1', 'r'); await store.markExchanged('hk', 'u1', 'k');
  await store.putPending('u1', 'link-u', { mode: 'update', itemId: 'r' });

  await store.setItemStatus('r', 'revoked', 'USER_PERMISSION_REVOKED'); // routes to revokeItem
  const r = await store.getItemById('r');
  assert.equal(r.status, 'revoked'); assert.equal(r.errorCode, 'USER_PERMISSION_REVOKED');
  assert.equal(r.transactionsCursor, null); assert.equal(r.newAccountsAvailable, false);
  assert.equal(r.accessToken, 'access-sandbox-r', 'encrypted token kept for update mode');
  assert.deepEqual((await store.storedTransactions('u1')).map(t => t.transaction_id), ['tk']);
  assert.equal(await store.getExchanged('hr'), null); assert.ok(await store.getExchanged('hk'));
  assert.equal(await store.getPending('u1'), null);
  assert.equal((await store.getItemById('k')).transactionsCursor, 'ck');

  assert.equal(await store.applySync('u1', { itemId: 'r' }, { upserts: [{ transaction_id: 'late' }], removedIds: [], cursor: 'late' }), false);
  assert.equal((await raw.query(`SELECT count(*)::int n FROM plaid_transactions WHERE item_id='r'`)).rows[0].n, 0);
  assert.equal((await store.getItemById('r')).transactionsCursor, null);
  await store.close(); await raw.end();
});

test('PgStore: billing entitlements and free-tier claims (conflict, release, cooldown purge)', { skip: !url && 'TEST_DATABASE_URL not set' }, async () => {
  const raw = new pg.Pool({ connectionString: url });
  await raw.query('DROP TABLE IF EXISTS billing_entitlements, free_tier_claims');
  const store = new PgStore({ url, ssl: false }, crypto.randomBytes(32));
  await store.init();
  const exp = new Date(Date.now() + 86400e3).toISOString();
  await store.putEntitlement({ tokenHash: 'th', userId: 'u1', productId: 'p', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: exp });
  await store.putEntitlement({ tokenHash: 'th', userId: 'u2', productId: 'p', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: exp }); // cannot steal
  assert.equal((await store.getEntitlementByTokenHash('th')).userId, 'u1');
  assert.equal((await store.getEntitlements('u1'))[0].expiresAt, exp);

  await store.putItem({ userId: 'u1', itemId: 'fi1', accessToken: 'a' });
  await store.claimFreeTier('u1', 'fi1', [{ kind: 'acct', hash: 'h1' }, { kind: 'device', hash: 'd1' }]);
  assert.equal(await store.findFreeTierConflict('u1', [{ kind: 'acct', hash: 'h1' }]), null, 'own claim is no conflict');
  assert.deepEqual(await store.findFreeTierConflict('u2', [{ kind: 'pacct', hash: 'zz' }, { kind: 'device', hash: 'd1' }]), { kind: 'device' });
  assert.equal(await store.findFreeTierConflict('u2', [{ kind: 'device', hash: 'h1' }]), null, 'kind is part of the key');
  await store.deleteItem('u1', 'fi1');
  assert.equal((await raw.query('SELECT count(*)::int n FROM free_tier_claims WHERE released_at IS NOT NULL')).rows[0].n, 2);
  assert.ok(await store.findFreeTierConflict('u2', [{ kind: 'acct', hash: 'h1' }]), 'still blocks during cooldown');
  assert.equal(await store.purgeFreeTier(30), 0);
  await raw.query(`UPDATE free_tier_claims SET released_at = NOW() - INTERVAL '31 days'`);
  assert.equal(await store.findFreeTierConflict('u2', [{ kind: 'acct', hash: 'h1' }], 30), null, 'expired hash ignored before purge');
  assert.equal(await store.purgeFreeTier(30), 2);
  await store.claimFreeTier('u3', 'fi3', [{ kind: 'acct', hash: 'h3' }]);
  await store.deleteUserData('u3');
  assert.equal((await raw.query(`SELECT count(*)::int n FROM free_tier_claims WHERE user_id='u3' AND released_at IS NOT NULL`)).rows[0].n, 1);
  await store.close(); await raw.end();
});

test('PgStore: stripe customers, event idempotency and event purge', { skip: !url && 'TEST_DATABASE_URL not set' }, async () => {
  const raw = new pg.Pool({ connectionString: url });
  await raw.query('DROP TABLE IF EXISTS stripe_customers, stripe_events');
  const store = new PgStore({ url, ssl: false }, crypto.randomBytes(32));
  await store.init();
  await store.putStripeCustomer('u1', 'cus_1');
  await store.putStripeCustomer('u1', 'cus_1');
  assert.equal(await store.getStripeCustomer('u1'), 'cus_1');
  assert.equal(await store.getUserByStripeCustomer('cus_1'), 'u1');
  assert.equal(await store.hasStripeEvent('evt_1'), false);
  await store.markStripeEvent('evt_1', 'checkout.session.completed');
  await store.markStripeEvent('evt_1', 'checkout.session.completed');
  assert.equal(await store.hasStripeEvent('evt_1'), true);
  await store.putEntitlement({ tokenHash: 'stripe_sub:sub_1', userId: 'u1', productId: 'price_m', platform: 'stripe', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: new Date(Date.now() + 86400e3).toISOString() });
  assert.equal((await store.getEntitlementByTokenHash('stripe_sub:sub_1')).platform, 'stripe');
  assert.equal(await store.purgeStripeEvents(30), 0);
  await raw.query(`UPDATE stripe_events SET processed_at = NOW() - INTERVAL '31 days'`);
  assert.equal(await store.purgeStripeEvents(30), 1);
  await store.close(); await raw.end();
});
