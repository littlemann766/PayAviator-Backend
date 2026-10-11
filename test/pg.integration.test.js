// Runs only when TEST_DATABASE_URL points at a disposable Postgres database.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { PgStore } from '../src/store.js';
import { isEncrypted } from '../src/crypto.js';

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

  await store.putItem({ userId: 'u1', itemId: 'i2', accessToken: 'access-sandbox-2', institutionName: 'Bank' });
  await store.putItem({ userId: 'attacker', itemId: 'i2', accessToken: 'access-sandbox-evil' });
  assert.equal((await store.getItemById('i2')).userId, 'u1');
  assert.equal((await store.getItemById('i2')).accessToken, 'access-sandbox-2');

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
  await store.close(); await raw.end();
});
