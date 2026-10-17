import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { SignJWT } from 'jose';
import { buildApp, fakePlaid, testConfig, JWT_SECRET } from './helpers.js';
import { handleWebhook } from '../src/webhooks.js';
import { MemoryStore, decideLive } from '../src/store.js';
import { silentLog } from '../src/log.js';

const bearer = async sub => `Bearer ${await new SignJWT({ email_verified: true }).setProtectedHeader({ alg: 'HS256' }).setSubject(sub).setIssuedAt().setExpirationTime('5m').sign(new TextEncoder().encode(JWT_SECRET))}`;
const future = (d = 30) => new Date(Date.now() + d * 86400e3).toISOString();
const acct = (id, cur) => ({ account_id: id, mask: id.slice(-4), type: 'depository', balances: { current: cur } });
function plaidSpy({ live, get } = {}) {
  return fakePlaid({
    accountsGet: get || (async ({ access_token }) => ({ accounts: [acct(`acc-${access_token}`, 1)] })),
    itemRemove: async () => ({}),
    accountsBalanceGet: live || (async ({ access_token }) => ({ accounts: [acct(`acc-${access_token}`, 99)] })),
  });
}
const n = (p, m) => p.calls.filter(c => c.method === m).length;
async function setup({ plaid = plaidSpy(), env = {}, uid = 'u', plus = true, items = ['1111'] } = {}) {
  const b = buildApp({ plaid, config: testConfig(env) });
  for (const i of items) await b.store.putItem({ userId: uid, itemId: `item-${i}`, accessToken: `tok-${i}`, institutionName: `Bank${i}` });
  if (plus) await b.store.putEntitlement({ tokenHash: `h-${uid}`, userId: uid, productId: 'p', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
  return { ...b, auth: await bearer(uid) };
}
const refresh = (app, auth, body = {}) => request(app).post('/api/plaid/accounts/refresh').set('Authorization', auth).send(body);

test('GET accounts keeps shape and adds balance_source + balance_as_of; no live call', async () => {
  const { app, plaid, auth } = await setup();
  const r = await request(app).get('/api/plaid/accounts').set('Authorization', auth);
  assert.equal(r.status, 200);
  assert.equal(r.body.accounts[0].balance_source, 'plaid_accounts_get');
  assert.ok(!Number.isNaN(Date.parse(r.body.accounts[0].balance_as_of)));
  assert.equal(r.body.accounts[0].balances.current, 1);
  assert.ok(Array.isArray(r.body.items) && Array.isArray(r.body.errors));
  assert.equal(n(plaid, 'accountsBalanceGet'), 0);
});

test('manual refresh: Plus user gets live balance, cooldown serves cache afterwards', async () => {
  const { app, plaid, auth, store } = await setup();
  const r1 = await refresh(app, auth);
  assert.equal(r1.status, 200);
  assert.equal(r1.body.accounts[0].balance_source, 'plaid_balance_get');
  assert.equal(r1.body.accounts[0].balances.current, 99);
  assert.deepEqual(r1.body.refresh.performed, [{ item_id: 'item-1111' }]);
  const r2 = await refresh(app, auth);
  assert.equal(n(plaid, 'accountsBalanceGet'), 1, 'cooldown: no second live call');
  assert.equal(r2.body.refresh.skipped[0].reason, 'cooldown');
  assert.ok(r2.body.refresh.skipped[0].retry_after_sec > 0);
  assert.equal(r2.body.accounts[0].balance_source, 'plaid_balance_get', 'served from live cache');
  assert.equal(r2.body.accounts[0].balances.current, 99);
  const g = await request(app).get('/api/plaid/accounts').set('Authorization', auth);
  assert.equal(g.body.accounts[0].balance_source, 'plaid_balance_get');
  assert.equal(n(plaid, 'accountsGet'), 0);
  assert.equal(store.liveCalls.length, 1);
  assert.deepEqual({ u: store.liveCalls[0].userId, i: store.liveCalls[0].itemId, o: store.liveCalls[0].outcome, p: store.liveCalls[0].plan }, { u: 'u', i: 'item-1111', o: 'success', p: 'premium' });
});

test('free and comp users never trigger live calls by default; env can allow a cap', async () => {
  for (const [uid, plus, env] of [['f', false, {}], ['c', false, { COMP_FIREBASE_UIDS: 'c' }]]) {
    const { app, plaid, auth } = await setup({ uid, plus, env });
    const r = await refresh(app, auth);
    assert.equal(r.status, 200);
    assert.equal(n(plaid, 'accountsBalanceGet'), 0);
    assert.equal(r.body.refresh.skipped[0].reason, 'plan_not_eligible');
    assert.equal(r.body.refresh.live_enabled, false);
    assert.equal(r.body.accounts[0].balance_source, 'plaid_accounts_get');
  }
  const { app, plaid, auth } = await setup({ uid: 'f2', plus: false, env: { LIVE_BALANCE_FREE_USER_DAILY_CAP: '1' } });
  await refresh(app, auth);
  assert.equal(n(plaid, 'accountsBalanceGet'), 1);
});

test('limits: per-user daily, per-item daily/monthly, global daily (pure decision + store)', async () => {
  const L = { cooldownSec: 900, itemDailyCap: 3, itemMonthlyCap: 10, userCap: 5, globalDailyCap: 200 };
  const base = { globalDay: 0, userDay: 0, itemDay: 0, itemMonth: 0, itemLast: null };
  const now = Date.now();
  assert.equal(decideLive(base, L, now).ok, true);
  assert.equal(decideLive({ ...base, itemLast: now - 60e3 }, L, now).reason, 'cooldown');
  assert.equal(decideLive({ ...base, itemLast: now - 901e3 }, L, now).ok, true);
  assert.equal(decideLive({ ...base, itemDay: 3 }, L, now).reason, 'item_daily_cap');
  assert.equal(decideLive({ ...base, itemMonth: 10 }, L, now).reason, 'item_monthly_cap');
  assert.equal(decideLive({ ...base, userDay: 5 }, L, now).reason, 'user_daily_cap');
  assert.equal(decideLive({ ...base, globalDay: 200 }, L, now).reason, 'global_daily_cap');
  assert.equal(decideLive(base, { ...L, userCap: 0 }, now).reason, 'plan_not_eligible');

  const s = new MemoryStore(); const day = Date.UTC(2026, 9, 10, 12);
  const l = { ...L, cooldownSec: 0 };
  for (let i = 0; i < 3; i++) assert.equal((await s.reserveLiveCall('u', 'it', 'premium', l, day + i)).ok, true);
  assert.equal((await s.reserveLiveCall('u', 'it', 'premium', l, day + 5)).reason, 'item_daily_cap');
  // next days: monthly cap of 10 for the bank
  let ok = 3;
  for (let d = 11; d < 20; d++) for (let i = 0; i < 3; i++) if ((await s.reserveLiveCall(`u${d}`, 'it', 'premium', l, Date.UTC(2026, 9, d, 12) + i)).ok) ok++;
  assert.equal(ok, 10);
  assert.equal((await s.reserveLiveCall('x', 'it', 'premium', l, Date.UTC(2026, 9, 25))).reason, 'item_monthly_cap');
  assert.equal((await s.reserveLiveCall('x', 'it', 'premium', l, Date.UTC(2026, 10, 1, 1))).ok, true, 'month rolls over');
  // global cap
  const g = new MemoryStore();
  assert.equal((await g.reserveLiveCall('a', 'i1', 'premium', { ...l, globalDailyCap: 1 }, day)).ok, true);
  assert.equal((await g.reserveLiveCall('b', 'i2', 'premium', { ...l, globalDailyCap: 1 }, day)).reason, 'global_daily_cap');
});

test('HTTP: user daily cap across banks, env-configurable', async () => {
  const items = ['1111', '2222', '3333'];
  const { app, plaid, auth } = await setup({ items, env: { LIVE_BALANCE_USER_DAILY_CAP: '2' }, plus: true });
  const r = await refresh(app, auth);
  assert.equal(r.status, 200);
  assert.equal(n(plaid, 'accountsBalanceGet'), 2);
  assert.ok(r.body.refresh.skipped.some(s => s.reason === 'user_daily_cap'));
  assert.equal(r.body.refresh.user_calls_today, 2);
  assert.equal(r.body.accounts.length, 3, 'skipped bank still returned via free accountsGet');
});

test('HTTP: global daily cap guard and per-bank daily cap env', async () => {
  const { app, plaid, auth } = await setup({ env: { LIVE_BALANCE_DAILY_CAP: '0' } });
  const r = await refresh(app, auth);
  assert.equal(n(plaid, 'accountsBalanceGet'), 0);
  assert.equal(r.body.refresh.skipped[0].reason, 'global_daily_cap');
  assert.equal(r.body.accounts[0].balance_source, 'plaid_accounts_get');
  const b = await setup({ uid: 'z', env: { LIVE_BALANCE_COOLDOWN_SEC: '0', LIVE_BALANCE_ITEM_DAILY_CAP: '1' } });
  await refresh(b.app, b.auth); const r2 = await refresh(b.app, b.auth);
  assert.equal(n(b.plaid, 'accountsBalanceGet'), 1);
  assert.equal(r2.body.refresh.skipped[0].reason, 'item_daily_cap');
});

test('live failure (PRODUCT_NOT_READY / rate limit) falls back to accountsGet and is logged as error', async () => {
  const err = code => Object.assign(new Error('x'), { response: { status: 400, data: { error_code: code, error_type: 'X' } } });
  for (const code of ['PRODUCT_NOT_READY', 'RATE_LIMIT_EXCEEDED']) {
    const { app, plaid, auth, store } = await setup({ plaid: plaidSpy({ live: async () => { throw err(code); } }), uid: `e-${code}` });
    const r = await refresh(app, auth);
    assert.equal(r.status, 200);
    assert.equal(r.body.accounts[0].balance_source, 'plaid_accounts_get');
    assert.equal(n(plaid, 'accountsGet'), 1);
    assert.equal(r.body.refresh.skipped[0].reason, 'live_failed_fallback');
    assert.equal(store.liveCalls[0].outcome, 'error'); assert.equal(store.liveCalls[0].errorCode, code);
    assert.equal(r.body.errors.length, 0);
  }
});

test('refresh: item_id filter, unknown item 404, other user forbidden, never exposes tokens', async () => {
  const { app, plaid, auth } = await setup({ items: ['1111', '2222'] });
  const r = await refresh(app, auth, { item_id: 'item-2222' });
  assert.equal(n(plaid, 'accountsBalanceGet'), 1);
  assert.equal(plaid.calls.find(c => c.method === 'accountsBalanceGet').req.access_token, 'tok-2222');
  assert.ok(!JSON.stringify(r.body).includes('access_token'));
  assert.equal((await refresh(app, auth, { item_id: 'nope' })).status, 404);
  assert.equal((await request(app).post('/api/plaid/accounts/someone-else/refresh').set('Authorization', auth)).status, 403);
  assert.equal((await request(app).post('/api/plaid/accounts/refresh')).status, 401);
});

test('webhook SYNC_UPDATES_AVAILABLE refreshes balances (webhook_refresh) alongside sync; failures do not break sync; live cache not overwritten', async () => {
  const plaid = plaidSpy({ get: async () => ({ accounts: [acct('acc-1111', 7)] }) });
  const { app, store, auth } = await setup({ plaid });
  const item = await store.getItemById('item-1111');
  const synced = [];
  const { background } = await handleWebhook({ webhook_type: 'TRANSACTIONS', webhook_code: 'SYNC_UPDATES_AVAILABLE', item_id: 'item-1111' }, {
    store, log: silentLog, syncItem: async i => { synced.push(i.itemId); return { ok: 1 }; },
    refreshBalances: async i => { const d = await plaid.call('accountsGet', { access_token: i.accessToken }); await store.putBalances(i.itemId, d.accounts, 'webhook_refresh'); },
  });
  await background;
  assert.deepEqual(synced, ['item-1111']);
  assert.equal((await store.getBalances(['item-1111'])).get('item-1111').source, 'webhook_refresh');
  // failing refresh must not reject the sync
  const r = await handleWebhook({ webhook_type: 'TRANSACTIONS', webhook_code: 'SYNC_UPDATES_AVAILABLE', item_id: 'item-1111' }, { store, log: silentLog, syncItem: async () => 'synced', refreshBalances: async () => { throw new Error('boom'); } });
  assert.equal(await r.background, 'synced');
  // legacy DEFAULT_UPDATE refreshes balances only
  let hits = 0;
  const l = await handleWebhook({ webhook_type: 'TRANSACTIONS', webhook_code: 'DEFAULT_UPDATE', item_id: 'item-1111' }, { store, log: silentLog, syncItem: async () => { throw new Error('no'); }, refreshBalances: async () => { hits++; } });
  await l.background; assert.equal(hits, 1);
  // GET: webhook cache is fallback only; a fresh GET stores accountsGet and live result is served until cooldown
  const l1 = await refresh(app, auth);
  assert.equal(l1.body.accounts[0].balance_source, 'plaid_balance_get');
  await store.putBalances('item-1111', [acct('acc-1111', 5)], 'webhook_refresh'); // simulated stale webhook write
  void item;
});

test('webhook refresh route: app wiring writes webhook_refresh and keeps fresh live balance', async () => {
  const get = async () => ({ accounts: [acct('acc-1111', 7)] });
  const { app, store, auth } = await setup({ plaid: plaidSpy({ get }) });
  const verified = [];
  const b = buildApp({ plaid: plaidSpy({ get }), store, webhookVerifier: async () => { verified.push(1); }, syncItem: async () => ({}) });
  const post = body => request(b.app).post('/api/plaid/webhook').set('Content-Type', 'application/json').send(JSON.stringify(body));
  await post({ webhook_type: 'TRANSACTIONS', webhook_code: 'SYNC_UPDATES_AVAILABLE', item_id: 'item-1111' });
  await new Promise(r => setTimeout(r, 50));
  const c = (await store.getBalances(['item-1111'])).get('item-1111');
  assert.equal(c.source, 'webhook_refresh'); assert.equal(c.accounts[0].balances.current, 7);
  await refresh(app, auth); // live
  await post({ webhook_type: 'TRANSACTIONS', webhook_code: 'SYNC_UPDATES_AVAILABLE', item_id: 'item-1111' });
  await new Promise(r => setTimeout(r, 50));
  assert.equal((await store.getBalances(['item-1111'])).get('item-1111').source, 'plaid_balance_get');
});

test('transient accountsGet failure serves last cached balance with honest balance_as_of; item errors still surface', async () => {
  let fail = false;
  const get = async () => { if (fail) throw Object.assign(new Error('down'), { response: { status: 500, data: { error_code: 'INTERNAL_SERVER_ERROR' } } }); return { accounts: [acct('acc-1111', 3)] }; };
  const { app, auth } = await setup({ plaid: plaidSpy({ get }), plus: false });
  const a = await request(app).get('/api/plaid/accounts').set('Authorization', auth);
  fail = true;
  const b = await request(app).get('/api/plaid/accounts').set('Authorization', auth);
  assert.equal(b.body.accounts[0].balances.current, 3);
  assert.equal(b.body.accounts[0].balance_as_of, a.body.accounts[0].balance_as_of);
  assert.equal(b.body.errors.length, 0);
});

test('deleting a bank removes its cached balances; live-call audit rows are kept', async () => {
  const { app, store, auth } = await setup();
  await refresh(app, auth);
  assert.equal(store.balances.size, 1);
  await request(app).delete('/api/plaid/user').set('Authorization', auth);
  assert.equal(store.balances.size, 0);
  assert.equal(store.liveCalls.length, 1);
});
