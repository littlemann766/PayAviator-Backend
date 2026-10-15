import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { SignJWT } from 'jose';
import { buildApp, testConfig, JWT_SECRET } from './helpers.js';
import { MemoryStore } from '../src/store.js';
import { validateSyncItem, incomingWins, contentHash, SYNC_LIMITS } from '../src/cloudSync.js';

const tok = (sub, claims = { email_verified: true }) => new SignJWT(claims).setProtectedHeader({ alg: 'HS256' }).setSubject(sub).setIssuedAt().setExpirationTime('5m').sign(new TextEncoder().encode(JWT_SECRET));
const bearer = async (sub = 'u1', c) => `Bearer ${await tok(sub, c)}`;
const it = (id, data, updatedAt, extra = {}) => ({ kind: 'bill', id, data, updatedAt, ...extra });
const push = async (app, auth, items) => request(app).post('/api/sync/push').set('Authorization', auth).send({ items });
const changes = (app, auth, q = '') => request(app).get(`/api/sync/changes${q}`).set('Authorization', auth);

test('auth required; unverified email 403; userId from body/query ignored', async () => {
  const { app } = buildApp();
  assert.equal((await request(app).get('/api/sync/changes')).status, 401);
  const unv = await bearer('u1', { email_verified: false });
  const r = await changes(app, unv);
  assert.equal(r.status, 403); assert.equal(r.body.code, 'EMAIL_NOT_VERIFIED');
  assert.equal((await push(app, unv, [])).status, 403);
  assert.equal((await request(app).delete('/api/sync/all').set('Authorization', unv)).status, 403);
  const a = await bearer('alice'), b = await bearer('bob');
  await request(app).post('/api/sync/push').set('Authorization', a).send({ userId: 'bob', items: [it('x', { n: 1 }, 1000)] });
  const rb = await request(app).get('/api/sync/changes?userId=alice&user_id=alice').set('Authorization', b);
  assert.deepEqual(rb.body.items, []);
  assert.equal((await changes(app, a)).body.items.length, 1);
});

test('push then pull; shapes, pagination (next/more), since', async () => {
  const { app } = buildApp(); const auth = await bearer();
  const items = ['a', 'b', 'c'].map((id, i) => it(id, { amount: i }, 1000 + i));
  const r = await push(app, auth, items);
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.results, items.map(x => ({ kind: 'bill', id: x.id, status: 'accepted' })));
  const p1 = await changes(app, auth, '?since=0&limit=2');
  assert.equal(p1.body.items.length, 2); assert.equal(p1.body.more, true);
  assert.deepEqual(Object.keys(p1.body.items[0]).sort(), ['data', 'deleted', 'id', 'kind', 'seq', 'updatedAt']);
  const p2 = await changes(app, auth, `?since=${p1.body.next}&limit=2`);
  assert.deepEqual(p2.body.items.map(x => x.id), ['c']); assert.equal(p2.body.more, false);
  const p3 = await changes(app, auth, `?since=${p2.body.next}`);
  assert.deepEqual(p3.body, { items: [], next: p2.body.next, more: false });
  assert.equal((await changes(app, auth, '?since=-1')).status, 400);
  assert.equal((await changes(app, auth, '?since=abc')).status, 400);
  assert.equal((await changes(app, auth, '?limit=0')).status, 400);
  assert.equal((await changes(app, auth, '?limit=99999')).status, 200, 'limit is capped, not an error');
});

test('last-write-wins: newer accepted, older rejected with winner, replay is idempotent (no new seq)', async () => {
  const { app } = buildApp(); const auth = await bearer();
  await push(app, auth, [it('a', { v: 'old' }, 1000)]);
  const seq1 = (await changes(app, auth)).body.items[0].seq;
  const newer = await push(app, auth, [it('a', { v: 'new' }, 2000)]);
  assert.equal(newer.body.results[0].status, 'accepted');
  const stale = await push(app, auth, [it('a', { v: 'older' }, 1500)]);
  assert.equal(stale.body.results[0].status, 'rejected'); assert.equal(stale.body.results[0].reason, 'stale');
  assert.equal(stale.body.results[0].winner.data.v, 'new'); assert.equal(stale.body.results[0].winner.updatedAt, 2000);
  const seq2 = (await changes(app, auth)).body.items[0].seq;
  assert.ok(seq2 > seq1);
  await push(app, auth, [it('a', { v: 'new' }, 2000)]);
  assert.equal((await changes(app, auth)).body.items[0].seq, seq2, 'identical replay does not bump seq');
});

test('equal updatedAt: deterministic regardless of arrival order', async () => {
  const A = it('t', { v: 'A' }, 5000), B = it('t', { v: 'B' }, 5000);
  const winner = contentHash(A.data, false) > contentHash(B.data, false) ? 'A' : 'B';
  for (const order of [[A, B], [B, A]]) {
    const { app } = buildApp(); const auth = await bearer();
    for (const x of order) await push(app, auth, [x]);
    assert.equal((await changes(app, auth)).body.items[0].data.v, winner);
  }
});

test('tombstones: delete clears data, propagates in changes, older edit cannot resurrect, newer edit can', async () => {
  const { app } = buildApp(); const auth = await bearer();
  await push(app, auth, [it('a', { secret: 'x' }, 1000)]);
  const d = await push(app, auth, [{ kind: 'bill', id: 'a', deleted: true, updatedAt: 2000 }]);
  assert.equal(d.body.results[0].status, 'accepted');
  const c = (await changes(app, auth)).body.items[0];
  assert.equal(c.deleted, true); assert.equal(c.data, null);
  const resurrect = await push(app, auth, [it('a', { secret: 'x' }, 1500)]);
  assert.equal(resurrect.body.results[0].status, 'rejected'); assert.equal(resurrect.body.results[0].winner.deleted, true);
  assert.equal((await push(app, auth, [it('a', { v: 2 }, 3000)])).body.results[0].status, 'accepted');
  assert.equal((await changes(app, auth)).body.items[0].deleted, false);
  // tombstone for an item the server never saw is stored (so other devices learn about it)
  await push(app, auth, [{ kind: 'income', id: 'ghost', deleted: true, updatedAt: 10 }]);
  assert.ok((await changes(app, auth)).body.items.some(x => x.id === 'ghost' && x.deleted));
});

test('validation: kinds, ids, data type, size, updatedAt; bad items rejected per item, good ones still accepted', async () => {
  const { app } = buildApp(); const auth = await bearer();
  for (const kind of ['bill', 'income', 'spending', 'cushion', 'budget', 'goal', 'category']) assert.equal((await push(app, auth, [{ kind, id: 'k', data: {}, updatedAt: 1 }])).body.results[0].status, 'accepted', kind);
  const big = { s: 'x'.repeat(SYNC_LIMITS.maxItemBytes) };
  const r = await push(app, auth, [
    { kind: 'nope', id: 'a', data: {}, updatedAt: 1 }, { kind: 'bill', id: '', data: {}, updatedAt: 1 }, { kind: 'bill', id: 'a b', data: {}, updatedAt: 1 },
    { kind: 'bill', id: 'a', data: [], updatedAt: 1 }, { kind: 'bill', id: 'a', data: 'str', updatedAt: 1 }, { kind: 'bill', id: 'a', data: big, updatedAt: 1 },
    { kind: 'bill', id: 'a', data: {}, updatedAt: -5 }, { kind: 'bill', id: 'a', data: {}, updatedAt: 1.5 }, { kind: 'bill', id: 'a', data: {}, updatedAt: '5' },
    { kind: 'bill', id: 'a', data: {}, updatedAt: 1, deleted: 'yes' }, null, 'x', { kind: 'bill', id: 'ok', data: { a: 1 }, updatedAt: 1 },
  ]);
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.results.map(x => x.reason), ['invalid_kind', 'invalid_id', 'invalid_id', 'invalid_data', 'invalid_data', 'too_large', 'invalid_updated_at', 'invalid_updated_at', 'invalid_updated_at', 'invalid_deleted', 'invalid_item', 'invalid_item', undefined]);
  assert.equal(r.body.results.at(-1).status, 'accepted');
  const okSize = { s: 'x'.repeat(SYNC_LIMITS.maxItemBytes - 20) };
  assert.equal((await push(app, auth, [{ kind: 'bill', id: 'fits', data: okSize, updatedAt: 1 }])).body.results[0].status, 'accepted');
});

test('push body shape: items must be array, max 200 per call', async () => {
  const { app } = buildApp(); const auth = await bearer();
  assert.equal((await request(app).post('/api/sync/push').set('Authorization', auth).send({})).status, 400);
  assert.equal((await request(app).post('/api/sync/push').set('Authorization', auth).send({ items: 'x' })).status, 400);
  const many = n => Array.from({ length: n }, (_, i) => it(`i${i}`, { i }, 100 + i));
  assert.equal((await push(app, auth, many(200))).status, 200);
  const over = await push(app, auth, many(201));
  assert.equal(over.status, 413); assert.equal(over.body.code, 'TOO_MANY_ITEMS');
});

test('updatedAt is clamped to now + 5 min (future timestamps cannot permanently win)', async () => {
  const { app } = buildApp(); const auth = await bearer();
  const before = Date.now();
  await push(app, auth, [it('f', { v: 1 }, Date.now() + 10 * 365 * 86400e3)]);
  const got = (await changes(app, auth)).body.items[0].updatedAt;
  assert.ok(got <= Date.now() + SYNC_LIMITS.maxFutureMs && got >= before + SYNC_LIMITS.maxFutureMs - 1000);
  assert.equal(validateSyncItem(it('f', {}, 1e15), 1000).item.updatedAt, 1000 + SYNC_LIMITS.maxFutureMs);
});

test('per-user item cap (20000): new items rejected with item_limit, existing ones still update', async () => {
  const store = new MemoryStore(); const { app } = buildApp({ store }); const auth = await bearer('cap');
  for (let i = 0; i < SYNC_LIMITS.maxItemsPerUser; i++) store.syncRows.set(`cap|bill|s${i}`, { userId: 'cap', kind: 'bill', id: `s${i}`, data: {}, updatedAt: 1, deleted: false, seq: i + 1 });
  const r = await push(app, auth, [it('new', {}, 5), it('s1', { v: 1 }, 5)]);
  assert.equal(r.body.results[0].status, 'rejected'); assert.equal(r.body.results[0].reason, 'item_limit');
  assert.equal(r.body.results[1].status, 'accepted');
});

test('DELETE /sync/all wipes only the caller', async () => {
  const { app } = buildApp(); const a = await bearer('a'), b = await bearer('b');
  await push(app, a, [it('x', {}, 1), it('y', {}, 2)]); await push(app, b, [it('x', {}, 1)]);
  const r = await request(app).delete('/api/sync/all').set('Authorization', a);
  assert.deepEqual(r.body, { deleted: 2 });
  assert.equal((await changes(app, a)).body.items.length, 0);
  assert.equal((await changes(app, b)).body.items.length, 1);
});

test('DELETE /plaid/user wipes sync data (and other users keep theirs)', async () => {
  const { app, store, plaid } = buildApp();
  plaid.call = async () => ({});
  const a = await bearer('a'), b = await bearer('b');
  await push(app, a, [it('x', {}, 1)]); await push(app, b, [it('x', {}, 1)]);
  await store.putItem({ userId: 'a', itemId: 'ia', accessToken: 'x' });
  assert.equal((await request(app).delete('/api/plaid/user').set('Authorization', a)).status, 200);
  assert.equal((await changes(app, a)).body.items.length, 0);
  assert.equal((await changes(app, b)).body.items.length, 1);
});

test('tombstone purge removes only tombstones older than 90 days', async () => {
  const store = new MemoryStore(); const now = Date.now(); const day = 86400e3;
  await store.syncPush('u', [it('live-old', { a: 1 }, now - 200 * day), { kind: 'bill', id: 'dead-old', deleted: true, updatedAt: now - 91 * day }, { kind: 'bill', id: 'dead-new', deleted: true, updatedAt: now - 89 * day }], now);
  assert.equal(await store.purgeSyncTombstones(90, now), 1);
  assert.deepEqual((await store.syncChanges('u')).items.map(x => x.id).sort(), ['dead-new', 'live-old']);
});

test('body limit: 512KB accepted on /sync, 100KB limit still applies elsewhere', async () => {
  const { app } = buildApp(); const auth = await bearer();
  const items = Array.from({ length: 80 }, (_, i) => it(`b${i}`, { s: 'x'.repeat(6000) }, 10 + i)); // ~480KB
  assert.equal((await push(app, auth, items)).status, 200);
  const huge = await push(app, auth, Array.from({ length: 100 }, (_, i) => it(`h${i}`, { s: 'x'.repeat(7000) }, 10)));
  assert.equal(huge.status, 413);
  const other = await request(app).post('/api/billing/google-play/verify').set('Authorization', auth).send({ productId: 'p', purchaseToken: 'x'.repeat(150000) });
  assert.equal(other.status, 413);
});

test('push limiter is stricter than the general limiter and per user', async () => {
  const config = testConfig({ RATE_LIMIT_MAX: '8' }); config.rateLimit.syncPushMax = 2;
  const { app } = buildApp({ config }); const a = await bearer('a'), b = await bearer('b');
  assert.equal((await push(app, a, [])).status, 200); assert.equal((await push(app, a, [])).status, 200);
  assert.equal((await push(app, a, [])).status, 429);
  assert.equal((await changes(app, a)).status, 200, 'reads use the general limiter');
  assert.equal((await push(app, b, [])).status, 200, 'other user unaffected');
});

test('CORS: payaviator.app and www allowed with Authorization header, evil origin not', async () => {
  const { app } = buildApp();
  for (const o of ['https://payaviator.app', 'https://www.payaviator.app']) {
    const r = await request(app).options('/api/sync/push').set('Origin', o).set('Access-Control-Request-Method', 'POST').set('Access-Control-Request-Headers', 'authorization,content-type');
    assert.equal(r.headers['access-control-allow-origin'], o);
    assert.match(r.headers['access-control-allow-headers'], /Authorization/i);
  }
  const bad = await request(app).options('/api/sync/push').set('Origin', 'https://evil.example').set('Access-Control-Request-Method', 'POST');
  assert.equal(bad.headers['access-control-allow-origin'], undefined);
});

test('concurrent pushes of the same item converge on the newest write', async () => {
  const { app } = buildApp(); const auth = await bearer();
  await Promise.all(Array.from({ length: 10 }, (_, i) => push(app, auth, [it('c', { i }, 1000 + i)])));
  assert.equal((await changes(app, auth)).body.items[0].data.i, 9);
});

test('incomingWins basics', () => {
  assert.equal(incomingWins({ updatedAt: 1, deleted: false, data: {} }, { updatedAt: 2, deleted: false, data: {} }), true);
  assert.equal(incomingWins({ updatedAt: 2, deleted: false, data: {} }, { updatedAt: 1, deleted: false, data: {} }), false);
});
