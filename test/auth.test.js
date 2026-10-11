import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { SignJWT } from 'jose';
import { buildApp, JWT_SECRET, fakePlaid } from './helpers.js';

const sign = (claims = {}, { secret = JWT_SECRET, exp = '5m' } = {}) =>
  new SignJWT(claims).setProtectedHeader({ alg: 'HS256' }).setSubject(claims.sub ?? 'user-1').setIssuedAt().setExpirationTime(exp)
    .sign(new TextEncoder().encode(secret));

test('rejects requests without a bearer token', async () => {
  const { app } = buildApp();
  const r = await request(app).get('/api/plaid/accounts');
  assert.equal(r.status, 401);
  assert.equal(r.body.code, 'UNAUTHENTICATED');
});

test('rejects bad signature and expired tokens', async () => {
  const { app } = buildApp();
  const bad = await sign({}, { secret: 'x'.repeat(40) });
  assert.equal((await request(app).get('/api/plaid/accounts').set('Authorization', `Bearer ${bad}`)).status, 401);
  const expired = await sign({}, { exp: Math.floor(Date.now() / 1000) - 3600 });
  assert.equal((await request(app).get('/api/plaid/accounts').set('Authorization', `Bearer ${expired}`)).status, 401);
  assert.equal((await request(app).get('/api/plaid/accounts').set('Authorization', 'Bearer not-a-jwt')).status, 401);
});

test('valid token is scoped to its own sub; legacy :userId must match', async () => {
  const { app, store } = buildApp({ plaid: fakePlaid({ accountsGet: async () => ({ accounts: [{ account_id: 'a1', mask: '1111', type: 'depository', balances: { current: 5 } }] }) }) });
  await store.putItem({ userId: 'user-1', itemId: 'item-1', accessToken: 'access-sandbox-1' });
  await store.putItem({ userId: 'user-2', itemId: 'item-2', accessToken: 'access-sandbox-2' });
  const t = await sign();
  const ok = await request(app).get('/api/plaid/accounts').set('Authorization', `Bearer ${t}`);
  assert.equal(ok.status, 200);
  assert.deepEqual(ok.body.items.map(i => i.item_id), ['item-1']);
  assert.ok(!JSON.stringify(ok.body).includes('access-sandbox'), 'access tokens never leave the server');
  assert.equal((await request(app).get('/api/plaid/accounts/user-1').set('Authorization', `Bearer ${t}`)).status, 200);
  const forbidden = await request(app).get('/api/plaid/accounts/user-2').set('Authorization', `Bearer ${t}`);
  assert.equal(forbidden.status, 403);
  const bodyMismatch = await request(app).post('/api/plaid/create-link-token').set('Authorization', `Bearer ${t}`).send({ userId: 'user-2' });
  assert.equal(bodyMismatch.status, 403);
  const del = await request(app).delete('/api/plaid/items/user-2/item-2').set('Authorization', `Bearer ${t}`);
  assert.equal(del.status, 403);
  assert.equal((await store.getItems('user-2')).length, 1);
});

test('CORS only reflects allowlisted origins and allows Authorization', async () => {
  const { app } = buildApp();
  const pre = await request(app).options('/api/plaid/accounts').set('Origin', 'https://appassets.androidplatform.net').set('Access-Control-Request-Method', 'GET').set('Access-Control-Request-Headers', 'authorization');
  assert.equal(pre.headers['access-control-allow-origin'], 'https://appassets.androidplatform.net');
  assert.match(pre.headers['access-control-allow-headers'], /Authorization/);
  const evil = await request(app).options('/api/plaid/accounts').set('Origin', 'https://evil.example').set('Access-Control-Request-Method', 'GET');
  assert.equal(evil.headers['access-control-allow-origin'], undefined);
});
