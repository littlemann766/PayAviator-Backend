import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import request from 'supertest';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createWebhookVerifier } from '../src/webhookVerify.js';
import { buildApp } from './helpers.js';

const { publicKey, privateKey } = await generateKeyPair('ES256');
const jwk = { ...(await exportJWK(publicKey)), kid: 'kid-1', alg: 'ES256', use: 'sig', created_at: 1, expired_at: null };
let fetches = 0;
const verifier = createWebhookVerifier({ fetchKey: async kid => { fetches++; if (kid !== 'kid-1') throw new Error('nope'); return jwk; } });

const sha = s => crypto.createHash('sha256').update(s).digest('hex');
async function signBody(body, { iat = Math.floor(Date.now() / 1000), kid = 'kid-1', key = privateKey, hash = sha(body) } = {}) {
  return new SignJWT({ request_body_sha256: hash }).setProtectedHeader({ alg: 'ES256', kid, typ: 'JWT' }).setIssuedAt(iat).sign(key);
}

const body = JSON.stringify({ webhook_type: 'ITEM', webhook_code: 'ERROR', item_id: 'item-1', error: { error_code: 'ITEM_LOGIN_REQUIRED' }, environment: 'sandbox' });

test('accepts a valid signature and caches the key by kid', async () => {
  const before = fetches;
  await verifier(Buffer.from(body), await signBody(body));
  await verifier(Buffer.from(body), await signBody(body));
  assert.equal(fetches - before, 1);
});

test('rejects missing header, body mismatch, stale iat, unknown kid, wrong key, wrong alg', async () => {
  await assert.rejects(verifier(Buffer.from(body), undefined), /missing_header/);
  await assert.rejects(verifier(Buffer.from(body + ' '), await signBody(body)), /body_mismatch/);
  await assert.rejects(verifier(Buffer.from(body), await signBody(body, { iat: Math.floor(Date.now() / 1000) - 6 * 60 })), /stale/);
  await assert.rejects(verifier(Buffer.from(body), await signBody(body, { kid: 'other' })), /key_fetch_failed/);
  const other = await generateKeyPair('ES256');
  await assert.rejects(verifier(Buffer.from(body), await signBody(body, { key: other.privateKey })), /bad_signature/);
  const hs = await new SignJWT({ request_body_sha256: sha(body) }).setProtectedHeader({ alg: 'HS256', kid: 'kid-1' }).setIssuedAt().sign(new TextEncoder().encode('x'.repeat(32)));
  await assert.rejects(verifier(Buffer.from(body), hs), /bad_alg/);
});

test('webhook endpoint rejects unsigned requests and updates item status on valid ones', async () => {
  const { app, store } = buildApp({ webhookVerifier: verifier });
  await store.putItem({ userId: 'u1', itemId: 'item-1', accessToken: 'access-sandbox-1' });

  const unsigned = await request(app).post('/api/plaid/webhook').set('Content-Type', 'application/json').send(body);
  assert.equal(unsigned.status, 401);
  assert.equal((await store.getItemById('item-1')).status, 'good');

  const forged = await request(app).post('/api/plaid/webhook').set('Content-Type', 'application/json')
    .set('Plaid-Verification', await signBody('{"other":"body"}')).send(body);
  assert.equal(forged.status, 401);

  const ok = await request(app).post('/api/plaid/webhook').set('Content-Type', 'application/json')
    .set('Plaid-Verification', await signBody(body)).send(body);
  assert.equal(ok.status, 200);
  const item = await store.getItemById('item-1');
  assert.equal(item.status, 'login_required');
  assert.equal(item.errorCode, 'ITEM_LOGIN_REQUIRED');
});

test('SYNC_UPDATES_AVAILABLE triggers a sync for that item', async () => {
  const synced = [];
  const { app, store } = buildApp({ webhookVerifier: verifier, syncItem: async item => { synced.push(item.itemId); return {}; } });
  await store.putItem({ userId: 'u1', itemId: 'item-9', accessToken: 'access-sandbox-9' });
  const b = JSON.stringify({ webhook_type: 'TRANSACTIONS', webhook_code: 'SYNC_UPDATES_AVAILABLE', item_id: 'item-9' });
  const r = await request(app).post('/api/plaid/webhook').set('Content-Type', 'application/json').set('Plaid-Verification', await signBody(b)).send(b);
  assert.equal(r.status, 200);
  assert.deepEqual(synced, ['item-9']);
});
