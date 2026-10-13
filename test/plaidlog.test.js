import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { redact } from '../src/log.js';
import { instrumentPlaid, plaidCallFields, plaidWebhookFields, userRef, safeLinkSessionId, withPlaidContext } from '../src/plaidLog.js';
import { handleWebhook } from '../src/webhooks.js';
import { MemoryStore } from '../src/store.js';
import { createApp } from '../src/app.js';
import { createTokenVerifier } from '../src/auth.js';
import { testConfig, fakePlaid, JWT_SECRET } from './helpers.js';

const SECRETS = ['access-production-FAKE-TEST-FIXTURE-NOT-REAL', 'public-sandbox-aaaa-bbbb-cccc',
  'link-production-9999-8888', 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl', 'robert@example.com',
  'Robert Lawson', 'Chase Checking', '1234.56', 'Starbucks'];

function captureLog() {
  const lines = [];
  const push = level => (msg, fields) => lines.push(JSON.stringify({ level, msg: redact(String(msg)), ...redact(fields || {}) }));
  return { lines, log: { info: push('info'), warn: push('warn'), error: push('error') } };
}
const assertClean = text => { for (const s of SECRETS) assert.ok(!text.includes(s), `leaked ${s}`); };

test('redact() removes tokens, JWTs, emails, PII and balance fields at any depth', () => {
  const out = JSON.stringify(redact({
    msg: `token ${SECRETS[0]} user robert@example.com`, public_token: SECRETS[1], nested: { link_token: SECRETS[2], id_token: SECRETS[3] },
    accounts: [{ name: 'Chase Checking', balances: { current: 1234.56 } }], name: 'Robert Lawson', email: 'robert@example.com',
    amount: 1234.56, merchant_name: 'Starbucks', item_id: 'item_ok', request_id: 'req_ok',
  }));
  assertClean(out);
  assert.ok(out.includes('item_ok') && out.includes('req_ok'));
});

test('redact() email regex is linear on adversarial input', () => {
  const evil = 'a'.repeat(50000) + '@' + 'b.'.repeat(20000) + '!';
  const t0 = performance.now(); redact(evil); assert.ok(performance.now() - t0 < 500);
});

test('instrumentPlaid logs one allow-listed line per successful call', async () => {
  const { lines, log } = captureLog();
  const plaid = instrumentPlaid(fakePlaid({
    itemPublicTokenExchange: () => ({ access_token: SECRETS[0], item_id: 'item_1', request_id: 'req_1' }),
    accountsGet: () => ({ item: { item_id: 'item_1' }, accounts: [{ account_id: 'acc_1', name: 'Chase Checking', balances: { current: 1234.56 } }], request_id: 'req_2' }),
  }), log);
  await withPlaidContext({ userId: 'firebaseUid123', linkSessionId: 'ls-abc-123' }, async () => {
    await plaid.call('itemPublicTokenExchange', { public_token: SECRETS[1] });
    await plaid.call('accountsGet', { access_token: SECRETS[0] });
  });
  assert.equal(lines.length, 2);
  assertClean(lines.join('\n'));
  const [a, b] = lines.map(l => JSON.parse(l));
  assert.equal(a.event, 'plaid_api'); assert.equal(a.method, 'itemPublicTokenExchange');
  assert.equal(a.request_id, 'req_1'); assert.equal(a.item_id, 'item_1'); assert.equal(a.link_session_id, 'ls-abc-123');
  assert.equal(a.user_ref, userRef('firebaseUid123')); assert.ok(!lines[0].includes('firebaseUid123'));
  assert.deepEqual(b.account_ids, ['acc_1']);
});

test('instrumentPlaid logs error_type/error_code/request_id on failure and rethrows', async () => {
  const { lines, log } = captureLog();
  const err = Object.assign(new Error(`bad ${SECRETS[0]}`), { response: { status: 400, data: {
    error_type: 'ITEM_ERROR', error_code: 'ITEM_LOGIN_REQUIRED', request_id: 'req_e', error_message: `token ${SECRETS[0]}`, display_message: 'Robert Lawson' } } });
  const plaid = instrumentPlaid({ call: async () => { throw err; } }, log);
  await assert.rejects(plaid.call('itemGet', { access_token: SECRETS[0] }, { ctx: { itemId: 'item_9' } }), e => e === err);
  const l = JSON.parse(lines[0]);
  assert.deepEqual([l.outcome, l.error_type, l.error_code, l.request_id, l.item_id, l.http_status], ['error', 'ITEM_ERROR', 'ITEM_LOGIN_REQUIRED', 'req_e', 'item_9', 400]);
  assertClean(lines[0]);
});

test('token-shaped or junk ids are never logged as ids', () => {
  const f = plaidCallFields('x', { data: { item_id: SECRETS[0], request_id: 'robert@example.com' }, ctx: { linkSessionId: SECRETS[2] } });
  assert.equal(f.item_id, undefined); assert.equal(f.request_id, undefined); assert.equal(f.link_session_id, undefined);
  assert.equal(safeLinkSessionId('  ls-1  '), 'ls-1'); assert.equal(safeLinkSessionId('x'.repeat(65)), null);
});

test('webhook line has ids + error codes only', async () => {
  const { lines, log } = captureLog();
  const store = new MemoryStore();
  await store.putItem({ userId: 'uidW', itemId: 'item_w', accessToken: SECRETS[0], institutionId: 'ins_1', institutionName: 'Chase' });
  await handleWebhook({ webhook_type: 'ITEM', webhook_code: 'ERROR', item_id: 'item_w', environment: 'production',
    error: { error_type: 'ITEM_ERROR', error_code: 'ITEM_LOGIN_REQUIRED', display_message: 'Robert Lawson' } }, { store, syncItem: async () => {}, log });
  const l = JSON.parse(lines.find(x => x.includes('plaid_webhook')));
  assert.deepEqual([l.item_id, l.error_code, l.user_ref], ['item_w', 'ITEM_LOGIN_REQUIRED', userRef('uidW')]);
  assertClean(lines.join('\n'));
  assert.deepEqual(plaidWebhookFields({ webhook_type: 'LINK', webhook_code: 'SESSION_FINISHED', link_session_id: 'ls-9' }).link_session_id, 'ls-9');
});

test('exchange route with X-Link-Session-Id + junk body link_session_id never logs tokens or emails', async () => {
  const { lines, log } = captureLog();
  const config = testConfig({ AUTH_MODE: 'app_jwt' });
  const plaid = instrumentPlaid(fakePlaid({
    linkTokenCreate: () => ({ link_token: SECRETS[2], request_id: 'req_lt' }),
  }), log);
  const app = createApp({ config, store: new MemoryStore(), plaid, log, tokenVerifier: createTokenVerifier(config.auth),
    webhookVerifier: async () => {}, syncItem: async () => {} });
  // Bad body field is ignored safely; header is honored on any Plaid route.
  await request(app).post('/api/plaid/exchange-public-token').set('X-Link-Session-Id', 'ls-hdr-1')
    .send({ public_token: SECRETS[1], link_session_id: 'robert@example.com' });
  assertClean(lines.join('\n'));
  void JWT_SECRET;
});
