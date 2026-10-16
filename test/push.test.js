import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import request from 'supertest';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createWebhookVerifier } from '../src/webhookVerify.js';
import { MemoryStore } from '../src/store.js';
import { redact } from '../src/log.js';
import { loadConfig } from '../src/config.js';
import { createReconnectNotifier, reconnectMessage, isValidFcmToken, RECONNECT_PUSH } from '../src/push.js';
import { buildApp, testConfig, JWT_SECRET } from './helpers.js';

const sign = (sub) => new SignJWT({}).setProtectedHeader({ alg: 'HS256' }).setSubject(sub).setIssuedAt().setExpirationTime('5m')
  .sign(new TextEncoder().encode(JWT_SECRET));
const fakeToken = (n = 1) => `fakeInstance${n}:APA91bFAKEFAKEFAKEFAKE${'x'.repeat(40)}${n}`;

const { publicKey, privateKey } = await generateKeyPair('ES256');
const jwk = { ...(await exportJWK(publicKey)), kid: 'kid-p', alg: 'ES256', use: 'sig', created_at: 1, expired_at: null };
const verifier = createWebhookVerifier({ fetchKey: async () => jwk });
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const signBody = b => new SignJWT({ request_body_sha256: sha(b) }).setProtectedHeader({ alg: 'ES256', kid: 'kid-p', typ: 'JWT' }).setIssuedAt().sign(privateKey);

function capLog() {
  const lines = [];
  const mk = level => (msg, fields = {}) => lines.push({ level, msg, ...redact(fields) });
  return { lines, info: mk('info'), warn: mk('warn'), error: mk('error') };
}

function mockMessaging(handler) {
  const sent = [];
  return {
    sent,
    async sendEachForMulticast(msg) {
      sent.push(msg);
      if (handler) return handler(msg);
      return { successCount: msg.tokens.length, failureCount: 0, responses: msg.tokens.map(() => ({ success: true })) };
    },
  };
}

test('token validation', () => {
  assert.ok(isValidFcmToken(fakeToken()));
  for (const bad of [undefined, null, 5, '', 'short', 'has space '.repeat(5), 'x'.repeat(4097), `${'a'.repeat(30)}<script>`]) assert.equal(isValidFcmToken(bad), false);
});

test('POST/DELETE /api/devices/fcm: auth, validation, upsert, cap, unregister', async () => {
  const store = new MemoryStore();
  const { app } = buildApp({ store, config: testConfig({ FCM_MAX_TOKENS_PER_USER: '3' }) });
  assert.equal((await request(app).post('/api/devices/fcm').send({ token: fakeToken() })).status, 401);
  const auth = `Bearer ${await sign('user-1')}`;
  const bad = await request(app).post('/api/devices/fcm').set('Authorization', auth).send({ token: 'nope' });
  assert.equal(bad.status, 400); assert.equal(bad.body.code, 'INVALID_FCM_TOKEN');
  const badPlat = await request(app).post('/api/devices/fcm').set('Authorization', auth).send({ token: fakeToken(), platform: 'blackberry' });
  assert.equal(badPlat.status, 400); assert.equal(badPlat.body.code, 'INVALID_PLATFORM');

  const ok = await request(app).post('/api/devices/fcm').set('Authorization', auth).send({ token: fakeToken(1) });
  assert.equal(ok.status, 200);
  assert.deepEqual(ok.body, { registered: true, devices: 1, max_devices: 3, push_configured: false });
  // re-register is idempotent
  assert.equal((await request(app).post('/api/devices/fcm').set('Authorization', auth).send({ token: fakeToken(1), platform: 'android' })).body.devices, 1);
  for (const n of [2, 3, 4]) await request(app).post('/api/devices/fcm').set('Authorization', auth).send({ token: fakeToken(n) });
  const toks = await store.getFcmTokens('user-1');
  assert.equal(toks.length, 3); assert.ok(!toks.includes(fakeToken(1)), 'oldest evicted');

  // token moves to another account when that user signs in on the same phone
  const auth2 = `Bearer ${await sign('user-2')}`;
  await request(app).post('/api/devices/fcm').set('Authorization', auth2).send({ token: fakeToken(4) });
  assert.deepEqual(await store.getFcmTokens('user-2'), [fakeToken(4)]);
  assert.ok(!(await store.getFcmTokens('user-1')).includes(fakeToken(4)));

  // user-2 cannot unregister user-1's token
  assert.equal((await request(app).delete('/api/devices/fcm').set('Authorization', auth2).send({ token: fakeToken(2) })).body.removed, false);
  const del = await request(app).delete('/api/devices/fcm').set('Authorization', auth).send({ token: fakeToken(2) });
  assert.equal(del.status, 200); assert.deepEqual(del.body, { unregistered: true, removed: true });
  assert.equal((await request(app).delete('/api/devices/fcm').set('Authorization', auth).send({})).status, 400);
});

test('DELETE /api/devices/fcm: accepts ?token= when body has none; still owner-only', async () => {
  const store = new MemoryStore();
  const { app } = buildApp({ store });
  const auth = `Bearer ${await sign('user-1')}`;
  const auth2 = `Bearer ${await sign('user-2')}`;
  const tok = fakeToken(9);
  await request(app).post('/api/devices/fcm').set('Authorization', auth).send({ token: tok });
  // query-only unregister
  const delQ = await request(app).delete(`/api/devices/fcm?token=${encodeURIComponent(tok)}`).set('Authorization', auth);
  assert.equal(delQ.status, 200);
  assert.deepEqual(delQ.body, { unregistered: true, removed: true });
  assert.deepEqual(await store.getFcmTokens('user-1'), []);
  // re-register, then other user cannot remove via query
  await request(app).post('/api/devices/fcm').set('Authorization', auth).send({ token: tok });
  assert.equal((await request(app).delete(`/api/devices/fcm?token=${encodeURIComponent(tok)}`).set('Authorization', auth2)).body.removed, false);
  assert.deepEqual(await store.getFcmTokens('user-1'), [tok]);
  // body wins over query when both present
  const other = fakeToken(8);
  await request(app).post('/api/devices/fcm').set('Authorization', auth).send({ token: other });
  const delBoth = await request(app).delete(`/api/devices/fcm?token=${encodeURIComponent(tok)}`).set('Authorization', auth).send({ token: other });
  assert.equal(delBoth.status, 200);
  assert.equal(delBoth.body.removed, true);
  assert.ok((await store.getFcmTokens('user-1')).includes(tok), 'query token not removed when body token present');
  assert.ok(!(await store.getFcmTokens('user-1')).includes(other));
  // empty body + missing query still 400
  assert.equal((await request(app).delete('/api/devices/fcm').set('Authorization', auth).send({})).status, 400);
  // invalid query token
  assert.equal((await request(app).delete('/api/devices/fcm?token=nope').set('Authorization', auth)).status, 400);
});

test('device routes work even when Plaid is not configured', async () => {
  const { app } = buildApp({ config: testConfig({ PLAID_CLIENT_ID: '', PLAID_SECRET: '' }) });
  const r = await request(app).post('/api/devices/fcm').set('Authorization', `Bearer ${await sign('u')}`).send({ token: fakeToken() });
  assert.equal(r.status, 200);
});

test('account deletion removes FCM tokens', async () => {
  const store = new MemoryStore();
  const { app } = buildApp({ store });
  const auth = `Bearer ${await sign('user-1')}`;
  await request(app).post('/api/devices/fcm').set('Authorization', auth).send({ token: fakeToken() });
  assert.equal((await request(app).delete('/api/plaid/user').set('Authorization', auth)).status, 200);
  assert.deepEqual(await store.getFcmTokens('user-1'), []);
});

test('payload is generic: no amounts, account numbers or bank names', () => {
  const m = reconnectMessage([fakeToken()], { itemId: 'item-1', reason: 'ITEM_LOGIN_REQUIRED' });
  assert.deepEqual(m.notification, { title: RECONNECT_PUSH.title, body: RECONNECT_PUSH.body });
  assert.deepEqual(m.data, { type: 'bank_reconnect', item_id: 'item-1', reason: 'ITEM_LOGIN_REQUIRED' });
  assert.equal(m.android.notification.channelId, 'bank_reconnect');
  assert.doesNotMatch(JSON.stringify(m), /\$|\d{4,}|balance|amount|Chase/i);
});

test('webhooks send one push per item per 24h to all devices; others do not push', async () => {
  const store = new MemoryStore();
  const messaging = mockMessaging();
  let clock = 1_000_000_000_000;
  const log = capLog();
  const notifyReconnect = createReconnectNotifier({ store, messaging, log, now: () => clock });
  const { app } = buildApp({ store, webhookVerifier: verifier, notifyReconnect });
  await store.putItem({ userId: 'user-1', itemId: 'item-1', accessToken: 'a1', institutionName: 'Chase' });
  await store.upsertFcmToken('user-1', fakeToken(1), 'android', 10);
  await store.upsertFcmToken('user-1', fakeToken(2), 'android', 10);
  const hook = async obj => {
    const b = JSON.stringify(obj);
    const r = await request(app).post('/api/plaid/webhook').set('Content-Type', 'application/json').set('Plaid-Verification', await signBody(b)).send(b);
    assert.equal(r.status, 200);
    await new Promise(r2 => setImmediate(r2));
  };
  await hook({ webhook_type: 'ITEM', webhook_code: 'ERROR', item_id: 'item-1', error: { error_code: 'ITEM_LOGIN_REQUIRED' } });
  assert.equal(messaging.sent.length, 1);
  assert.equal(messaging.sent[0].tokens.length, 2);
  assert.equal(messaging.sent[0].data.item_id, 'item-1');
  assert.equal((await store.getItemById('item-1')).status, 'login_required');

  await hook({ webhook_type: 'ITEM', webhook_code: 'PENDING_EXPIRATION', item_id: 'item-1' });
  assert.equal(messaging.sent.length, 1, 'deduped within 24h');
  clock += 24 * 3600 * 1000 + 1;
  await hook({ webhook_type: 'ITEM', webhook_code: 'PENDING_DISCONNECT', item_id: 'item-1' });
  assert.equal(messaging.sent.length, 2);
  assert.equal(messaging.sent[1].data.reason, 'PENDING_DISCONNECT');

  clock += 25 * 3600 * 1000;
  await hook({ webhook_type: 'ITEM', webhook_code: 'ERROR', item_id: 'item-1', error: { error_code: 'INSTITUTION_DOWN' } });
  await hook({ webhook_type: 'ITEM', webhook_code: 'LOGIN_REPAIRED', item_id: 'item-1' });
  await hook({ webhook_type: 'TRANSACTIONS', webhook_code: 'SYNC_UPDATES_AVAILABLE', item_id: 'item-1' });
  await hook({ webhook_type: 'ITEM', webhook_code: 'PENDING_EXPIRATION', item_id: 'unknown-item' });
  assert.equal(messaging.sent.length, 2, 'non-reconnect webhooks and unknown items do not push');
  assert.doesNotMatch(JSON.stringify(log.lines), /APA91/, 'tokens never logged');
});

test('dead tokens are removed; total failure frees the dedupe slot', async () => {
  const store = new MemoryStore();
  await store.putItem({ userId: 'u', itemId: 'i', accessToken: 'a' });
  for (const n of [1, 2, 3]) await store.upsertFcmToken('u', fakeToken(n), 'android', 10);
  const log = capLog();
  const messaging = mockMessaging(msg => ({
    successCount: 0, failureCount: 3,
    responses: msg.tokens.map(t => ({ success: false, error: { code: t === fakeToken(3) ? 'messaging/internal-error' : (t === fakeToken(1) ? 'messaging/registration-token-not-registered' : 'messaging/invalid-registration-token') } })),
  }));
  const notify = createReconnectNotifier({ store, messaging, log });
  const item = await store.getItemById('i');
  assert.equal(await notify(item, 'ITEM_LOGIN_REQUIRED'), 'all_failed');
  assert.deepEqual(await store.getFcmTokens('u'), [fakeToken(3)]);
  assert.equal(await store.claimPushSlot('i', 1000), true, 'slot released after total failure');
  assert.doesNotMatch(JSON.stringify(log.lines), /APA91/);

  const throwing = { async sendEachForMulticast() { throw Object.assign(new Error('boom'), { code: 'app/network-error' }); } };
  await store.releasePushSlot('i');
  assert.equal(await createReconnectNotifier({ store, messaging: throwing, log })(item, 'PENDING_EXPIRATION'), 'send_error');
  assert.equal(await store.claimPushSlot('i', 1000), true);
});

test('not configured or no devices: logged and skipped, webhook still 200', async () => {
  const store = new MemoryStore();
  await store.putItem({ userId: 'u', itemId: 'i', accessToken: 'a' });
  const { app } = buildApp({ store, webhookVerifier: verifier }); // notifyReconnect = null
  const b = JSON.stringify({ webhook_type: 'ITEM', webhook_code: 'PENDING_EXPIRATION', item_id: 'i' });
  assert.equal((await request(app).post('/api/plaid/webhook').set('Content-Type', 'application/json').set('Plaid-Verification', await signBody(b)).send(b)).status, 200);
  const log = capLog();
  assert.equal(await createReconnectNotifier({ store, messaging: null, log })(await store.getItemById('i'), 'X'), 'not_configured');
  assert.equal(await createReconnectNotifier({ store, messaging: mockMessaging(), log })(await store.getItemById('i'), 'X'), 'no_devices');
  // store failure inside the notifier never throws
  const broken = { getFcmTokens: async () => { throw new Error('db down'); } };
  assert.equal(await createReconnectNotifier({ store: broken, messaging: mockMessaging(), log })({ userId: 'u', itemId: 'i' }, 'X'), 'error');
});

test('log redaction covers FCM tokens', () => {
  const t = fakeToken();
  assert.equal(redact({ fcm_token: t }).fcm_token, '[REDACTED]');
  assert.doesNotMatch(redact(`sending to ${t}`), /APA91/);
});

test('config: push needs a Firebase service account + project id', () => {
  const base = { PLAID_ENV: 'sandbox', APP_JWT_SECRET: JWT_SECRET };
  assert.equal(loadConfig(base).config.push.configured, false);
  const sa = JSON.stringify({ client_email: 'x@y.iam.gserviceaccount.com', private_key: 'k', project_id: 'payaviator' });
  const c = loadConfig({ ...base, FIREBASE_SERVICE_ACCOUNT_JSON: sa }).config.push;
  assert.equal(c.configured, true); assert.equal(c.projectId, 'payaviator'); assert.equal(c.maxTokensPerUser, 10);
  assert.equal(loadConfig({ ...base, FIREBASE_SERVICE_ACCOUNT_JSON: '{bad' }).config.push.configured, false);
  assert.equal(loadConfig({ ...base, GOOGLE_PLAY_SERVICE_ACCOUNT_JSON: sa }).config.push.configured, false, 'Play key not reused unless opted in');
  assert.equal(loadConfig({ ...base, GOOGLE_PLAY_SERVICE_ACCOUNT_JSON: sa, FCM_USE_PLAY_SERVICE_ACCOUNT: 'true' }).config.push.configured, true);
});
