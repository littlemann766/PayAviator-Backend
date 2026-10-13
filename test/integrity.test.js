import { test } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import { SignJWT } from 'jose';
import { buildApp, fakePlaid, testConfig, JWT_SECRET } from './helpers.js';
import { expectedRequestHash, checkVerdict, INTEGRITY_MAX_AGE_MS } from '../src/integrity.js';

const SA = JSON.stringify({ type: 'service_account', client_email: 'x@y.iam.gserviceaccount.com', private_key: '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n' });
const PKG = 'app.payaviator';
const DEV = 'a1b2c3d4e5f60718';
const cfg = (extra = {}) => testConfig({ GOOGLE_PLAY_SERVICE_ACCOUNT_JSON: SA, ANDROID_PACKAGE_NAME: PKG, PLAY_INTEGRITY_ENFORCE: 'true', ...extra });
const token = sub => new SignJWT({ email_verified: true }).setProtectedHeader({ alg: 'HS256' }).setSubject(sub).setIssuedAt().setExpirationTime('5m').sign(new TextEncoder().encode(JWT_SECRET));
const future = () => new Date(Date.now() + 30 * 86400e3).toISOString();

const good = (uid = 'u1', over = {}) => ({
  requestDetails: { requestPackageName: PKG, timestampMillis: String(Date.now()), requestHash: expectedRequestHash(DEV, uid), ...over.rd },
  appIntegrity: { appRecognitionVerdict: 'PLAY_RECOGNIZED', packageName: PKG, ...over.app },
  deviceIntegrity: { deviceRecognitionVerdict: ['MEETS_DEVICE_INTEGRITY'], ...over.dev },
});
const mockIntegrity = payload => { const calls = []; return { calls, async decode(t) { calls.push(t); if (payload instanceof Error) throw payload; return payload; } }; };
const plaid = () => fakePlaid({ linkTokenCreate: async () => ({ link_token: 'link-x' }) });
const link = async (app, { uid = 'u1', dev = DEV, itok } = {}) => {
  const r = request(app).post('/api/plaid/create-link-token').set('Authorization', `Bearer ${await token(uid)}`);
  if (dev) r.set('X-Device-Id', dev);
  if (itok) r.set('X-Play-Integrity-Token', itok);
  return r.send({});
};

test('requestHash formula: sha256 hex of lower(androidId)|uid', () => {
  assert.equal(expectedRequestHash('A1B2C3D4E5F60718', 'u1'), expectedRequestHash('a1b2c3d4e5f60718', 'u1'));
  assert.match(expectedRequestHash(DEV, 'u1'), /^[0-9a-f]{64}$/);
  assert.notEqual(expectedRequestHash(DEV, 'u1'), expectedRequestHash(DEV, 'u2'));
});

test('device id must be 16 hex chars -> 400 device_id_invalid', async () => {
  const { app } = buildApp({ plaid: plaid() });
  for (const bad of ['device-aaaa1111', 'abc', 'a1b2c3d4e5f6071g', 'a1b2c3d4e5f607189', '9774d56d682e549c ' + 'x']) {
    const r = await link(app, { dev: bad });
    assert.equal(r.status, 400, bad); assert.equal(r.body.error, 'device_id_invalid');
  }
  assert.equal((await link(app, { dev: 'A1B2C3D4E5F60718' })).status, 200);
});

test('device id is case-insensitive for the per-device slot', async () => {
  const { app, store } = buildApp({ plaid: plaid() });
  await store.claimFreeTier('u1', 'i1', [(await import('../src/freeTier.js')).deviceFingerprint(testConfig().freeTier.secret, DEV)]);
  const r = await link(app, { uid: 'u2', dev: DEV.toUpperCase() });
  assert.equal(r.status, 402); assert.equal(r.body.reason, 'device_already_used_free');
});

test('enforce off: token ignored, decode never called', async () => {
  const integ = mockIntegrity(new Error('should not be called'));
  const { app } = buildApp({ config: cfg({ PLAY_INTEGRITY_ENFORCE: 'false' }), plaid: plaid(), integrity: integ });
  assert.equal((await link(app, { itok: 'junk' })).status, 200);
  assert.equal((await link(app)).status, 200);
  assert.equal(integ.calls.length, 0);
});

test('enforce on but Play not configured -> 503 integrity_not_configured', async () => {
  const { app } = buildApp({ config: testConfig({ PLAY_INTEGRITY_ENFORCE: 'true' }), plaid: plaid(), integrity: mockIntegrity(good()) });
  const r = await link(app, { itok: 't' });
  assert.equal(r.status, 503); assert.equal(r.body.error, 'integrity_not_configured');
  const { app: app2 } = buildApp({ config: cfg(), plaid: plaid(), integrity: null });
  assert.equal((await link(app2, { itok: 't' })).status, 503);
});

test('enforce on: valid verdict links', async () => {
  const integ = mockIntegrity(good());
  const { app } = buildApp({ config: cfg(), plaid: plaid(), integrity: integ });
  assert.equal((await link(app, { itok: 'tok-1' })).status, 200);
  assert.deepEqual(integ.calls, ['tok-1']);
});

test('enforce on: missing token / decode error -> 403', async () => {
  let { app } = buildApp({ config: cfg(), plaid: plaid(), integrity: mockIntegrity(good()) });
  let r = await link(app); assert.equal(r.status, 403); assert.equal(r.body.error, 'integrity_failed'); assert.equal(r.body.reason, 'token_missing');
  ({ app } = buildApp({ config: cfg(), plaid: plaid(), integrity: mockIntegrity(new Error('400 bad token')) }));
  r = await link(app, { itok: 'x' }); assert.equal(r.status, 403); assert.equal(r.body.reason, 'token_invalid');
  r = await link(app, { itok: 'x'.repeat(9000) }); assert.equal(r.body.reason, 'token_invalid');
});

const failures = [
  ['app_not_recognized', { app: { appRecognitionVerdict: 'UNRECOGNIZED_VERSION' } }],
  ['device_integrity_failed', { dev: { deviceRecognitionVerdict: ['MEETS_BASIC_INTEGRITY'] } }],
  ['device_integrity_failed', { dev: { deviceRecognitionVerdict: undefined } }],
  ['package_mismatch', { rd: { requestPackageName: 'com.evil' } }],
  ['package_mismatch', { app: { packageName: 'com.evil' } }],
  ['stale_token', { rd: { timestampMillis: String(Date.now() - INTEGRITY_MAX_AGE_MS - 1000) } }],
  ['stale_token', { rd: { timestampMillis: 'nope' } }],
  ['request_hash_mismatch', { rd: { requestHash: expectedRequestHash('ffffffffffffffff', 'u1') } }],
];
for (const [reason, over] of failures) {
  test(`enforce on: ${reason} -> 403`, async () => {
    const { app } = buildApp({ config: cfg(), plaid: plaid(), integrity: mockIntegrity(good('u1', over)) });
    const r = await link(app, { itok: 't' });
    assert.equal(r.status, 403); assert.equal(r.body.error, 'integrity_failed'); assert.equal(r.body.reason, reason);
  });
}

test('verdict for another uid is rejected (request_hash_mismatch)', async () => {
  const { app } = buildApp({ config: cfg(), plaid: plaid(), integrity: mockIntegrity(good('someoneElse')) });
  assert.equal((await link(app, { itok: 't' })).body.reason, 'request_hash_mismatch');
});

test('integrity also enforced on exchange-public-token', async () => {
  const { app } = buildApp({ config: cfg(), plaid: plaid(), integrity: mockIntegrity(good()) });
  const r = await request(app).post('/api/plaid/exchange-public-token').set('Authorization', `Bearer ${await token('u1')}`).set('X-Device-Id', DEV).send({ public_token: 'public-x' });
  assert.equal(r.status, 403); assert.equal(r.body.reason, 'token_missing');
});

test('subscribers skip integrity (even unconfigured)', async () => {
  const integ = mockIntegrity(new Error('nope'));
  const { app, store } = buildApp({ config: testConfig({ PLAY_INTEGRITY_ENFORCE: 'true' }), plaid: plaid(), integrity: integ });
  await store.putEntitlement({ tokenHash: 'h', userId: 'u1', productId: 'p', state: 'SUBSCRIPTION_STATE_ACTIVE', expiresAt: future() });
  assert.equal((await link(app, { dev: null })).status, 200);
  assert.equal(integ.calls.length, 0);
});

test('checkVerdict rejects null payload and future timestamps', () => {
  assert.equal(checkVerdict(null, { packageName: PKG, deviceId: DEV, uid: 'u1' }), 'package_mismatch');
  assert.equal(checkVerdict(good('u1', { rd: { timestampMillis: String(Date.now() + 120_000) } }), { packageName: PKG, deviceId: DEV, uid: 'u1' }), 'stale_token');
  assert.equal(checkVerdict(good(), { packageName: PKG, deviceId: DEV, uid: 'u1' }), null);
});

test('config: PLAY_INTEGRITY_ENFORCE parsing', () => {
  assert.equal(cfg().integrity.enforce, true);
  assert.equal(cfg({ PLAY_INTEGRITY_ENFORCE: '' }).integrity.enforce, false);
  assert.equal(cfg({ PLAY_INTEGRITY_ENFORCE: '1' }).integrity.enforce, false);
  assert.equal(testConfig({ PLAY_INTEGRITY_ENFORCE: 'true' }).integrity.configured, false);
});
