import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { encryptToken, decryptToken, isEncrypted, parseEncryptionKey, TOKEN_PREFIX } from '../src/crypto.js';
import { MemoryStore } from '../src/store.js';

const key = crypto.randomBytes(32);

test('AES-256-GCM round trip with enc:v1 prefix and random IV', () => {
  const token = 'access-sandbox-12345678-aaaa-bbbb-cccc-1234567890ab';
  const a = encryptToken(token, key), b = encryptToken(token, key);
  assert.ok(a.startsWith(TOKEN_PREFIX));
  assert.notEqual(a, b);
  assert.ok(!a.includes(token));
  assert.equal(decryptToken(a, key), token);
  assert.equal(encryptToken(a, key), a, 'already-encrypted values are not double-encrypted');
});

test('tampering or wrong key fails authentication', () => {
  const enc = encryptToken('access-sandbox-x', key);
  const parts = enc.split(':');
  const ct = Buffer.from(parts[4], 'base64'); ct[0] ^= 1; parts[4] = ct.toString('base64');
  assert.throws(() => decryptToken(parts.join(':'), key));
  assert.throws(() => decryptToken(enc, crypto.randomBytes(32)));
});

test('legacy plaintext is passed through (migrated on boot)', () => {
  assert.equal(isEncrypted('access-sandbox-x'), false);
  assert.equal(decryptToken('access-sandbox-x', key), 'access-sandbox-x');
});

test('parseEncryptionKey requires exactly 32 bytes', () => {
  assert.equal(parseEncryptionKey(key.toString('base64')).length, 32);
  assert.deepEqual(parseEncryptionKey(key.toString('hex')), key);
  assert.throws(() => parseEncryptionKey(crypto.randomBytes(31).toString('base64')));
});

test('store keeps tokens encrypted at rest and returns plaintext to the server only', async () => {
  const store = new MemoryStore(key);
  const U1 = 'FirebaseUidOwner0000000000A1', U2 = 'FirebaseUidOther0000000000B2';
  await store.putItem({ userId: U1, itemId: 'i1', accessToken: 'access-sandbox-secret' });
  assert.ok(isEncrypted(store.items.get('i1').access_token));
  assert.equal((await store.getItems(U1))[0].accessToken, 'access-sandbox-secret');
  // Another Firebase user cannot take over an existing item_id.
  await store.putItem({ userId: U2, itemId: 'i1', accessToken: 'access-sandbox-other' });
  assert.equal((await store.getItems(U1)).length, 1);
  assert.equal((await store.getItems(U2)).length, 0);
});

test('an item held by a legacy (pre-Firebase) identity moves to the verified user on relink', async () => {
  const store = new MemoryStore(key);
  const U = 'FirebaseUidOwner0000000000A1';
  await store.putItem({ userId: 'payaviator-local-user', itemId: 'i9', accessToken: 'access-old' });
  await store.putItem({ userId: U, itemId: 'i9', accessToken: 'access-new' });
  assert.equal((await store.getItems('payaviator-local-user')).length, 0);
  assert.equal((await store.getItems(U))[0].accessToken, 'access-new');
});
