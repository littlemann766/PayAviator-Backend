import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact } from '../src/log.js';
import { isLegacyUserId } from '../src/legacy.js';

test('log redaction strips tokens, JWTs, encrypted values and payload fields', () => {
  const out = JSON.stringify(redact({
    error_message: 'provided access-sandbox-1234abcd-ef56-7890 and public-production-aaaa-bbbb invalid',
    note: 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.sig and enc:v1:aaa:bbb:ccc',
    access_token: 'anything', transactions: [{ amount: 12.5, name: 'Coffee' }], payload: { x: 1 },
    nested: { link_token: 'link-sandbox-zzz' },
    user_id: 'AbCdEfGhIjKlMnOpQrStUvWxYz12', item_id: 'item-1', request_id: 'req-1',
  }));
  for (const leaked of ['1234abcd', 'aaaa-bbbb', 'eyJhbGci', 'aaa:bbb', 'anything', 'Coffee', 'zzz']) assert.ok(!out.includes(leaked), `leaked ${leaked}`);
  for (const kept of ['AbCdEfGhIjKlMnOpQrStUvWxYz12', 'item-1', 'req-1']) assert.ok(out.includes(kept));
});

test('legacy user id detection', () => {
  for (const id of ['pp-lq2x9k-abc123def4', 'ppd_Ab12Cd34Ef56Gh78Ij90Kl12', 'payaviator-local-user', '', null, 'short']) assert.equal(isLegacyUserId(id), true, String(id));
  for (const id of ['kX3vT9qLmN2pR7sW1yZ4bC6dE8fG', 'AbCdEfGhIjKlMnOpQrStUvWxYz12']) assert.equal(isLegacyUserId(id), false, id);
});
