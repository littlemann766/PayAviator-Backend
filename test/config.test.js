import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { loadConfig, ConfigError } from '../src/config.js';

const key = crypto.randomBytes(32).toString('base64');
const prodEnv = {
  PLAID_ENV: 'production', PLAID_CLIENT_ID: 'cid', PLAID_SECRET: 'sec',
  DATABASE_URL: 'postgres://u:p@db.example.com:5432/app', TOKEN_ENCRYPTION_KEY: key,
  PLAID_WEBHOOK_URL: 'https://api.example.com/api/plaid/webhook',
  PLAID_REDIRECT_URI: 'https://api.example.com/plaid/oauth-redirect',
  FIREBASE_PROJECT_ID: 'payaviator',
};

test('invalid PLAID_ENV fails fast', () => {
  assert.throws(() => loadConfig({ PLAID_ENV: 'development', AUTH_DISABLED: 'true' }), e => e instanceof ConfigError && /PLAID_ENV/.test(e.message));
  assert.throws(() => loadConfig({ PLAID_ENV: 'prod', AUTH_DISABLED: 'true' }), ConfigError);
});

test('PLAID_ENV defaults to sandbox', () => {
  const { config } = loadConfig({ AUTH_DISABLED: 'true' });
  assert.equal(config.plaid.env, 'sandbox');
  assert.equal(config.plaid.basePath, 'https://sandbox.plaid.com');
});

test('valid production config loads with TLS verification on', () => {
  const { config } = loadConfig(prodEnv);
  assert.equal(config.plaid.basePath, 'https://production.plaid.com');
  assert.equal(config.auth.mode, 'firebase');
  assert.equal(config.db.ssl.rejectUnauthorized, true);
  assert.equal(config.plaid.daysRequested, 730);
});

test('production requires db, key, webhook, redirect and auth', () => {
  for (const missing of ['DATABASE_URL', 'TOKEN_ENCRYPTION_KEY', 'PLAID_WEBHOOK_URL', 'PLAID_REDIRECT_URI', 'FIREBASE_PROJECT_ID', 'PLAID_SECRET']) {
    const env = { ...prodEnv };
    delete env[missing];
    assert.throws(() => loadConfig(env), ConfigError, `expected failure without ${missing}`);
  }
});

test('AUTH_DISABLED is refused in production', () => {
  const env = { ...prodEnv, AUTH_DISABLED: 'true' };
  delete env.FIREBASE_PROJECT_ID;
  assert.throws(() => loadConfig(env), /AUTH_DISABLED/);
});

test('no auth config fails even in sandbox', () => {
  assert.throws(() => loadConfig({ PLAID_ENV: 'sandbox' }), /No auth configured/);
});

test('bad encryption key and DATABASE_URL without key are rejected', () => {
  assert.throws(() => loadConfig({ AUTH_DISABLED: 'true', TOKEN_ENCRYPTION_KEY: Buffer.alloc(16).toString('base64') }), /32 bytes/);
  assert.throws(() => loadConfig({ AUTH_DISABLED: 'true', DATABASE_URL: 'postgres://x/y' }), /TOKEN_ENCRYPTION_KEY/);
});

test('days_requested is validated and DB TLS escape hatch warns', () => {
  assert.throws(() => loadConfig({ AUTH_DISABLED: 'true', PLAID_TRANSACTIONS_DAYS_REQUESTED: '900' }), /DAYS_REQUESTED/);
  const { config, warnings } = loadConfig({ ...prodEnv, DATABASE_SSL_REJECT_UNAUTHORIZED: 'false' });
  assert.equal(config.db.ssl.rejectUnauthorized, false);
  assert.ok(warnings.some(w => /NOT verified/.test(w)));
});

test('non-https webhook URL rejected', () => {
  assert.throws(() => loadConfig({ ...prodEnv, PLAID_WEBHOOK_URL: 'http://insecure.example.com/hook' }), /https/);
});

test('DB TLS: certificate verification defaults to on in production when DATABASE_SSL_REJECT_UNAUTHORIZED is unset or empty', () => {
  for (const v of [undefined, '', 'true', '1', 'yes']) {
    const env = { ...prodEnv };
    if (v !== undefined) env.DATABASE_SSL_REJECT_UNAUTHORIZED = v;
    const { config, warnings } = loadConfig(env);
    assert.equal(config.db.ssl.rejectUnauthorized, true, `value ${JSON.stringify(v)}`);
    assert.ok(!warnings.some(w => /NOT verified/.test(w)));
  }
  // With a pinned CA, verification stays on unless explicitly disabled.
  const ca = Buffer.from('-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----').toString('base64');
  assert.equal(loadConfig({ ...prodEnv, DATABASE_SSL_CA: ca }).config.db.ssl.rejectUnauthorized, true);
  assert.match(loadConfig({ ...prodEnv, DATABASE_SSL_CA: ca }).config.db.ssl.ca, /BEGIN CERTIFICATE/);
  // PGSSL=disable turns TLS off entirely (only intended for *.railway.internal).
  assert.equal(loadConfig({ ...prodEnv, PGSSL: 'disable', DATABASE_URL: 'postgres://u:p@postgres.railway.internal:5432/railway' }).config.db.ssl, false);
});
