import { loadConfig } from '../src/config.js';
import { createApp } from '../src/app.js';
import { createTokenVerifier } from '../src/auth.js';
import { MemoryStore } from '../src/store.js';
import { silentLog } from '../src/log.js';

export const JWT_SECRET = 'test-secret-that-is-at-least-32-characters-long';

export function testConfig(extra = {}) {
  return loadConfig({
    PLAID_ENV: 'sandbox', PLAID_CLIENT_ID: 'cid', PLAID_SECRET: 'sec',
    APP_JWT_SECRET: JWT_SECRET, PLAID_WEBHOOK_URL: 'https://example.com/api/plaid/webhook',
    PLAID_REDIRECT_URI: 'https://example.com/plaid/oauth-redirect', ...extra,
  }).config;
}

export function fakePlaid(handlers = {}) {
  const calls = [];
  return {
    calls,
    async call(method, req) {
      calls.push({ method, req });
      if (handlers[method]) return handlers[method](req);
      throw new Error(`unexpected plaid call ${method}`);
    },
  };
}

export function buildApp({ config = testConfig(), store = new MemoryStore(), plaid = fakePlaid(), webhookVerifier, syncItem, googlePlay = null, pubsubVerifier = null } = {}) {
  const app = createApp({
    config, store, plaid, log: silentLog, googlePlay, pubsubVerifier,
    tokenVerifier: createTokenVerifier(config.auth),
    webhookVerifier: webhookVerifier || (async () => { throw new Error('no verifier'); }),
    syncItem: syncItem || (async item => ({ item_id: item.itemId })),
  });
  return { app, store, plaid, config };
}
