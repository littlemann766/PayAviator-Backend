import 'dotenv/config';
import { loadConfig, ConfigError } from './src/config.js';
import { log } from './src/log.js';
import { createTokenVerifier } from './src/auth.js';
import { createPlaidClient } from './src/plaid.js';
import { instrumentPlaid } from './src/plaidLog.js';
import { createWebhookVerifier } from './src/webhookVerify.js';
import { PgStore, MemoryStore } from './src/store.js';
import { createSyncer } from './src/sync.js';
import { createApp } from './src/app.js';
import { createMessagingClient, createReconnectNotifier } from './src/push.js';
import { createIntegrityClient } from './src/integrity.js';
import { createGooglePlayClient, createPubSubVerifier } from './src/billing.js';

let config, warnings;
try {
  ({ config, warnings } = loadConfig(process.env));
} catch (e) {
  if (e instanceof ConfigError) {
    console.error(e.message);
    process.exit(1);
  }
  throw e;
}
for (const w of warnings) log.warn(w);

const plaid = instrumentPlaid(createPlaidClient(config.plaid, { log }), log); // one plaid_api JSON line per call

let store;
let dbReady = false;
let storageKind = 'memory';
if (config.db) {
  const pgStore = new PgStore(config.db, config.tokenEncryptionKey, { log });
  try {
    await pgStore.init();
    store = pgStore;
    dbReady = true;
    storageKind = 'postgres';
    log.info('database ready');
  } catch (e) {
    if (config.isProduction) {
      log.error('database unavailable in production; refusing to start with in-memory storage', { error_message: e.message });
      process.exit(1);
    }
    log.warn('database unavailable; using in-memory storage (sandbox only)', { error_message: e.message });
    await pgStore.close().catch(() => {});
  }
}
if (!store) {
  if (config.isProduction) { log.error('in-memory storage is not allowed in production'); process.exit(1); }
  store = new MemoryStore(config.tokenEncryptionKey);
  storageKind = config.db ? 'memory-fallback' : 'memory';
}

const tokenVerifier = createTokenVerifier(config.auth);
const webhookVerifier = createWebhookVerifier({
  fetchKey: async kid => (await plaid.call('webhookVerificationKeyGet', { key_id: kid })).key,
});
const syncItem = createSyncer({ store, plaid, log });

if (!config.freeTier.configured) log.error('FREE_TIER_FINGERPRINT_SECRET missing/invalid: free-tier bank links return 503 free_tier_not_configured (subscribers unaffected)');
// Purge free-tier hashes whose 30-day (FREE_TIER_COOLDOWN_DAYS) cooldown has ended: on startup and daily.
const purgeFreeTier = () => store.purgeFreeTier(config.freeTier.cooldownDays)
  .then(n => { if (n) log.info('purged expired free-tier hashes', { count: n }); })
  .catch(e => log.error('free-tier purge failed', { error_message: e.message }));
purgeFreeTier();
setInterval(purgeFreeTier, 24 * 60 * 60 * 1000).unref();

const integrity = config.integrity.configured ? createIntegrityClient(config.integrity) : null;
const googlePlay = config.billing.configured ? createGooglePlayClient(config.billing) : null;
const pubsubVerifier = config.billing.configured && config.billing.rtdnAudience
  ? createPubSubVerifier({ audience: config.billing.rtdnAudience, serviceAccountEmail: config.billing.rtdnServiceAccountEmail })
  : null;
if (!googlePlay) log.warn('billing_not_configured: /api/billing/google-play/* return 503; free one-bank limit still enforced');

let messaging = null;
try { messaging = await createMessagingClient(config.push); }
catch (e) { log.error('fcm init failed; bank-reconnect pushes disabled', { error_message: e.message }); }
if (messaging) log.info('fcm push ready', { project_id: config.push.projectId, credential_source: config.push.credentialSource });
const notifyReconnect = messaging ? createReconnectNotifier({ store, messaging, log, dedupeMs: config.push.dedupeHours * 3600 * 1000 }) : null;

const app = createApp({
  config, store, plaid, tokenVerifier, webhookVerifier, syncItem, log, googlePlay, pubsubVerifier, integrity, notifyReconnect,
  health: () => ({ storage: storageKind, databaseReady: dbReady, pushConfigured: Boolean(messaging) }),
});

const server = app.listen(config.port, '0.0.0.0', () => {
  log.info('PayAviator backend listening', {
    version: config.appVersion, port: config.port, plaid_env: config.plaid.env,
    plaid_configured: config.plaid.configured, storage: storageKind, auth_mode: config.auth.mode,
  });
});

function shutdown(signal) {
  log.info('shutting down', { signal });
  server.close(() => store.close().finally(() => process.exit(0)));
  setTimeout(() => process.exit(1), 10000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
