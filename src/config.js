import { PlaidEnvironments } from 'plaid';
import { parseEncryptionKey } from './crypto.js';

export const VALID_PLAID_ENVS = Object.keys(PlaidEnvironments); // ['production', 'sandbox']
export const FIREBASE_JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

export class ConfigError extends Error {
  constructor(errors) {
    super(`Invalid PayAviator configuration:\n - ${errors.join('\n - ')}`);
    this.name = 'ConfigError';
    this.errors = errors;
  }
}

const truthy = v => ['1', 'true', 'yes', 'on'].includes(String(v || '').trim().toLowerCase());
const falsy = v => ['0', 'false', 'no', 'off'].includes(String(v || '').trim().toLowerCase());
const isHttps = v => { try { return new URL(v).protocol === 'https:'; } catch { return false; } };
const list = v => String(v || '').split(',').map(s => s.trim()).filter(Boolean);

function readCa(value) {
  if (!value) return undefined;
  const v = String(value).trim();
  if (v.includes('-----BEGIN')) return v.replace(/\\n/g, '\n');
  return Buffer.from(v, 'base64').toString('utf8');
}

function dbHost(url) {
  try { return new URL(url).hostname; } catch { return ''; }
}

/**
 * Validates environment variables and returns { config, warnings }.
 * Throws ConfigError listing every problem at once (fail fast at startup).
 */
export function loadConfig(env = process.env) {
  const errors = [];
  const warnings = [];

  const plaidEnvName = String(env.PLAID_ENV || 'sandbox').trim().toLowerCase();
  if (!VALID_PLAID_ENVS.includes(plaidEnvName)) {
    errors.push(`PLAID_ENV must be one of ${VALID_PLAID_ENVS.join(', ')} (got "${env.PLAID_ENV}")${plaidEnvName === 'development' ? '; Plaid retired the Development environment, use sandbox or production' : ''}`);
  }
  const isProduction = plaidEnvName === 'production';

  const clientId = env.PLAID_CLIENT_ID || '';
  const secret = env.PLAID_SECRET || '';
  if (isProduction && (!clientId || !secret)) errors.push('PLAID_CLIENT_ID and PLAID_SECRET are required in production');

  // --- Token encryption ---
  let tokenEncryptionKey = null;
  if (env.TOKEN_ENCRYPTION_KEY) {
    try { tokenEncryptionKey = parseEncryptionKey(env.TOKEN_ENCRYPTION_KEY); } catch (e) { errors.push(e.message); }
  } else if (isProduction) {
    errors.push('TOKEN_ENCRYPTION_KEY is required in production');
  } else if (env.DATABASE_URL) {
    errors.push('TOKEN_ENCRYPTION_KEY is required whenever DATABASE_URL is set (access tokens are encrypted at rest)');
  }

  // --- Database ---
  const databaseUrl = env.DATABASE_URL || '';
  if (isProduction && !databaseUrl) errors.push('DATABASE_URL is required in production (in-memory storage is refused)');
  let ssl = false;
  if (databaseUrl) {
    if (env.PGSSL === 'disable') {
      ssl = false;
      if (isProduction && !dbHost(databaseUrl).endsWith('.railway.internal')) {
        warnings.push('PGSSL=disable in production on a non-private database host: database traffic (including encrypted access tokens) is NOT protected by TLS');
      }
    } else {
      const ca = readCa(env.DATABASE_SSL_CA);
      let rejectUnauthorized = isProduction;
      if (env.DATABASE_SSL_REJECT_UNAUTHORIZED !== undefined && env.DATABASE_SSL_REJECT_UNAUTHORIZED !== '') {
        rejectUnauthorized = !falsy(env.DATABASE_SSL_REJECT_UNAUTHORIZED);
      }
      if (ca) rejectUnauthorized = rejectUnauthorized || !falsy(env.DATABASE_SSL_REJECT_UNAUTHORIZED);
      if (isProduction && !rejectUnauthorized) {
        warnings.push('!!! DATABASE_SSL_REJECT_UNAUTHORIZED=false: Postgres TLS certificate is NOT verified in production. Prefer DATABASE_SSL_CA or Railway private networking.');
      }
      ssl = { rejectUnauthorized, ...(ca ? { ca } : {}) };
    }
  }

  // --- Plaid Link ---
  const webhookUrl = env.PLAID_WEBHOOK_URL || '';
  const redirectUri = env.PLAID_REDIRECT_URI || '';
  if (webhookUrl && !isHttps(webhookUrl)) errors.push('PLAID_WEBHOOK_URL must be an https:// URL');
  if (redirectUri && !isHttps(redirectUri)) errors.push('PLAID_REDIRECT_URI must be an https:// URL');
  if (isProduction && !webhookUrl) errors.push('PLAID_WEBHOOK_URL is required in production');
  if (isProduction && !redirectUri) errors.push('PLAID_REDIRECT_URI is required in production (OAuth institutions)');
  if (!isProduction && !redirectUri) warnings.push('PLAID_REDIRECT_URI not set: OAuth institutions will not work in Link');
  if (!isProduction && !webhookUrl) warnings.push('PLAID_WEBHOOK_URL not set: item status and transaction webhooks will not be received');

  const daysRequested = env.PLAID_TRANSACTIONS_DAYS_REQUESTED ? Number(env.PLAID_TRANSACTIONS_DAYS_REQUESTED) : 730;
  if (!Number.isInteger(daysRequested) || daysRequested < 1 || daysRequested > 730) {
    errors.push('PLAID_TRANSACTIONS_DAYS_REQUESTED must be an integer between 1 and 730');
  }
  const timeoutMs = env.PLAID_TIMEOUT_MS ? Number(env.PLAID_TIMEOUT_MS) : 30000;
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1000) errors.push('PLAID_TIMEOUT_MS must be a number >= 1000');

  // --- Auth ---
  let auth = null;
  if (env.FIREBASE_PROJECT_ID) {
    auth = {
      mode: 'firebase',
      jwksUrl: FIREBASE_JWKS_URL,
      issuer: `https://securetoken.google.com/${env.FIREBASE_PROJECT_ID}`,
      audience: env.FIREBASE_PROJECT_ID,
      algorithms: ['RS256'],
    };
  } else if (env.AUTH_JWKS_URL) {
    if (!isHttps(env.AUTH_JWKS_URL)) errors.push('AUTH_JWKS_URL must be an https:// URL');
    auth = {
      mode: 'jwks',
      jwksUrl: env.AUTH_JWKS_URL,
      issuer: env.AUTH_JWT_ISSUER || undefined,
      audience: env.AUTH_JWT_AUDIENCE || undefined,
      algorithms: list(env.AUTH_JWT_ALGORITHMS).length ? list(env.AUTH_JWT_ALGORITHMS) : ['RS256', 'ES256'],
    };
    if (!auth.issuer || !auth.audience) {
      (isProduction ? errors : warnings).push('AUTH_JWT_ISSUER and AUTH_JWT_AUDIENCE should be set with AUTH_JWKS_URL (required in production)');
    }
  } else if (env.APP_JWT_SECRET) {
    if (String(env.APP_JWT_SECRET).length < 32) errors.push('APP_JWT_SECRET must be at least 32 characters');
    auth = {
      mode: 'hs256',
      secret: env.APP_JWT_SECRET,
      issuer: env.AUTH_JWT_ISSUER || undefined,
      audience: env.AUTH_JWT_AUDIENCE || undefined,
      algorithms: ['HS256'],
    };
  } else if (truthy(env.AUTH_DISABLED)) {
    if (isProduction) errors.push('AUTH_DISABLED is not allowed in production');
    else {
      auth = { mode: 'disabled' };
      warnings.push('!!! AUTH_DISABLED=true: API authentication is OFF. Local Sandbox testing only.');
    }
  } else {
    errors.push('No auth configured: set FIREBASE_PROJECT_ID, AUTH_JWKS_URL, or APP_JWT_SECRET (or AUTH_DISABLED=true for local sandbox only)');
  }

  const corsOrigins = list(env.CORS_ORIGINS);

  // --- Google Play billing (optional: missing/invalid => billing endpoints 503, free limit still enforced) ---
  let playServiceAccount = null;
  if (env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON) {
    try {
      const raw = String(env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON).trim();
      playServiceAccount = JSON.parse(raw.startsWith('{') ? raw : Buffer.from(raw, 'base64').toString('utf8'));
      if (!playServiceAccount.client_email || !playServiceAccount.private_key) throw new Error('missing client_email/private_key');
    } catch (e) {
      playServiceAccount = null;
      warnings.push(`GOOGLE_PLAY_SERVICE_ACCOUNT_JSON is invalid (${e.message}); Google Play billing disabled`);
    }
  }
  const androidPackageName = String(env.ANDROID_PACKAGE_NAME || '').trim();
  const playProductIds = list(env.GOOGLE_PLAY_PRODUCT_IDS);
  let freeTierSecret = String(env.FREE_TIER_FINGERPRINT_SECRET || '');
  if (freeTierSecret && freeTierSecret.length < 32) { warnings.push('FREE_TIER_FINGERPRINT_SECRET must be at least 32 characters; ignoring it'); freeTierSecret = ''; }
  if (!freeTierSecret) warnings.push('FREE_TIER_FINGERPRINT_SECRET not set: free-tier bank links fail closed with 503 free_tier_not_configured');
  const cooldownDays = Number(env.FREE_TIER_COOLDOWN_DAYS || 30);
  const freeTier = { secret: freeTierSecret || null, configured: Boolean(freeTierSecret), cooldownDays: Number.isFinite(cooldownDays) && cooldownDays >= 0 ? cooldownDays : 30 };
  const billing = {
    configured: Boolean(playServiceAccount && androidPackageName),
    serviceAccount: playServiceAccount,
    packageName: androidPackageName || null,
    productIds: playProductIds,
    rtdnAudience: env.GOOGLE_PLAY_RTDN_AUDIENCE || null,
    rtdnServiceAccountEmail: env.GOOGLE_PLAY_RTDN_SERVICE_ACCOUNT || null,
    // Owner/comp accounts (Firebase UIDs): unlimited banks, no subscription, skip free-tier checks.
    // Founders (FOUNDER_FIREBASE_UIDS) always count as comp too; they additionally get tier 'founder'.
    compUids: new Set([...list(env.COMP_FIREBASE_UIDS), ...list(env.FOUNDER_FIREBASE_UIDS)]),
    founderUids: new Set(list(env.FOUNDER_FIREBASE_UIDS)),
  };
  // --- Stripe web subscriptions (optional: all four required, else /api/billing/stripe/* return 503) ---
  const stripeVars = ['STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'STRIPE_PRICE_MONTHLY', 'STRIPE_PRICE_YEARLY'];
  const stripeSet = stripeVars.filter(k => String(env[k] || '').trim());
  const stripe = {
    configured: stripeSet.length === stripeVars.length,
    secretKey: String(env.STRIPE_SECRET_KEY || '').trim() || null,
    webhookSecret: String(env.STRIPE_WEBHOOK_SECRET || '').trim() || null,
    priceMonthly: String(env.STRIPE_PRICE_MONTHLY || '').trim() || null,
    priceYearly: String(env.STRIPE_PRICE_YEARLY || '').trim() || null,
  };
  if (stripeSet.length && !stripe.configured) warnings.push(`Stripe partially configured; missing ${stripeVars.filter(k => !stripeSet.includes(k)).join(', ')}: /api/billing/stripe/* return 503`);
  const integrity = {
    enforce: String(env.PLAY_INTEGRITY_ENFORCE || '').trim().toLowerCase() === 'true',
    configured: Boolean(playServiceAccount && androidPackageName),
    serviceAccount: playServiceAccount,
    packageName: androidPackageName || null,
  };
  if (integrity.enforce && !integrity.configured) warnings.push('PLAY_INTEGRITY_ENFORCE=true but GOOGLE_PLAY_SERVICE_ACCOUNT_JSON/ANDROID_PACKAGE_NAME missing: free-tier links return 503 integrity_not_configured');
  if (isProduction && !billing.configured) warnings.push('Google Play billing not configured (GOOGLE_PLAY_SERVICE_ACCOUNT_JSON + ANDROID_PACKAGE_NAME); second bank links will be refused');

  // --- FCM push (optional: missing => pushes are logged and skipped; FCM itself is free, no Blaze needed) ---
  let fcmServiceAccount = null, fcmCredentialSource = null;
  if (env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    try {
      const raw = String(env.FIREBASE_SERVICE_ACCOUNT_JSON).trim();
      fcmServiceAccount = JSON.parse(raw.startsWith('{') ? raw : Buffer.from(raw, 'base64').toString('utf8'));
      if (!fcmServiceAccount.client_email || !fcmServiceAccount.private_key) throw new Error('missing client_email/private_key');
      fcmCredentialSource = 'FIREBASE_SERVICE_ACCOUNT_JSON';
    } catch (e) {
      fcmServiceAccount = null;
      warnings.push(`FIREBASE_SERVICE_ACCOUNT_JSON is invalid (${e.message}); push notifications disabled`);
    }
  } else if (playServiceAccount && truthy(env.FCM_USE_PLAY_SERVICE_ACCOUNT)) {
    fcmServiceAccount = playServiceAccount; fcmCredentialSource = 'GOOGLE_PLAY_SERVICE_ACCOUNT_JSON';
  }
  const fcmProjectId = String(env.FCM_PROJECT_ID || env.FIREBASE_PROJECT_ID || fcmServiceAccount?.project_id || '').trim();
  const maxTokens = Number(env.FCM_MAX_TOKENS_PER_USER || 10);
  const push = {
    configured: Boolean(fcmServiceAccount && fcmProjectId) && !truthy(env.PUSH_DISABLED),
    serviceAccount: fcmServiceAccount,
    credentialSource: fcmCredentialSource,
    projectId: fcmProjectId || null,
    maxTokensPerUser: Number.isInteger(maxTokens) && maxTokens > 0 && maxTokens <= 50 ? maxTokens : 10,
    dedupeHours: 24,
  };
  if (!push.configured) warnings.push('push_not_configured: FIREBASE_SERVICE_ACCOUNT_JSON (+ FIREBASE_PROJECT_ID) missing; bank-reconnect pushes are logged and skipped');

  if (errors.length) throw new ConfigError(errors);

  return {
    config: {
      appVersion: '4.0.0',
      port: Number(env.PORT || 8787),
      trustProxy: env.TRUST_PROXY === undefined ? 1 : (Number.isNaN(Number(env.TRUST_PROXY)) ? env.TRUST_PROXY : Number(env.TRUST_PROXY)),
      isProduction,
      plaid: {
        env: plaidEnvName,
        basePath: PlaidEnvironments[plaidEnvName],
        clientId,
        secret,
        configured: Boolean(clientId && secret),
        clientName: env.PLAID_CLIENT_NAME || 'PayAviator',
        countryCodes: list(env.PLAID_COUNTRY_CODES).length ? list(env.PLAID_COUNTRY_CODES) : ['US'],
        webhookUrl: webhookUrl || null,
        redirectUri: redirectUri || null,
        completionRedirectUri: env.PLAID_COMPLETION_REDIRECT_URI || 'payaviator://plaid-complete',
        oauthReturnUri: env.PLAID_OAUTH_RETURN_URI || 'payaviator://plaid-oauth-return',
        daysRequested,
        timeoutMs,
      },
      db: databaseUrl ? { url: databaseUrl, ssl } : null,
      tokenEncryptionKey,
      auth,
      corsOrigins: corsOrigins.length ? corsOrigins : ['https://appassets.androidplatform.net', 'https://payaviator.app', 'https://www.payaviator.app'],
      billing,
      freeTier,
      stripe,
      integrity,
      push,
      rateLimit: {
        windowMs: 15 * 60 * 1000,
        max: Number(env.RATE_LIMIT_MAX || 300),
        linkMax: Number(env.RATE_LIMIT_LINK_MAX || 30),
      },
    },
    warnings,
  };
}
