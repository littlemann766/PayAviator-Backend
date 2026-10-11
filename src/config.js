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

  if (errors.length) throw new ConfigError(errors);

  return {
    config: {
      appVersion: '3.2.0',
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
      corsOrigins: corsOrigins.length ? corsOrigins : ['https://appassets.androidplatform.net'],
      rateLimit: {
        windowMs: 15 * 60 * 1000,
        max: Number(env.RATE_LIMIT_MAX || 300),
        linkMax: Number(env.RATE_LIMIT_LINK_MAX || 30),
      },
    },
    warnings,
  };
}
