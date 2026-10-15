import { Configuration, PlaidApi } from 'plaid';
import { withRetry, isRateLimitOnly } from './retry.js';

export const PLAID_API_VERSION = '2020-09-14';

/**
 * Single Plaid client for every call. plaid-node >= 48 sends nested fields
 * such as hosted_link unchanged (plain JSON body), so the raw fetch calls from
 * the old server.js are no longer needed. One Plaid-Version header, one
 * timeout, one retry policy.
 */
export function createPlaidClient(plaidConfig, { log, retryOptions = {} } = {}) {
  const api = new PlaidApi(new Configuration({
    basePath: plaidConfig.basePath,
    baseOptions: {
      timeout: plaidConfig.timeoutMs,
      headers: {
        'PLAID-CLIENT-ID': plaidConfig.clientId,
        'PLAID-SECRET': plaidConfig.secret,
        'Plaid-Version': PLAID_API_VERSION,
      },
    },
  }));

  async function call(method, request, { idempotent = true } = {}) {
    const res = await withRetry(() => api[method](request), {
      // Non-idempotent calls (public_token exchange) only retry when Plaid
      // explicitly rejected the request for rate limiting.
      ...(idempotent ? {} : { isRetryable: isRateLimitOnly }),
      onRetry: (err, attempt, delayMs) => log?.warn('plaid retry', { method, attempt, delayMs, ...plaidErrorInfo(err) }),
      ...retryOptions,
    });
    return res.data;
  }

  return { api, call };
}

/** Safe-to-log subset of a Plaid/axios error (never includes request headers). */
export function plaidErrorInfo(err) {
  const d = err?.response?.data;
  if (d && typeof d === 'object' && (d.error_code || d.error_type)) {
    return {
      http_status: err.response.status,
      error_type: d.error_type || null,
      error_code: d.error_code || null,
      error_message: d.error_message || null,
      request_id: d.request_id || null,
    };
  }
  return { http_status: err?.response?.status || null, error_code: err?.code || null, error_message: err?.message || String(err) };
}

/** Client-facing error body: Plaid's display_message when present, else generic. */
export function clientError(err, fallbackMessage, fallbackCode) {
  const d = err?.response?.data || {};
  return {
    error: d.display_message || fallbackMessage,
    code: d.error_code || fallbackCode,
    request_id: d.request_id || null,
  };
}

export const ITEM_STATUS = {
  GOOD: 'good',
  LOGIN_REQUIRED: 'login_required',
  ERROR: 'error',
  PENDING_DISCONNECT: 'pending_disconnect',
  PENDING_EXPIRATION: 'pending_expiration',
  REVOKED: 'revoked',
  PAUSED: 'paused', // virtual: derived per request when the user has no active Plus (never stored)
};

/** Item error codes that mean the user must re-authenticate via update mode. */
export const LOGIN_REQUIRED_CODES = new Set([
  'ITEM_LOGIN_REQUIRED', 'INVALID_CREDENTIALS', 'INVALID_MFA', 'ITEM_LOCKED',
  'USER_SETUP_REQUIRED', 'MFA_NOT_SUPPORTED', 'INSUFFICIENT_CREDENTIALS',
  'PASSWORD_RESET_REQUIRED', 'ACCESS_NOT_GRANTED', 'NO_ACCOUNTS',
]);

/** Item error codes / reasons that mean the user withdrew consent: stored data for the Item is purged. */
export const REVOKED_CODES = new Set(['USER_PERMISSION_REVOKED', 'USER_ACCOUNT_REVOKED']);
export const REVOKED_REASONS = new Set(['OAUTH_USER_REVOKED']);

export function statusForItemError(errorCode, errorCodeReason = null) {
  if (REVOKED_CODES.has(errorCode) || REVOKED_REASONS.has(errorCodeReason)) return ITEM_STATUS.REVOKED;
  return LOGIN_REQUIRED_CODES.has(errorCode) ? ITEM_STATUS.LOGIN_REQUIRED : ITEM_STATUS.ERROR;
}

/** Returns the Item error code if the Plaid error is an ITEM_ERROR, else null. */
export function itemErrorCode(err) {
  const d = err?.response?.data || {};
  return d.error_type === 'ITEM_ERROR' ? d.error_code : null;
}
