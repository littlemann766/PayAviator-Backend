// Retry/backoff for Plaid calls: retries network errors, timeouts, HTTP 429
// and 5xx, and Plaid RATE_LIMIT_EXCEEDED / INTERNAL_SERVER_ERROR /
// PLANNED_MAINTENANCE. Item errors (ITEM_LOGIN_REQUIRED etc.) are never retried.
const RETRYABLE_CODES = new Set(['RATE_LIMIT_EXCEEDED', 'INTERNAL_SERVER_ERROR', 'PLANNED_MAINTENANCE']);
const NETWORK_CODES = new Set(['ECONNRESET', 'ETIMEDOUT', 'ECONNABORTED', 'ECONNREFUSED', 'EAI_AGAIN', 'ENOTFOUND', 'EPIPE', 'ERR_NETWORK', 'UND_ERR_SOCKET']);

export function isRetryablePlaidError(err) {
  const status = err?.response?.status;
  const data = err?.response?.data || {};
  if (data.error_type === 'RATE_LIMIT_EXCEEDED' || RETRYABLE_CODES.has(data.error_code)) return true;
  if (status === 429 || (status >= 500 && status <= 599)) return true;
  if (!err?.response && NETWORK_CODES.has(err?.code)) return true;
  return false;
}

export function isRateLimitOnly(err) {
  const data = err?.response?.data || {};
  return err?.response?.status === 429 || data.error_type === 'RATE_LIMIT_EXCEEDED';
}

const defaultSleep = ms => new Promise(r => setTimeout(r, ms));

export async function withRetry(fn, {
  retries = 3,
  baseDelayMs = 500,
  maxDelayMs = 8000,
  isRetryable = isRetryablePlaidError,
  onRetry = () => {},
  sleep = defaultSleep,
} = {}) {
  let attempt = 0;
  for (;;) {
    try {
      return await fn(attempt);
    } catch (err) {
      if (attempt >= retries || !isRetryable(err)) throw err;
      const delay = Math.min(maxDelayMs, baseDelayMs * 2 ** attempt) * (0.5 + Math.random() / 2);
      onRetry(err, attempt + 1, Math.round(delay));
      await sleep(delay);
      attempt++;
    }
  }
}
