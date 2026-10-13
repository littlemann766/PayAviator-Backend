// Minimal structured (JSON lines) logger.
// Plaid audit lines (event plaid_api / plaid_webhook) are built in plaidLog.js.
// What server logs contain: message, user_id (Firebase uid), item_id, Plaid request_id,
// error_type/error_code/HTTP status, webhook type/code, counts. Never access/public/link
// tokens, secrets, Authorization headers, or transaction/account payloads.
// Call sites must pass only such fields; redact() below is a defense-in-depth backstop.

const REDACTIONS = [
  [/\b(access|public|link)-(sandbox|production|development)-[A-Za-z0-9-]+/g, '$1-$2-[REDACTED]'],
  [/enc:v1:[A-Za-z0-9+/=:]+/g, 'enc:v1:[REDACTED]'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [REDACTED]'],
  [/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g, '[REDACTED_JWT]'],
  // FCM registration tokens (<instance id>:APA91...).
  [/\b[A-Za-z0-9_-]{8,}:APA91[A-Za-z0-9_-]+/g, '[REDACTED_FCM_TOKEN]'],
  // Emails. Bounded, non-overlapping character classes: no catastrophic backtracking.
  [/[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){1,8}/g, '[REDACTED_EMAIL]'],
];

// Keys whose values are never logged, whatever they contain.
const BLOCKED_KEYS = new Set(['access_token', 'accessToken', 'public_token', 'link_token', 'secret', 'authorization',
  'transactions', 'added', 'modified', 'payload', 'accounts', 'balances', 'body', 'config', 'headers',
  // PII / financial values / Firebase credentials (Plaid production checklist logging rules).
  'balance', 'current', 'available', 'limit', 'amount', 'name', 'official_name', 'merchant_name', 'owners',
  'email', 'emails', 'phone', 'phone_numbers', 'address', 'addresses', 'id_token', 'idToken', 'token',
  'firebase_token', 'refresh_token', 'purchase_token', 'purchaseToken', 'integrity_token', 'password',
  'Authorization', 'cookie', 'fcm_token', 'fcmToken', 'tokens', 'registration_token', 'registration_ids', 'processor_token', 'link_session', 'results', 'on_success', 'metadata']);

export function redact(value, depth = 0) {
  if (typeof value === 'string') return REDACTIONS.reduce((s, [re, rep]) => s.replace(re, rep), value);
  if (value === null || typeof value !== 'object' || depth > 4) return value;
  if (Array.isArray(value)) return value.map(v => redact(v, depth + 1));
  const out = {};
  for (const [k, v] of Object.entries(value)) out[k] = BLOCKED_KEYS.has(k) ? '[REDACTED]' : redact(v, depth + 1);
  return out;
}

function emit(level, msg, fields = {}) {
  const line = JSON.stringify({ ts: new Date().toISOString(), level, msg: redact(String(msg)), ...redact(fields) });
  if (level === 'error' || level === 'warn') console.error(line);
  else console.log(line);
}

export const log = {
  info: (msg, fields) => emit('info', msg, fields),
  warn: (msg, fields) => emit('warn', msg, fields),
  error: (msg, fields) => emit('error', msg, fields),
};

export const silentLog = { info() {}, warn() {}, error() {} };
