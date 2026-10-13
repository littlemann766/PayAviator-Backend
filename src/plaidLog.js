// Structured Plaid audit logging (Plaid production checklist: "log request_id, item_id, link_session_id").
// One JSON line per Plaid API call ("plaid_api") and per webhook ("plaid_webhook").
// Logged: event, method, outcome, duration_ms, request_id, item_id, account_ids, link_session_id,
// error_type/error_code/http_status, user_ref (sha256 of the uid, 12 hex). Never logged: access/public/link
// tokens, balances, transactions, names, emails, Firebase tokens. Fields are built from an allow-list,
// then passed through log.js redact() as a backstop.
import crypto from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';

const als = new AsyncLocalStorage();
const ID_RE = /^[A-Za-z0-9_-]{1,100}$/; // anchored, no nested quantifiers: linear time
const LS_RE = /^[A-Za-z0-9-]{1,64}$/;
const MAX_ACCOUNT_IDS = 20;

/** Short, non-reversible user reference. */
export function userRef(userId) {
  if (!userId) return null;
  return crypto.createHash('sha256').update(String(userId)).digest('hex').slice(0, 12);
}

/** Accept only a plausible Plaid id; anything else (tokens, emails, junk) is dropped. */
export function safeId(v, re = ID_RE) {
  if (typeof v !== 'string' || !re.test(v)) return null;
  if (/^(access|public|link)-/.test(v)) return null; // token-shaped values are never ids
  return v;
}
export const safeLinkSessionId = v => safeId(typeof v === 'string' ? v.trim() : v, LS_RE);

/** Run fn with request-scoped Plaid log context ({ userId, linkSessionId, itemId }). */
export function withPlaidContext(ctx, fn) {
  return als.run({ ...(als.getStore() || {}), ...ctx }, fn);
}

/** Express middleware: binds user_ref + optional link_session_id (X-Link-Session-Id header or body.link_session_id). */
export function plaidContextMiddleware(req, _res, next) {
  const ls = safeLinkSessionId(req.get?.('x-link-session-id')) || safeLinkSessionId(req.body?.link_session_id);
  als.run({ userId: req.userId, linkSessionId: ls }, next);
}

function errorFields(err) {
  const d = err?.response?.data;
  const out = { http_status: err?.response?.status || null };
  if (d && typeof d === 'object') {
    out.error_type = typeof d.error_type === 'string' ? d.error_type : null;
    out.error_code = typeof d.error_code === 'string' ? d.error_code : null;
    out.request_id = safeId(d.request_id);
  } else {
    out.error_type = 'NETWORK_OR_CLIENT';
    out.error_code = typeof err?.code === 'string' ? err.code : null;
  }
  return out;
}

function accountIds(data) {
  const list = Array.isArray(data?.accounts) ? data.accounts : [];
  return list.slice(0, MAX_ACCOUNT_IDS).map(a => safeId(a?.account_id)).filter(Boolean);
}

/** Build the allow-listed log line for one Plaid API call. */
export function plaidCallFields(method, { data, err, ctx = {}, durationMs }) {
  const store = als.getStore() || {};
  const c = { ...store, ...ctx };
  const fields = {
    event: 'plaid_api', method: String(method), outcome: err ? 'error' : 'ok',
    duration_ms: Number.isFinite(durationMs) ? Math.round(durationMs) : null,
    request_id: err ? null : safeId(data?.request_id),
    item_id: safeId(data?.item_id) || safeId(data?.item?.item_id) || safeId(c.itemId),
    user_ref: userRef(c.userId),
    link_session_id: safeLinkSessionId(c.linkSessionId),
  };
  if (!err) {
    const ids = accountIds(data);
    if (ids.length) fields.account_ids = ids;
    // link/token/get: surface the Link session ids Plaid reports (ids only, never results/tokens).
    if (Array.isArray(data?.link_sessions)) {
      const ls = data.link_sessions.map(s => safeLinkSessionId(s?.link_session_id)).filter(Boolean).slice(0, 10);
      if (ls.length) fields.link_session_ids = ls;
    }
  } else Object.assign(fields, errorFields(err));
  for (const k of Object.keys(fields)) if (fields[k] === null) delete fields[k];
  return fields;
}

/** Wrap a Plaid client ({ call }) so every call emits exactly one structured line. */
export function instrumentPlaid(plaid, log) {
  return {
    ...plaid,
    async call(method, request, opts = {}) {
      const { ctx, ...rest } = opts || {};
      const t0 = performance.now();
      try {
        const data = await plaid.call(method, request, rest);
        log.info('plaid_api', plaidCallFields(method, { data, ctx, durationMs: performance.now() - t0 }));
        return data;
      } catch (err) {
        log.warn('plaid_api', plaidCallFields(method, { err, ctx, durationMs: performance.now() - t0 }));
        throw err;
      }
    },
  };
}

/** Allow-listed log line for a verified Plaid webhook. */
export function plaidWebhookFields(payload, { userId, outcome = 'received' } = {}) {
  const p = payload || {};
  const fields = {
    event: 'plaid_webhook', outcome,
    webhook_type: safeId(p.webhook_type), webhook_code: safeId(p.webhook_code),
    item_id: safeId(p.item_id), environment: safeId(p.environment),
    request_id: safeId(p.request_id),
    link_session_id: safeLinkSessionId(p.link_session_id),
    user_ref: userRef(userId),
    error_type: safeId(p.error?.error_type), error_code: safeId(p.error?.error_code),
  };
  if (Array.isArray(p.account_ids)) fields.account_ids = p.account_ids.slice(0, MAX_ACCOUNT_IDS).map(a => safeId(a)).filter(Boolean);
  for (const k of Object.keys(fields)) if (fields[k] === null) delete fields[k];
  return fields;
}
