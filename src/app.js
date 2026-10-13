import crypto from 'node:crypto';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { rateLimit, ipKeyGenerator } from 'express-rate-limit';
import { requireAuth, enforceUserMatch } from './auth.js';
import { clientError, plaidErrorInfo, itemErrorCode, statusForItemError, ITEM_STATUS } from './plaid.js';
import { sha256Hex } from './crypto.js';
import { handleWebhook } from './webhooks.js';
import { plaidContextMiddleware } from './plaidLog.js';
import { accountFingerprints, deviceFingerprint, readDeviceId, gateError } from './freeTier.js';
import { checkVerdict } from './integrity.js';
import { stripeRoutes, stripeWebhookRoute } from './stripeBilling.js';
import { FREE_BANK_LIMIT, billingSummary, entitlementFromPurchase, isEntitlementActive } from './billing.js';

/** Items in these states cannot be used until the user completes update mode. */
const BLOCKED_STATUSES = new Set([ITEM_STATUS.LOGIN_REQUIRED, ITEM_STATUS.REVOKED]);

export function physicalAccountKey(a, institutionName = '') {
  const norm = v => String(v || '').trim().toLowerCase().replace(/\s+/g, ' ');
  const mask = norm(a?.mask);
  const institution = norm(institutionName || a?.institution_name || a?.institution);
  const type = norm(a?.type), subtype = norm(a?.subtype), name = norm(a?.official_name || a?.name);
  // Institution + last four + account class identifies the same physical account
  // across duplicate Plaid Items/reconnections; fall back to account_id without a mask.
  return mask ? [institution, mask, type, subtype, name].join('|') : String(a?.account_id || [institution, type, subtype, name].join('|'));
}

export function itemSummary(i) {
  return {
    item_id: i.itemId,
    institution_id: i.institutionId,
    institution_name: i.institutionName,
    status: i.status,
    error_code: i.errorCode,
    needs_update: BLOCKED_STATUSES.has(i.status) || i.status === ITEM_STATUS.PENDING_EXPIRATION || i.status === ITEM_STATUS.PENDING_DISCONNECT || i.newAccountsAvailable,
    new_accounts_available: i.newAccountsAvailable,
  };
}

function decorateAccount(a, item) {
  const isCredit = String(a?.type || '').toLowerCase() === 'credit';
  const current = Number(a?.balances?.current);
  const available = Number(a?.balances?.available);
  const directLimit = Number(a?.balances?.limit);
  // Never manufacture a credit limit from current + available.
  const creditLimit = isCredit && Number.isFinite(directLimit) && directLimit > 0 ? directLimit : null;
  const balanceUsed = isCredit && Number.isFinite(current) ? Math.max(0, current) : null;
  const availableCredit = isCredit
    ? (Number.isFinite(available) && available >= 0 ? available
      : (creditLimit != null && balanceUsed != null ? Math.max(0, creditLimit - balanceUsed) : null))
    : null;
  const utilization = isCredit && creditLimit > 0 && balanceUsed != null ? Math.max(0, Math.min(100, (balanceUsed / creditLimit) * 100)) : null;
  return {
    ...a,
    credit_limit: creditLimit,
    balance_used: balanceUsed,
    available_credit: availableCredit,
    utilization_percent: utilization,
    balance_source: 'plaid_accounts_get',
    item_id: item.itemId,
    institution_id: item.institutionId,
    institution_name: item.institutionName || 'Connected institution',
    item_status: item.status,
  };
}

export function createApp({ config, store, plaid, tokenVerifier, webhookVerifier, syncItem, log, health = () => ({}), googlePlay = null, pubsubVerifier = null, integrity = null, stripe = null }) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy);

  app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
  const allowed = new Set(config.corsOrigins);
  app.use(cors({
    origin: (origin, cb) => cb(null, !origin || allowed.has(origin)),
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Accept', 'Authorization', 'X-Device-Id', 'X-Play-Integrity-Token', 'X-Link-Session-Id'],
    maxAge: 600,
  }));
  app.use((req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

  // ---------- Public endpoints ----------
  const publicLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: 'draft-8', legacyHeaders: false });

  app.get('/', publicLimiter, (_req, res) => res.json({ status: 'ok', app: 'PayAviator', version: config.appVersion }));
  app.get('/api/health', publicLimiter, (_req, res) => res.json({
    status: 'ok', app: 'PayAviator', version: config.appVersion, plaidEnvironment: config.plaid.env,
    plaidConfigured: config.plaid.configured, webhookConfigured: Boolean(config.plaid.webhookUrl), ...health(),
  }));

  // OAuth/app-to-app handoff page for Hosted Link: immediately returns to the app's custom scheme.
  app.get('/plaid/oauth-redirect', publicLimiter, (_req, res) => {
    const nonce = crypto.randomBytes(16).toString('base64');
    const target = JSON.stringify(config.plaid.oauthReturnUri);
    res.set('Content-Security-Policy', `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'`);
    res.type('html').send(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="0;url=${config.plaid.oauthReturnUri}"><title>Returning to PayAviator</title></head><body style="font-family:sans-serif;background:#071521;color:white;padding:32px">Returning to PayAviator…<script nonce="${nonce}">location.replace(${target});</script></body></html>`);
  });

  // Plaid webhooks: raw body is required to verify request_body_sha256.
  app.post('/api/plaid/webhook', express.raw({ type: '*/*', limit: '1mb' }), async (req, res) => {
    let payload;
    try {
      await webhookVerifier(req.body, req.get('plaid-verification'));
      payload = JSON.parse(req.body.toString('utf8'));
    } catch (e) {
      log.warn('webhook rejected', { reason: e.message });
      return res.status(401).json({ error: 'invalid_webhook' });
    }
    try {
      const { background } = await handleWebhook(payload, { store, syncItem, log });
      res.json({ received: true });
      background?.catch(e => log.error('webhook background task failed', { item_id: payload.item_id, ...plaidErrorInfo(e) }));
    } catch (e) {
      log.error('webhook handling failed', { webhook_type: payload?.webhook_type, webhook_code: payload?.webhook_code, item_id: payload?.item_id, ...plaidErrorInfo(e) });
      res.status(500).json({ error: 'webhook_failed' }); // Plaid will retry.
    }
  });

  // ---------- Google Play Real-time Developer Notifications (Pub/Sub push; public, OIDC-verified) ----------
  const summaryOpts = { compUids: config.billing?.compUids || new Set() };
  const billingReady = () => Boolean(config.billing?.configured && googlePlay);
  const notConfigured = res => res.status(503).json({ error: 'billing_not_configured', code: 'BILLING_NOT_CONFIGURED' });

  /** Fetch a purchase from Google, store it for userId, acknowledge if needed. Returns the entitlement. */
  async function refreshPurchase({ userId, productId, purchaseToken }) {
    const p = await googlePlay.getSubscription(purchaseToken);
    const ent = entitlementFromPurchase(p, productId);
    const tokenHash = sha256Hex(purchaseToken);
    await store.putEntitlement({ tokenHash, userId, productId, state: ent.state, expiresAt: ent.expiresAt });
    // An upgrade/resubscribe replaces the old token: mark the old one superseded.
    if (ent.linkedPurchaseToken) {
      const old = await store.getEntitlementByTokenHash(sha256Hex(ent.linkedPurchaseToken));
      if (old && old.userId === userId) await store.putEntitlement({ ...old, state: 'SUPERSEDED' });
    }
    return { ...ent, tokenHash };
  }

  app.post('/api/billing/google-play/rtdn', publicLimiter, express.json({ limit: '100kb' }), async (req, res) => {
    if (!billingReady() || !pubsubVerifier) return notConfigured(res);
    try { await pubsubVerifier(req.get('authorization')); } catch (e) {
      log.warn('rtdn rejected', { reason: e.message });
      return res.status(401).json({ error: 'invalid_push', code: 'INVALID_PUSH' });
    }
    let n;
    try { n = JSON.parse(Buffer.from(String(req.body?.message?.data || ''), 'base64').toString('utf8')); } catch { n = null; }
    const sub = n?.subscriptionNotification;
    // Ack (2xx) anything we do not act on so Pub/Sub stops redelivering it.
    if (!sub?.purchaseToken || n.packageName !== config.billing.packageName) return res.status(204).end();
    try {
      const known = await store.getEntitlementByTokenHash(sha256Hex(sub.purchaseToken));
      if (!known) return res.status(204).end(); // not yet claimed by a user via /verify
      const ent = await refreshPurchase({ userId: known.userId, productId: sub.subscriptionId || known.productId, purchaseToken: sub.purchaseToken });
      log.info('rtdn processed', { notification_type: sub.notificationType, state: ent.state });
      res.status(204).end();
    } catch (e) {
      log.error('rtdn processing failed', { error_message: e.message });
      res.status(500).json({ error: 'rtdn_failed' }); // Pub/Sub will retry.
    }
  });

  // ---------- Stripe webhook (public, signature-verified, raw body) ----------
  stripeWebhookRoute(app, { config, store, stripe, log, limiter: publicLimiter });

  // ---------- Billing API (signed-in) ----------
  const billing = express.Router();
  billing.use(rateLimit({ windowMs: config.rateLimit.windowMs, limit: config.rateLimit.max, standardHeaders: 'draft-8', legacyHeaders: false }));
  billing.use(express.json({ limit: '100kb' }));
  billing.use(requireAuth(tokenVerifier, { log }));

  billing.get('/status', async (req, res) => {
    try {
      const s = await billingSummary(store, req.userId, Date.now(), summaryOpts);
      res.json({ ...s, billingConfigured: billingReady(), stripeConfigured: Boolean(config.stripe?.configured && stripe) });
    } catch (e) {
      log.error('billing status failed', { error_message: e.message });
      res.status(500).json({ error: 'Could not load plan.', code: 'BILLING_STATUS_FAILED' });
    }
  });

  billing.post('/google-play/verify', async (req, res) => {
    if (!billingReady()) return notConfigured(res);
    const productId = typeof req.body?.productId === 'string' ? req.body.productId.trim() : '';
    const purchaseToken = typeof req.body?.purchaseToken === 'string' ? req.body.purchaseToken.trim() : '';
    if (!productId || !purchaseToken || purchaseToken.length > 4096 || productId.length > 200) return res.status(400).json({ error: 'missing_purchase', code: 'MISSING_PURCHASE' });
    if (config.billing.productIds.length && !config.billing.productIds.includes(productId)) return res.status(400).json({ error: 'unknown_product', code: 'UNKNOWN_PRODUCT' });
    try {
      const owner = await store.getEntitlementByTokenHash(sha256Hex(purchaseToken));
      if (owner && owner.userId !== req.userId) return res.status(409).json({ error: 'purchase_in_use', code: 'PURCHASE_IN_USE' });
      const ent = await refreshPurchase({ userId: req.userId, productId, purchaseToken });
      if (!ent.productMatches) return res.status(400).json({ error: 'product_mismatch', code: 'PRODUCT_MISMATCH' });
      const active = isEntitlementActive(ent);
      if (active && !ent.acknowledged) {
        // Google refunds unacknowledged purchases after 3 days; failure here is retried on the next verify.
        try { await googlePlay.acknowledge(productId, purchaseToken); } catch (e) { log.error('purchase acknowledge failed', { error_message: e.message }); }
      }
      res.status(active ? 200 : 402).json({
        ...(active ? {} : { error: 'subscription_inactive', code: 'SUBSCRIPTION_INACTIVE' }),
        ...(await billingSummary(store, req.userId, Date.now(), summaryOpts)), subscriptionState: ent.state,
      });
    } catch (e) {
      const st = e?.response?.status || e?.status;
      if (st === 400 || st === 404 || st === 410) return res.status(400).json({ error: 'invalid_purchase', code: 'INVALID_PURCHASE' });
      log.error('google play verify failed', { status: st, error_message: e.message });
      res.status(502).json({ error: 'verify_failed', code: 'VERIFY_FAILED' });
    }
  });

  stripeRoutes(billing, { config, store, stripe, log, summary: uid => billingSummary(store, uid, Date.now(), summaryOpts) });

  app.use('/api/billing', billing);

  // ---------- Authenticated API ----------
  const api = express.Router();
  api.use(rateLimit({ windowMs: config.rateLimit.windowMs, limit: config.rateLimit.max * 2, standardHeaders: 'draft-8', legacyHeaders: false })); // per-IP, before auth
  api.use(express.json({ limit: '100kb' }));
  api.use(requireAuth(tokenVerifier, { log }));
  api.use(plaidContextMiddleware); // user_ref + optional link_session_id on every Plaid log line
  const userKey = req => req.userId || ipKeyGenerator(req.ip);
  api.use(rateLimit({ windowMs: config.rateLimit.windowMs, limit: config.rateLimit.max, keyGenerator: userKey, standardHeaders: 'draft-8', legacyHeaders: false }));
  const linkLimiter = rateLimit({ windowMs: config.rateLimit.windowMs, limit: config.rateLimit.linkMax, keyGenerator: userKey, standardHeaders: 'draft-8', legacyHeaders: false });
  api.use((req, res, next) => {
    if (config.plaid.configured) return next();
    res.status(503).json({ error: 'Plaid credentials are not configured on the PayAviator backend.', code: 'PLAID_NOT_CONFIGURED' });
  });

  const fail = (res, e, ctx, message, code, status = 502) => {
    log.error(ctx, plaidErrorInfo(e));
    res.status(status).json(clientError(e, message, code));
  };

  function linkTokenRequest(userId, extra) {
    return {
      user: { client_user_id: userId },
      client_name: config.plaid.clientName,
      country_codes: config.plaid.countryCodes,
      language: 'en',
      hosted_link: { completion_redirect_uri: config.plaid.completionRedirectUri, is_mobile_app: true, url_lifetime_seconds: 1800 },
      ...(config.plaid.redirectUri ? { redirect_uri: config.plaid.redirectUri } : {}),
      ...(config.plaid.webhookUrl ? { webhook: config.plaid.webhookUrl } : {}),
      ...extra,
    };
  }

  const linkResponse = d => ({ link_token: d.link_token, hosted_link_url: d.hosted_link_url || null, expiration: d.expiration || null, request_id: d.request_id || null });

  const isGateError = e => Boolean(e?.body && [400, 402, 403, 503].includes(e.status));

  /**
   * Checks before a NEW bank link (never update mode): verified email, plan limit, and for the free
   * tier a per-device slot (ANDROID_ID, HMAC'd) and, when PLAY_INTEGRITY_ENFORCE=true, a valid
   * Play Integrity verdict bound to sha256(androidId|uid). Subscribers skip all of it.
   */
  async function checkIntegrity(req, deviceId, userId) {
    if (!config.integrity.configured || !integrity) throw gateError(503, { error: 'integrity_not_configured', code: 'INTEGRITY_NOT_CONFIGURED' });
    const deny = reason => gateError(403, { error: 'integrity_failed', code: 'INTEGRITY_FAILED', reason });
    const token = String(req.get('x-play-integrity-token') || '').trim();
    if (!token) throw deny('token_missing');
    if (token.length > 8192) throw deny('token_invalid');
    let payload;
    try { payload = await integrity.decode(token); } catch (e) {
      log.warn('integrity decode failed', { user_id: userId, error_message: e.message });
      throw deny('token_invalid');
    }
    const reason = checkVerdict(payload, { packageName: config.integrity.packageName, deviceId, uid: userId });
    if (reason) { log.warn('integrity check failed', { user_id: userId, reason }); throw deny(reason); }
  }

  async function linkGate(req, userId) {
    if (config.auth?.mode !== 'disabled' && req.authClaims?.email_verified !== true) {
      throw gateError(403, { error: 'email_not_verified', code: 'EMAIL_NOT_VERIFIED' });
    }
    const s = await billingSummary(store, userId, Date.now(), summaryOpts);
    if (s.plan === 'premium' || s.plan === 'comp') return { free: false }; // comp/owner: no limit, no device/fingerprint/integrity, no claim
    const limitBody = reason => ({ error: 'subscription_required', code: 'SUBSCRIPTION_REQUIRED', limit: FREE_BANK_LIMIT, linked: s.linkedBanks, ...(reason ? { reason } : {}) });
    if (s.linkedBanks >= FREE_BANK_LIMIT) throw gateError(402, limitBody());
    if (!config.freeTier?.configured) throw gateError(503, { error: 'free_tier_not_configured', code: 'FREE_TIER_NOT_CONFIGURED' });
    const dev = readDeviceId(req);
    if (dev.missing) throw gateError(400, { error: 'device_id_required', code: 'DEVICE_ID_REQUIRED' });
    if (dev.invalid) throw gateError(400, { error: 'device_id_invalid', code: 'DEVICE_ID_INVALID' });
    const deviceId = dev.id;
    if (config.integrity?.enforce) await checkIntegrity(req, deviceId, userId);
    const device = deviceFingerprint(config.freeTier.secret, deviceId);
    if (await store.findFreeTierConflict(userId, [device], config.freeTier.cooldownDays)) throw gateError(402, limitBody('device_already_used_free'));
    return { free: true, device, limitBody };
  }

  api.post('/plaid/create-link-token', linkLimiter, enforceUserMatch, async (req, res) => {
    try { await linkGate(req, req.userId); } catch (e) {
      if (isGateError(e)) return res.status(e.status).json(e.body);
      log.error('bank limit check failed', { error_message: e.message });
      return res.status(500).json({ error: 'Could not check your plan.', code: 'BILLING_CHECK_FAILED' });
    }
    try {
      const d = await plaid.call('linkTokenCreate', linkTokenRequest(req.userId, {
        products: ['transactions'],
        transactions: { days_requested: config.plaid.daysRequested },
      }));
      await store.putPending(req.userId, d.link_token, { mode: 'add' });
      res.json(linkResponse(d));
    } catch (e) { fail(res, e, 'link token create failed', 'Could not start a bank connection.', 'LINK_TOKEN_FAILED'); }
  });

  // Update mode: re-authenticate an existing Item (ITEM_LOGIN_REQUIRED etc.) or add new accounts.
  api.post('/plaid/update-link-token', linkLimiter, enforceUserMatch, async (req, res) => {
    const itemId = String(req.body?.item_id || '');
    if (!itemId) return res.status(400).json({ error: 'Missing item_id.', code: 'MISSING_ITEM_ID' });
    const item = (await store.getItems(req.userId)).find(i => i.itemId === itemId);
    if (!item) return res.status(404).json({ error: 'Connection not found.', code: 'ITEM_NOT_FOUND' });
    try {
      const d = await plaid.call('linkTokenCreate', linkTokenRequest(req.userId, {
        access_token: item.accessToken, // update mode: no products
        ...(item.newAccountsAvailable ? { update: { account_selection_enabled: true } } : {}),
      }), { ctx: { itemId } });
      await store.putPending(req.userId, d.link_token, { mode: 'update', itemId });
      res.json({ ...linkResponse(d), mode: 'update', item_id: itemId });
    } catch (e) { fail(res, e, 'update link token create failed', 'Could not start reconnecting this bank.', 'LINK_TOKEN_FAILED'); }
  });

  async function exchangeOnce(req, userId, publicToken, metadata = {}) {
    const hash = sha256Hex(publicToken);
    const prior = await store.getExchanged(hash);
    if (prior) {
      if (prior.userId !== userId) throw Object.assign(new Error('public token belongs to another user'), { status: 403 });
      return { connected: true, item_id: prior.itemId, institution: metadata?.institution?.name || null, duplicate_exchange: true };
    }
    const gate = await linkGate(req, userId); // before exchange: no new Plaid Item is created over the limit
    const ex = await plaid.call('itemPublicTokenExchange', { public_token: publicToken }, { idempotent: false, ctx: { userId } });
    const institution = metadata?.institution || {};
    let fps = [];
    if (gate.free) {
      // Fingerprint the real accounts BEFORE storing this as the user's free bank.
      const removeAtPlaid = () => plaid.call('itemRemove', { access_token: ex.access_token }, { ctx: { itemId: ex.item_id } })
        .catch(e => log.error('item remove after free-tier rejection failed', { item_id: ex.item_id, ...plaidErrorInfo(e) }));
      let acc;
      try { acc = await plaid.call('accountsGet', { access_token: ex.access_token }, { ctx: { itemId: ex.item_id } }); } catch (e) { await removeAtPlaid(); throw e; }
      const instId = acc?.item?.institution_id || institution.institution_id || institution.id || '';
      fps = accountFingerprints(config.freeTier.secret, instId, acc?.accounts || []);
      if (await store.findFreeTierConflict(userId, fps, config.freeTier.cooldownDays)) {
        await removeAtPlaid();
        log.warn('free-tier link rejected: account already used', { user_id: userId });
        throw gateError(402, gate.limitBody('account_already_used_free'));
      }
    }
    await store.putItem({
      userId, itemId: ex.item_id, accessToken: ex.access_token,
      institutionId: institution.institution_id || institution.id || '', institutionName: institution.name || '',
    });
    if (gate.free) await store.claimFreeTier(userId, ex.item_id, [...fps, gate.device]);
    await store.markExchanged(hash, userId, ex.item_id);
    log.info('item linked', { user_id: userId, item_id: ex.item_id, request_id: ex.request_id });
    return { connected: true, item_id: ex.item_id, institution: institution.name || null };
  }

  /** Completes update mode once Plaid reports the Item healthy again. */
  async function completeUpdate(userId, itemId) {
    const item = (await store.getItems(userId)).find(i => i.itemId === itemId);
    if (!item) return { ok: false, status: 404, body: { error: 'Connection not found.', code: 'ITEM_NOT_FOUND' } };
    const d = await plaid.call('itemGet', { access_token: item.accessToken }, { ctx: { itemId: item.itemId } });
    const err = d?.item?.error;
    if (err && err.error_code) {
      await store.setItemStatus(itemId, statusForItemError(err.error_code, err.error_code_reason), err.error_code);
      return { ok: false, status: 409, body: { error: err.display_message || 'This bank still needs attention.', code: err.error_code } };
    }
    await store.setItemStatus(itemId, ITEM_STATUS.GOOD, null);
    if (item.newAccountsAvailable) await store.setNewAccountsAvailable(itemId, false);
    return { ok: true, body: { connected: true, pending: false, status: 'success', mode: 'update', item_id: itemId, institution: item.institutionName || null } };
  }

  api.get(['/plaid/hosted-status', '/plaid/hosted-status/:userId'], enforceUserMatch, async (req, res) => {
    const userId = req.userId;
    try {
      const pending = await store.getPending(userId);
      if (!pending) return res.json({ connected: false, pending: false, status: 'missing', error: 'No pending bank connection was found.' });

      const data = await plaid.call('linkTokenGet', { link_token: pending.linkToken });
      const sessions = Array.isArray(data.link_sessions) ? data.link_sessions : [];
      if (!sessions.length) return res.json({ connected: false, pending: true, status: 'waiting_for_session' });

      if (pending.mode === 'update') {
        const succeeded = sessions.some(s => s?.on_success || s?.results?.item_add_results?.length);
        const finished = sessions.some(s => s?.finished_at);
        if (succeeded || finished) {
          const out = await completeUpdate(userId, pending.itemId);
          if (out.ok || finished) await store.clearPending(userId);
          if (out.ok) return res.json(out.body);
          if (finished && !succeeded) return res.json({ connected: false, pending: false, status: 'exited', mode: 'update', item_id: pending.itemId, error: out.body.error, code: out.body.code });
          return res.json({ connected: false, pending: !finished, status: finished ? 'failed' : 'pending', mode: 'update', item_id: pending.itemId, error: out.body.error, code: out.body.code });
        }
        return res.json({ connected: false, pending: true, status: 'pending', mode: 'update' });
      }

      // Add mode: exchange every successful result across all sessions; exchanges are idempotent.
      const results = [];
      for (const s of sessions) {
        const adds = Array.isArray(s?.results?.item_add_results) ? s.results.item_add_results : [];
        if (adds.length) results.push(...adds.map(r => ({ publicToken: r?.public_token, metadata: r?.metadata || { institution: r?.institution || null, accounts: r?.accounts || [] } })));
        else if (s?.on_success?.public_token) results.push({ publicToken: s.on_success.public_token, metadata: s.on_success.metadata || {} });
      }
      const connectedItems = [];
      let limitHit = null;
      for (const r of results) {
        if (!r.publicToken) continue;
        try {
          connectedItems.push(await exchangeOnce(req, userId, r.publicToken, r.metadata)); // throws -> pending kept, safe to retry
        } catch (e) {
          if (e.status === 402 && connectedItems.length) { limitHit = e.body; continue; }
          throw e;
        }
      }
      if (connectedItems.length) {
        await store.clearPending(userId);
        return res.json({ connected: true, pending: false, status: 'success', count: connectedItems.length, institution: connectedItems[0]?.institution || null, items: connectedItems, ...(limitHit ? { skipped: limitHit } : {}) });
      }

      const last = sessions[sessions.length - 1];
      if (sessions.every(s => s?.finished_at)) {
        const exit = last?.on_exit || last?.exit || {};
        const exitErr = exit?.error || {};
        const message = exitErr.display_message || null;
        await store.clearPending(userId);
        return res.json({
          connected: false, pending: false, status: exitErr.error_code ? 'failed' : 'exited',
          error: message || (exitErr.error_code ? 'The bank connection could not be completed.' : 'The bank connection was closed before an account was connected.'),
          code: exitErr.error_code || null, link_session_id: last?.link_session_id || null,
        });
      }
      return res.json({ connected: false, pending: true, status: 'pending' });
    } catch (e) {
      if (e.status === 403) return res.status(403).json({ error: 'Forbidden.', code: 'USER_MISMATCH' });
      if (isGateError(e)) {
        await store.clearPending(userId).catch(() => {});
        return res.status(e.status).json({ connected: false, pending: false, status: e.body.error, ...e.body });
      }
      const pd = e?.response?.data || {};
      const pmsg = String(pd.error_message || pd.display_message || '');
      if (['INVALID_LINK_TOKEN', 'INVALID_PUBLIC_TOKEN'].includes(pd.error_code) || /expired|invalid.*token/i.test(pmsg)) {
        await store.clearPending(userId).catch(() => {});
        log.warn('hosted link expired; pending cleared', { user_id: userId, ...plaidErrorInfo(e) });
        return res.json({ connected: false, pending: false, status: 'expired', error: 'The previous bank connection expired. Tap Connect again to start a fresh one.', plaid_error_code: pd.error_code || 'INVALID_LINK_TOKEN' });
      }
      log.error('hosted status failed', { user_id: userId, ...plaidErrorInfo(e) });
      res.status(502).json({ connected: false, pending: true, status: 'error', ...clientError(e, 'Could not read the bank connection result. Please try again.', 'HOSTED_STATUS_FAILED') });
    }
  });

  api.post('/plaid/exchange-public-token', enforceUserMatch, async (req, res) => {
    if (!req.body?.public_token) return res.status(400).json({ error: 'Missing public token.', code: 'MISSING_PUBLIC_TOKEN' });
    try {
      const out = await exchangeOnce(req, req.userId, String(req.body.public_token), req.body.metadata || {});
      await store.clearPending(req.userId);
      res.json(out);
    } catch (e) {
      if (isGateError(e)) return res.status(e.status).json(e.body);
      if (e.status === 403) return res.status(403).json({ error: 'Forbidden.', code: 'USER_MISMATCH' });
      fail(res, e, 'public token exchange failed', 'Could not finish connecting this bank.', 'TOKEN_EXCHANGE_FAILED');
    }
  });

  // For non-hosted Link flows: call after update mode onSuccess.
  api.post('/plaid/update-complete', enforceUserMatch, async (req, res) => {
    const itemId = String(req.body?.item_id || '');
    if (!itemId) return res.status(400).json({ error: 'Missing item_id.', code: 'MISSING_ITEM_ID' });
    try {
      const out = await completeUpdate(req.userId, itemId);
      await store.clearPending(req.userId);
      res.status(out.ok ? 200 : out.status).json(out.body);
    } catch (e) { fail(res, e, 'update complete failed', 'Could not confirm the reconnection.', 'UPDATE_COMPLETE_FAILED'); }
  });

  api.get(['/plaid/accounts', '/plaid/accounts/:userId'], enforceUserMatch, async (req, res) => {
    try {
      const items = await store.getItems(req.userId);
      if (!items.length) return res.json({ accounts: [], items: [], errors: [] });
      const accounts = [], errors = [];
      for (const item of items) {
        if (BLOCKED_STATUSES.has(item.status)) { errors.push({ item_id: item.itemId, institution_name: item.institutionName || 'Connected institution', code: item.errorCode || item.status, message: 'Reconnect this bank to refresh its balance.', needs_update: true }); continue; }
        try {
          const d = await plaid.call('accountsGet', { access_token: item.accessToken }, { ctx: { itemId: item.itemId } });
          for (const a of d.accounts) accounts.push(decorateAccount(a, item));
        } catch (e) {
          const code = itemErrorCode(e);
          if (code) { item.status = statusForItemError(code, e?.response?.data?.error_code_reason); item.errorCode = code; await store.setItemStatus(item.itemId, item.status, code); }
          log.error('accounts get failed', { item_id: item.itemId, ...plaidErrorInfo(e) });
          errors.push({ item_id: item.itemId, institution_name: item.institutionName || 'Connected institution', code: code || 'ACCOUNTS_FAILED', message: e?.response?.data?.error_message || 'A fresh balance is temporarily unavailable.', needs_update: Boolean(code && item.status === ITEM_STATUS.LOGIN_REQUIRED) });
        }
      }
      const uniqueAccounts = [...new Map(accounts.map(a => [physicalAccountKey(a, a.institution_name), a])).values()];
      res.json({ accounts: uniqueAccounts, items: items.map(itemSummary), errors });
    } catch (e) {
      log.error('accounts failed', plaidErrorInfo(e));
      res.status(500).json({ error: 'Could not load accounts.', code: 'ACCOUNTS_FAILED' });
    }
  });

  /** Calls /item/remove; "already gone" at Plaid counts as removed. Throws on other errors. */
  async function removeAtPlaid(item) {
    try {
      await plaid.call('itemRemove', { access_token: item.accessToken }, { ctx: { itemId: item.itemId } });
    } catch (e) {
      const code = e?.response?.data?.error_code;
      if (!['ITEM_NOT_FOUND', 'INVALID_ACCESS_TOKEN'].includes(code)) throw e;
      log.warn('item already removed at Plaid', { item_id: item.itemId, ...plaidErrorInfo(e) });
    }
  }

  async function removeItem(userId, item) {
    await removeAtPlaid(item);
    await store.deleteItem(userId, item.itemId); // also deletes its transactions
    log.info('item removed', { user_id: userId, item_id: item.itemId });
  }

  api.delete(['/plaid/items/:itemId', '/plaid/items/:userId/:itemId'], enforceUserMatch, async (req, res) => {
    const item = (await store.getItems(req.userId)).find(x => x.itemId === req.params.itemId);
    if (!item) return res.json({ disconnected: true });
    try {
      await removeItem(req.userId, item);
      res.json({ disconnected: true });
    } catch (e) {
      // Keep the row so the Item is not orphaned (and still billed) at Plaid.
      fail(res, e, 'item remove failed', 'Could not disconnect this bank right now. Please try again.', 'DISCONNECT_FAILED');
    }
  });

  // Account deletion: removes every Item at Plaid, then deletes all of the user's stored data
  // (items, transactions, pending links, exchanged-token rows) in one DB transaction.
  // Items whose /item/remove failed are kept (with their rows) so the call can be retried.
  api.delete('/plaid/user', async (req, res) => {
    try {
      const items = await store.getItems(req.userId);
      const failed = [];
      for (const item of items) {
        try { await removeAtPlaid(item); }
        catch (e) { log.error('item remove failed', { item_id: item.itemId, ...plaidErrorInfo(e) }); failed.push(item.itemId); }
      }
      await store.deleteUserData(req.userId, { keepItemIds: failed });
      log.info('user data deleted', { user_id: req.userId, removed: items.length - failed.length, failed: failed.length });
      res.status(failed.length ? 502 : 200).json({ removed: items.length - failed.length, failed_item_ids: failed });
    } catch (e) {
      log.error('user deletion failed', { user_id: req.userId, ...plaidErrorInfo(e) });
      res.status(500).json({ error: 'Could not delete account data. Please try again.', code: 'USER_DELETE_FAILED' });
    }
  });

  api.get(['/plaid/transactions', '/plaid/transactions/:userId'], enforceUserMatch, async (req, res) => {
    try {
      const items = await store.getItems(req.userId);
      const refresh = !['0', 'false'].includes(String(req.query.refresh ?? '1'));
      const sync = [], errors = [];
      if (refresh) {
        for (const item of items) {
          if (BLOCKED_STATUSES.has(item.status)) { errors.push({ item_id: item.itemId, institution_name: item.institutionName || 'Connected institution', code: item.errorCode || item.status, needs_update: true }); continue; }
          try { sync.push(await syncItem(item)); }
          catch (e) {
            log.error('transactions sync failed', { item_id: item.itemId, ...plaidErrorInfo(e) });
            const c = clientError(e, 'Transaction sync failed.', 'TRANSACTIONS_SYNC_FAILED');
            errors.push({ item_id: item.itemId, institution_name: item.institutionName || 'Connected institution', code: c.code, message: c.error, needs_update: Boolean(itemErrorCode(e)) });
          }
        }
      }
      res.json({ transactions: await store.storedTransactions(req.userId, req.query.limit || 250), fetched_at: new Date().toISOString(), sync, errors });
    } catch (e) {
      log.error('transactions failed', plaidErrorInfo(e));
      res.status(500).json({ error: 'Could not load transactions.', code: 'TRANSACTIONS_FAILED' });
    }
  });

  api.get(['/plaid/transactions-status', '/plaid/transactions-status/:userId'], enforceUserMatch, async (req, res) => {
    try {
      const items = await store.getItems(req.userId), status = [];
      for (const item of items) {
        try {
          const d = await plaid.call('itemGet', { access_token: item.accessToken }, { ctx: { itemId: item.itemId } });
          status.push({ ...itemSummary(item), billed_products: d?.item?.billed_products || [], available_products: d?.item?.available_products || [], has_transactions_cursor: Boolean(item.transactionsCursor) });
        } catch (e) {
          log.error('item get failed', { item_id: item.itemId, ...plaidErrorInfo(e) });
          status.push({ ...itemSummary(item), ...clientError(e, 'Unable to read connection status.', 'ITEM_STATUS_FAILED') });
        }
      }
      res.json({ items: status });
    } catch (e) {
      log.error('transactions status failed', plaidErrorInfo(e));
      res.status(500).json({ error: 'Could not load status.', code: 'TRANSACTIONS_STATUS_FAILED' });
    }
  });

  app.use('/api', api);

  app.use((_req, res) => res.status(404).json({ error: 'Not found.', code: 'NOT_FOUND' }));
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    const status = err?.status || err?.statusCode || 500;
    // 4xx (e.g. malformed JSON) messages can echo request body fragments: log only the type.
    log.error('unhandled error', { type: err?.type || err?.name, status, ...(status >= 500 ? { error_message: err?.message } : {}) });
    res.status(status >= 400 && status < 600 ? status : 500).json({ error: status < 500 ? 'Bad request.' : 'Internal error.', code: status < 500 ? 'BAD_REQUEST' : 'INTERNAL' });
  });

  return app;
}
