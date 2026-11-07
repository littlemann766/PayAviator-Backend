import { sha256Hex } from './crypto.js';
import { entitlementFromPurchase, isEntitlementActive } from './billing.js';

/**
 * Android applicationId from the app review (PayAviator @ 5e1a036).
 * Backend tests use the fixture package `app.payaviator` and product `payaviator_premium`.
 * Those fixture values are not a verified production package or SKU. This module does not change them.
 */
export const ANDROID_APPLICATION_ID = 'com.payaviator.app';
export const FIXTURE_ANDROID_PACKAGE = 'app.payaviator';
export const FIXTURE_PLAY_PRODUCT_ID = 'payaviator_premium';

/** Play subscriptionsv2 states that can still renew, resume, or finish a charge. Expired/revoked are not in this set. */
const MAY_BILL_STATES = new Set([
  'SUBSCRIPTION_STATE_ACTIVE',
  'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
  'SUBSCRIPTION_STATE_CANCELED',
  'SUBSCRIPTION_STATE_PAUSED',
  'SUBSCRIPTION_STATE_ON_HOLD',
  'SUBSCRIPTION_STATE_PENDING',
]);

export function subscriptionMayStillBill(state, expiresAt, now = Date.now()) {
  if (!MAY_BILL_STATES.has(state)) return false;
  if (state === 'SUBSCRIPTION_STATE_PAUSED' || state === 'SUBSCRIPTION_STATE_ON_HOLD' || state === 'SUBSCRIPTION_STATE_PENDING') return true;
  return isEntitlementActive({ state, expiresAt }, now);
}

/**
 * Firebase Admin getUser: `auth/user-not-found` is the only definitive "no such account" signal
 * (deleted, or never created in this project). Disabled users still resolve and must not be treated as deleted.
 * Every other error, including permission and network failures, is unavailable — not proof of deletion.
 */
export function classifyAccountLookupError(err) {
  const code = err?.code || err?.errorInfo?.code || '';
  if (code === 'auth/user-not-found') return 'deleted';
  return 'unavailable';
}

export async function lookupAccount(accountLookup, uid) {
  if (!accountLookup?.getUser || !uid) return 'unavailable';
  try {
    await accountLookup.getUser(uid);
    return 'exists';
  } catch (e) {
    return classifyAccountLookupError(e);
  }
}

/** Identifiers Play itself returns. Client body fields with the same names are ignored by the caller. */
export function playBindingIds(purchase) {
  const ext = purchase?.externalAccountIdentifiers;
  if (!ext || typeof ext !== 'object') return [];
  const ids = [];
  for (const key of ['obfuscatedExternalAccountId', 'externalAccountId']) {
    const v = ext[key];
    if (typeof v === 'string' && v.trim()) ids.push(v.trim());
  }
  return ids;
}

/**
 * `unbound` — Play did not send an account id (current app builds do not set obfuscatedAccountId).
 * `caller` / `stored_owner` — exact string match only. Hashes are not interpreted.
 * `other` — Play named an id that is neither sign-in. Fail closed; do not reassign.
 * Subscribe with Google email is intentionally not read.
 */
export function classifyPlayBinding(bindingIds, callerId, ownerUserId) {
  if (!bindingIds?.length) return 'unbound';
  if (bindingIds.includes(callerId)) return 'caller';
  if (ownerUserId && bindingIds.includes(ownerUserId)) return 'stored_owner';
  return 'other';
}

/**
 * Cross-user decision. Never returns a grant by itself; the caller still has to have a Play-verified purchase.
 * `conflict` keeps today's 409 and does not move the row.
 * `reassign` is only when the stored owner is definitively gone AND Play did not name some other account id.
 * `ownership_unconfirmed` is the honest fail-closed path: no transfer, and checkout is blocked when the sub may still bill.
 */
export function decideCrossUserRestore({ lookup, binding, mayBill }) {
  if (lookup === 'exists') return { action: 'conflict', recoveryRequired: false, duplicateCheckoutBlocked: false };
  if (binding === 'other') {
    return mayBill
      ? { action: 'ownership_unconfirmed', recoveryRequired: true, duplicateCheckoutBlocked: true }
      : { action: 'conflict', recoveryRequired: false, duplicateCheckoutBlocked: false };
  }
  if (lookup === 'deleted') {
    return mayBill
      ? { action: 'reassign', recoveryRequired: false, duplicateCheckoutBlocked: false }
      : { action: 'conflict', recoveryRequired: false, duplicateCheckoutBlocked: false };
  }
  if (mayBill) return { action: 'ownership_unconfirmed', recoveryRequired: true, duplicateCheckoutBlocked: true };
  return { action: 'conflict', recoveryRequired: false, duplicateCheckoutBlocked: false };
}

export function recoveryFlags({ hold, entitlements, plan, now = Date.now() }) {
  const recoveryRequired = Boolean(hold?.duplicateCheckoutBlocked);
  const mayResume = (entitlements || []).some(e => subscriptionMayStillBill(e.state, e.expiresAt, now) && !isEntitlementActive(e, now));
  return {
    recoveryRequired,
    duplicateCheckoutBlocked: plan !== 'free' || recoveryRequired || mayResume,
  };
}

/** Removes raw purchase tokens / Play token URLs from a provider error before it is logged. */
export function scrubBillingMessage(message, secrets = []) {
  let m = String(message || '');
  for (const secret of secrets) {
    if (typeof secret === 'string' && secret.length >= 8) m = m.split(secret).join('[REDACTED]');
  }
  return m
    .replace(/subscriptionsv2\/tokens\/[^/?\s"']+/g, 'subscriptionsv2/tokens/[REDACTED]')
    .replace(/\/tokens\/[^/?\s"']+/g, '/tokens/[REDACTED]');
}

async function clearMatchingHold(store, userId, tokenHash) {
  const hold = await store.getRecoveryHold(userId);
  if (hold && hold.tokenHash === tokenHash) await store.clearRecoveryHold(userId);
}

function conflictBody() {
  return { error: 'purchase_in_use', code: 'PURCHASE_IN_USE' };
}

function unconfirmedBody() {
  return {
    error: 'purchase_in_use',
    code: 'PURCHASE_IN_USE',
    recoveryRequired: true,
    duplicateCheckoutBlocked: true,
    recoveryCode: 'OWNERSHIP_UNCONFIRMED',
  };
}

function playHttpStatus(err) {
  return err?.response?.status || err?.status || 0;
}

async function loadSummary(summary, userId) {
  return summary(userId);
}

async function flagsFor(store, userId, plan, now) {
  const [hold, entitlements] = await Promise.all([store.getRecoveryHold(userId), store.getEntitlements(userId)]);
  return recoveryFlags({ hold, entitlements, plan, now });
}

/**
 * Verifies a Play purchase and, only when the stored owner is definitively gone, moves that entitlement
 * to the signed-in user. A living owner, an auth lookup failure, or a Play failure never moves it.
 * Bank rows are not touched.
 */
export async function handleGooglePlayVerify({ userId, body, config, store, googlePlay, accountLookup, log, summary, now = Date.now() }) {
  const productId = typeof body?.productId === 'string' ? body.productId.trim() : '';
  const purchaseToken = typeof body?.purchaseToken === 'string' ? body.purchaseToken.trim() : '';
  if (!productId || !purchaseToken || purchaseToken.length > 4096 || productId.length > 200) {
    return { status: 400, body: { error: 'missing_purchase', code: 'MISSING_PURCHASE' } };
  }
  if (config.billing.productIds.length && !config.billing.productIds.includes(productId)) {
    return { status: 400, body: { error: 'unknown_product', code: 'UNKNOWN_PRODUCT' } };
  }

  const tokenHash = sha256Hex(purchaseToken);
  const owner = await store.getEntitlementByTokenHash(tokenHash);
  const secrets = [purchaseToken];

  const finishOwned = async (ent, { mode = 'same', recovered = false, supersede = [], fromUserId = userId } = {}) => {
    const claim = from => store.applyPlayClaim({
      mode, tokenHash, userId, fromUserId: from, productId,
      state: ent.state, expiresAt: ent.expiresAt, platform: 'google_play', supersede,
    });
    let applied = await claim(fromUserId);
    if (!applied.ok && applied.ownerUserId === userId) {
      applied = await store.applyPlayClaim({
        mode: 'same', tokenHash, userId, fromUserId: userId, productId,
        state: ent.state, expiresAt: ent.expiresAt, platform: 'google_play', supersede,
      });
    } else if (!applied.ok && applied.ownerUserId && mode === 'reassign') {
      const winnerLookup = await lookupAccount(accountLookup, applied.ownerUserId);
      if (winnerLookup === 'deleted') {
        applied = await claim(applied.ownerUserId);
        if (!applied.ok && applied.ownerUserId === userId) {
          applied = await store.applyPlayClaim({
            mode: 'same', tokenHash, userId, fromUserId: userId, productId,
            state: ent.state, expiresAt: ent.expiresAt, platform: 'google_play', supersede,
          });
        }
      } else if (winnerLookup === 'unavailable' && subscriptionMayStillBill(ent.state, ent.expiresAt, now)) {
        await store.putRecoveryHold(userId, { code: 'OWNERSHIP_UNCONFIRMED', duplicateCheckoutBlocked: true, tokenHash });
        return { status: 409, body: unconfirmedBody() };
      } else {
        await store.clearRecoveryHold(userId);
        return { status: 409, body: conflictBody() };
      }
    }
    if (!applied.ok) return { status: 409, body: conflictBody() };
    const hold = await store.getRecoveryHold(userId);
    if (!hold || hold.tokenHash === tokenHash || isEntitlementActive({ state: ent.state, expiresAt: ent.expiresAt }, now)) {
      await store.clearRecoveryHold(userId);
    }
    const active = isEntitlementActive({ state: ent.state, expiresAt: ent.expiresAt }, now);
    if (active && !ent.acknowledged) {
      try { await googlePlay.acknowledge(productId, purchaseToken); }
      catch (e) { log.error('purchase acknowledge failed', { error_message: scrubBillingMessage(e.message, secrets) }); }
    }
    const summaryBody = await loadSummary(summary, userId);
    const flags = await flagsFor(store, userId, summaryBody.plan, now);
    return {
      status: active ? 200 : 402,
      body: {
        ...(active ? {} : { error: 'subscription_inactive', code: 'SUBSCRIPTION_INACTIVE' }),
        ...summaryBody,
        ...flags,
        subscriptionState: ent.state,
        ...(recovered ? { recovered: true } : {}),
      },
    };
  };

  const verifyWithPlay = async () => {
    let purchase;
    try { purchase = await googlePlay.getSubscription(purchaseToken); }
    catch (e) {
      const st = playHttpStatus(e);
      if (st === 400 || st === 404 || st === 410) return { error: { status: 400, body: { error: 'invalid_purchase', code: 'INVALID_PURCHASE' } } };
      log.error('google play verify failed', { status: st || undefined, error_message: scrubBillingMessage(e.message, secrets) });
      return { error: { status: 502, body: { error: 'verify_failed', code: 'VERIFY_FAILED' } } };
    }
    const ent = entitlementFromPurchase(purchase, productId);
    if (ent.linkedPurchaseToken) secrets.push(ent.linkedPurchaseToken);
    if (!ent.productMatches) return { error: { status: 400, body: { error: 'product_mismatch', code: 'PRODUCT_MISMATCH' } } };
    return { purchase, ent };
  };

  // Same sign-in already holds the token, or nobody does: verify, then refuse a replacement token whose
  // previous token still belongs to a living different account.
  if (!owner || owner.userId === userId) {
    const verified = await verifyWithPlay();
    if (verified.error) return verified.error;
    const { purchase, ent } = verified;
    const linkedRaw = ent.linkedPurchaseToken;
    let supersede = [];
    if (linkedRaw) {
      const linked = await store.getEntitlementByTokenHash(sha256Hex(linkedRaw));
      if (linked && linked.userId !== userId) {
        const linkedLookup = await lookupAccount(accountLookup, linked.userId);
        const decision = decideCrossUserRestore({
          lookup: linkedLookup,
          binding: classifyPlayBinding(playBindingIds(purchase), userId, linked.userId),
          mayBill: subscriptionMayStillBill(ent.state, ent.expiresAt, now),
        });
        if (decision.action === 'conflict') {
          await clearMatchingHold(store, userId, sha256Hex(linkedRaw));
          return { status: 409, body: conflictBody() };
        }
        if (decision.action === 'ownership_unconfirmed') {
          await store.putRecoveryHold(userId, { code: 'OWNERSHIP_UNCONFIRMED', duplicateCheckoutBlocked: true, tokenHash: sha256Hex(linkedRaw) });
          return { status: 409, body: unconfirmedBody() };
        }
        supersede = [{ tokenHash: linked.tokenHash, userId: linked.userId }];
        return finishOwned(ent, { mode: 'same', recovered: true, supersede });
      } else if (linked && linked.userId === userId) {
        supersede = [{ tokenHash: linked.tokenHash, userId }];
      }
    }
    return finishOwned(ent, { mode: 'same', recovered: false, supersede });
  }

  // Different stored owner. Do not call Play when Auth still has that user — the 409 is the ownership check.
  const ownerLookup = await lookupAccount(accountLookup, owner.userId);
  if (ownerLookup === 'exists') {
    await clearMatchingHold(store, userId, tokenHash);
    return { status: 409, body: conflictBody() };
  }

  const verified = await verifyWithPlay();
  if (verified.error) return verified.error;
  const { purchase, ent } = verified;
  const decision = decideCrossUserRestore({
    lookup: ownerLookup,
    binding: classifyPlayBinding(playBindingIds(purchase), userId, owner.userId),
    mayBill: subscriptionMayStillBill(ent.state, ent.expiresAt, now),
  });
  if (decision.action === 'conflict') {
    await clearMatchingHold(store, userId, tokenHash);
    return { status: 409, body: conflictBody() };
  }
  if (decision.action === 'ownership_unconfirmed') {
    await store.putRecoveryHold(userId, { code: 'OWNERSHIP_UNCONFIRMED', duplicateCheckoutBlocked: true, tokenHash });
    log.info('play restore not transferred', { reason: 'ownership_unconfirmed' });
    return { status: 409, body: unconfirmedBody() };
  }

  const linkedRaw = ent.linkedPurchaseToken;
  let supersede = [];
  if (linkedRaw) {
    const linked = await store.getEntitlementByTokenHash(sha256Hex(linkedRaw));
    if (linked && linked.userId === owner.userId) supersede = [{ tokenHash: linked.tokenHash, userId: owner.userId }];
    else if (linked && linked.userId !== userId) {
      const linkedLookup = await lookupAccount(accountLookup, linked.userId);
        if (linkedLookup !== 'deleted') {
          if (linkedLookup === 'unavailable' && subscriptionMayStillBill(ent.state, ent.expiresAt, now)) {
            await store.putRecoveryHold(userId, { code: 'OWNERSHIP_UNCONFIRMED', duplicateCheckoutBlocked: true, tokenHash });
            return { status: 409, body: unconfirmedBody() };
          }
          await clearMatchingHold(store, userId, tokenHash);
          return { status: 409, body: conflictBody() };
        }
      supersede = [{ tokenHash: linked.tokenHash, userId: linked.userId }];
    }
  }
  log.info('play entitlement recovered onto deleted-account successor', { state: ent.state });
  return finishOwned(ent, { mode: 'reassign', recovered: true, supersede, fromUserId: owner.userId });
}
