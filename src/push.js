// Bank-reconnect push notifications via Firebase Cloud Messaging (free; works on the Spark plan).
// Payloads never carry balances, amounts, account numbers or bank names: generic text + item_id only.

export const RECONNECT_PUSH = Object.freeze({
  title: 'Reconnect your bank',
  body: 'One of your bank connections needs attention. Open PayAviator to reconnect.',
  type: 'bank_reconnect',
  androidChannelId: 'bank_reconnect',
});

const TOKEN_RE = /^[A-Za-z0-9_:.\-]{20,4096}$/;
export const PLATFORMS = new Set(['android', 'ios', 'web']);
export const isValidFcmToken = t => typeof t === 'string' && TOKEN_RE.test(t);

// FCM errors that mean the token will never work again: delete it.
const DEAD_TOKEN_CODES = new Set([
  'messaging/registration-token-not-registered',
  'messaging/invalid-registration-token',
]);

/** Real FCM client (firebase-admin). Returns null when push is not configured. */
export async function createMessagingClient(push) {
  if (!push?.configured) return null;
  const { initializeApp, cert, getApps } = await import('firebase-admin/app');
  const { getMessaging } = await import('firebase-admin/messaging');
  const name = 'payaviator-fcm';
  const app = getApps().find(a => a.name === name) || initializeApp({ credential: cert(push.serviceAccount), projectId: push.projectId }, name);
  const m = getMessaging(app);
  return { sendEachForMulticast: msg => m.sendEachForMulticast(msg) };
}

export function reconnectMessage(tokens, { itemId, reason }) {
  return {
    tokens,
    notification: { title: RECONNECT_PUSH.title, body: RECONNECT_PUSH.body },
    data: { type: RECONNECT_PUSH.type, item_id: String(itemId), reason: String(reason) },
    android: {
      priority: 'high',
      collapseKey: `bank_reconnect_${itemId}`.slice(0, 64),
      notification: { channelId: RECONNECT_PUSH.androidChannelId, tag: `bank_reconnect_${itemId}`, visibility: 'private' },
    },
    apns: { headers: { 'apns-collapse-id': `bank_reconnect_${itemId}`.slice(0, 64) } },
  };
}

/**
 * Sends one reconnect push for an Item to all of its owner's devices.
 * Never throws: returns an outcome string for logs/tests.
 */
export function createReconnectNotifier({ store, messaging, log, dedupeMs = 24 * 60 * 60 * 1000, now = () => Date.now() }) {
  return async function notifyReconnect(item, reason) {
    const ctx = { user_id: item.userId, item_id: item.itemId, reason };
    try {
      if (!messaging) { log.info('push skipped', { ...ctx, outcome: 'not_configured' }); return 'not_configured'; }
      const tokens = await store.getFcmTokens(item.userId);
      if (!tokens.length) { log.info('push skipped', { ...ctx, outcome: 'no_devices' }); return 'no_devices'; }
      if (!(await store.claimPushSlot(item.itemId, dedupeMs, now()))) { log.info('push skipped', { ...ctx, outcome: 'deduped' }); return 'deduped'; }
      let res;
      try { res = await messaging.sendEachForMulticast(reconnectMessage(tokens, { itemId: item.itemId, reason })); }
      catch (e) {
        await store.releasePushSlot(item.itemId).catch(() => {}); // nothing delivered: allow a retry
        log.error('push failed', { ...ctx, outcome: 'send_error', error_code: e?.code, error_message: e?.message });
        return 'send_error';
      }
      const dead = [];
      (res.responses || []).forEach((r, i) => { if (!r.success && DEAD_TOKEN_CODES.has(r.error?.code)) dead.push(tokens[i]); });
      if (dead.length) await store.deleteFcmTokens(dead);
      if (!res.successCount) await store.releasePushSlot(item.itemId).catch(() => {});
      const errorCodes = [...new Set((res.responses || []).filter(r => !r.success).map(r => r.error?.code || 'unknown'))];
      log.info('push sent', { ...ctx, outcome: res.successCount ? 'sent' : 'all_failed', devices: tokens.length, success: res.successCount, failure: res.failureCount, removed_tokens: dead.length, error_codes: errorCodes });
      return res.successCount ? 'sent' : 'all_failed';
    } catch (e) {
      log.error('push failed', { ...ctx, outcome: 'error', error_message: e?.message });
      return 'error';
    }
  };
}
