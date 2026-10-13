import { ITEM_STATUS, statusForItemError } from './plaid.js';
import { plaidWebhookFields, withPlaidContext } from './plaidLog.js';

/**
 * Routes a verified Plaid webhook. Status updates are awaited (so Plaid retries
 * on DB failure); transaction syncs run in the background and are returned as
 * `background` so the HTTP response is not delayed.
 */
export async function handleWebhook(payload, { store, syncItem, log }) {
  const { webhook_type: type, webhook_code: code, item_id: itemId } = payload || {};
  const ctx = { webhook_type: type, webhook_code: code, item_id: itemId, environment: payload?.environment };
  const item = itemId ? await store.getItemById(itemId) : null;
  if (itemId && !item) { log.warn('plaid_webhook', plaidWebhookFields(payload, { outcome: 'unknown_item' })); return {}; }
  log.info('plaid_webhook', plaidWebhookFields(payload, { userId: item?.userId }));
  if (type === 'TRANSACTIONS' && code === 'SYNC_UPDATES_AVAILABLE') {
    return { background: withPlaidContext({ userId: item?.userId, itemId }, () => syncItem(item)) };
  }

  if (type === 'TRANSACTIONS') {
    if (code === 'SYNC_UPDATES_AVAILABLE') return { background: syncItem(item) };
    return {}; // legacy INITIAL_UPDATE / HISTORICAL_UPDATE / DEFAULT_UPDATE are superseded by sync
  }

  if (type === 'ITEM') {
    switch (code) {
      case 'ERROR': {
        const errCode = payload?.error?.error_code || 'ITEM_ERROR';
        // A revoked status purges the Item's stored transactions (see store.revokeItem).
        await store.setItemStatus(itemId, statusForItemError(errCode, payload?.error?.error_code_reason), errCode);
        break;
      }
      case 'LOGIN_REPAIRED':
        await store.setItemStatus(itemId, ITEM_STATUS.GOOD, null);
        break;
      case 'PENDING_DISCONNECT':
        await store.setItemStatus(itemId, ITEM_STATUS.PENDING_DISCONNECT, payload?.reason || 'PENDING_DISCONNECT');
        break;
      case 'PENDING_EXPIRATION':
        await store.setItemStatus(itemId, ITEM_STATUS.PENDING_EXPIRATION, 'PENDING_EXPIRATION');
        break;
      case 'USER_PERMISSION_REVOKED':
      case 'USER_ACCOUNT_REVOKED':
        // Consent withdrawn: delete the Item's transactions, sync cursor, pending link and exchanged-token
        // rows; keep only the minimal Item row so the app can show "Reconnect". /item/remove is NOT called:
        // Plaid stops subscription billing on user revocation, and keeping the Item lets update mode restore it.
        await store.revokeItem(itemId, payload?.error?.error_code || code);
        log.info('item revoked, stored data purged', ctx);
        break;
      case 'NEW_ACCOUNTS_AVAILABLE':
        await store.setNewAccountsAvailable(itemId, true);
        break;
      default:
        break; // WEBHOOK_UPDATE_ACKNOWLEDGED etc.: logged only
    }
  }
  return {};
}
