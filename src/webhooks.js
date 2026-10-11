import { ITEM_STATUS, statusForItemError } from './plaid.js';

/**
 * Routes a verified Plaid webhook. Status updates are awaited (so Plaid retries
 * on DB failure); transaction syncs run in the background and are returned as
 * `background` so the HTTP response is not delayed.
 */
export async function handleWebhook(payload, { store, syncItem, log }) {
  const { webhook_type: type, webhook_code: code, item_id: itemId } = payload || {};
  const ctx = { webhook_type: type, webhook_code: code, item_id: itemId, environment: payload?.environment };
  const item = itemId ? await store.getItemById(itemId) : null;
  if (itemId && !item) { log.warn('webhook for unknown item', ctx); return {}; }
  log.info('webhook received', ctx);

  if (type === 'TRANSACTIONS') {
    if (code === 'SYNC_UPDATES_AVAILABLE') return { background: syncItem(item) };
    return {}; // legacy INITIAL_UPDATE / HISTORICAL_UPDATE / DEFAULT_UPDATE are superseded by sync
  }

  if (type === 'ITEM') {
    switch (code) {
      case 'ERROR': {
        const errCode = payload?.error?.error_code || 'ITEM_ERROR';
        await store.setItemStatus(itemId, statusForItemError(errCode), errCode);
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
        await store.setItemStatus(itemId, ITEM_STATUS.REVOKED, payload?.error?.error_code || code);
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
