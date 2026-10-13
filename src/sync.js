import { plaidErrorInfo, itemErrorCode, statusForItemError } from './plaid.js';

export function normalizeTransaction(t, item) {
  const cp = Array.isArray(t.counterparties) ? t.counterparties.find(x => x?.logo_url || x?.name) : null;
  return {
    ...t,
    merchant_name: t.merchant_name || cp?.name || t.name || 'Transaction',
    logo_url: t.logo_url || cp?.logo_url || null,
    merchant_logo_url: t.logo_url || cp?.logo_url || null,
    category_icon_url: t.personal_finance_category_icon_url || null,
    website: t.website || cp?.website || null,
    item_id: item.itemId,
    institution_name: item.institutionName || 'Connected institution',
  };
}

/**
 * Creates syncItem(item) implementing Plaid's recommended /transactions/sync loop:
 * page until has_more=false, then apply all pages + the new cursor atomically.
 * TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION restarts from the saved cursor.
 * Concurrent syncs of one item (webhook + app refresh) share a single run.
 */
export function createSyncer({ store, plaid, log, maxPages = 100, maxRestarts = 3 }) {
  const inFlight = new Map();

  async function run(item) {
    for (let restart = 0; ; restart++) {
      let cursor = item.transactionsCursor || null;
      const upserts = new Map();
      const removed = new Set();
      let pages = 0, hasMore = true, added = 0, modified = 0, removedCount = 0;
      try {
        while (hasMore) {
          if (pages >= maxPages) throw Object.assign(new Error('transactions sync exceeded max pages'), { code: 'SYNC_MAX_PAGES' });
          const req = { access_token: item.accessToken, count: 500, ...(cursor ? { cursor } : {}) };
          const d = await plaid.call('transactionsSync', req, { ctx: { itemId: item.itemId, userId: item.userId } });
          for (const t of [...(d.added || []), ...(d.modified || [])]) {
            removed.delete(String(t.transaction_id));
            upserts.set(String(t.transaction_id), normalizeTransaction(t, item));
          }
          for (const r of d.removed || []) {
            const id = String(r.transaction_id || r);
            upserts.delete(id);
            removed.add(id);
          }
          added += (d.added || []).length; modified += (d.modified || []).length; removedCount += (d.removed || []).length;
          cursor = d.next_cursor || cursor;
          hasMore = Boolean(d.has_more);
          pages++;
        }
      } catch (e) {
        const code = e?.response?.data?.error_code;
        if (code === 'TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION' && restart < maxRestarts) {
          log.warn('transactions sync restarted (mutation during pagination)', { item_id: item.itemId, restart: restart + 1, ...plaidErrorInfo(e) });
          continue;
        }
        const itemCode = itemErrorCode(e);
        if (itemCode) await store.setItemStatus(item.itemId, statusForItemError(itemCode, e?.response?.data?.error_code_reason), itemCode);
        throw e;
      }
      const applied = await store.applySync(item.userId, item, { upserts: [...upserts.values()], removedIds: [...removed], cursor });
      if (applied === false) {
        log.warn('transactions sync discarded (item revoked or removed meanwhile)', { item_id: item.itemId });
        return { item_id: item.itemId, institution_name: item.institutionName || 'Connected institution', added: 0, modified: 0, removed: 0, pages, discarded: true };
      }
      item.transactionsCursor = cursor;
      return { item_id: item.itemId, institution_name: item.institutionName || 'Connected institution', added, modified, removed: removedCount, pages };
    }
  }

  return function syncItem(item) {
    if (inFlight.has(item.itemId)) return inFlight.get(item.itemId);
    const p = run(item).finally(() => inFlight.delete(item.itemId));
    inFlight.set(item.itemId, p);
    return p;
  };
}
