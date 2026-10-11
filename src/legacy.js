import { decryptToken } from './crypto.js';

// Firebase Auth auto-generated uids are 28 alphanumeric characters; accept 20-128 to
// tolerate other Firebase uid lengths. Legacy app IDs ("pp-…", "ppd_…",
// "payaviator-local-user") contain '-' or '_' and never match.
const FIREBASE_UID = /^[A-Za-z0-9]{20,128}$/;
export const isLegacyUserId = id => !FIREBASE_UID.test(String(id ?? ''));

const GONE_AT_PLAID = new Set(['ITEM_NOT_FOUND', 'INVALID_ACCESS_TOKEN']);

/**
 * Finds data owned by legacy (non-Firebase) user IDs. With apply=true, calls
 * /item/remove for each legacy item and deletes the item, its transactions,
 * and the legacy users' pending links and exchanged-token rows.
 * Returns counts only; never returns or logs tokens.
 */
export async function cleanupLegacyItems({ pool, plaid, key, apply = false }) {
  const q = (sql, params) => pool.query(sql, params);
  const userRows = (await q(`
    SELECT user_id FROM plaid_items UNION SELECT user_id FROM plaid_transactions
    UNION SELECT user_id FROM plaid_pending_links UNION SELECT user_id FROM plaid_exchanged_public_tokens`)).rows;
  const legacyUsers = userRows.map(r => r.user_id).filter(isLegacyUserId);
  const count = async (table, extra = '') =>
    Number((await q(`SELECT count(*)::int AS n FROM ${table} WHERE (user_id = ANY($1) OR user_id IS NULL) ${extra}`, [legacyUsers])).rows[0].n);

  const report = {
    mode: apply ? 'apply' : 'dry-run',
    legacy_users: legacyUsers.length,
    legacy_items: await count('plaid_items'),
    legacy_transactions: await count('plaid_transactions'),
    legacy_pending_links: await count('plaid_pending_links'),
    legacy_exchanged_tokens: await count('plaid_exchanged_public_tokens'),
    firebase_items_kept: Number((await q('SELECT count(*)::int AS n FROM plaid_items WHERE NOT (user_id = ANY($1)) AND user_id IS NOT NULL', [legacyUsers])).rows[0].n),
  };
  if (!apply) return report;

  const items = (await q('SELECT item_id, access_token FROM plaid_items WHERE user_id = ANY($1) OR user_id IS NULL', [legacyUsers])).rows;
  let removedAtPlaid = 0, alreadyGone = 0, deleted = 0;
  const failed = [];
  for (const row of items) {
    try {
      const accessToken = decryptToken(row.access_token, key);
      if (accessToken) {
        try { await plaid.call('itemRemove', { access_token: accessToken }); removedAtPlaid++; }
        catch (e) {
          if (!GONE_AT_PLAID.has(e?.response?.data?.error_code)) throw e;
          alreadyGone++;
        }
      }
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query('DELETE FROM plaid_transactions WHERE item_id=$1', [row.item_id]);
        await client.query('DELETE FROM plaid_exchanged_public_tokens WHERE item_id=$1', [row.item_id]);
        await client.query('DELETE FROM plaid_items WHERE item_id=$1', [row.item_id]);
        await client.query('COMMIT');
        deleted++;
      } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; } finally { client.release(); }
    } catch (e) {
      failed.push({ item_id: row.item_id, error_code: e?.response?.data?.error_code || e?.code || 'ERROR', request_id: e?.response?.data?.request_id || null });
    }
  }
  const keep = failed.map(f => f.item_id);
  // Remaining legacy rows not tied to a kept (failed) item.
  const orphanTx = (await q('DELETE FROM plaid_transactions WHERE (user_id = ANY($1) OR user_id IS NULL) AND NOT (item_id = ANY($2))', [legacyUsers, keep])).rowCount;
  const orphanEx = (await q('DELETE FROM plaid_exchanged_public_tokens WHERE user_id = ANY($1) AND NOT (item_id = ANY($2))', [legacyUsers, keep])).rowCount;
  const pending = (await q('DELETE FROM plaid_pending_links WHERE user_id = ANY($1) OR user_id IS NULL', [legacyUsers])).rowCount;

  return {
    ...report,
    removed_at_plaid: removedAtPlaid,
    already_gone_at_plaid: alreadyGone,
    items_deleted: deleted,
    items_failed: failed.length,
    failed, // item_id + Plaid error_code/request_id only
    orphan_transactions_deleted: orphanTx,
    orphan_exchanged_tokens_deleted: orphanEx,
    pending_links_deleted: pending,
  };
}
