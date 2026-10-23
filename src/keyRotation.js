import { decryptToken, encryptToken, decryptsWith, isEncrypted } from './crypto.js';

/**
 * Re-encrypt plaid_items.access_token from oldKey to newKey in ONE transaction.
 * Verifies inside the transaction and rolls back on any problem. Counts only; never logs tokens.
 * apply=false: dry run (always rolls back).
 */
export async function reencryptTokens(pool, newKey, oldKey, { apply = false } = {}) {
  const client = await pool.connect();
  const c = { total: 0, newKey: 0, oldKey: 0, plaintext: 0, undecryptable: 0, reencrypted: 0 };
  try {
    await client.query('BEGIN');
    const rows = (await client.query(
      `SELECT item_id, access_token FROM plaid_items WHERE access_token IS NOT NULL AND access_token <> '' FOR UPDATE`)).rows;
    c.total = rows.length;
    for (const r of rows) {
      if (!isEncrypted(r.access_token)) { c.plaintext++; continue; }
      if (decryptsWith(r.access_token, newKey)) { c.newKey++; continue; }
      if (oldKey && decryptsWith(r.access_token, oldKey)) {
        c.oldKey++;
        if (apply) {
          await client.query('UPDATE plaid_items SET access_token=$1 WHERE item_id=$2',
            [encryptToken(decryptToken(r.access_token, oldKey), newKey), r.item_id]);
          c.reencrypted++;
        }
        continue;
      }
      c.undecryptable++;
    }
    if (!apply) { await client.query('ROLLBACK'); return { ...c, result: 'dry-run' }; }
    const after = (await client.query(`SELECT access_token FROM plaid_items WHERE access_token IS NOT NULL AND access_token <> ''`)).rows;
    c.verifyFailuresAfter = after.filter(r => isEncrypted(r.access_token) && !decryptsWith(r.access_token, newKey)).length;
    if (c.verifyFailuresAfter || c.undecryptable) { await client.query('ROLLBACK'); return { ...c, result: 'rolled_back' }; }
    await client.query('COMMIT');
    return { ...c, result: 'committed' };
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally { client.release(); }
}
