import pg from 'pg';
import crypto from 'node:crypto';
import { encryptToken, decryptToken, isEncrypted, TOKEN_PREFIX } from './crypto.js';
import { ITEM_STATUS } from './plaid.js';

function rowToItem(x, key) {
  return {
    userId: x.user_id,
    itemId: x.item_id,
    accessToken: decryptToken(x.access_token, key),
    institutionId: x.institution_id,
    institutionName: x.institution_name,
    transactionsCursor: x.transactions_cursor || null,
    status: x.status || ITEM_STATUS.GOOD,
    errorCode: x.error_code || null,
    newAccountsAvailable: Boolean(x.new_accounts_available),
    statusUpdatedAt: x.status_updated_at || null,
  };
}

// sslmode/sslrootcert in the connection string override pg's `ssl` option, so
// strip them and let DATABASE_SSL_* / PGSSL control TLS explicitly.
export function stripSslParams(url) {
  try {
    const u = new URL(url);
    for (const p of ['sslmode', 'sslrootcert', 'sslcert', 'sslkey', 'ssl']) u.searchParams.delete(p);
    return u.toString();
  } catch { return url; }
}

export class PgStore {
  constructor({ url, ssl }, key, { log } = {}) {
    this.key = key;
    this.log = log;
    this.kind = 'postgres';
    this.pool = new pg.Pool({ connectionString: stripSslParams(url), ssl, connectionTimeoutMillis: 8000, max: 10 });
  }

  async init() {
    const q = s => this.pool.query(s);
    await q(`CREATE TABLE IF NOT EXISTS plaid_items (
      user_id TEXT, item_id TEXT PRIMARY KEY, access_token TEXT,
      institution_id TEXT, institution_name TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW())`);
    for (const col of [
      'user_id TEXT', 'access_token TEXT', 'institution_id TEXT', 'institution_name TEXT',
      'created_at TIMESTAMPTZ DEFAULT NOW()', 'updated_at TIMESTAMPTZ DEFAULT NOW()',
      'transactions_cursor TEXT', `status TEXT DEFAULT '${ITEM_STATUS.GOOD}'`, 'error_code TEXT',
      'new_accounts_available BOOLEAN DEFAULT FALSE', 'status_updated_at TIMESTAMPTZ',
    ]) await q(`ALTER TABLE plaid_items ADD COLUMN IF NOT EXISTS ${col}`);
    await q('CREATE INDEX IF NOT EXISTS plaid_items_user_id_idx ON plaid_items(user_id)');

    await q(`CREATE TABLE IF NOT EXISTS plaid_transactions (
      user_id TEXT NOT NULL, item_id TEXT NOT NULL, transaction_id TEXT PRIMARY KEY,
      payload JSONB NOT NULL, removed BOOLEAN DEFAULT FALSE, updated_at TIMESTAMPTZ DEFAULT NOW())`);
    await q('CREATE INDEX IF NOT EXISTS plaid_transactions_user_idx ON plaid_transactions(user_id)');
    await q('CREATE INDEX IF NOT EXISTS plaid_transactions_item_idx ON plaid_transactions(item_id)');

    await q(`CREATE TABLE IF NOT EXISTS plaid_pending_links (
      user_id TEXT PRIMARY KEY, link_token TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW())`);
    await q(`ALTER TABLE plaid_pending_links ADD COLUMN IF NOT EXISTS mode TEXT DEFAULT 'add'`);
    await q('ALTER TABLE plaid_pending_links ADD COLUMN IF NOT EXISTS item_id TEXT');

    // Idempotency for public_token exchange (stores sha256 of the token, never the token).
    await q(`CREATE TABLE IF NOT EXISTS plaid_exchanged_public_tokens (
      token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, item_id TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW())`);

    await this.encryptLegacyTokens();
  }

  /** One-time, idempotent: encrypt any access_token not yet carrying the enc:v1: prefix. */
  async encryptLegacyTokens() {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const r = await client.query(
        `SELECT item_id, access_token FROM plaid_items
         WHERE access_token IS NOT NULL AND access_token <> '' AND access_token NOT LIKE $1
         FOR UPDATE`, [`${TOKEN_PREFIX}%`]);
      for (const row of r.rows) {
        await client.query('UPDATE plaid_items SET access_token=$1, updated_at=NOW() WHERE item_id=$2',
          [encryptToken(row.access_token, this.key), row.item_id]);
      }
      await client.query('COMMIT');
      if (r.rows.length) this.log?.info('encrypted legacy plaintext access tokens', { count: r.rows.length });
      return r.rows.length;
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      throw e;
    } finally {
      client.release();
    }
  }

  async putItem(x) {
    await this.pool.query(
      `INSERT INTO plaid_items(user_id,item_id,access_token,institution_id,institution_name,status,error_code,status_updated_at)
       VALUES($1,$2,$3,$4,$5,'${ITEM_STATUS.GOOD}',NULL,NOW())
       ON CONFLICT(item_id) DO UPDATE SET
         access_token=EXCLUDED.access_token, institution_id=EXCLUDED.institution_id,
         institution_name=EXCLUDED.institution_name, status=EXCLUDED.status, error_code=NULL,
         status_updated_at=NOW(), updated_at=NOW()
       WHERE plaid_items.user_id=EXCLUDED.user_id`,
      [x.userId, x.itemId, encryptToken(x.accessToken, this.key), x.institutionId || null, x.institutionName || null]);
  }

  async getItems(userId) {
    const r = await this.pool.query('SELECT * FROM plaid_items WHERE user_id=$1 ORDER BY created_at', [userId]);
    return r.rows.map(x => rowToItem(x, this.key));
  }

  async getItemById(itemId) {
    const r = await this.pool.query('SELECT * FROM plaid_items WHERE item_id=$1', [itemId]);
    return r.rows[0] ? rowToItem(r.rows[0], this.key) : null;
  }

  async deleteItem(userId, itemId) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM plaid_transactions WHERE user_id=$1 AND item_id=$2', [userId, itemId]);
      await client.query('DELETE FROM plaid_items WHERE user_id=$1 AND item_id=$2', [userId, itemId]);
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      throw e;
    } finally { client.release(); }
  }

  /** Deletes all of a user's rows in one transaction, except items listed in keepItemIds (and their rows). */
  async deleteUserData(userId, { keepItemIds = [] } = {}) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM plaid_transactions WHERE user_id=$1 AND NOT (item_id = ANY($2))', [userId, keepItemIds]);
      await client.query('DELETE FROM plaid_exchanged_public_tokens WHERE user_id=$1 AND NOT (item_id = ANY($2))', [userId, keepItemIds]);
      await client.query('DELETE FROM plaid_items WHERE user_id=$1 AND NOT (item_id = ANY($2))', [userId, keepItemIds]);
      await client.query('DELETE FROM plaid_pending_links WHERE user_id=$1', [userId]);
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      throw e;
    } finally { client.release(); }
  }

  async setItemStatus(itemId, status, errorCode = null) {
    await this.pool.query('UPDATE plaid_items SET status=$1, error_code=$2, status_updated_at=NOW(), updated_at=NOW() WHERE item_id=$3',
      [status, errorCode, itemId]);
  }

  async setNewAccountsAvailable(itemId, value) {
    await this.pool.query('UPDATE plaid_items SET new_accounts_available=$1, updated_at=NOW() WHERE item_id=$2', [Boolean(value), itemId]);
  }

  /** Applies a fully-paginated /transactions/sync result and the new cursor atomically. */
  async applySync(userId, item, { upserts, removedIds, cursor }) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      for (const t of upserts) {
        await client.query(
          `INSERT INTO plaid_transactions(user_id,item_id,transaction_id,payload,removed,updated_at)
           VALUES($1,$2,$3,$4::jsonb,FALSE,NOW())
           ON CONFLICT(transaction_id) DO UPDATE SET payload=EXCLUDED.payload,removed=FALSE,updated_at=NOW()`,
          [userId, item.itemId, String(t.transaction_id), JSON.stringify(t)]);
      }
      if (removedIds.length) {
        await client.query('UPDATE plaid_transactions SET removed=TRUE,updated_at=NOW() WHERE item_id=$1 AND transaction_id = ANY($2)',
          [item.itemId, removedIds]);
      }
      await client.query('UPDATE plaid_items SET transactions_cursor=$1,updated_at=NOW() WHERE item_id=$2', [cursor || null, item.itemId]);
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      throw e;
    } finally { client.release(); }
  }

  async storedTransactions(userId, limit = 250) {
    const safeLimit = Math.max(1, Math.min(Number(limit) || 250, 500));
    const r = await this.pool.query(
      `SELECT payload FROM plaid_transactions WHERE user_id=$1 AND removed=FALSE
       ORDER BY COALESCE(payload->>'datetime',payload->>'date') DESC LIMIT $2`, [userId, safeLimit]);
    return r.rows.map(x => x.payload);
  }

  async putPending(userId, linkToken, { mode = 'add', itemId = null } = {}) {
    await this.pool.query(
      `INSERT INTO plaid_pending_links(user_id,link_token,mode,item_id) VALUES($1,$2,$3,$4)
       ON CONFLICT(user_id) DO UPDATE SET link_token=EXCLUDED.link_token,mode=EXCLUDED.mode,item_id=EXCLUDED.item_id,updated_at=NOW()`,
      [userId, linkToken, mode, itemId]);
  }

  async getPending(userId) {
    const r = await this.pool.query('SELECT link_token, mode, item_id FROM plaid_pending_links WHERE user_id=$1', [userId]);
    const x = r.rows[0];
    return x ? { linkToken: x.link_token, mode: x.mode || 'add', itemId: x.item_id || null } : null;
  }

  async clearPending(userId) {
    await this.pool.query('DELETE FROM plaid_pending_links WHERE user_id=$1', [userId]);
  }

  async getExchanged(tokenHash) {
    const r = await this.pool.query('SELECT item_id, user_id FROM plaid_exchanged_public_tokens WHERE token_hash=$1', [tokenHash]);
    return r.rows[0] ? { itemId: r.rows[0].item_id, userId: r.rows[0].user_id } : null;
  }

  async markExchanged(tokenHash, userId, itemId) {
    await this.pool.query(
      'INSERT INTO plaid_exchanged_public_tokens(token_hash,user_id,item_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',
      [tokenHash, userId, itemId]);
  }

  async close() { await this.pool.end(); }
}

/** In-memory store for local Sandbox only (refused in production by config/server). */
export class MemoryStore {
  constructor(key) {
    this.key = key || crypto.randomBytes(32);
    this.kind = 'memory';
    this.items = new Map();       // itemId -> row (encrypted token)
    this.transactions = new Map(); // transactionId -> {userId,itemId,payload,removed}
    this.pending = new Map();
    this.exchanged = new Map();
  }
  async init() {}
  async putItem(x) {
    const existing = this.items.get(x.itemId);
    if (existing && existing.user_id !== x.userId) return;
    this.items.set(x.itemId, {
      ...(existing || { created_at: Date.now(), transactions_cursor: null, new_accounts_available: false }),
      user_id: x.userId, item_id: x.itemId, access_token: encryptToken(x.accessToken, this.key),
      institution_id: x.institutionId || null, institution_name: x.institutionName || null,
      status: ITEM_STATUS.GOOD, error_code: null, status_updated_at: new Date(),
    });
  }
  async getItems(userId) {
    return [...this.items.values()].filter(x => x.user_id === userId).sort((a, b) => a.created_at - b.created_at).map(x => rowToItem(x, this.key));
  }
  async getItemById(itemId) { const x = this.items.get(itemId); return x ? rowToItem(x, this.key) : null; }
  async deleteItem(userId, itemId) {
    const x = this.items.get(itemId);
    if (!x || x.user_id !== userId) return;
    this.items.delete(itemId);
    for (const [id, t] of this.transactions) if (t.itemId === itemId) this.transactions.delete(id);
  }
  async deleteUserData(userId, { keepItemIds = [] } = {}) {
    const keep = new Set(keepItemIds);
    for (const [id, x] of this.items) if (x.user_id === userId && !keep.has(id)) this.items.delete(id);
    for (const [id, t] of this.transactions) if (t.userId === userId && !keep.has(t.itemId)) this.transactions.delete(id);
    for (const [h, x] of this.exchanged) if (x.userId === userId && !keep.has(x.itemId)) this.exchanged.delete(h);
    this.pending.delete(userId);
  }
  async setItemStatus(itemId, status, errorCode = null) {
    const x = this.items.get(itemId); if (x) Object.assign(x, { status, error_code: errorCode, status_updated_at: new Date() });
  }
  async setNewAccountsAvailable(itemId, value) { const x = this.items.get(itemId); if (x) x.new_accounts_available = Boolean(value); }
  async applySync(userId, item, { upserts, removedIds, cursor }) {
    for (const t of upserts) this.transactions.set(String(t.transaction_id), { userId, itemId: item.itemId, payload: t, removed: false });
    for (const id of removedIds) { const t = this.transactions.get(id); if (t && t.itemId === item.itemId) t.removed = true; }
    const x = this.items.get(item.itemId); if (x) x.transactions_cursor = cursor || null;
  }
  async storedTransactions(userId, limit = 250) {
    const safeLimit = Math.max(1, Math.min(Number(limit) || 250, 500));
    return [...this.transactions.values()].filter(t => t.userId === userId && !t.removed).map(t => t.payload)
      .sort((a, b) => String(b.datetime || b.date || '').localeCompare(String(a.datetime || a.date || ''))).slice(0, safeLimit);
  }
  async putPending(userId, linkToken, { mode = 'add', itemId = null } = {}) { this.pending.set(userId, { linkToken, mode, itemId }); }
  async getPending(userId) { return this.pending.get(userId) || null; }
  async clearPending(userId) { this.pending.delete(userId); }
  async getExchanged(h) { return this.exchanged.get(h) || null; }
  async markExchanged(h, userId, itemId) { if (!this.exchanged.has(h)) this.exchanged.set(h, { userId, itemId }); }
  async encryptLegacyTokens() { return 0; }
  async close() {}
}

export { isEncrypted };
