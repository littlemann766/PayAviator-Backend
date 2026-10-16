import pg from 'pg';
import crypto from 'node:crypto';
import { encryptToken, decryptToken, isEncrypted, TOKEN_PREFIX } from './crypto.js';
import { ITEM_STATUS } from './plaid.js';
import { isLegacyUserId } from './legacy.js';
import { applyPush, publicItem, SYNC_LIMITS } from './cloudSync.js';

const rowToSync = x => ({ kind: x.kind, id: x.id, data: x.data, deleted: Boolean(x.deleted), updatedAt: Number(x.updated_at), seq: Number(x.seq) });

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

function rowToEnt(x) {
  return { tokenHash: x.purchase_token_hash, userId: x.user_id, productId: x.product_id, platform: x.platform,
    state: x.state, expiresAt: x.expires_at ? new Date(x.expires_at).toISOString() : null };
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

    // Paid entitlements (Google Play subscriptions). Only a sha256 of the purchase token is stored.
    await q(`CREATE TABLE IF NOT EXISTS billing_entitlements (
      purchase_token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, product_id TEXT NOT NULL,
      platform TEXT NOT NULL DEFAULT 'google_play', state TEXT NOT NULL, expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW())`);
    await q('CREATE INDEX IF NOT EXISTS billing_entitlements_user_idx ON billing_entitlements(user_id)');

    // Free-tier fingerprints: keyed HMACs only. released_at set when the bank/account is deleted; purged after the cooldown.
    await q(`CREATE TABLE IF NOT EXISTS fcm_tokens (
      token TEXT PRIMARY KEY, user_id TEXT NOT NULL, platform TEXT NOT NULL DEFAULT 'android',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
    await q('CREATE INDEX IF NOT EXISTS fcm_tokens_user_idx ON fcm_tokens(user_id)');
    await q(`CREATE TABLE IF NOT EXISTS push_dedupe (
      item_id TEXT PRIMARY KEY, sent_at TIMESTAMPTZ NOT NULL)`);
    await q(`CREATE TABLE IF NOT EXISTS free_tier_claims (
      kind TEXT NOT NULL, hash TEXT NOT NULL, user_id TEXT NOT NULL, item_id TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(), released_at TIMESTAMPTZ,
      PRIMARY KEY (kind, hash, user_id))`);
    await q('CREATE INDEX IF NOT EXISTS free_tier_claims_item_idx ON free_tier_claims(item_id)');
    await q('CREATE INDEX IF NOT EXISTS free_tier_claims_user_idx ON free_tier_claims(user_id)');

    // Stripe web billing: uid <-> Stripe customer id (for the portal), and processed webhook event ids (idempotency).
    await q(`CREATE TABLE IF NOT EXISTS stripe_customers (
      user_id TEXT PRIMARY KEY, customer_id TEXT NOT NULL UNIQUE, created_at TIMESTAMPTZ DEFAULT NOW())`);
    await q(`CREATE TABLE IF NOT EXISTS stripe_events (
      event_id TEXT PRIMARY KEY, type TEXT NOT NULL, processed_at TIMESTAMPTZ DEFAULT NOW())`);

    // Cloud sync: per-user items (bills, income, ...). Tombstones (deleted=true) keep data '{}' and are purged after 90 days.
    await q(`CREATE TABLE IF NOT EXISTS sync_items (
      user_id TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL, data JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at BIGINT NOT NULL, deleted BOOLEAN NOT NULL DEFAULT FALSE, seq BIGSERIAL,
      PRIMARY KEY (user_id, kind, id))`);
    await q('CREATE INDEX IF NOT EXISTS sync_items_user_seq_idx ON sync_items(user_id, seq)');

    await this.encryptLegacyTokens();
  }

  /** Items changed after `since` (seq), oldest first, tombstones included. */
  async syncChanges(userId, since = 0, limit = SYNC_LIMITS.maxChangesLimit) {
    const lim = Math.max(1, Math.min(Number(limit) || SYNC_LIMITS.maxChangesLimit, SYNC_LIMITS.maxChangesLimit));
    const r = await this.pool.query('SELECT * FROM sync_items WHERE user_id=$1 AND seq>$2 ORDER BY seq LIMIT $3', [userId, Math.max(0, Number(since) || 0), lim + 1]);
    const more = r.rows.length > lim;
    const items = r.rows.slice(0, lim).map(rowToSync).map(publicItem);
    return { items, next: items.length ? items[items.length - 1].seq : Math.max(0, Number(since) || 0), more };
  }

  /** Applies a push under a per-user advisory lock so seq order == commit order for that user. */
  async syncPush(userId, items, now = Date.now()) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`sync:${userId}`]);
      const tx = {
        count: async () => Number((await client.query('SELECT COUNT(*) AS n FROM sync_items WHERE user_id=$1', [userId])).rows[0].n),
        getRow: async (kind, id) => { const r = await client.query('SELECT * FROM sync_items WHERE user_id=$1 AND kind=$2 AND id=$3', [userId, kind, id]); return r.rows[0] ? rowToSync(r.rows[0]) : null; },
        insert: it => client.query('INSERT INTO sync_items(user_id,kind,id,data,updated_at,deleted) VALUES($1,$2,$3,$4,$5,$6)', [userId, it.kind, it.id, JSON.stringify(it.data ?? {}), it.updatedAt, it.deleted]),
        update: it => client.query(`UPDATE sync_items SET data=$4, updated_at=$5, deleted=$6, seq=nextval(pg_get_serial_sequence('sync_items','seq')) WHERE user_id=$1 AND kind=$2 AND id=$3`, [userId, it.kind, it.id, JSON.stringify(it.data ?? {}), it.updatedAt, it.deleted]),
      };
      const results = await applyPush(tx, items, now);
      await client.query('COMMIT');
      return results;
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      throw e;
    } finally { client.release(); }
  }

  async syncDeleteAll(userId, client = this.pool) {
    return (await client.query('DELETE FROM sync_items WHERE user_id=$1', [userId])).rowCount;
  }

  /** Tombstones older than `days` are no longer needed by devices that synced within that window. */
  async purgeSyncTombstones(days = SYNC_LIMITS.tombstoneDays, now = Date.now()) {
    return (await this.pool.query('DELETE FROM sync_items WHERE deleted AND updated_at < $1', [now - Math.floor(days) * 86400e3])).rowCount;
  }

  async putStripeCustomer(userId, customerId) {
    await this.pool.query(`INSERT INTO stripe_customers(user_id,customer_id) VALUES($1,$2)
      ON CONFLICT(user_id) DO UPDATE SET customer_id=EXCLUDED.customer_id`, [userId, customerId]);
  }
  async getStripeCustomer(userId) {
    const r = await this.pool.query('SELECT customer_id FROM stripe_customers WHERE user_id=$1', [userId]);
    return r.rows[0]?.customer_id || null;
  }
  async getUserByStripeCustomer(customerId) {
    const r = await this.pool.query('SELECT user_id FROM stripe_customers WHERE customer_id=$1', [customerId]);
    return r.rows[0]?.user_id || null;
  }
  async hasStripeEvent(id) {
    return (await this.pool.query('SELECT 1 FROM stripe_events WHERE event_id=$1', [id])).rowCount > 0;
  }
  async markStripeEvent(id, type) {
    await this.pool.query('INSERT INTO stripe_events(event_id,type) VALUES($1,$2) ON CONFLICT DO NOTHING', [id, type]);
  }
  /** Stripe retries for at most 3 days; event ids older than 30 days are no longer needed. */
  async purgeStripeEvents(days = 30) {
    return (await this.pool.query('DELETE FROM stripe_events WHERE processed_at < NOW() - make_interval(days => $1::int)', [Math.floor(days)])).rowCount;
  }

  /** First claim on any of these hashes held by a different user (active or still in cooldown), else null. */
  /** Released claims older than cooldownDays are ignored (purge-on-access), even if the purge job has not run yet. */
  async findFreeTierConflict(userId, fps, cooldownDays = 30) {
    if (!fps.length) return null;
    const r = await this.pool.query(
      `SELECT kind FROM free_tier_claims WHERE user_id<>$1 AND (kind, hash) IN (SELECT * FROM unnest($2::text[], $3::text[]))
         AND (released_at IS NULL OR released_at >= NOW() - make_interval(days => $4::int)) LIMIT 1`,
      [userId, fps.map(f => f.kind), fps.map(f => f.hash), Math.floor(cooldownDays)]);
    return r.rows[0] ? { kind: r.rows[0].kind } : null;
  }

  async claimFreeTier(userId, itemId, fps) {
    for (const f of fps) {
      await this.pool.query(
        `INSERT INTO free_tier_claims(kind,hash,user_id,item_id) VALUES($1,$2,$3,$4)
         ON CONFLICT(kind,hash,user_id) DO UPDATE SET item_id=EXCLUDED.item_id, released_at=NULL`,
        [f.kind, f.hash, userId, itemId]);
    }
  }

  async releaseFreeTierItem(itemId, client = this.pool) {
    await client.query('UPDATE free_tier_claims SET released_at=NOW() WHERE item_id=$1 AND released_at IS NULL', [itemId]);
  }

  async releaseFreeTierUser(userId, keepItemIds = [], client = this.pool) {
    await client.query('UPDATE free_tier_claims SET released_at=NOW() WHERE user_id=$1 AND released_at IS NULL AND (item_id IS NULL OR NOT (item_id = ANY($2)))', [userId, keepItemIds]);
  }

  async purgeFreeTier(cooldownDays) {
    const r = await this.pool.query(`DELETE FROM free_tier_claims WHERE released_at IS NOT NULL AND released_at < NOW() - make_interval(days => $1::int)`, [Math.floor(cooldownDays)]);
    return r.rowCount;
  }

  async putEntitlement(e) {
    await this.pool.query(
      `INSERT INTO billing_entitlements(purchase_token_hash,user_id,product_id,platform,state,expires_at)
       VALUES($1,$2,$3,$4,$5,$6)
       ON CONFLICT(purchase_token_hash) DO UPDATE SET product_id=EXCLUDED.product_id, state=EXCLUDED.state,
         expires_at=EXCLUDED.expires_at, updated_at=NOW()
       WHERE billing_entitlements.user_id=EXCLUDED.user_id`,
      [e.tokenHash, e.userId, e.productId, e.platform || 'google_play', e.state, e.expiresAt || null]);
  }

  async getEntitlementByTokenHash(h) {
    const r = await this.pool.query('SELECT * FROM billing_entitlements WHERE purchase_token_hash=$1', [h]);
    return r.rows[0] ? rowToEnt(r.rows[0]) : null;
  }

  async getEntitlements(userId) {
    const r = await this.pool.query('SELECT * FROM billing_entitlements WHERE user_id=$1', [userId]);
    return r.rows.map(rowToEnt);
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
         user_id=EXCLUDED.user_id,
         access_token=EXCLUDED.access_token, institution_id=EXCLUDED.institution_id,
         institution_name=EXCLUDED.institution_name, status=EXCLUDED.status, error_code=NULL,
         status_updated_at=NOW(), updated_at=NOW()
       WHERE plaid_items.user_id=EXCLUDED.user_id OR plaid_items.user_id !~ '^[A-Za-z0-9]{20,128}$'`,
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

  /** Single-bank disconnect: deletes the Item, its transactions, exchanged-token hashes and a pending update link for it. */
  async deleteItem(userId, itemId) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM plaid_transactions WHERE user_id=$1 AND item_id=$2', [userId, itemId]);
      await client.query('DELETE FROM plaid_exchanged_public_tokens WHERE user_id=$1 AND item_id=$2', [userId, itemId]);
      await client.query('DELETE FROM plaid_pending_links WHERE user_id=$1 AND item_id=$2', [userId, itemId]);
      await client.query('DELETE FROM plaid_items WHERE user_id=$1 AND item_id=$2', [userId, itemId]);
      await client.query('DELETE FROM push_dedupe WHERE item_id=$1', [itemId]);
      await this.releaseFreeTierItem(itemId, client); // keep hashes for the cooldown, then purge
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
      await this.syncDeleteAll(userId, client);
      await client.query('DELETE FROM push_dedupe d WHERE NOT EXISTS (SELECT 1 FROM plaid_items p WHERE p.item_id=d.item_id)');
      await client.query('DELETE FROM fcm_tokens WHERE user_id=$1', [userId]);
      await this.releaseFreeTierUser(userId, keepItemIds, client);
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      throw e;
    } finally { client.release(); }
  }

  async setItemStatus(itemId, status, errorCode = null) {
    if (status === ITEM_STATUS.REVOKED) return this.revokeItem(itemId, errorCode);
    await this.pool.query('UPDATE plaid_items SET status=$1, error_code=$2, status_updated_at=NOW(), updated_at=NOW() WHERE item_id=$3',
      [status, errorCode, itemId]);
  }

  /**
   * User revoked consent: in one DB transaction delete the Item's transactions, exchanged-token hashes and any
   * pending update-mode link for it, reset its sync cursor, and mark it revoked. Only the minimal Item row
   * (ids, institution, status, encrypted access token for update mode) is kept so the app can offer "Reconnect";
   * a successful reconnect re-syncs from scratch because the cursor is cleared.
   */
  async revokeItem(itemId, errorCode = 'USER_PERMISSION_REVOKED') {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      // Lock the Item row first so a concurrent applySync cannot re-insert rows after the purge.
      await client.query('SELECT 1 FROM plaid_items WHERE item_id=$1 FOR UPDATE', [itemId]);
      await client.query('DELETE FROM plaid_transactions WHERE item_id=$1', [itemId]);
      await client.query('DELETE FROM plaid_exchanged_public_tokens WHERE item_id=$1', [itemId]);
      await client.query('DELETE FROM plaid_pending_links WHERE item_id=$1', [itemId]);
      await client.query(
        `UPDATE plaid_items SET status=$1, error_code=$2, transactions_cursor=NULL, new_accounts_available=FALSE,
           status_updated_at=NOW(), updated_at=NOW() WHERE item_id=$3`, [ITEM_STATUS.REVOKED, errorCode, itemId]);
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      throw e;
    } finally { client.release(); }
  }

  async setNewAccountsAvailable(itemId, value) {
    await this.pool.query('UPDATE plaid_items SET new_accounts_available=$1, updated_at=NOW() WHERE item_id=$2', [Boolean(value), itemId]);
  }

  /** Applies a fully-paginated /transactions/sync result and the new cursor atomically. */
  async applySync(userId, item, { upserts, removedIds, cursor }) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      // Serialize with revokeItem/deleteItem: never write transactions for a revoked or deleted Item.
      const cur = await client.query('SELECT status FROM plaid_items WHERE item_id=$1 FOR UPDATE', [item.itemId]);
      if (!cur.rows[0] || cur.rows[0].status === ITEM_STATUS.REVOKED) { await client.query('ROLLBACK'); return false; }
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
      return true;
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

  // ---------- FCM device tokens + push dedupe ----------
  /** Upserts token for userId (a token moving to a new account is reassigned) and trims to the newest `max`. */
  async upsertFcmToken(userId, token, platform, max) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`INSERT INTO fcm_tokens(token,user_id,platform) VALUES($1,$2,$3)
        ON CONFLICT (token) DO UPDATE SET user_id=EXCLUDED.user_id, platform=EXCLUDED.platform, updated_at=now()`, [token, userId, platform]);
      const r = await client.query(`DELETE FROM fcm_tokens WHERE user_id=$1 AND token IN (
        SELECT token FROM fcm_tokens WHERE user_id=$1 ORDER BY updated_at DESC, created_at DESC OFFSET $2)`, [userId, max]);
      const c = await client.query('SELECT count(*)::int AS n FROM fcm_tokens WHERE user_id=$1', [userId]);
      await client.query('COMMIT');
      return { count: c.rows[0].n, evicted: r.rowCount };
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      throw e;
    } finally { client.release(); }
  }
  async deleteFcmToken(userId, token) {
    const r = await this.pool.query('DELETE FROM fcm_tokens WHERE user_id=$1 AND token=$2', [userId, token]);
    return r.rowCount > 0;
  }
  async getFcmTokens(userId) {
    const r = await this.pool.query('SELECT token FROM fcm_tokens WHERE user_id=$1 ORDER BY updated_at DESC', [userId]);
    return r.rows.map(x => x.token);
  }
  async deleteFcmTokens(tokens) {
    if (!tokens.length) return 0;
    return (await this.pool.query('DELETE FROM fcm_tokens WHERE token = ANY($1)', [tokens])).rowCount;
  }
  /** Atomically claims the item's push slot if none was used in the last `windowMs`. */
  async claimPushSlot(itemId, windowMs, now = Date.now()) {
    const r = await this.pool.query(`INSERT INTO push_dedupe(item_id, sent_at) VALUES($1, to_timestamp($2/1000.0))
      ON CONFLICT (item_id) DO UPDATE SET sent_at=EXCLUDED.sent_at
      WHERE push_dedupe.sent_at <= to_timestamp(($2 - $3)/1000.0) RETURNING item_id`, [itemId, now, windowMs]);
    return r.rowCount > 0;
  }
  async releasePushSlot(itemId) { await this.pool.query('DELETE FROM push_dedupe WHERE item_id=$1', [itemId]); }

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
    this.entitlements = new Map(); // tokenHash -> entitlement
    this.stripeCustomers = new Map(); // userId -> customerId
    this.stripeEvents = new Map(); // eventId -> {type, at}
    this.claims = new Map(); // `${kind}|${hash}|${userId}` -> {kind,hash,userId,itemId,releasedAt}
    this.syncRows = new Map(); // `${userId}|${kind}|${id}` -> {userId,kind,id,data,updatedAt,deleted,seq}
    this.syncSeq = 0;
    this.syncLock = Promise.resolve();
    this.fcmTokens = new Map(); // token -> {userId, platform, createdAt, updatedAt, seq}
    this.pushDedupe = new Map(); // itemId -> sentAt ms
    this.seq = 0;
  }
  async syncChanges(userId, since = 0, limit = SYNC_LIMITS.maxChangesLimit) {
    const lim = Math.max(1, Math.min(Number(limit) || SYNC_LIMITS.maxChangesLimit, SYNC_LIMITS.maxChangesLimit));
    const s = Math.max(0, Number(since) || 0);
    const rows = [...this.syncRows.values()].filter(r => r.userId === userId && r.seq > s).sort((a, b) => a.seq - b.seq);
    const items = rows.slice(0, lim).map(publicItem);
    return { items, next: items.length ? items[items.length - 1].seq : s, more: rows.length > lim };
  }
  async syncPush(userId, items, now = Date.now()) {
    const run = async () => {
      const staged = new Map(); // all-or-nothing like the PG transaction
      const key = (k, i) => `${userId}|${k}|${i}`;
      const tx = {
        count: async () => [...this.syncRows.values()].filter(r => r.userId === userId).length,
        getRow: async (k, i) => { const r = staged.get(key(k, i)) || this.syncRows.get(key(k, i)); return r ? { ...r } : null; },
        insert: async it => { staged.set(key(it.kind, it.id), { ...it, userId, seq: 0 }); },
        update: async it => { staged.set(key(it.kind, it.id), { ...it, userId, seq: 0 }); },
      };
      const out = await applyPush(tx, items, now);
      for (const [k, r] of staged) this.syncRows.set(k, { ...r, seq: ++this.syncSeq });
      return out;
    };
    const p = this.syncLock.then(run, run);
    this.syncLock = p.catch(() => {});
    return p;
  }
  async syncDeleteAll(userId) {
    let n = 0;
    for (const [k, r] of this.syncRows) if (r.userId === userId) { this.syncRows.delete(k); n++; }
    return n;
  }
  async purgeSyncTombstones(days = SYNC_LIMITS.tombstoneDays, now = Date.now()) {
    let n = 0;
    for (const [k, r] of this.syncRows) if (r.deleted && r.updatedAt < now - Math.floor(days) * 86400e3) { this.syncRows.delete(k); n++; }
    return n;
  }
  async findFreeTierConflict(userId, fps, cooldownDays = 30, now = Date.now()) {
    const want = new Set(fps.map(f => `${f.kind}|${f.hash}`));
    const cutoff = now - cooldownDays * 86400e3;
    for (const c of this.claims.values()) if (c.userId !== userId && want.has(`${c.kind}|${c.hash}`) && (!c.releasedAt || c.releasedAt >= cutoff)) return { kind: c.kind };
    return null;
  }
  async claimFreeTier(userId, itemId, fps) { for (const f of fps) this.claims.set(`${f.kind}|${f.hash}|${userId}`, { ...f, userId, itemId, releasedAt: null }); }
  async releaseFreeTierItem(itemId) { for (const c of this.claims.values()) if (c.itemId === itemId && !c.releasedAt) c.releasedAt = Date.now(); }
  async releaseFreeTierUser(userId, keepItemIds = []) { const k = new Set(keepItemIds); for (const c of this.claims.values()) if (c.userId === userId && !c.releasedAt && !k.has(c.itemId)) c.releasedAt = Date.now(); }
  async purgeFreeTier(cooldownDays, now = Date.now()) {
    let n = 0;
    for (const [k, c] of this.claims) if (c.releasedAt && c.releasedAt < now - cooldownDays * 86400e3) { this.claims.delete(k); n++; }
    return n;
  }
  async putEntitlement(e) {
    const prev = this.entitlements.get(e.tokenHash);
    if (prev && prev.userId !== e.userId) return;
    this.entitlements.set(e.tokenHash, { tokenHash: e.tokenHash, userId: e.userId, productId: e.productId, platform: e.platform || 'google_play', state: e.state, expiresAt: e.expiresAt || null });
  }
  async putStripeCustomer(userId, customerId) { this.stripeCustomers.set(userId, customerId); }
  async getStripeCustomer(userId) { return this.stripeCustomers.get(userId) || null; }
  async getUserByStripeCustomer(cid) { for (const [u, c] of this.stripeCustomers) if (c === cid) return u; return null; }
  async hasStripeEvent(id) { return this.stripeEvents.has(id); }
  async markStripeEvent(id, type) { if (!this.stripeEvents.has(id)) this.stripeEvents.set(id, { type, at: Date.now() }); }
  async purgeStripeEvents(days = 30, now = Date.now()) { let n = 0; for (const [k, v] of this.stripeEvents) if (v.at < now - days * 86400e3) { this.stripeEvents.delete(k); n++; } return n; }
  async getEntitlementByTokenHash(h) { const e = this.entitlements.get(h); return e ? { ...e } : null; }
  async getEntitlements(userId) { return [...this.entitlements.values()].filter(e => e.userId === userId).map(e => ({ ...e })); }
  async init() {}
  async putItem(x) {
    const existing = this.items.get(x.itemId);
    if (existing && existing.user_id !== x.userId && !isLegacyUserId(existing.user_id)) return;
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
    await this.releaseFreeTierItem(itemId);
    this.pushDedupe.delete(itemId);
    for (const [h, e] of this.exchanged) if (e.itemId === itemId && e.userId === userId) this.exchanged.delete(h);
    const p = this.pending.get(userId); if (p && p.itemId === itemId) this.pending.delete(userId);
  }
  async deleteUserData(userId, { keepItemIds = [] } = {}) {
    const keep = new Set(keepItemIds);
    for (const [id, x] of this.items) if (x.user_id === userId && !keep.has(id)) this.items.delete(id);
    for (const [id, t] of this.transactions) if (t.userId === userId && !keep.has(t.itemId)) this.transactions.delete(id);
    for (const [h, x] of this.exchanged) if (x.userId === userId && !keep.has(x.itemId)) this.exchanged.delete(h);
    this.pending.delete(userId);
    await this.syncDeleteAll(userId);
    for (const id of this.pushDedupe.keys()) if (!this.items.has(id)) this.pushDedupe.delete(id);
    for (const [t, v] of this.fcmTokens) if (v.userId === userId) this.fcmTokens.delete(t);
    await this.releaseFreeTierUser(userId, keepItemIds);
  }
  async setItemStatus(itemId, status, errorCode = null) {
    if (status === ITEM_STATUS.REVOKED) return this.revokeItem(itemId, errorCode);
    const x = this.items.get(itemId); if (x) Object.assign(x, { status, error_code: errorCode, status_updated_at: new Date() });
  }
  async revokeItem(itemId, errorCode = 'USER_PERMISSION_REVOKED') {
    for (const [id, t] of this.transactions) if (t.itemId === itemId) this.transactions.delete(id);
    for (const [h, x] of this.exchanged) if (x.itemId === itemId) this.exchanged.delete(h);
    for (const [u, p] of this.pending) if (p.itemId === itemId) this.pending.delete(u);
    const x = this.items.get(itemId);
    if (x) Object.assign(x, { status: ITEM_STATUS.REVOKED, error_code: errorCode, transactions_cursor: null, new_accounts_available: false, status_updated_at: new Date() });
  }
  async setNewAccountsAvailable(itemId, value) { const x = this.items.get(itemId); if (x) x.new_accounts_available = Boolean(value); }
  async applySync(userId, item, { upserts, removedIds, cursor }) {
    const row = this.items.get(item.itemId);
    if (!row || row.status === ITEM_STATUS.REVOKED) return false;
    for (const t of upserts) this.transactions.set(String(t.transaction_id), { userId, itemId: item.itemId, payload: t, removed: false });
    for (const id of removedIds) { const t = this.transactions.get(id); if (t && t.itemId === item.itemId) t.removed = true; }
    row.transactions_cursor = cursor || null;
    return true;
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
  async upsertFcmToken(userId, token, platform, max) {
    const prev = this.fcmTokens.get(token);
    this.fcmTokens.set(token, { userId, platform, createdAt: prev?.createdAt ?? Date.now(), seq: ++this.seq });
    const mine = [...this.fcmTokens.entries()].filter(([, v]) => v.userId === userId).sort((a, b) => b[1].seq - a[1].seq);
    const extra = mine.slice(max);
    for (const [t] of extra) this.fcmTokens.delete(t);
    return { count: mine.length - extra.length, evicted: extra.length };
  }
  async deleteFcmToken(userId, token) {
    const v = this.fcmTokens.get(token);
    if (!v || v.userId !== userId) return false;
    return this.fcmTokens.delete(token);
  }
  async getFcmTokens(userId) {
    return [...this.fcmTokens.entries()].filter(([, v]) => v.userId === userId).sort((a, b) => b[1].seq - a[1].seq).map(([t]) => t);
  }
  async deleteFcmTokens(tokens) { let n = 0; for (const t of tokens) if (this.fcmTokens.delete(t)) n++; return n; }
  async claimPushSlot(itemId, windowMs, now = Date.now()) {
    const last = this.pushDedupe.get(itemId);
    if (last !== undefined && last > now - windowMs) return false;
    this.pushDedupe.set(itemId, now);
    return true;
  }
  async releasePushSlot(itemId) { this.pushDedupe.delete(itemId); }
  async encryptLegacyTokens() { return 0; }
  async close() {}
}

export { isEncrypted };
