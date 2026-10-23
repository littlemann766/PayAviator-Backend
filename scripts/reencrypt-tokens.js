#!/usr/bin/env node
// One-off: re-encrypt plaid_items.access_token from TOKEN_ENCRYPTION_KEY_OLD to TOKEN_ENCRYPTION_KEY.
// Dry run by default (counts only). Never prints tokens or keys.
//   node scripts/reencrypt-tokens.js            # dry run: how many rows use old / new / neither key
//   node scripts/reencrypt-tokens.js --apply    # re-encrypt in ONE transaction, verify, then commit
//   node scripts/reencrypt-tokens.js --verify   # fail unless every encrypted row decrypts with the new key
import 'dotenv/config';
import pg from 'pg';
import { loadConfig } from '../src/config.js';
import { stripSslParams } from '../src/store.js';
import { decryptToken, encryptToken, decryptsWith, isEncrypted } from '../src/crypto.js';

const args = new Set(process.argv.slice(2));
const apply = args.has('--apply'), verifyOnly = args.has('--verify');
const { config } = loadConfig(process.env);
const NEW = config.tokenEncryptionKey, OLD = config.tokenEncryptionKeyOld;
if (!config.db) { console.error('DATABASE_URL is required.'); process.exit(2); }
if (!NEW) { console.error('TOKEN_ENCRYPTION_KEY is required.'); process.exit(2); }
if (apply && !OLD) { console.error('TOKEN_ENCRYPTION_KEY_OLD is required for --apply.'); process.exit(2); }
if (OLD && OLD.equals(NEW)) { console.error('TOKEN_ENCRYPTION_KEY_OLD equals TOKEN_ENCRYPTION_KEY; nothing to rotate.'); process.exit(2); }

const pool = new pg.Pool({ connectionString: stripSslParams(config.db.url), ssl: config.db.ssl, max: 2 });
const client = await pool.connect();
let code = 0;
try {
  await client.query('BEGIN');
  const rows = (await client.query(
    `SELECT item_id, access_token FROM plaid_items WHERE access_token IS NOT NULL AND access_token <> '' FOR UPDATE`)).rows;
  const c = { total: rows.length, newKey: 0, oldKey: 0, plaintext: 0, undecryptable: 0, reencrypted: 0 };
  for (const r of rows) {
    if (!isEncrypted(r.access_token)) { c.plaintext++; continue; }
    if (decryptsWith(r.access_token, NEW)) { c.newKey++; continue; }
    if (OLD && decryptsWith(r.access_token, OLD)) {
      c.oldKey++;
      if (apply) {
        const enc = encryptToken(decryptToken(r.access_token, OLD), NEW);
        await client.query('UPDATE plaid_items SET access_token=$1 WHERE item_id=$2', [enc, r.item_id]);
        c.reencrypted++;
      }
      continue;
    }
    c.undecryptable++;
  }
  if (apply) {
    // Verify inside the transaction before committing.
    const after = (await client.query(`SELECT access_token FROM plaid_items WHERE access_token IS NOT NULL AND access_token <> ''`)).rows;
    const bad = after.filter(r => isEncrypted(r.access_token) && !decryptsWith(r.access_token, NEW)).length;
    c.verifyFailuresAfter = bad;
    if (bad || c.undecryptable) { await client.query('ROLLBACK'); console.log(JSON.stringify({ ...c, result: 'ROLLED BACK' })); code = 1; }
    else { await client.query('COMMIT'); console.log(JSON.stringify({ ...c, result: 'COMMITTED' })); }
  } else {
    await client.query('ROLLBACK');
    console.log(JSON.stringify({ ...c, mode: verifyOnly ? 'verify' : 'dry-run' }));
    if (verifyOnly && (c.oldKey || c.undecryptable)) code = 1;
  }
} catch (e) { await client.query('ROLLBACK').catch(() => {}); console.error('error:', e.message); code = 1; }
finally { client.release(); await pool.end(); }
process.exit(code);
