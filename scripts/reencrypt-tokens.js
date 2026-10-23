#!/usr/bin/env node
// One-off (the server also does this automatically at boot when TOKEN_ENCRYPTION_KEY_OLD is set): re-encrypt plaid_items.access_token from TOKEN_ENCRYPTION_KEY_OLD to TOKEN_ENCRYPTION_KEY.
// Dry run by default (counts only). Never prints tokens or keys.
//   node scripts/reencrypt-tokens.js            # dry run: how many rows use old / new / neither key
//   node scripts/reencrypt-tokens.js --apply    # re-encrypt in ONE transaction, verify, then commit
//   node scripts/reencrypt-tokens.js --verify   # fail unless every encrypted row decrypts with the new key
import 'dotenv/config';
import pg from 'pg';
import { loadConfig } from '../src/config.js';
import { stripSslParams } from '../src/store.js';
import { reencryptTokens } from '../src/keyRotation.js';

const args = new Set(process.argv.slice(2));
const apply = args.has('--apply'), verifyOnly = args.has('--verify');
const { config } = loadConfig(process.env);
const NEW = config.tokenEncryptionKey, OLD = config.tokenEncryptionKeyOld;
if (!config.db) { console.error('DATABASE_URL is required.'); process.exit(2); }
if (!NEW) { console.error('TOKEN_ENCRYPTION_KEY is required.'); process.exit(2); }
if (apply && !OLD) { console.error('TOKEN_ENCRYPTION_KEY_OLD is required for --apply.'); process.exit(2); }
if (OLD && OLD.equals(NEW)) { console.error('TOKEN_ENCRYPTION_KEY_OLD equals TOKEN_ENCRYPTION_KEY; nothing to rotate.'); process.exit(2); }

const pool = new pg.Pool({ connectionString: stripSslParams(config.db.url), ssl: config.db.ssl, max: 2 });
let code = 0;
try {
  const r = await reencryptTokens(pool, NEW, OLD, { apply });
  console.log(JSON.stringify({ ...r, mode: apply ? 'apply' : verifyOnly ? 'verify' : 'dry-run' }));
  if (r.result === 'rolled_back' || r.undecryptable || (verifyOnly && r.oldKey)) code = 1;
} catch (e) { console.error('error:', e.message); code = 1; }
finally { await pool.end(); }
process.exit(code);
