#!/usr/bin/env node
// One-off admin script (post app 3.9.7 / Firebase sign-in rollout).
// Removes Plaid Items owned by legacy, non-Firebase user IDs ("pp-…", "ppd_…", etc.):
// calls Plaid /item/remove, then deletes the items, their transactions, pending links
// and exchanged-token rows. Dry-run by default; prints counts only, never tokens.
//
//   node scripts/cleanup-legacy-items.js            # dry run (default)
//   node scripts/cleanup-legacy-items.js --dry-run  # same
//   node scripts/cleanup-legacy-items.js --apply    # actually remove and delete
//
// Uses the same environment as the server (PLAID_*, DATABASE_URL, TOKEN_ENCRYPTION_KEY, DB TLS vars).
import 'dotenv/config';
import pg from 'pg';
import { loadConfig } from '../src/config.js';
import { createPlaidClient } from '../src/plaid.js';
import { stripSslParams } from '../src/store.js';
import { cleanupLegacyItems } from '../src/legacy.js';

const args = new Set(process.argv.slice(2));
if (args.has('--apply') && args.has('--dry-run')) { console.error('Use either --dry-run or --apply, not both.'); process.exit(2); }
const apply = args.has('--apply');

const { config } = loadConfig(process.env);
if (!config.db) { console.error('DATABASE_URL is required.'); process.exit(2); }
if (!config.tokenEncryptionKey) { console.error('TOKEN_ENCRYPTION_KEY is required.'); process.exit(2); }
if (apply && !config.plaid.configured) { console.error('PLAID_CLIENT_ID / PLAID_SECRET are required for --apply.'); process.exit(2); }

const pool = new pg.Pool({ connectionString: stripSslParams(config.db.url), ssl: config.db.ssl, max: 2 });
const plaid = createPlaidClient(config.plaid);
try {
  console.log(`PayAviator legacy item cleanup (plaid_env=${config.plaid.env}, mode=${apply ? 'APPLY' : 'dry-run'})`);
  const report = await cleanupLegacyItems({ pool, plaid, key: config.tokenEncryptionKey, apply });
  console.log(JSON.stringify(report, null, 2));
  if (!apply) console.log('Dry run only. Re-run with --apply to remove these items at Plaid and delete their data.');
  process.exitCode = report.items_failed ? 1 : 0;
} catch (e) {
  console.error('cleanup failed:', e?.code || e?.name || 'error', e?.response?.data?.error_code || '');
  process.exitCode = 1;
} finally {
  await pool.end();
}
