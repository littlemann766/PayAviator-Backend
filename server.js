import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import pg from 'pg';
import { Configuration, PlaidApi, PlaidEnvironments, Products, CountryCode } from 'plaid';

const APP_VERSION = '3.1.7';
const app = express();

// The Android app is served from appassets.androidplatform.net and the browser/PWA
// can have a different origin. The API contains no browser cookies, so allowing the
// requesting origin is appropriate here and keeps Android WebView preflights simple.
app.use(cors({ origin: true, methods: ['GET', 'POST', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Accept'] }));
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

const env = process.env.PLAID_ENV || 'sandbox';
const plaidConfigured = Boolean(process.env.PLAID_CLIENT_ID && process.env.PLAID_SECRET);
const DEFAULT_PLAID_REDIRECT_URI = 'https://pay-pilot-backend-production.up.railway.app/plaid/oauth-redirect';
const PLAID_REDIRECT_URI = process.env.PLAID_REDIRECT_URI || DEFAULT_PLAID_REDIRECT_URI;
const PLAID_COMPLETION_REDIRECT_URI = process.env.PLAID_COMPLETION_REDIRECT_URI || 'payaviator://plaid-complete';
const plaidEnv = PlaidEnvironments[env] || PlaidEnvironments.sandbox;
const config = new Configuration({
  basePath: plaidEnv,
  baseOptions: {
    headers: {
      'PLAID-CLIENT-ID': process.env.PLAID_CLIENT_ID || '',
      'PLAID-SECRET': process.env.PLAID_SECRET || '',
    },
  },
});
const plaid = new PlaidApi(config);

const { Pool } = pg;
const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.PGSSL === 'disable' ? false : { rejectUnauthorized: false },
      connectionTimeoutMillis: 8000,
    })
  : null;
let dbReady = false;
let dbError = null;

const memory = new Map();
const pendingMemory = new Map();

async function initStorage() {
  if (!pool) {
    dbReady = false;
    return;
  }
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS plaid_items (
      user_id TEXT,
      item_id TEXT PRIMARY KEY,
      access_token TEXT,
      institution_id TEXT,
      institution_name TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )`);

    // Existing Railway databases may have been created by an older PayAviator
    // backend. CREATE TABLE IF NOT EXISTS does not add columns to an existing
    // table, so apply idempotent migrations before any Plaid item is saved.
    await pool.query('ALTER TABLE plaid_items ADD COLUMN IF NOT EXISTS user_id TEXT');
    await pool.query('ALTER TABLE plaid_items ADD COLUMN IF NOT EXISTS access_token TEXT');
    await pool.query('ALTER TABLE plaid_items ADD COLUMN IF NOT EXISTS institution_id TEXT');
    await pool.query('ALTER TABLE plaid_items ADD COLUMN IF NOT EXISTS institution_name TEXT');
    await pool.query('ALTER TABLE plaid_items ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()');
    await pool.query('ALTER TABLE plaid_items ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()');
    await pool.query('CREATE INDEX IF NOT EXISTS plaid_items_user_id_idx ON plaid_items(user_id)');
    await pool.query('ALTER TABLE plaid_items ADD COLUMN IF NOT EXISTS transactions_cursor TEXT');
    await pool.query(`CREATE TABLE IF NOT EXISTS plaid_transactions (
      user_id TEXT NOT NULL, item_id TEXT NOT NULL, transaction_id TEXT PRIMARY KEY,
      payload JSONB NOT NULL, removed BOOLEAN DEFAULT FALSE, updated_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await pool.query('CREATE INDEX IF NOT EXISTS plaid_transactions_user_idx ON plaid_transactions(user_id)');

    await pool.query(`CREATE TABLE IF NOT EXISTS plaid_pending_links (
      user_id TEXT PRIMARY KEY,
      link_token TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await pool.query('ALTER TABLE plaid_pending_links ADD COLUMN IF NOT EXISTS user_id TEXT');
    await pool.query('ALTER TABLE plaid_pending_links ADD COLUMN IF NOT EXISTS link_token TEXT');
    await pool.query('ALTER TABLE plaid_pending_links ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()');
    await pool.query('ALTER TABLE plaid_pending_links ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()');

    console.log('PayAviator database schema verified for 3.1.3.');
    dbReady = true;
    dbError = null;
    console.log('PayAviator database connected.');
  } catch (err) {
    // Do not take the whole Plaid API offline just because Postgres is unavailable.
    // Sandbox/testing can continue with in-memory storage while Railway/DB is fixed.
    dbReady = false;
    dbError = err?.message || String(err);
    console.error('Database unavailable; using memory fallback:', dbError);
  }
}

function useDb() { return Boolean(pool && dbReady); }

async function putItem(x) {
  if (useDb()) {
    await pool.query(
      `INSERT INTO plaid_items(user_id,item_id,access_token,institution_id,institution_name)
       VALUES($1,$2,$3,$4,$5)
       ON CONFLICT(item_id) DO UPDATE SET
         access_token=EXCLUDED.access_token,
         institution_id=EXCLUDED.institution_id,
         institution_name=EXCLUDED.institution_name,
         updated_at=NOW()`,
      [x.userId, x.itemId, x.accessToken, x.institutionId || null, x.institutionName || null]
    );
  } else {
    const a = memory.get(x.userId) || [];
    memory.set(x.userId, [...a.filter(i => i.itemId !== x.itemId), x]);
  }
}

async function getItems(userId) {
  if (useDb()) {
    const r = await pool.query('SELECT * FROM plaid_items WHERE user_id=$1 ORDER BY created_at', [userId]);
    return r.rows.map(x => ({
      userId: x.user_id,
      itemId: x.item_id,
      accessToken: x.access_token,
      institutionId: x.institution_id,
      institutionName: x.institution_name,
      transactionsCursor: x.transactions_cursor || null,
    }));
  }
  return memory.get(userId) || [];
}

async function delItem(userId, itemId) {
  if (useDb()) await pool.query('DELETE FROM plaid_items WHERE user_id=$1 AND item_id=$2', [userId, itemId]);
  else memory.set(userId, (memory.get(userId) || []).filter(x => x.itemId !== itemId));
}

async function putPending(userId, linkToken) {
  if (useDb()) {
    await pool.query(
      `INSERT INTO plaid_pending_links(user_id,link_token) VALUES($1,$2)
       ON CONFLICT(user_id) DO UPDATE SET link_token=EXCLUDED.link_token,updated_at=NOW()`,
      [userId, linkToken]
    );
  } else pendingMemory.set(userId, linkToken);
}

async function getPending(userId) {
  if (useDb()) {
    const r = await pool.query('SELECT link_token FROM plaid_pending_links WHERE user_id=$1', [userId]);
    return r.rows[0]?.link_token || null;
  }
  return pendingMemory.get(userId) || null;
}

async function clearPending(userId) {
  if (useDb()) await pool.query('DELETE FROM plaid_pending_links WHERE user_id=$1', [userId]);
  else pendingMemory.delete(userId);
}

function plaidError(e, fallback) {
  const d = e?.response?.data;
  console.error('Plaid error:', d || e);
  return d?.display_message || d?.error_message || d?.error_code || fallback;
}

function requirePlaid(res) {
  if (plaidConfigured) return true;
  res.status(503).json({
    error: 'Plaid credentials are not configured on the PayAviator backend.',
    code: 'PLAID_NOT_CONFIGURED',
  });
  return false;
}

async function plaidRaw(path, body) {
  const response = await fetch(plaidEnv + path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'PLAID-CLIENT-ID': process.env.PLAID_CLIENT_ID || '',
      'PLAID-SECRET': process.env.PLAID_SECRET || '',
    },
    body: JSON.stringify(body || {}),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const err = new Error(data.display_message || data.error_message || data.error_code || `Plaid request failed (${response.status})`);
    err.response = { data, status: response.status };
    throw err;
  }
  return data;
}

async function exchangeAndStore(userId, publicToken, metadata = {}) {
  const exchange = await plaidRaw('/item/public_token/exchange', { public_token: publicToken });
  const institution = metadata?.institution || {};
  await putItem({
    userId,
    itemId: exchange.item_id,
    accessToken: exchange.access_token,
    institutionId: institution.institution_id || institution.id || '',
    institutionName: institution.name || '',
  });
  return {
    connected: true,
    item_id: exchange.item_id,
    institution: institution.name || null,
  };
}

function healthPayload() {
  return {
    status: 'ok',
    app: 'PayAviator',
    version: APP_VERSION,
    plaidEnvironment: env,
    plaidConfigured,
    hostedLink: true,
    storage: useDb() ? 'postgres' : (pool ? 'memory-fallback' : 'memory'),
    databaseConfigured: Boolean(pool),
    databaseReady: dbReady,
  };
}

app.get('/', (req, res) => res.json(healthPayload()));
app.get('/api/health', (req, res) => res.json({...healthPayload(), plaidRedirectUri: PLAID_REDIRECT_URI, plaidCompletionRedirectUri: PLAID_COMPLETION_REDIRECT_URI}));

// OAuth/app-to-app handoff target required by Plaid Hosted Link mobile sessions.
// Plaid requires this value to be HTTPS. This tiny page immediately hands control
// back to PayAviator's registered custom scheme, where the app resumes status polling.
app.get('/plaid/oauth-redirect', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.type('html').send(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="0;url=payaviator://plaid-oauth-return"><title>Returning to PayAviator</title></head><body style="font-family:sans-serif;background:#071521;color:white;padding:32px">Returning to PayAviator…<script>location.replace('payaviator://plaid-oauth-return');</script></body></html>`);
});

app.post('/api/plaid/create-link-token', async (req, res) => {
  if (!requirePlaid(res)) return;
  const userId = String(req.body.userId || 'payaviator-local-user');
  try {
    const request = {
      user: { client_user_id: userId },
      client_name: 'PayAviator',
      products: [Products.Transactions],
      country_codes: [CountryCode.Us],
      language: 'en',
      hosted_link: {
        completion_redirect_uri: PLAID_COMPLETION_REDIRECT_URI,
        is_mobile_app: true,
        url_lifetime_seconds: 1800,
      },
    };

    // Needed for OAuth/app-to-app institutions. Only send it when the Railway
    // environment contains an HTTPS URI that is also allowlisted in Plaid.
    request.redirect_uri = PLAID_REDIRECT_URI;
    if (process.env.PLAID_WEBHOOK_URL) request.webhook = process.env.PLAID_WEBHOOK_URL;

    // Send this request directly to Plaid instead of relying on SDK model
    // serialization. Hosted Link fields are relatively new and older/generated
    // SDK serializers can silently omit nested hosted_link values even when the
    // JavaScript object contains them. A raw JSON request guarantees Plaid receives
    // redirect_uri, hosted_link.completion_redirect_uri and is_mobile_app exactly.
    const plaidBase = env === 'production' ? 'https://production.plaid.com' : 'https://sandbox.plaid.com';
    const rawResponse = await fetch(plaidBase + '/link/token/create', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'PLAID-CLIENT-ID': process.env.PLAID_CLIENT_ID || '',
        'PLAID-SECRET': process.env.PLAID_SECRET || '',
        'Plaid-Version': '2020-09-14',
      },
      body: JSON.stringify(request),
    });
    const rawData = await rawResponse.json().catch(() => ({}));
    if (!rawResponse.ok) {
      const err = new Error(rawData.error_message || rawData.display_message || 'Plaid link token request failed');
      err.response = { data: rawData };
      throw err;
    }
    await putPending(userId, rawData.link_token);
    res.json({
      link_token: rawData.link_token,
      hosted_link_url: rawData.hosted_link_url || null,
      expiration: rawData.expiration || null,
      request_id: rawData.request_id || null,
    });
  } catch (e) {
    res.status(500).json({ error: plaidError(e, 'link_token_failed') });
  }
});

app.get('/api/plaid/hosted-status/:userId', async (req, res) => {
  if (!requirePlaid(res)) return;
  const userId = String(req.params.userId || '');
  try {
    const linkToken = await getPending(userId);
    if (!linkToken) {
      return res.json({ connected: false, pending: false, status: 'missing', error: 'No pending bank connection was found.' });
    }

    // Hosted Link does not return public_token to the app. Read the completed
    // Link session directly from Plaid. Using the raw REST response here avoids
    // SDK model/version mismatches and preserves results.item_add_results.
    const data = await plaidRaw('/link/token/get', { link_token: linkToken });
    const sessions = Array.isArray(data.link_sessions) ? data.link_sessions : [];
    const session = sessions.length ? sessions[sessions.length - 1] : null;

    if (!session) {
      return res.json({ connected: false, pending: true, status: 'waiting_for_session' });
    }

    const itemResults = Array.isArray(session?.results?.item_add_results)
      ? session.results.item_add_results
      : [];
    const legacy = session?.on_success?.public_token
      ? [{ public_token: session.on_success.public_token, metadata: session.on_success.metadata || {} }]
      : [];
    const successes = itemResults.length ? itemResults : legacy;

    if (successes.length) {
      const connectedItems = [];
      for (const result of successes) {
        const publicToken = result?.public_token;
        if (!publicToken) continue;
        const metadata = result?.metadata || {
          institution: result?.institution || session?.on_success?.metadata?.institution || null,
          accounts: result?.accounts || [],
        };
        connectedItems.push(await exchangeAndStore(userId, publicToken, metadata));
      }
      if (connectedItems.length) {
        await clearPending(userId);
        return res.json({
          connected: true,
          pending: false,
          status: 'success',
          count: connectedItems.length,
          institution: connectedItems[0]?.institution || null,
          items: connectedItems,
        });
      }
    }

    // The completion URI fires for both success and exit. finished_at tells us
    // the Hosted Link session ended; on_exit contains the reason when available.
    if (session?.finished_at) {
      const exit = session?.on_exit || session?.exit || {};
      const exitErr = exit?.error || {};
      const message = exitErr?.display_message || exitErr?.error_message || exit?.error_message || null;
      const status = message ? 'failed' : 'exited';
      await clearPending(userId);
      return res.json({
        connected: false,
        pending: false,
        status,
        error: message || 'The bank connection was closed before an account was connected.',
        link_session_id: session?.link_session_id || null,
      });
    }

    return res.json({ connected: false, pending: true, status: 'pending' });
  } catch (e) {
    const d = e?.response?.data || {};
    console.error('Hosted Link status error:', d || e);
    res.status(500).json({
      connected: false,
      pending: false,
      status: 'error',
      error: d?.display_message || d?.error_message || d?.error_code || e?.message || 'Could not read the Plaid session result.',
      plaid_error_code: d?.error_code || null,
      request_id: d?.request_id || null,
    });
  }
});

app.post('/api/plaid/exchange-public-token', async (req, res) => {
  if (!requirePlaid(res)) return;
  try {
    const userId = String(req.body.userId || 'payaviator-local-user');
    if (!req.body.public_token) return res.status(400).json({ error: 'Missing public token.' });
    const out = await exchangeAndStore(userId, req.body.public_token, req.body.metadata || {});
    await clearPending(userId);
    res.json(out);
  } catch (e) {
    res.status(500).json({ error: plaidError(e, 'token_exchange_failed') });
  }
});


function physicalAccountKey(a, institutionName = '') {
  const norm = v => String(v || '').trim().toLowerCase().replace(/\s+/g, ' ');
  const mask = norm(a?.mask);
  const type = norm(a?.type);
  const subtype = norm(a?.subtype);
  const name = norm(a?.official_name || a?.name);
  const institution = norm(institutionName || a?.institution_name || a?.institution);
  // Institution + last four + account class identifies the same physical account
  // across duplicate Plaid Items/reconnections. Fall back to Plaid account_id only
  // when a mask is unavailable.
  return mask
    ? [institution, mask, type, subtype, name].join('|')
    : String(a?.account_id || a?.id || [institution,type,subtype,name].join('|'));
}

app.get('/api/plaid/accounts/:userId', async (req, res) => {
  if (!requirePlaid(res)) return;
  try {
    const items = await getItems(req.params.userId);
    if (!items.length) return res.json({ accounts: [], items: [] });
    const accounts = [];
    for (const item of items) {
      try {
        const r = await plaid.accountsGet({ access_token: item.accessToken });
        for (const a of r.data.accounts) {
          // Plaid is authoritative for connected-account balances. For credit
          // accounts, balances.current is amount owed, balances.limit is the
          // institution-provided credit limit, and balances.available is the
          // institution-provided available credit when supplied.
          const isCredit = String(a?.type || '').toLowerCase() === 'credit';
          const current = Number(a?.balances?.current);
          const available = Number(a?.balances?.available);
          const directLimit = Number(a?.balances?.limit);
          // Never manufacture a credit limit from current + available. Plaid notes
          // that pending activity can make available differ from limit-current.
          const creditLimit = isCredit && Number.isFinite(directLimit) && directLimit > 0 ? directLimit : null;
          const balanceUsed = isCredit && Number.isFinite(current) ? Math.max(0, current) : null;
          const availableCredit = isCredit
            ? (Number.isFinite(available) && available >= 0
                ? available
                : (creditLimit != null && balanceUsed != null ? Math.max(0, creditLimit - balanceUsed) : null))
            : null;
          const utilization = isCredit && creditLimit > 0 && balanceUsed != null
            ? Math.max(0, Math.min(100, (balanceUsed / creditLimit) * 100))
            : null;
          accounts.push({
            ...a,
            credit_limit: creditLimit,
            balance_used: balanceUsed,
            available_credit: availableCredit,
            utilization_percent: utilization,
            balance_source: 'plaid_accounts_get',
            item_id: item.itemId,
            institution_id: item.institutionId,
            institution_name: item.institutionName || 'Connected institution',
          });
        }
      } catch (e) {
        console.error('accounts item failed', item.itemId, e.response?.data || e);
      }
    }
    const uniqueAccounts = [...new Map(accounts.map(a => [
      physicalAccountKey(a, a.institution_name),
      a
    ])).values()];
    res.json({
      accounts: uniqueAccounts,
      items: items.map(i => ({ item_id: i.itemId, institution_id: i.institutionId, institution_name: i.institutionName })),
    });
  } catch (e) {
    res.status(500).json({ error: 'accounts_failed' });
  }
});

app.delete('/api/plaid/items/:userId/:itemId', async (req, res) => {
  if (!requirePlaid(res)) return;
  try {
    const items = await getItems(req.params.userId);
    const item = items.find(x => x.itemId === req.params.itemId);
    if (item) {
      try { await plaid.itemRemove({ access_token: item.accessToken }); }
      catch (e) { console.error('Plaid remove warning', e.response?.data || e); }
      await delItem(req.params.userId, req.params.itemId);
    }
    res.json({ disconnected: true });
  } catch (e) {
    res.status(500).json({ error: 'disconnect_failed' });
  }
});


async function setTransactionsCursor(itemId,cursor){
  if(useDb()) await pool.query('UPDATE plaid_items SET transactions_cursor=$1,updated_at=NOW() WHERE item_id=$2',[cursor||null,itemId]);
  else for(const [uid,arr] of memory.entries()) memory.set(uid,arr.map(x=>x.itemId===itemId?{...x,transactionsCursor:cursor||null}:x));
}
function normalizeTransaction(t,item){
  const cp=Array.isArray(t.counterparties)?t.counterparties.find(x=>x?.logo_url||x?.name):null;
  return {...t,merchant_name:t.merchant_name||cp?.name||t.name||'Transaction',
    logo_url:t.logo_url||cp?.logo_url||null,merchant_logo_url:t.logo_url||cp?.logo_url||null,
    category_icon_url:t.personal_finance_category_icon_url||null,website:t.website||cp?.website||null,
    item_id:item.itemId,institution_name:item.institutionName||'Connected institution'};
}
async function upsertPlaidTransactions(userId,item,rows){
  if(useDb()){
    for(const t of rows) await pool.query(
      `INSERT INTO plaid_transactions(user_id,item_id,transaction_id,payload,removed,updated_at)
       VALUES($1,$2,$3,$4::jsonb,FALSE,NOW())
       ON CONFLICT(transaction_id) DO UPDATE SET payload=EXCLUDED.payload,removed=FALSE,updated_at=NOW()`,
      [userId,item.itemId,String(t.transaction_id),JSON.stringify(normalizeTransaction(t,item))]);
  } else { item.transactions=item.transactions||{}; for(const t of rows)item.transactions[String(t.transaction_id)]=normalizeTransaction(t,item); }
}
async function removePlaidTransactions(ids){
  const txids=ids.map(x=>String(x.transaction_id||x)).filter(Boolean); if(!txids.length)return;
  if(useDb()) await pool.query('UPDATE plaid_transactions SET removed=TRUE,updated_at=NOW() WHERE transaction_id = ANY($1)',[txids]);
  else for(const arr of memory.values())for(const item of arr)for(const id of txids)if(item.transactions)delete item.transactions[id];
}
async function storedTransactions(userId, limit=250){
  const safeLimit=Math.max(1,Math.min(Number(limit)||250,500));
  if(useDb()){
    const r=await pool.query(
      `SELECT payload FROM plaid_transactions
       WHERE user_id=$1 AND removed=FALSE
       ORDER BY COALESCE(payload->>'datetime',payload->>'date') DESC
       LIMIT $2`,[userId,safeLimit]);
    return r.rows.map(x=>x.payload);
  }
  return (memory.get(userId)||[]).flatMap(i=>Object.values(i.transactions||{}))
    .sort((a,b)=>String(b.datetime||b.date||'').localeCompare(String(a.datetime||a.date||'')))
    .slice(0,safeLimit);
}

app.get('/api/plaid/transactions/:userId', async (req,res)=>{
  if(!requirePlaid(res))return;
  try{
    const userId=req.params.userId,items=await getItems(userId),errors=[],sync=[];
    for(const item of items){
      try{
        let cursor=item.transactionsCursor||null,hasMore=true,addedCount=0,modifiedCount=0,removedCount=0,pages=0;
        while(hasMore&&pages<100){
          const request={access_token:item.accessToken,count:500}; if(cursor)request.cursor=cursor;
          const r=await plaid.transactionsSync(request),d=r.data||{};
          const added=Array.isArray(d.added)?d.added:[],modified=Array.isArray(d.modified)?d.modified:[],removed=Array.isArray(d.removed)?d.removed:[];
          await upsertPlaidTransactions(userId,item,[...added,...modified]); await removePlaidTransactions(removed);
          addedCount+=added.length;modifiedCount+=modified.length;removedCount+=removed.length;
          cursor=d.next_cursor||cursor;hasMore=Boolean(d.has_more);pages++;
        }
        await setTransactionsCursor(item.itemId,cursor);
        sync.push({item_id:item.itemId,institution_name:item.institutionName||'Connected institution',added:addedCount,modified:modifiedCount,removed:removedCount,pages});
      }catch(e){const d=e?.response?.data||{};console.error('transactions sync item failed',item.itemId,d||e);errors.push({item_id:item.itemId,institution_name:item.institutionName||'Connected institution',code:d.error_code||'transactions_sync_failed',message:d.error_message||e?.message||'Transaction sync failed'})}
    }
    res.json({transactions:await storedTransactions(userId,req.query.limit||250),fetched_at:new Date().toISOString(),sync,errors});
  }catch(e){console.error('transactions sync failed',e?.response?.data||e);res.status(500).json({error:'transactions_sync_failed',message:e?.response?.data?.error_message||e?.message||String(e)})}
});


app.get('/api/plaid/transactions-status/:userId', async (req,res)=>{
  if(!requirePlaid(res))return;
  try{
    const items=await getItems(req.params.userId),status=[];
    for(const item of items){
      try{
        const r=await plaid.itemGet({access_token:item.accessToken});
        status.push({
          item_id:item.itemId,
          institution_name:item.institutionName||'Connected institution',
          billed_products:r.data?.item?.billed_products||[],
          available_products:r.data?.item?.available_products||[],
          has_transactions_cursor:Boolean(item.transactionsCursor)
        });
      }catch(e){
        const d=e?.response?.data||{};
        status.push({item_id:item.itemId,institution_name:item.institutionName||'Connected institution',
          error_code:d.error_code||'item_status_failed',error_message:d.error_message||e?.message||'Unable to read Item status'});
      }
    }
    res.json({items:status});
  }catch(e){res.status(500).json({error:'transactions_status_failed',message:e?.message||String(e)})}
});

const port = Number(process.env.PORT || 8787);
await initStorage();
app.listen(port, '0.0.0.0', () => {
  console.log(`PayAviator backend ${APP_VERSION} listening on 0.0.0.0:${port}`);
  console.log(`Plaid ${plaidConfigured ? 'configured' : 'NOT configured'} (${env}); storage=${useDb() ? 'postgres' : 'memory'}`);
  if (dbError) console.log('Database startup error:', dbError);
});
