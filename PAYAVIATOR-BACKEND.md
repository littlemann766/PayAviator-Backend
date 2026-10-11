# PayAviator Backend Authority (backend 3.2.0)

This is the single deployment authority for the PayAviator banking backend.

## Runtime
- Node 24 LTS / Express 5 backend for Plaid read-only connected accounts (Transactions + balances).
- Node version: Railway builds this service with Railpack, which takes the version from `RAILPACK_NODE_VERSION` (if set), else
  `package.json` `engines.node` (`24.x`), else `.nvmrc` / `.node-version` (both `24`). Leave `RAILPACK_NODE_VERSION` unset so the repo
  stays the single source of truth. Node 20 reached end of life on 2026-04-30; do not pin below 24. After a deploy, the build log
  shows the resolved Node version.
- Railway service + Railway PostgreSQL.
- Entry point `server.js`; modules in `src/` (`config`, `auth`, `crypto`, `store`, `plaid`, `sync`, `webhooks`, `webhookVerify`, `app`).
- `npm test` runs the unit tests. Set `TEST_DATABASE_URL` to a disposable Postgres DB to also run the storage integration test.

## Financial rule
Transactions returned to the app are history/information. The app uses live included balances for Available Now, so transaction history must not be subtracted a second time.

## Security model
- Every `/api/plaid/*` endpoint except the webhook requires `Authorization: Bearer <token>`. The user is the token's `sub` (Firebase `uid`); user IDs in URLs/bodies are never trusted.
- Plaid access tokens are encrypted at rest (AES-256-GCM, `enc:v1:` prefix) with `TOKEN_ENCRYPTION_KEY`, and never returned to the app. Plaintext rows from older versions are encrypted automatically on boot (idempotent).
- Plaid webhooks are accepted only with a valid `Plaid-Verification` JWT (ES256, key from `/webhook_verification_key/get`, max age 5 min, body SHA-256 match).
- Startup fails fast on invalid configuration. With `PLAID_ENV=production` the server refuses to run without Postgres, encryption key, webhook URL, redirect URI and auth.
- Secrets live only in Railway variables. Never place secrets in the Android/WebView app.

## Railway deployment
1. Generate the encryption key once and store it in a password manager (losing it means every user must relink):
   `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`
2. Set Railway service variables (see `.env.example` for all options):

   | Variable | Production value |
   |---|---|
   | `PLAID_ENV` | `production` |
   | `PLAID_CLIENT_ID`, `PLAID_SECRET` | Production secret from Plaid Dashboard > Developers > Keys |
   | `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` (private network) |
   | `PGSSL` | `disable` **only** when DATABASE_URL uses `*.railway.internal` (traffic stays on Railway's encrypted private network). Otherwise leave unset and provide `DATABASE_SSL_CA`. |
   | `TOKEN_ENCRYPTION_KEY` | key from step 1 |
   | `PLAID_WEBHOOK_URL` | `https://<your-domain>/api/plaid/webhook` |
   | `PLAID_REDIRECT_URI` | `https://<your-domain>/plaid/oauth-redirect` (also add it in Plaid Dashboard > Allowed redirect URIs) |
   | `FIREBASE_PROJECT_ID` **or** `AUTH_JWKS_URL` + `AUTH_JWT_ISSUER` + `AUTH_JWT_AUDIENCE` **or** `APP_JWT_SECRET` | your auth provider |
   | `CORS_ORIGINS` | `https://appassets.androidplatform.net` plus any PWA origin |

   | `DATABASE_SSL_REJECT_UNAUTHORIZED` | Leave **unset** (defaults to `true` in production). `false` disables certificate checks and logs a `!!!` warning at boot. |

   Do not put `sslmode=` in `DATABASE_URL`; TLS is controlled by the variables above.

   Migrating from the old single-file server: it ignored `DATABASE_SSL_REJECT_UNAUTHORIZED` and always connected with TLS
   verification off. This version honors it, so before merging check the Railway service: with `DATABASE_URL` on
   `*.railway.internal`, set `PGSSL=disable` and delete `DATABASE_SSL_REJECT_UNAUTHORIZED`; with a public/proxy host, set
   `DATABASE_SSL_CA` (Railway's Postgres certificate is self-signed, so verification without a CA makes startup fail).
3. Deploy (`npm ci && npm start`; Railpack installs Node 24 from `engines.node`). Check the logs for `database ready` and any `!!!` warnings, then `GET /api/health`.
4. In Sandbox first: link a Sandbox institution, then fire test webhooks with `/sandbox/item/fire_webhook` and test update mode with `/sandbox/item/reset_login`.
5. Switch to Production only by changing `PLAID_ENV` + `PLAID_SECRET`. Sandbox Items do not work in Production; users relink.

## Endpoints
Public: `GET /`, `GET /api/health`, `GET /plaid/oauth-redirect`, `POST /api/plaid/webhook` (Plaid-signed).

Authenticated (`Authorization: Bearer ...`). Legacy `/:userId` variants still work but return 403 unless the ID equals the token's user:

| Method & path | Purpose |
|---|---|
| `POST /api/plaid/create-link-token` | New connection (Hosted Link). Returns `link_token`, `hosted_link_url`. |
| `GET /api/plaid/hosted-status` | Poll after Hosted Link completes; exchanges tokens idempotently. Handles add and update mode. |
| `POST /api/plaid/exchange-public-token` | `{ public_token, metadata }` for non-hosted Link SDK flows. |
| `POST /api/plaid/update-link-token` | `{ item_id }`: starts update mode (re-login / new accounts). |
| `POST /api/plaid/update-complete` | `{ item_id }`: for non-hosted flows after update-mode success. |
| `GET /api/plaid/accounts` | Balances plus `items[]` with `status`, `error_code`, `needs_update`, `new_accounts_available`. |
| `GET /api/plaid/transactions?limit=250&refresh=1` | Syncs (unless `refresh=0`) and returns stored transactions + per-item `errors`. |
| `GET /api/plaid/transactions-status` | Per-item Plaid product status. |
| `DELETE /api/plaid/items/:itemId` | Disconnects one bank: calls `/item/remove`, then deletes the item, its transactions, its exchanged-public-token hash rows and any pending update-mode link for it, in one DB transaction. If `/item/remove` fails the row is kept so the call can be retried. |
| `DELETE /api/plaid/user` | Account deletion: removes every Item at Plaid, then deletes the user's items, transactions, pending links and exchanged-token rows in one DB transaction. Items whose removal failed are kept (502 + `failed_item_ids`) so the call can be retried. |

## Android app changes required (breaking)
1. **Send `Authorization: Bearer <ID token>` on every `/api/plaid/*` call** (e.g. Firebase `user.getIdToken()`, refreshed when it expires). Unauthenticated calls get `401 {code: "UNAUTHENTICATED" | "INVALID_TOKEN"}`; on 401 refresh the token once, then sign the user in again.
2. Stop sending a self-generated `userId`. Call the path-less routes (`/api/plaid/accounts` etc.). If you keep `/:userId` routes, the ID must equal the token's `sub`, otherwise `403 USER_MISMATCH`.
   Existing rows are keyed by the old app user ID, so after switching to authenticated IDs those users must relink their banks (or run a one-off SQL `UPDATE plaid_items/plaid_transactions SET user_id=<new>` mapping).
3. Handle item health: in `GET /api/plaid/accounts`, for each `items[]` entry with `needs_update: true` show "Reconnect", call `POST /api/plaid/update-link-token {item_id}`, open the returned `hosted_link_url`, then poll `GET /api/plaid/hosted-status` until `status` is `success` / `exited` / `failed`. `errors[]` in the accounts and transactions responses carry `code` + `needs_update`.
4. Show `error` from error responses to users (it is Plaid's `display_message` or a generic message); log `request_id` for support.
5. Call `DELETE /api/plaid/user` when a user deletes their PayAviator account.

## Revoked consent (USER_PERMISSION_REVOKED / USER_ACCOUNT_REVOKED)
When Plaid reports that the user revoked access (the `ITEM` webhooks `USER_PERMISSION_REVOKED` or `USER_ACCOUNT_REVOKED`, an `ITEM`
`ERROR` / API error with one of those codes, or any Item error with reason `OAUTH_USER_REVOKED`), the backend, in one DB transaction:
- deletes all of that Item's stored transactions and its exchanged-public-token hash rows,
- deletes a pending update-mode link for that Item and resets its `/transactions/sync` cursor,
- keeps only the minimal Item row (item/institution ids and name, `status: "revoked"`, error code, encrypted access token) so
  `GET /api/plaid/accounts` still lists it with `needs_update: true` and the app can offer "Reconnect" or "Remove".

Syncs that were already running when the revocation arrived are discarded instead of written back. `/item/remove` is not called
automatically: Plaid ends subscription billing when the user revokes, and keeping the Item lets update mode restore it. If the user
reconnects, the Item returns to `good` and re-syncs from scratch. If they choose "Remove", `DELETE /api/plaid/items/:itemId`
deletes the row. If update mode can't start for a revoked Item, Plaid's guidance is to create a fresh link token (new connection).

## Post-3.9.7 step: remove legacy (pre-Firebase) bank links
App versions before 3.9.7 stored banks under self-generated IDs (`pp-…`, `ppd_…`). After the Firebase sign-in build is live and
users have relinked, remove those orphaned Plaid Items. Otherwise they stay billed and their data stays stored.

`scripts/cleanup-legacy-items.js` treats any `user_id` that is not a Firebase uid (20-128 alphanumeric characters) as legacy.
It uses the same environment variables as the server. Run it inside the Railway service so the private database host resolves:

```bash
railway ssh --service PayAviator-Backend          # or the dashboard's shell
node scripts/cleanup-legacy-items.js              # dry run (default): prints counts only
node scripts/cleanup-legacy-items.js --apply      # /item/remove each legacy Item, then delete items,
                                                  # transactions, pending links, exchanged-token rows
```

Output is counts plus, for failures, `item_id` + Plaid `error_code`/`request_id` (never tokens). Items whose `/item/remove`
fails are kept and can be retried by re-running `--apply`. It's safe to re-run.

## Logging and retention
Server logs are JSON lines on stdout/stderr, captured by Railway. They contain only: message, Firebase `user_id`, Plaid `item_id`,
Plaid `request_id`, `error_type` / `error_code` / HTTP status, webhook type/code, and counts.
They never contain access/public/link tokens, the Plaid secret, Authorization headers or ID tokens, or transaction/account/balance payloads.
`src/log.js` also redacts token- and JWT-shaped strings and drops payload-type fields as a backstop. Malformed-request errors (4xx) log only
their type, not the message, because parser messages can echo the request body.
Railway retains these logs for the period of the workspace's plan (see Railway's pricing/plan docs). Mention this in the privacy
policy's "service providers / logs" section.
