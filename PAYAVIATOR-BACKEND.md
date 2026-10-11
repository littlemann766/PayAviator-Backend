# PayAviator Backend Authority (backend 3.2.0)

This is the single deployment authority for the PayAviator banking backend.

## Runtime
- Node >= 20 / Express 5 backend for Plaid read-only connected accounts (Transactions + balances).
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

   Do not put `sslmode=` in `DATABASE_URL`; TLS is controlled by the variables above.
3. Deploy (`npm ci && npm start`). Check the logs for `database ready` and any `!!!` warnings, then `GET /api/health`.
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
| `DELETE /api/plaid/items/:itemId` | Disconnects (calls `/item/remove`, deletes the item's transactions). |
| `DELETE /api/plaid/user` | Account deletion: removes every Item at Plaid and all stored data. |

## Android app changes required (breaking)
1. **Send `Authorization: Bearer <ID token>` on every `/api/plaid/*` call** (e.g. Firebase `user.getIdToken()`, refreshed when it expires). Unauthenticated calls get `401 {code: "UNAUTHENTICATED" | "INVALID_TOKEN"}`; on 401 refresh the token once, then sign the user in again.
2. Stop sending a self-generated `userId`. Call the path-less routes (`/api/plaid/accounts` etc.). If you keep `/:userId` routes, the ID must equal the token's `sub`, otherwise `403 USER_MISMATCH`.
   Existing rows are keyed by the old app user ID, so after switching to authenticated IDs those users must relink their banks (or run a one-off SQL `UPDATE plaid_items/plaid_transactions SET user_id=<new>` mapping).
3. Handle item health: in `GET /api/plaid/accounts`, for each `items[]` entry with `needs_update: true` show "Reconnect", call `POST /api/plaid/update-link-token {item_id}`, open the returned `hosted_link_url`, then poll `GET /api/plaid/hosted-status` until `status` is `success` / `exited` / `failed`. `errors[]` in the accounts and transactions responses carry `code` + `needs_update`.
4. Show `error` from error responses to users (it is Plaid's `display_message` or a generic message); log `request_id` for support.
5. Call `DELETE /api/plaid/user` when a user deletes their PayAviator account.
